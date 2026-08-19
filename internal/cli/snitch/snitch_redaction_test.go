package snitch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSensitiveTextPatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "authorization header",
			input: "request failed with authorization=Basic dXNlcjpwYXNzd29yZA== after retry",
			want:  "request failed with Authorization: [REDACTED] after retry",
		},
		{
			name:  "standalone bearer credential",
			input: "server returned Bearer eyJhbGciOiJFUzI1NiJ9.fake.signature",
			want:  "server returned Bearer [REDACTED]",
		},
		{
			name:  "signed URL credentials",
			input: "upload https://example.test/file?part=1&X-Amz-Credential=ACCESS%2F20260819&X-Amz-Signature=abcdef0123456789#result",
			want:  "upload https://example.test/file?part=1&X-Amz-Credential=[REDACTED]&X-Amz-Signature=[REDACTED]#result",
		},
		{
			name:  "private key block",
			input: "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nkey-material\n-----END OPENSSH PRIVATE KEY-----\nafter",
			want:  "before\n[REDACTED PRIVATE KEY]\nafter",
		},
		{
			name:  "PGP private key block",
			input: "before\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nkey-material\n-----END PGP PRIVATE KEY BLOCK-----\nafter",
			want:  "before\n[REDACTED PRIVATE KEY]\nafter",
		},
		{
			name:  "shell assignment",
			input: `command CLIENT_SECRET="super secret value" --verbose`,
			want:  "command CLIENT_SECRET=[REDACTED] --verbose",
		},
		{
			name:  "space-separated secret flag",
			input: `asc web sandbox create --email "user@example.test" --password "Passwordtest1" --territory "USA"`,
			want:  `asc web sandbox create --email "user@example.test" --password [REDACTED] --territory "USA"`,
		},
		{
			name:  "JSON assignment",
			input: `response {"refresh_token":"refresh-value","status":"failed"}`,
			want:  `response {"refresh_token":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "JWT",
			input: "decoded eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.c2lnbmF0dXJl failed",
			want:  "decoded [REDACTED] failed",
		},
		{
			name:  "known opaque token",
			input: "credential ghp_abcdefghijklmnopqrstuvwxyz123456",
			want:  "credential [REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := redactSensitiveText(tt.input)
			if !changed {
				t.Fatalf("redactSensitiveText() did not report a change for %q", tt.input)
			}
			if got != tt.want {
				t.Fatalf("redactSensitiveText() = %q, want %q", got, tt.want)
			}
			gotAgain, changedAgain := redactSensitiveText(got)
			if changedAgain || gotAgain != got {
				t.Fatalf("redaction is not idempotent: second result %q, changed=%t", gotAgain, changedAgain)
			}
		})
	}
}

func TestSnitchDryRunRedactsEveryReportField(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"eyJhbGciOiJFUzI1NiJ9.fake.signature",
		"0123456789abcdef0123456789abcdef",
		"private-key-payload",
		"client-secret-value",
		"Passwordtest1",
	}
	privateKey := "-----BEGIN PRIVATE KEY-----\n" + secrets[2] + "\n-----END PRIVATE KEY-----"

	_, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", `curl "https://uploads.example.test/file?X-Amz-Signature=`+secrets[1]+`&part=2"`+"\n"+`asc web sandbox create --password "`+secrets[4]+`"`,
		"--expected", "load this key\n"+privateKey+"\nthen retry",
		"--actual", `client_secret="`+secrets[3]+`"`,
		"Authorization: Bearer "+secrets[0]+" failed",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range secrets {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked %q: %q", secret, stderr)
		}
	}
	for _, want := range []string{
		"Authorization: [REDACTED] failed",
		"X-Amz-Signature=[REDACTED]&part=2",
		"asc web sandbox create --password [REDACTED]",
		"load this key\n[REDACTED PRIVATE KEY]\nthen retry",
		"client_secret=[REDACTED]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
	if got := strings.Count(stderr, "sensitive values were redacted"); got != 1 {
		t.Fatalf("stderr = %q, want exactly one redaction notice, got %d", stderr, got)
	}
}

func TestWriteLocalLogRedactsEveryStringField(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origDir); err != nil {
			t.Fatalf("os.Chdir restore error: %v", err)
		}
	})
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("os.Chdir temp dir error: %v", err)
	}

	secrets := []string{
		"description-secret",
		"reproduction-secret",
		"expected-secret",
		"actual-secret",
		"label-secret",
		"version-secret",
		"os-secret",
	}
	entry := LogEntry{
		Description: "token=" + secrets[0],
		Repro:       "api_key=" + secrets[1],
		Expected:    "password=" + secrets[2],
		Actual:      "refresh_token=" + secrets[3],
		Labels:      []string{"client_secret=" + secrets[4]},
		Severity:    "bug",
		ASCVersion:  "access_token=" + secrets[5],
		OS:          "webhook_secret=" + secrets[6],
	}

	if err := writeLocalLog(entry); err != nil {
		t.Fatalf("writeLocalLog() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(".asc", "snitch.log"))
	if err != nil {
		t.Fatalf("os.ReadFile() error: %v", err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatalf("local log leaked %q: %s", secret, data)
		}
	}
	if got := strings.Count(string(data), "[REDACTED]"); got != len(secrets) {
		t.Fatalf("local log = %s, want %d redaction markers, got %d", data, len(secrets), got)
	}
}

func TestSearchIssuesRedactsCredentialInQuery(t *testing.T) {
	const secret = "query-bearer-secret"
	var searchQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searchQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"items":[]}`)); err != nil {
			t.Fatalf("w.Write() error: %v", err)
		}
	}))
	defer server.Close()

	origBase := githubAPIBase
	defer func() { setGitHubAPIBase(origBase) }()
	setGitHubAPIBase(server.URL)

	if _, err := searchIssues(t.Context(), "test-token", "Authorization: Bearer "+secret); err != nil {
		t.Fatalf("searchIssues() error: %v", err)
	}
	if strings.Contains(searchQuery, secret) {
		t.Fatalf("duplicate-search query leaked the credential: %q", searchQuery)
	}
	if !strings.Contains(searchQuery, "Authorization: [REDACTED]") {
		t.Fatalf("duplicate-search query = %q, want redacted context", searchQuery)
	}
}

func TestCreateIssueRedactsCredentialPayload(t *testing.T) {
	const secret = "issue-payload-secret"
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("json.Decode() error: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"number":42,"title":"redacted","html_url":"https://example.test/issues/42"}`)); err != nil {
			t.Fatalf("w.Write() error: %v", err)
		}
	}))
	defer server.Close()

	origBase := githubAPIBase
	defer func() { setGitHubAPIBase(origBase) }()
	setGitHubAPIBase(server.URL)

	entry := LogEntry{
		Description: "token=" + secret,
		Actual:      "Bearer " + secret,
		Severity:    "bug",
	}
	if _, err := createIssue(t.Context(), "test-token", entry); err != nil {
		t.Fatalf("createIssue() error: %v", err)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("issue request leaked the credential: %s", encoded)
	}
	if got := strings.Count(string(encoded), "[REDACTED]"); got < 2 {
		t.Fatalf("issue request = %s, want redacted title and body", encoded)
	}
}

func TestAddIssueLabelsRedactsSensitiveValues(t *testing.T) {
	const secret = "label-payload-secret"
	var payload map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("json.Decode() error: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"labels":[]}`)); err != nil {
			t.Fatalf("w.Write() error: %v", err)
		}
	}))
	defer server.Close()

	origBase := githubAPIBase
	defer func() { setGitHubAPIBase(origBase) }()
	setGitHubAPIBase(server.URL)

	if err := addIssueLabels(t.Context(), "test-token", 42, []string{"token=" + secret}); err != nil {
		t.Fatalf("addIssueLabels() error: %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("label request leaked the credential: %s", encoded)
	}
	if !strings.Contains(string(encoded), "[REDACTED]") {
		t.Fatalf("label request = %s, want a redaction marker", encoded)
	}
}

func TestFormatLocalEntriesRedactsLegacyCredentials(t *testing.T) {
	const secret = "legacy-log-secret"
	formatted := formatLocalEntries([]LogEntry{{
		Description: "old entry",
		Actual:      "Authorization: Bearer " + secret,
		Severity:    "bug",
	}})

	if strings.Contains(formatted, secret) {
		t.Fatalf("formatted log leaked the credential: %q", formatted)
	}
	if !strings.Contains(formatted, "Authorization: [REDACTED]") {
		t.Fatalf("formatted log = %q, want redacted context", formatted)
	}
}

func TestIssueBodyPreservesBenignSecurityVocabulary(t *testing.T) {
	entry := LogEntry{
		Description: "token refresh failed",
		Repro:       "asc builds list --filter-key token\nasc signing sync pull --password-file /tmp/sync-password",
		Expected:    "secret scanning documentation remains visible",
		Actual:      "request to https://example.test/path?signature_state=missing returned 401",
		Severity:    "bug",
	}
	body := issueBody(entry)

	for _, want := range []string{entry.Description, entry.Repro, entry.Expected, entry.Actual} {
		if !strings.Contains(body, want) {
			t.Fatalf("issue body = %q, want benign text %q preserved", body, want)
		}
	}
	if strings.Contains(body, "[REDACTED]") {
		t.Fatalf("issue body unexpectedly redacted benign diagnostics: %q", body)
	}
}
