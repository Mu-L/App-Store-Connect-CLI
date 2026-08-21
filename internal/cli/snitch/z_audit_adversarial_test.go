package snitch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditAdversarialCredentialBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"curl certificate continuation", "curl --cert \\\n  client.p12:curl-continuation-secret https://example.test", "curl --cert \\\n  client.p12:[REDACTED] https://example.test"},
		{"curl empty certificate path", "curl --cert :empty-path-cert-secret https://example.test", "curl --cert :[REDACTED] https://example.test"},
		{"curl empty proxy certificate path", "curl --proxy-cert :empty-proxy-cert-secret https://example.test", "curl --proxy-cert :[REDACTED] https://example.test"},
		{"curl short certificate path", "curl -E :short-cert-secret https://example.test", "curl -E :[REDACTED] https://example.test"},
		{"curl user continuation", "curl --user \\\n  alice:continued-curl-secret https://example.test", "curl --user \\\n  [REDACTED] https://example.test"},
		{"authorization query preserves URL shape", "https://example.test/auth?authorization=authorization-query-secret&state=ok", "https://example.test/auth?authorization=[REDACTED]&state=ok"},
		{"double encoded password query", "https://example.test/auth?pass%2577ord=double-encoded-query-secret&state=ok", "https://example.test/auth?pass%2577ord=[REDACTED]&state=ok"},
		{"bare auth query", "https://example.test/auth?auth=opaque-auth-query-secret&state=ok", "https://example.test/auth?auth=[REDACTED]&state=ok"},
		{"xml authorization element", "<authorization>xml-authorization-secret</authorization><status>ok</status>", "<authorization>[REDACTED]</authorization><status>ok</status>"},
		{"redis short pass", "redis-cli -a redis-short-secret GET foo", "redis-cli -a [REDACTED] GET foo"},
		{"redis long pass", "redis-cli --pass redis-long-secret GET foo", "redis-cli --pass [REDACTED] GET foo"},
		{"redis attached short option is positional", "redis-cli -akey GET foo", "redis-cli -akey GET foo"},
		{"redis continuation", "redis-cli -a \\\n  redis-continuation-secret PING", "redis-cli -a \\\n  [REDACTED] PING"},
		{"grep password", "grep --password public-word logfile", "grep --password public-word logfile"},
		{"nested curl in echo", "echo \"$(curl --user alice:nested-curl-secret https://example.test)\"", "echo \"$(curl --user [REDACTED] https://example.test)\""},
		{"wrapped curl", "env -- curl --user alice:wrapped-curl-secret https://example.test", "env -- curl --user [REDACTED] https://example.test"},
		{"echo password", "echo --password public-word", "echo --password public-word"},
		{"launchctl executable boundary", "launchctl submit -l signer -p echo -- echo openssl s_client -psk launchctl-public-secret", "launchctl submit -l signer -p echo -- echo openssl s_client -psk launchctl-public-secret"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, changed := redactSensitiveText(test.input)
			if got != test.want {
				t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want %q", test.input, got, changed, test.want)
			}
			again, changedAgain := redactSensitiveText(got)
			if again != got || changedAgain {
				t.Fatalf("redaction is not idempotent: second result %q, changed=%t", again, changedAgain)
			}
		})
	}
}

func TestAuditMalformedKubernetesSecretJSONStopsAtUnmatchedOuterContainer(t *testing.T) {
	var input strings.Builder
	input.WriteString(`{"kind":"Secret","data":`)
	for index := 0; index < 4000; index++ {
		input.WriteByte('{')
	}
	for index := 0; index < 4000; index++ {
		input.WriteByte('}')
	}

	value := input.String()
	if end := findJSONContainerEndAtDepthStrict(value, strings.IndexByte(value, '{'), 0); end >= 0 {
		t.Fatalf("unmatched outer JSON object reported close at %d", end)
	}
	got, changed := redactSensitiveText(value)
	if changed || got != value {
		t.Fatalf("malformed JSON changed unexpectedly: changed=%t, output prefix=%q", changed, got[:min(len(got), 120)])
	}
}

func BenchmarkAuditMalformedKubernetesSecretJSON(b *testing.B) {
	var input strings.Builder
	input.WriteString(`{"kind":"Secret","data":`)
	for index := 0; index < 4000; index++ {
		input.WriteByte('{')
	}
	for index := 0; index < 4000; index++ {
		input.WriteByte('}')
	}
	value := input.String()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		redactSensitiveText(value)
	}
}

func TestAuditDuplicateSearchSinkRedactsRedisCredential(t *testing.T) {
	const secret = "redis-sink-secret"
	var searchQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searchQuery = r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	originalBase := githubAPIBase
	t.Cleanup(func() { setGitHubAPIBase(originalBase) })
	setGitHubAPIBase(server.URL)

	if _, err := searchIssues(t.Context(), "synthetic-token", "redis-cli -a "+secret+" GET foo"); err != nil {
		t.Fatalf("searchIssues() error: %v", err)
	}
	if strings.Contains(searchQuery, secret) {
		t.Fatalf("duplicate-search query leaked the credential: %q", searchQuery)
	}
	if !strings.Contains(searchQuery, "redis-cli -a [REDACTED] GET foo") {
		t.Fatalf("duplicate-search query = %q, want scoped redaction", searchQuery)
	}
}
