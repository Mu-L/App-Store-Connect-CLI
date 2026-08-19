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
			name:  "parameterized authorization header",
			input: "Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260819/region/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef0123456789",
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "digest authorization header",
			input: `Authorization: Digest username="user", nonce="nonce-value", response="credential-value"`,
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "signature authorization header with arbitrary first parameter",
			input: `Authorization: Signature keyId="my-key",algorithm="rsa-sha256",signature="credential-value"`,
			want:  "Authorization: [REDACTED]",
		},
		{
			name:  "arbitrary authorization token scheme",
			input: `Authorization: Negotiate dG9rZW4tc2VjcmV0`,
			want:  "Authorization: [REDACTED]",
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
			name:  "client secret URL parameter",
			input: "callback https://example.test/path?client_secret=client-value&state=ready",
			want:  "callback https://example.test/path?client_secret=[REDACTED]&state=ready",
		},
		{
			name:  "refresh token URL parameter",
			input: "callback https://example.test/path?refresh_token=refresh-value&state=ready",
			want:  "callback https://example.test/path?refresh_token=[REDACTED]&state=ready",
		},
		{
			name:  "password URL parameter",
			input: "callback https://example.test/path?password=password-value&state=ready",
			want:  "callback https://example.test/path?password=[REDACTED]&state=ready",
		},
		{
			name:  "private key URL parameter",
			input: "callback https://example.test/path?private_key=private-key-value&state=ready",
			want:  "callback https://example.test/path?private_key=[REDACTED]&state=ready",
		},
		{
			name:  "URL userinfo credentials",
			input: "fetch https://user:p%40ss%2Fword@example.test/private/path?part=1",
			want:  "fetch https://[REDACTED]@example.test/private/path?part=1",
		},
		{
			name:  "URL userinfo with encoded separator",
			input: "fetch sftp://user%3Ap%2540ss@example.test/private/path",
			want:  "fetch sftp://[REDACTED]@example.test/private/path",
		},
		{
			name:  "URL username-only credential",
			input: "fetch https://access-token@example.test/private/path",
			want:  "fetch https://[REDACTED]@example.test/private/path",
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
			name:  "unterminated private key block",
			input: "before\n-----BEGIN PRIVATE KEY-----\ntruncated-key-material",
			want:  "before\n[REDACTED PRIVATE KEY]",
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
			name:  "escaped quote in secret flag",
			input: `asc deploy --password "pa\"ssword" --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "comma in unquoted secret flag",
			input: `asc web sandbox create --password Password1,remaining-secret --territory USA`,
			want:  `asc web sandbox create --password [REDACTED] --territory USA`,
		},
		{
			name:  "compound password flag",
			input: `asc review details-create --demo-account-password "app-specific-password" --notes ready`,
			want:  `asc review details-create --demo-account-password [REDACTED] --notes ready`,
		},
		{
			name:  "single dash password flag",
			input: `asc web sandbox create -password "Passwordtest1" -territory USA`,
			want:  `asc web sandbox create -password [REDACTED] -territory USA`,
		},
		{
			name:  "password value beginning with double dash",
			input: `asc web sandbox create --password --Passwordtest1 --territory USA`,
			want:  `asc web sandbox create --password [REDACTED] --territory USA`,
		},
		{
			name:  "boolean secret marker with sensitive named value",
			input: `asc web xcode-cloud env-vars create --name MY_SECRET --value s3cret --secret --apple-id 123456789`,
			want:  `asc web xcode-cloud env-vars create --name MY_SECRET --value [REDACTED] --secret --apple-id 123456789`,
		},
		{
			name:  "boolean secret marker before value",
			input: `asc web xcode-cloud env-vars create --name PRIVATE_CONFIG --secret --value s3cret --apple-id 123456789`,
			want:  `asc web xcode-cloud env-vars create --name PRIVATE_CONFIG --secret --value [REDACTED] --apple-id 123456789`,
		},
		{
			name:  "boolean secret marker after intervening flag",
			input: `asc web xcode-cloud env-vars create --value s3cret --name MY_SECRET --secret --apple-id 123456789`,
			want:  `asc web xcode-cloud env-vars create --value [REDACTED] --name MY_SECRET --secret --apple-id 123456789`,
		},
		{
			name:  "boolean secret marker before intervening flag",
			input: `asc web xcode-cloud env-vars create --secret --name MY_SECRET --value s3cret --apple-id 123456789`,
			want:  `asc web xcode-cloud env-vars create --secret --name MY_SECRET --value [REDACTED] --apple-id 123456789`,
		},
		{
			name:  "boolean secret marker redacts duplicate values",
			input: `asc web xcode-cloud env-vars create --value old-secret --value effective-secret --secret`,
			want:  `asc web xcode-cloud env-vars create --value [REDACTED] --value [REDACTED] --secret`,
		},
		{
			name: "boolean secret marker after continued value",
			input: `asc web xcode-cloud env-vars create --value continued-secret \
  --secret`,
			want: `asc web xcode-cloud env-vars create --value [REDACTED] \
  --secret`,
		},
		{
			name: "boolean secret marker before continued value",
			input: `asc web xcode-cloud env-vars create --secret \
  --value continued-secret`,
			want: `asc web xcode-cloud env-vars create --secret \
  --value [REDACTED]`,
		},
		{
			name:  "boolean secret marker with value equals form",
			input: `asc web xcode-cloud env-vars create --value=s3cret --secret`,
			want:  `asc web xcode-cloud env-vars create --value=[REDACTED] --secret`,
		},
		{
			name:  "boolean secret marker with explicit true value",
			input: `asc web xcode-cloud env-vars create --value s3cret --secret=true`,
			want:  `asc web xcode-cloud env-vars create --value [REDACTED] --secret=[REDACTED]`,
		},
		{
			name:  "boolean secret marker with explicit numeric true value",
			input: `asc web xcode-cloud env-vars create --secret=1 --value s3cret`,
			want:  `asc web xcode-cloud env-vars create --secret=[REDACTED] --value [REDACTED]`,
		},
		{
			name:  "boolean secret marker does not affect another line",
			input: "asc unrelated --value public\nasc webhooks create --secret webhook-secret",
			want:  "asc unrelated --value public\nasc webhooks create --secret [REDACTED]",
		},
		{
			name:  "unterminated quoted secret flag",
			input: "asc deploy --password \"super secret value",
			want:  "asc deploy --password [REDACTED]",
		},
		{
			name:  "ANSI-C quoted secret flag",
			input: `asc deploy --password $'super secret value' --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "ANSI-C quoted assignment",
			input: `PASSWORD=$'super secret value' asc builds list`,
			want:  `PASSWORD=[REDACTED] asc builds list`,
		},
		{
			name:  "backslash escaped whitespace in secret flag",
			input: `asc deploy --password super\ secret --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "backslash escaped whitespace in assignment",
			input: `PASSWORD=super\ secret asc builds list`,
			want:  `PASSWORD=[REDACTED] asc builds list`,
		},
		{
			name:  "equals form secret flag",
			input: `asc deploy --demo-account-password=super-secret --verbose`,
			want:  `asc deploy --demo-account-password=[REDACTED] --verbose`,
		},
		{
			name:  "curl long user password flag",
			input: `curl --user alice:supersensitive https://example.test`,
			want:  `curl --user [REDACTED] https://example.test`,
		},
		{
			name:  "curl short user password flag",
			input: `curl -u 'alice:super sensitive' https://example.test`,
			want:  `curl -u [REDACTED] https://example.test`,
		},
		{
			name:  "curl attached short user password flag",
			input: `curl -ualice:supersensitive https://example.test`,
			want:  `curl -u[REDACTED] https://example.test`,
		},
		{
			name:  "curl equals user password flag",
			input: `curl --user=alice:supersensitive https://example.test`,
			want:  `curl --user=[REDACTED] https://example.test`,
		},
		{
			name:  "curl OAuth bearer flag",
			input: `curl --oauth2-bearer supersensitive https://example.test`,
			want:  `curl --oauth2-bearer [REDACTED] https://example.test`,
		},
		{
			name:  "curl long proxy user password flag",
			input: `curl --proxy-user alice:supersensitive https://example.test`,
			want:  `curl --proxy-user [REDACTED] https://example.test`,
		},
		{
			name:  "curl short proxy user password flag",
			input: `curl -U 'alice:super sensitive' https://example.test`,
			want:  `curl -U [REDACTED] https://example.test`,
		},
		{
			name:  "curl attached short proxy user password flag",
			input: `curl -Ualice:supersensitive https://example.test`,
			want:  `curl -U[REDACTED] https://example.test`,
		},
		{
			name:  "comma in unquoted assignment",
			input: `PASSWORD=Password1,remaining-secret asc builds list`,
			want:  `PASSWORD=[REDACTED] asc builds list`,
		},
		{
			name:  "prefixed environment assignment",
			input: `AWS_SECRET_ACCESS_KEY="cloud-secret" MY_CLIENT_SECRET='client-secret'`,
			want:  `AWS_SECRET_ACCESS_KEY=[REDACTED] MY_CLIENT_SECRET=[REDACTED]`,
		},
		{
			name:  "leading underscore assignment",
			input: `//registry.npmjs.org/:_authToken=npm-secret`,
			want:  `//registry.npmjs.org/:_authToken=[REDACTED]`,
		},
		{
			name:  "JSON assignment",
			input: `response {"refresh_token":"refresh-value","status":"failed"}`,
			want:  `response {"refresh_token":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "prefixed JSON assignments",
			input: `response {"AWS_SECRET_ACCESS_KEY":"cloud-secret-value","MY_CLIENT_SECRET":"client secret value"}`,
			want:  `response {"AWS_SECRET_ACCESS_KEY":"[REDACTED]","MY_CLIENT_SECRET":"[REDACTED]"}`,
		},
		{
			name:  "pretty-printed JSON assignment",
			input: "response {\n  \"client_secret\":\n    \"arbitrary secret\",\n  \"status\": \"failed\"\n}",
			want:  "response {\n  \"client_secret\":\n    \"[REDACTED]\",\n  \"status\": \"failed\"\n}",
		},
		{
			name:  "camel case JSON assignments",
			input: `response {"demoAccountPassword":"review-secret","awsSecretAccessKey":"cloud-secret"}`,
			want:  `response {"demoAccountPassword":"[REDACTED]","awsSecretAccessKey":"[REDACTED]"}`,
		},
		{
			name:  "escaped JSON assignment",
			input: `response {\"client_secret\":\"super\\\"sensitive\",\"status\":\"failed\"}`,
			want:  `response {\"client_secret\":\"[REDACTED]\",\"status\":\"failed\"}`,
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

func TestRedactSensitiveTextFalseSecretMarkerPreservesValue(t *testing.T) {
	const publicValue = "public-value"
	input := "asc web xcode-cloud env-vars create --value " + publicValue + " --secret=false"
	want := "asc web xcode-cloud env-vars create --value " + publicValue + " --secret=[REDACTED]"

	got, changed := redactSensitiveText(input)
	if !changed || got != want {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want %q", input, got, changed, want)
	}
}

func TestRedactSensitiveTextDoesNotJoinEscapedBackslashLines(t *testing.T) {
	input := `asc unrelated --value public \\
asc web xcode-cloud env-vars create --secret`

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
	}
}

func TestRedactSensitiveTextPreservesURLQueryAndFragmentAtSigns(t *testing.T) {
	tests := []string{
		"https://example.test?next=a:b@evil.test",
		"https://example.test/path#value=a:b@evil.test",
	}

	for _, input := range tests {
		got, changed := redactSensitiveText(input)
		if changed || got != input {
			t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
		}
	}
}

func TestSnitchDryRunRedactsURLUserinfoCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	const userinfo = "user:p%40ss%2Fword"
	const usernameOnly = "access-token"
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--actual", "requests to https://"+userinfo+"@example.test/private/path and sftp://"+usernameOnly+"@files.example.test/upload failed",
		"userinfo redaction probe",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range []string{userinfo, usernameOnly} {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked URL userinfo credentials: %q", stderr)
		}
		if strings.Contains(stdout, secret) {
			t.Fatalf("stdout leaked URL userinfo credentials: %q", stdout)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	if !strings.Contains(stderr, "https://[REDACTED]@example.test/private/path") {
		t.Fatalf("stderr = %q, want the URL without userinfo credentials", stderr)
	}
	if !strings.Contains(stderr, "sftp://[REDACTED]@files.example.test/upload") {
		t.Fatalf("stderr = %q, want the username-only URL without credentials", stderr)
	}
	if !strings.Contains(stderr, "sensitive values were redacted") {
		t.Fatalf("stderr = %q, want a generic redaction notice", stderr)
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
		"remaining-secret",
		"prefixed-secret",
	}
	privateKey := "-----BEGIN PRIVATE KEY-----\n" + secrets[2] + "\n-----END PRIVATE KEY-----"

	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", `curl "https://uploads.example.test/file?X-Amz-Signature=`+secrets[1]+`&part=2"`+"\n"+`asc web sandbox create --password "`+secrets[4]+`"`+"\n"+`asc deploy --password "pa\"`+secrets[5]+`"`,
		"--expected", "load this key\n"+privateKey+"\nthen retry",
		"--actual", `client_secret="`+secrets[3]+`" MY_CLIENT_SECRET="`+secrets[6]+`"`,
		"Authorization: Bearer "+secrets[0]+" failed",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range secrets {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked %q: %q", secret, stderr)
		}
		if strings.Contains(stdout, secret) {
			t.Fatalf("stdout leaked %q: %q", secret, stdout)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	for _, want := range []string{
		"Authorization: [REDACTED] failed",
		"X-Amz-Signature=[REDACTED]&part=2",
		"asc web sandbox create --password [REDACTED]",
		"asc deploy --password [REDACTED]",
		"load this key\n[REDACTED PRIVATE KEY]\nthen retry",
		"client_secret=[REDACTED] MY_CLIENT_SECRET=[REDACTED]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
	if got := strings.Count(stderr, "sensitive values were redacted"); got != 1 {
		t.Fatalf("stderr = %q, want exactly one redaction notice, got %d", stderr, got)
	}
}

func TestSnitchDryRunRedactsMalformedAndCompoundCLISecrets(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"app-specific-password",
		"xcode-cloud-value",
		"unterminated secret value",
		"Password1,remaining-secret",
		"credential-value",
		"single-dash-password",
		"ANSI-C quoted password",
		"ANSI-C assigned password",
		"escaped-flag-tail",
		"escaped-assignment-tail",
		"reordered-cloud-value",
		"--DoubleDashPassword",
		"curl-password-tail",
		"curl-oauth-bearer-tail",
		"curl-attached-user-tail",
		"curl-attached-proxy-tail",
	}
	repro := strings.Join([]string{
		`asc review details-create --demo-account-password "` + secrets[0] + `" --notes ready`,
		`asc web xcode-cloud env-vars create --name MY_SECRET --value ` + secrets[1] + ` --secret --apple-id 123456789`,
		`asc web xcode-cloud env-vars create --value ` + secrets[10] + ` --name MY_SECRET --secret --apple-id 123456789`,
		`asc deploy --password "` + secrets[2],
		`asc web sandbox create -password "` + secrets[5] + `" -territory USA`,
		`asc deploy --password $'` + secrets[6] + `' --verbose`,
		`asc deploy --password prefix\ ` + secrets[8] + ` --verbose`,
		`asc web sandbox create --password ` + secrets[11] + ` --territory USA`,
		`curl -u alice:` + secrets[12] + ` https://example.test`,
		`curl --oauth2-bearer ` + secrets[13] + ` https://example.test`,
		`curl -ualice:` + secrets[14] + ` https://example.test`,
		`curl -Ualice:` + secrets[15] + ` https://example.test`,
	}, "\n")
	actual := "PASSWORD=" + secrets[3] + "\n" +
		`PASSWORD=$'` + secrets[7] + "'\n" +
		`PASSWORD=prefix\ ` + secrets[9] + "\n" +
		`Authorization: Signature keyId="my-key",algorithm="rsa-sha256",signature="` + secrets[4] + `"`

	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", repro,
		"--actual", actual,
		"compound redaction probe",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range secrets {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked %q: %q", secret, stderr)
		}
		if strings.Contains(stdout, secret) {
			t.Fatalf("stdout leaked %q: %q", secret, stdout)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	for _, want := range []string{
		"--demo-account-password [REDACTED] --notes ready",
		"--name MY_SECRET --value [REDACTED] --secret --apple-id 123456789",
		"--value [REDACTED] --name MY_SECRET --secret --apple-id 123456789",
		"--password [REDACTED]",
		"-password [REDACTED] -territory USA",
		"--password [REDACTED] --territory USA",
		"--password [REDACTED] --verbose",
		"curl -u [REDACTED] https://example.test",
		"curl --oauth2-bearer [REDACTED] https://example.test",
		"curl -u[REDACTED] https://example.test",
		"curl -U[REDACTED] https://example.test",
		"PASSWORD=[REDACTED]",
		"Authorization: [REDACTED]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsTruncatedPrivateKeyAndProxyCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	const keyMaterial = "truncated-key-material"
	const proxyPassword = "proxy-password-tail"
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl --proxy-user alice:"+proxyPassword+" https://example.test",
		"--actual", "failed to load\n-----BEGIN PRIVATE KEY-----\n"+keyMaterial,
		"malformed credential redaction probe",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range []string{keyMaterial, proxyPassword} {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked %q: %q", secret, stderr)
		}
		if strings.Contains(stdout, secret) {
			t.Fatalf("stdout leaked %q: %q", secret, stdout)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	for _, want := range []string{
		"curl --proxy-user [REDACTED] https://example.test",
		"failed to load\n[REDACTED PRIVATE KEY]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsExplicitMarkersAuthorizationAndStructuredKeys(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"marked-value", "authorization-credential", "structured-secret", "continued-secret", "pretty-structured-secret", "camel-structured-secret", "escaped-structured-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "asc web xcode-cloud env-vars create --value "+secrets[0]+" --secret=true\n"+
			"asc web xcode-cloud env-vars create --value "+secrets[3]+" \\\n  --secret",
		"--actual", `Authorization: ApiKey `+secrets[1]+"\n"+`{"MY_CLIENT_SECRET":"`+secrets[2]+`"}`+"\n"+
			"{\n  \"client_secret\":\n    \""+secrets[4]+"\"\n}\n"+
			`{"demoAccountPassword":"`+secrets[5]+`"}`+"\n"+
			`response {\"client_secret\":\"`+secrets[6]+`\"}`,
		"explicit credential redaction probe",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	for _, secret := range secrets {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr leaked %q: %q", secret, stderr)
		}
		if strings.Contains(stdout, secret) {
			t.Fatalf("stdout leaked %q: %q", secret, stdout)
		}
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	for _, want := range []string{
		"--value [REDACTED] --secret=[REDACTED]",
		"--value [REDACTED] \\\n  --secret",
		"Authorization: [REDACTED]",
		`{"MY_CLIENT_SECRET":"[REDACTED]"}`,
		"\"client_secret\":\n    \"[REDACTED]\"",
		`{"demoAccountPassword":"[REDACTED]"}`,
		`response {\"client_secret\":\"[REDACTED]\"}`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
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
		Repro:       "asc builds list --filter-key token\nasc signing sync pull --password-file /tmp/sync-password\nasc auth login --private-key /path/to/AuthKey.p8\nasc auth login --private-key=/path/to/AuthKey.p8\nasc xcode validate --api-key KEY123ABC\ncurl --user alice https://example.test\ncurl --proxy-user alice https://example.test\ngit clone https://example.test/repo",
		Expected:    "secret scanning documentation remains visible",
		Actual:      `request to https://example.test/path?signature_state=missing returned 401 with {"passwordPolicy":"strict","tokenCount":0}`,
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
