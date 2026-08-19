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
			name:  "single quoted authorization header argument",
			input: `curl -H 'Authorization: Bearer opaque-secret' https://example.test`,
			want:  `curl -H 'Authorization: [REDACTED]' https://example.test`,
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
			name:  "cookie request header",
			input: "Cookie: myacinfo=super-session-secret; dslang=US-EN",
			want:  "Cookie: [REDACTED]",
		},
		{
			name:  "set cookie response header",
			input: "< Set-Cookie: myacinfo=super-response-secret; Path=/; Secure; HttpOnly",
			want:  "< Set-Cookie: [REDACTED]",
		},
		{
			name:  "two factor continuation header",
			input: "< scnt: opaque-lowercase-continuation",
			want:  "< scnt: [REDACTED]",
		},
		{
			name:  "account session continuation header",
			input: "< X-Apple-ID-Session-Id: opaque-lowercase-session",
			want:  "< X-Apple-ID-Session-Id: [REDACTED]",
		},
		{
			name:  "quoted continuation header argument",
			input: `curl -H "scnt: opaque-lowercase-continuation" https://example.test`,
			want:  `curl -H "scnt: [REDACTED]" https://example.test`,
		},
		{
			name:  "portal csrf header",
			input: "< csrf: opaque-lowercase-token-value",
			want:  "< csrf: [REDACTED]",
		},
		{
			name:  "portal csrf timestamp header",
			input: "< csrf_ts: opaque-lowercase-timestamp-value",
			want:  "< csrf_ts: [REDACTED]",
		},
		{
			name:  "structured portal csrf headers",
			input: `{"csrf":"opaque-lowercase-token-value","csrf_ts":"opaque-lowercase-timestamp-value","status":"failed"}`,
			want:  `{"csrf":"[REDACTED]","csrf_ts":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "quoted cookie header argument",
			input: `curl -H "Cookie: myacinfo=super-session-secret; dslang=US-EN" https://example.test`,
			want:  `curl -H "Cookie: [REDACTED]" https://example.test`,
		},
		{
			name:  "continued quoted cookie header argument",
			input: "curl -H \"Cookie: myacinfo=super\\\nsecret\" https://example.test",
			want:  `curl -H "Cookie: [REDACTED]" https://example.test`,
		},
		{
			name:  "attached cookie header argument",
			input: `curl -HCookie:myacinfo=super-session-secret https://example.test`,
			want:  `curl -HCookie:[REDACTED] https://example.test`,
		},
		{
			name:  "attached service credential header argument",
			input: `curl -HX-Apple-Widget-Key:header-service-secret https://example.test`,
			want:  `curl -HX-Apple-Widget-Key:[REDACTED] https://example.test`,
		},
		{
			name:  "unquoted separated cookie header argument",
			input: `curl -H Cookie:myacinfo=super-session-secret https://example.test`,
			want:  `curl -H Cookie:[REDACTED] https://example.test`,
		},
		{
			name:  "unquoted long cookie header argument",
			input: `curl --header=Cookie:myacinfo=super-session-secret https://example.test`,
			want:  `curl --header=Cookie:[REDACTED] https://example.test`,
		},
		{
			name:  "unquoted proxy cookie header argument",
			input: `curl --proxy-header Cookie:myacinfo=super-session-secret https://example.test`,
			want:  `curl --proxy-header Cookie:[REDACTED] https://example.test`,
		},
		{
			name:  "curl long cookie data argument",
			input: `curl --cookie 'myacinfo=super-session-secret; dslang=US-EN' https://example.test`,
			want:  `curl --cookie [REDACTED] https://example.test`,
		},
		{
			name:  "curl short cookie data argument",
			input: `curl -b "myacinfo=super-session-secret" https://example.test`,
			want:  `curl -b [REDACTED] https://example.test`,
		},
		{
			name:  "curl cookie equals data argument",
			input: `curl --cookie="myacinfo=super-session-secret" https://example.test`,
			want:  `curl --cookie=[REDACTED] https://example.test`,
		},
		{
			name:  "curl attached short cookie data argument",
			input: `curl -bmyacinfo=super-session-secret https://example.test`,
			want:  `curl -b[REDACTED] https://example.test`,
		},
		{
			name:  "curl certificate password argument",
			input: `curl --cert client.p12:supersensitive https://example.test`,
			want:  `curl --cert client.p12:[REDACTED] https://example.test`,
		},
		{
			name:  "curl certificate password equals argument",
			input: `curl --cert="client cert.p12:secret with spaces" https://example.test`,
			want:  `curl --cert="client cert.p12:[REDACTED]" https://example.test`,
		},
		{
			name:  "curl attached short certificate password argument",
			input: `curl -Eclient.p12:supersensitive https://example.test`,
			want:  `curl -Eclient.p12:[REDACTED] https://example.test`,
		},
		{
			name:  "curl certificate password quoted suffix",
			input: `curl --cert client.p12:'supersensitive password' https://example.test`,
			want:  `curl --cert client.p12:[REDACTED] https://example.test`,
		},
		{
			name:  "persisted session cookie values",
			input: `{"cookies":{"https://appstoreconnect.apple.com":[{"name":"myacinfo","value":"super-session-secret","path":"/"},{"name":"dqsid","value":"second-session-secret"}]},"version":1}`,
			want:  `{"cookies":{"https://appstoreconnect.apple.com":[{"name":"myacinfo","value":"[REDACTED]","path":"/"},{"name":"dqsid","value":"[REDACTED]"}]},"version":1}`,
		},
		{
			name:  "persisted session cookie value before name",
			input: `{"cookies":{"https://appstoreconnect.apple.com":[{"value":"super-session-secret","name":"myacinfo"}]},"version":1}`,
			want:  `{"cookies":{"https://appstoreconnect.apple.com":[{"value":"[REDACTED]","name":"myacinfo"}]},"version":1}`,
		},
		{
			name:  "escaped persisted session cookie value",
			input: `cache {\"cookies\":{\"https://appstoreconnect.apple.com\":[{\"name\":\"myacinfo\",\"value\":\"super-session-secret\",\"path\":\"/\"}]}}`,
			want:  `cache {\"cookies\":{\"https://appstoreconnect.apple.com\":[{\"name\":\"myacinfo\",\"value\":\"[REDACTED]\",\"path\":\"/\"}]}}`,
		},
		{
			name:  "upload operation request header values",
			input: `{"uploadOperations":[{"method":"PUT","requestHeaders":[{"name":"Authorization","value":"opaque-upload-secret"},{"name":"x-amz-checksum-sha256","value":"checksum-capability"}],"length":12}],"status":"pending"}`,
			want:  `{"uploadOperations":[{"method":"PUT","requestHeaders":[{"name":"Authorization","value":"[REDACTED]"},{"name":"x-amz-checksum-sha256","value":"[REDACTED]"}],"length":12}],"status":"pending"}`,
		},
		{
			name:  "escaped upload operation request header value",
			input: `response {\"requestHeaders\":[{\"name\":\"x-upload-token\",\"value\":\"escaped-upload-secret\"}],\"method\":\"PUT\"}`,
			want:  `response {\"requestHeaders\":[{\"name\":\"x-upload-token\",\"value\":\"[REDACTED]\"}],\"method\":\"PUT\"}`,
		},
		{
			name:  "structured credential headers",
			input: `{"Authorization":"Basic c3VwZXJzZWNyZXQ=","Cookie":"myacinfo=super-session-secret","status":"failed"}`,
			want:  `{"Authorization":"[REDACTED]","Cookie":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "go formatted credential header map",
			input: `request headers: map[Cookie:[myacinfo=opaque-lowercase-secret] Content-Type:[application/json]]`,
			want:  `request headers: map[Cookie:[REDACTED] Content-Type:[application/json]]`,
		},
		{
			name:  "object valued structured credential",
			input: `{"token":{"type":"bearer","value":"opaque-lowercase-secret"},"status":"failed"}`,
			want:  `{"token":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "escaped object valued structured credential",
			input: `trace {\"token\":{\"type\":\"bearer\",\"value\":\"opaque-lowercase-secret\"},\"status\":\"failed\"}`,
			want:  `trace {\"token\":\"[REDACTED]\",\"status\":\"failed\"}`,
		},
		{
			name:  "truncated object valued structured credential",
			input: `{"token":{"type":"bearer","value":"opaque-lowercase-secret"`,
			want:  `{"token":"[REDACTED]"`,
		},
		{
			name:  "array-valued authorization header",
			input: `{"Authorization":["Bearer opaque-lowercase-secret"],"status":"failed"}`,
			want:  `{"Authorization":["[REDACTED]"],"status":"failed"}`,
		},
		{
			name:  "array-valued proxy authorization header",
			input: `{"Proxy-Authorization":["Basic dXNlcjpzdXBlcnNlY3JldA=="],"status":"failed"}`,
			want:  `{"Proxy-Authorization":["[REDACTED]"],"status":"failed"}`,
		},
		{
			name:  "escaped array-valued authorization header",
			input: `trace {\"Authorization\":[\"Bearer first-secret\",\"Basic second-secret\"],\"status\":\"failed\"}`,
			want:  `trace {\"Authorization\":[\"[REDACTED]\"],\"status\":\"failed\"}`,
		},
		{
			name: "web auth service credentials",
			input: `X-Apple-Widget-Key: header-service-secret
{"authServiceKey":"auth-service-secret","serviceKey":"response-service-secret","status":"failed"}`,
			want: `X-Apple-Widget-Key: [REDACTED]
{"authServiceKey":"[REDACTED]","serviceKey":"[REDACTED]","status":"failed"}`,
		},
		{
			name:  "nested two factor request code",
			input: `{"securityCode":{"code":"123456"},"mode":"sms"}`,
			want:  `{"securityCode":{"code":"[REDACTED]"},"mode":"sms"}`,
		},
		{
			name:  "escaped nested two factor request code",
			input: `trace {\"securityCode\":{\"code\":\"654321\"},\"mode\":\"sms\"}`,
			want:  `trace {\"securityCode\":{\"code\":\"[REDACTED]\"},\"mode\":\"sms\"}`,
		},
		{
			name:  "unescaped structured credential headers",
			input: "{\"Authorization\":\"Basic c3VwZXJzZWNyZXQ=\",\"Cookie\":\"myacinfo=super-session-secret\",\"status\":\"failed\"}",
			want:  "{\"Authorization\":\"[REDACTED]\",\"Cookie\":\"[REDACTED]\",\"status\":\"failed\"}",
		},
		{
			name:  "escaped structured credential headers",
			input: `response {\"Authorization\":\"Basic c3VwZXJzZWNyZXQ=\",\"Set-Cookie\":\"myacinfo=super-session-secret\",\"status\":\"failed\"}`,
			want:  `response {\"Authorization\":\"[REDACTED]\",\"Set-Cookie\":\"[REDACTED]\",\"status\":\"failed\"}`,
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
			name:  "web auth query credentials",
			input: "authenticate https://example.test/auth?widgetKey=widget-secret&code=123456&scnt=continuation-secret&flow=login",
			want:  "authenticate https://example.test/auth?widgetKey=[REDACTED]&code=[REDACTED]&scnt=[REDACTED]&flow=login",
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
			name:  "scp style remote credentials",
			input: "asc signing sync --repo user:supersensitive@github.com:team/certs.git",
			want:  "asc signing sync --repo [REDACTED]@github.com:team/certs.git",
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
			name:  "unquoted assignment before command separator",
			input: `PASSWORD=supersecret; echo next`,
			want:  `PASSWORD=[REDACTED]; echo next`,
		},
		{
			name:  "unquoted secret flag before conditional operator",
			input: `asc deploy --password supersecret && echo next`,
			want:  `asc deploy --password [REDACTED] && echo next`,
		},
		{
			name:  "multiword plain yaml scalar",
			input: "password: correct horse battery staple\nstatus: failed",
			want:  "password: [REDACTED]\nstatus: failed",
		},
		{
			name:  "YAML single quoted scalar with doubled quote",
			input: "password: 'super''sensitive'\nstatus: failed",
			want:  "password: [REDACTED]\nstatus: failed",
		},
		{
			name:  "space-separated secret flag",
			input: `asc web sandbox create --email "user@example.test" --password "Passwordtest1" --territory "USA"`,
			want:  `asc web sandbox create --email "user@example.test" --password [REDACTED] --territory "USA"`,
		},
		{
			name:  "adjacent quoted fragments in secret flag",
			input: `asc deploy --password 'super''secret' --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "backtick command substitution in secret flag",
			input: "asc deploy --password `printf supersecret` --verbose",
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "dollar command substitution in secret flag",
			input: `asc deploy --password $(printf supersecret) --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "mixed adjacent fragments in secret assignment",
			input: `PASSWORD=pre'super'"secret"post asc builds list`,
			want:  `PASSWORD=[REDACTED] asc builds list`,
		},
		{
			name:  "notification webhook flag",
			input: `asc notify slack --webhook https://hooks.slack.com/services/T/B/super-secret --message ready`,
			want:  `asc notify slack --webhook [REDACTED] --message ready`,
		},
		{
			name:  "notification webhook environment assignment",
			input: `ASC_SLACK_WEBHOOK=https://hooks.slack.com/services/T/B/super-secret asc notify slack --message ready`,
			want:  `ASC_SLACK_WEBHOOK=[REDACTED] asc notify slack --message ready`,
		},
		{
			name:  "Fish exported credential assignment",
			input: `set -x ASC_SIGNING_SYNC_PASSWORD opaque-lowercase-secret; asc signing sync pull`,
			want:  `set -x ASC_SIGNING_SYNC_PASSWORD [REDACTED]; asc signing sync pull`,
		},
		{
			name:  "quoted custom secret header",
			input: `asc web xcode-cloud usage alert --webhook-header "X-API-Key: supersecret" --webhook https://example.test`,
			want:  `asc web xcode-cloud usage alert --webhook-header "X-API-Key: [REDACTED]" --webhook [REDACTED]`,
		},
		{
			name:  "xcode cloud slack webhook flag",
			input: `asc web xcode-cloud usage alert --slack-webhook=https://hooks.slack.com/services/T/B/super-secret --threshold 90`,
			want:  `asc web xcode-cloud usage alert --slack-webhook=[REDACTED] --threshold 90`,
		},
		{
			name:  "direct two factor code flag",
			input: `asc web auth login --two-factor-code 123456 --apple-id user@example.test`,
			want:  `asc web auth login --two-factor-code [REDACTED] --apple-id user@example.test`,
		},
		{
			name:  "direct two factor code equals flag",
			input: `asc web auth login --two-factor-code=654321 --apple-id user@example.test`,
			want:  `asc web auth login --two-factor-code=[REDACTED] --apple-id user@example.test`,
		},
		{
			name:  "escaped quote in secret flag",
			input: `asc deploy --password "pa\"ssword" --verbose`,
			want:  `asc deploy --password [REDACTED] --verbose`,
		},
		{
			name:  "multiline double quoted secret flag",
			input: "asc deploy --password \"multiline-head\nmultiline tail secret\" --verbose",
			want:  "asc deploy --password [REDACTED] --verbose",
		},
		{
			name:  "multiline single quoted assignment",
			input: "PASSWORD='multiline-head\nmultiline-tail-secret' asc builds list",
			want:  "PASSWORD=[REDACTED] asc builds list",
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
			want:  `asc web xcode-cloud env-vars create --value [REDACTED] --secret=true`,
		},
		{
			name:  "boolean secret marker with explicit numeric true value",
			input: `asc web xcode-cloud env-vars create --secret=1 --value s3cret`,
			want:  `asc web xcode-cloud env-vars create --secret=1 --value [REDACTED]`,
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
			name:  "backslash continued secret flag",
			input: "asc deploy --password super\\\nremainingcredential --verbose",
			want:  "asc deploy --password [REDACTED] --verbose",
		},
		{
			name:  "backslash continued assignment",
			input: "PASSWORD=super\\\nremainingcredential asc builds list",
			want:  "PASSWORD=[REDACTED] asc builds list",
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
			name:  "multiline quoted curl user password flag",
			input: "curl --user \"alice:first\nsecond-secret\" https://example.test",
			want:  "curl --user [REDACTED] https://example.test",
		},
		{
			name:  "continued curl user password flag",
			input: "curl --user alice:super\\\nremainingcredential https://example.test",
			want:  "curl --user [REDACTED] https://example.test",
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
			name:  "curl private key passphrase flag",
			input: `curl --pass superprivatephrase --key client.pem https://example.test`,
			want:  `curl --pass [REDACTED] --key client.pem https://example.test`,
		},
		{
			name:  "curl TLS password flag",
			input: `curl --tlspassword supertlsphrase https://example.test`,
			want:  `curl --tlspassword [REDACTED] https://example.test`,
		},
		{
			name:  "multiline quoted curl certificate password",
			input: "curl --cert \"client.p12:first\nsecond-secret\" https://example.test",
			want:  "curl --cert \"client.p12:[REDACTED]\" https://example.test",
		},
		{
			name:  "curl proxy TLS password flag",
			input: `curl --proxy-tlspassword superproxyphrase https://example.test`,
			want:  `curl --proxy-tlspassword [REDACTED] https://example.test`,
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
			name:  "scoped base64 private key assignments",
			input: `ASC_STOREKIT_PRIVATE_KEY_B64=c3RvcmVraXQtcHJpdmF0ZS1rZXk= ASC_ADS_PRIVATE_KEY_B64=YWRzLXByaXZhdGUta2V5`,
			want:  `ASC_STOREKIT_PRIVATE_KEY_B64=[REDACTED] ASC_ADS_PRIVATE_KEY_B64=[REDACTED]`,
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
			name:  "YAML literal secret block",
			input: "client_secret: |\n  super\n  sensitive\nstatus: failed",
			want:  "client_secret: [REDACTED]\nstatus: failed",
		},
		{
			name:  "YAML sequence literal secret block",
			input: "items:\n  - password: |\n      super\n      sensitive\nstatus: failed",
			want:  "items:\n  - password: [REDACTED]\nstatus: failed",
		},
		{
			name:  "YAML flow sequence credential",
			input: "password: [first-secret, second-secret]\nstatus: failed",
			want:  "password: [REDACTED]\nstatus: failed",
		},
		{
			name:  "quoted YAML flow sequence credential",
			input: "\"password\": [first-secret, second-secret]\nstatus: failed",
			want:  "\"password\": [REDACTED]\nstatus: failed",
		},
		{
			name:  "YAML block mapping credential",
			input: "token:\n  type: bearer\n  value: opaque-secret\nstatus: failed",
			want:  "token: [REDACTED]\nstatus: failed",
		},
		{
			name:  "nested YAML block mapping preserves sibling field",
			input: "response:\n  token:\n    type: bearer\n    value: opaque-secret\n  status: failed",
			want:  "response:\n  token: [REDACTED]\n  status: failed",
		},
		{
			name:  "quoted YAML block mapping credential",
			input: "response:\n  \"password\":\n    value: quoted-map-secret\n  status: failed",
			want:  "response:\n  \"password\": [REDACTED]\n  status: failed",
		},
		{
			name:  "sequence YAML block mapping preserves sibling field",
			input: "items:\n  - token:\n      value: opaque-secret\n    status: failed",
			want:  "items:\n  - token: [REDACTED]\n    status: failed",
		},
		{
			name:  "nested YAML block scalar preserves sibling field",
			input: "response:\n  client_secret: |\n    opaque-secret\n  status: failed",
			want:  "response:\n  client_secret: [REDACTED]\n  status: failed",
		},
		{
			name:  "YAML folded base64 private key block",
			input: "private_key_b64: >- # encoded key\n  c3VwZXI=\n\n  c2VjcmV0\nnext: preserved",
			want:  "private_key_b64: [REDACTED]\nnext: preserved",
		},
		{
			name:  "camel case JSON assignments",
			input: `response {"demoAccountPassword":"review-secret","awsSecretAccessKey":"cloud-secret"}`,
			want:  `response {"demoAccountPassword":"[REDACTED]","awsSecretAccessKey":"[REDACTED]"}`,
		},
		{
			name:  "sandbox secret answer preserves question",
			input: `{"secretQuestion":"Public question","secretAnswer":"recovery-answer-secret","status":"active"}`,
			want:  `{"secretQuestion":"Public question","secretAnswer":"[REDACTED]","status":"active"}`,
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

func TestRedactSensitiveTextPreservesFalseSecretMarkerAndValue(t *testing.T) {
	const publicValue = "public-value"
	input := "asc web xcode-cloud env-vars create --value " + publicValue + " --secret=false"

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
	}
}

func TestRedactSensitiveTextPreservesCurlCookieFilenames(t *testing.T) {
	for _, input := range []string{
		`curl --cookie ./cookies.txt https://example.test`,
		`curl --cookie=./cookies.txt https://example.test`,
		`curl -b "$TMPDIR/cookies.jar" https://example.test`,
		`curl -b./cookies.jar https://example.test`,
	} {
		got, changed := redactSensitiveText(input)
		if changed || got != input {
			t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
		}
	}
}

func TestRedactSensitiveTextPreservesCurlReferer(t *testing.T) {
	input := `curl -e https://example.test/page https://target.test`

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
	}
}

func TestRedactSensitiveTextPreservesCurlCertificateWithoutPassword(t *testing.T) {
	for _, input := range []string{
		`curl --cert client.pem https://example.test`,
		`curl --cert="client cert.pem" https://example.test`,
		`curl -Eclient.p12 https://example.test`,
	} {
		got, changed := redactSensitiveText(input)
		if changed || got != input {
			t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
		}
	}
}

func TestRedactSensitiveTextPreservesAttachedBenignCurlHeader(t *testing.T) {
	for _, input := range []string{
		`curl -HAccept:application/json https://example.test`,
		`curl -H Accept:application/json https://example.test`,
		`curl --header=Accept:application/json https://example.test`,
	} {
		got, changed := redactSensitiveText(input)
		if changed || got != input {
			t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
		}
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

func TestRedactSensitiveTextPreservesUsernameOnlySCPRemote(t *testing.T) {
	input := "asc signing sync --repo git@github.com:team/certs.git"

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
	}
}

func TestRedactSensitiveTextPreservesOrdinaryCodeFields(t *testing.T) {
	input := `{"error":{"code":"ENTITY_ERROR"},"status":400}`

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
	}
}

func TestRedactSensitiveTextPreservesNameValuePairOutsideCookieJar(t *testing.T) {
	input := `{"cookies":{},"diagnostic":{"name":"failure","value":"preserve this explanation"}}`

	got, changed := redactSensitiveText(input)
	if changed || got != input {
		t.Fatalf("redactSensitiveText(%q) = %q, changed=%t; want unchanged", input, got, changed)
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
		"curl-private-key-passphrase-tail",
		"curl-tls-password-tail",
		"curl-proxy-tls-password-tail",
		"continued-flag-tail",
		"continued-assignment-tail",
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
		`curl --pass ` + secrets[16] + ` --key client.pem https://example.test`,
		`curl --tlspassword ` + secrets[17] + ` https://example.test`,
		`curl --proxy-tlspassword ` + secrets[18] + ` https://example.test`,
		"asc deploy --password prefix\\\n" + secrets[19] + " --verbose",
	}, "\n")
	actual := "PASSWORD=" + secrets[3] + "\n" +
		`PASSWORD=$'` + secrets[7] + "'\n" +
		`PASSWORD=prefix\ ` + secrets[9] + "\n" +
		"PASSWORD=prefix\\\n" + secrets[20] + " asc builds list\n" +
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
		"curl --pass [REDACTED] --key client.pem https://example.test",
		"curl --tlspassword [REDACTED] https://example.test",
		"curl --proxy-tlspassword [REDACTED] https://example.test",
		"asc deploy --password [REDACTED] --verbose",
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

	secrets := []string{"marked-value", "authorization-credential", "structured-secret", "continued-secret", "pretty-structured-secret", "camel-structured-secret", "escaped-structured-secret", "fish-assignment-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "asc web xcode-cloud env-vars create --value "+secrets[0]+" --secret=true\n"+
			"asc web xcode-cloud env-vars create --value "+secrets[3]+" \\\n  --secret\n"+
			"set --global --export ASC_SIGNING_SYNC_PASSWORD "+secrets[7]+"; asc signing sync pull",
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
		"--value [REDACTED] --secret=true",
		"--value [REDACTED] \\\n  --secret",
		"set --global --export ASC_SIGNING_SYNC_PASSWORD [REDACTED]; asc signing sync pull",
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

func TestSnitchDryRunRedactsCookieHeadersAndScopedPrivateKeys(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"web-session-secret",
		"response-session-secret",
		"c3RvcmVraXQtcHJpdmF0ZS1rZXk=",
		"YWRzLXByaXZhdGUta2V5",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", `curl -H "Cookie: myacinfo=`+secrets[0]+`; dslang=US-EN" https://example.test`,
		"--actual", "< Set-Cookie: myacinfo="+secrets[1]+"; Path=/; Secure\n"+
			"ASC_STOREKIT_PRIVATE_KEY_B64="+secrets[2]+"\n"+
			"ASC_ADS_PRIVATE_KEY_B64="+secrets[3],
		"session credential redaction probe",
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
		`curl -H "Cookie: [REDACTED]" https://example.test`,
		"< Set-Cookie: [REDACTED]",
		"ASC_STOREKIT_PRIVATE_KEY_B64=[REDACTED]",
		"ASC_ADS_PRIVATE_KEY_B64=[REDACTED]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsStructuredHeadersAndYAMLSecretBlocks(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"structured-authorization-secret",
		"structured-cookie-secret",
		"yaml-literal-secret",
		"yaml-folded-secret",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "{\"Authorization\":\"Basic "+secrets[0]+"\",\"Cookie\":\"myacinfo="+secrets[1]+"\",\"status\":\"failed\"}",
		"--actual", `{"Authorization":"Basic `+secrets[0]+`","Cookie":"myacinfo=`+secrets[1]+`","status":"failed"}`+"\n"+
			"client_secret: |\n  "+secrets[2]+"\nstatus: failed\n"+
			"private_key_b64: >-\n  "+secrets[3]+"\nnext: preserved",
		"structured credential redaction probe",
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
		"{\"Authorization\":\"[REDACTED]\",\"Cookie\":\"[REDACTED]\",\"status\":\"failed\"}",
		`{"Authorization":"[REDACTED]","Cookie":"[REDACTED]","status":"failed"}`,
		"client_secret: [REDACTED]\nstatus: failed",
		"private_key_b64: [REDACTED]\nnext: preserved",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsYAMLSingleQuotedScalarWithDoubledQuote(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	const secret = "super''sensitive"
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "password: '"+secret+"'\nstatus: failed",
		"YAML quoted credential redaction probe",
	)
	if err != nil {
		t.Fatalf("run snitch: %v", err)
	}

	if strings.Contains(stderr, secret) {
		t.Fatalf("stderr leaked %q: %q", secret, stderr)
	}
	if strings.Contains(stdout, secret) {
		t.Fatalf("stdout leaked %q: %q", secret, stdout)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want dry-run diagnostics on stderr only", stdout)
	}
	if want := "password: [REDACTED]\nstatus: failed"; !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
	}
}

func TestSnitchDryRunRedactsUploadOperationHeaderValues(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"authorization-upload-secret", "custom-upload-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--actual", `{"uploadOperations":[{"method":"PUT","requestHeaders":[{"name":"Authorization","value":"`+secrets[0]+`"},{"name":"x-upload-token","value":"`+secrets[1]+`"}],"length":12}],"diagnostic":{"name":"failure","value":"preserve this explanation"}}`,
		"upload operation credential redaction probe",
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
	want := `{"uploadOperations":[{"method":"PUT","requestHeaders":[{"name":"Authorization","value":"[REDACTED]"},{"name":"x-upload-token","value":"[REDACTED]"}],"length":12}],"diagnostic":{"name":"failure","value":"preserve this explanation"}}`
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want preserved response context %q", stderr, want)
	}
}

func TestSnitchDryRunRedactsNestedYAMLAndCommandSubstitutionCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"yaml-sequence-secret", "backtick-substitution-secret", "dollar-substitution-secret", "certificate-suffix-secret", "unquoted-flow-credential", "quoted-flow-credential", "yaml-block-mapping-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "items:\n  - password: |\n      "+secrets[0]+"\nstatus: failed\nasc deploy --password `printf "+secrets[1]+"` --verbose\nasc deploy --password $(printf "+secrets[2]+") --verbose\ncurl --cert client.p12:'"+secrets[3]+" password' https://example.test\npassword: [first-value, "+secrets[4]+"]\n\"password\": [first-value, "+secrets[5]+"]\nresponse:\n  token:\n    type: bearer\n    value: "+secrets[6]+"\n  status: failed\nnext: preserved",
		"nested credential redaction probe",
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
		"items:\n  - password: [REDACTED]\nstatus: failed",
		"asc deploy --password [REDACTED] --verbose",
		"curl --cert client.p12:[REDACTED] https://example.test",
		"password: [REDACTED]",
		"\"password\": [REDACTED]",
		"response:\n  token: [REDACTED]\n  status: failed\nnext: preserved",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsMultilineCurlAndYAMLCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"multiline-user-secret", "multiline-cert-secret", "quoted-yaml-secret", "sequence-yaml-secret"}
	repro := "curl --user \"alice:first\n" + secrets[0] + "\" https://example.test\n" +
		"curl --cert \"client.p12:first\n" + secrets[1] + "\" https://example.test\n" +
		"response:\n  \"password\":\n    value: " + secrets[2] + "\n  status: failed\n" +
		"items:\n  - token:\n      value: " + secrets[3] + "\n    status: failed"
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", repro,
		"multiline credential redaction probe",
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
		"curl --user [REDACTED] https://example.test",
		"curl --cert \"client.p12:[REDACTED]\" https://example.test",
		"response:\n  \"password\": [REDACTED]\n  status: failed",
		"items:\n  - token: [REDACTED]\n    status: failed",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsWebAuthenticationPayloads(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"array-authorization-secret",
		"header-service-secret",
		"auth-service-secret",
		"response-service-secret",
		"123456",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", `{"Authorization":["Bearer `+secrets[0]+`"],"X-Apple-Widget-Key":["`+secrets[1]+`"],"status":"failed"}`,
		"--actual", `{"authServiceKey":"`+secrets[2]+`","serviceKey":"`+secrets[3]+`","securityCode":{"code":"`+secrets[4]+`"},"mode":"sms"}`,
		"web authentication payload redaction probe",
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
		`{"Authorization":["[REDACTED]"],"X-Apple-Widget-Key":["[REDACTED]"],"status":"failed"}`,
		`{"authServiceKey":"[REDACTED]","serviceKey":"[REDACTED]","securityCode":{"code":"[REDACTED]"},"mode":"sms"}`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsCurlCertificatePasswords(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"space-secret", "equals-secret", "attached-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl --cert client.p12:"+secrets[0]+" --cert=client.pem:"+secrets[1]+" -Eclient.pfx:"+secrets[2]+" https://example.test",
		"certificate password redaction probe",
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
	want := "curl --cert client.p12:[REDACTED] --cert=client.pem:[REDACTED] -Eclient.pfx:[REDACTED] https://example.test"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
	}
}

func TestSnitchDryRunRedactsAttachedCurlCredentialHeaders(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"cookie-session-secret", "widget-service-secret", "separated-cookie-secret", "long-cookie-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl -HCookie:myacinfo="+secrets[0]+" -HX-Apple-Widget-Key:"+secrets[1]+" -H Cookie:myacinfo="+secrets[2]+" --header=Cookie:myacinfo="+secrets[3]+" -HAccept:application/json https://example.test",
		"attached credential header redaction probe",
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
	want := "curl -HCookie:[REDACTED] -HX-Apple-Widget-Key:[REDACTED] -H Cookie:[REDACTED] --header=Cookie:[REDACTED] -HAccept:application/json https://example.test"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
	}
}

func TestSnitchDryRunRedactsQuotedAuthorizationAndSCPRemoteCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"quoted-authorization-secret", "remote-password-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl -H 'Authorization: Bearer "+secrets[0]+"' https://example.test",
		"--actual", "asc signing sync --repo user:"+secrets[1]+"@github.com:team/certs.git",
		"quoted authorization and remote credential redaction probe",
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
		"curl -H 'Authorization: [REDACTED]' https://example.test",
		"asc signing sync --repo [REDACTED]@github.com:team/certs.git",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsCompositeYAMLAndProxyHeaderCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"yaml secret tail", "nested-object-secret", "proxy-header-secret", "webhook-secret", "truncated-object-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl --proxy-header Cookie:myacinfo="+secrets[2]+" https://example.test\nasc notify slack --webhook https://hooks.slack.com/services/T/B/"+secrets[3]+" --message ready",
		"--expected", "password: [REDACTED]",
		"--actual", "password: "+secrets[0]+"\nresponse: {\"token\":{\"type\":\"bearer\",\"value\":\""+secrets[1]+"\"},\"status\":\"failed\"}\ntruncated: {\"token\":{\"value\":\""+secrets[4]+"\"",
		"composite credential redaction probe",
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
		"curl --proxy-header Cookie:[REDACTED] https://example.test",
		"asc notify slack --webhook [REDACTED] --message ready",
		"password: [REDACTED]",
		`response: {"token":"[REDACTED]","status":"failed"}`,
		`truncated: {"token":"[REDACTED]"`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsGoHeaderMapsAndContinuedCurlCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"continued-user-secret", "go-header-secret", "proxy-authorization-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl --user alice:"+secrets[0]+"\\\n-tail https://example.test",
		"--actual", "request headers: map[Cookie:[myacinfo="+secrets[1]+"] Content-Type:[application/json]]\n{\"Proxy-Authorization\":[\"Basic "+secrets[2]+"\"],\"status\":\"failed\"}",
		"header map and continued credential redaction probe",
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
		"curl --user [REDACTED] https://example.test",
		"request headers: map[Cookie:[REDACTED] Content-Type:[application/json]]",
		`{"Proxy-Authorization":["[REDACTED]"],"status":"failed"}`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunPreservesOperatorsAroundContinuedHeaderCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{"continued-header-secret", "boundary-assignment-credential", "operator-flag-credential", "fragmented-flag-credential", "fragmented-env-credential", "environment-webhook-secret", "custom-header-secret"}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl -H \"Cookie: myacinfo="+secrets[0]+"\\\n-tail\" https://example.test\nPASSWORD="+secrets[1]+"; echo next\nasc deploy --password "+secrets[2]+" && echo done\nasc deploy --password 'adjacent-'\""+secrets[3]+"\" --verbose\nPASSWORD='adjacent-'\""+secrets[4]+"\" asc builds list\nASC_SLACK_WEBHOOK=https://hooks.slack.com/services/T/B/"+secrets[5]+" asc notify slack --message ready\nasc web xcode-cloud usage alert --webhook-header \"X-API-Key: "+secrets[6]+"\" --webhook https://example.test",
		"continued header and operator preservation probe",
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
		`curl -H "Cookie: [REDACTED]" https://example.test`,
		"PASSWORD=[REDACTED]; echo next",
		"asc deploy --password [REDACTED] && echo done",
		"asc deploy --password [REDACTED] --verbose",
		"PASSWORD=[REDACTED] asc builds list",
		"ASC_SLACK_WEBHOOK=[REDACTED] asc notify slack --message ready",
		`asc web xcode-cloud usage alert --webhook-header "X-API-Key: [REDACTED]" --webhook [REDACTED]`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsMultilineQuotedAndSecretAnswerValues(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"multiline-head",
		"multiline-tail-secret",
		"recovery-answer-secret",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "asc deploy --password \""+secrets[0]+"\n"+secrets[1]+" with space\" --verbose",
		"--actual", `{"secretQuestion":"Public question","secretAnswer":"`+secrets[2]+`","status":"active"}`,
		"multiline and recovery credential redaction probe",
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
		"asc deploy --password [REDACTED] --verbose",
		`{"secretQuestion":"Public question","secretAnswer":"[REDACTED]","status":"active"}`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsTwoFactorContinuationCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"123456",
		"opaque-lowercase-continuation",
		"opaque-lowercase-session",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "asc web auth login --two-factor-code "+secrets[0]+" --apple-id user@example.test",
		"--actual", "< scnt: "+secrets[1]+"\n< X-Apple-ID-Session-Id: "+secrets[2],
		"two factor continuation credential redaction probe",
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
		"asc web auth login --two-factor-code [REDACTED] --apple-id user@example.test",
		"< scnt: [REDACTED]",
		"< X-Apple-ID-Session-Id: [REDACTED]",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsPortalCSRFCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"opaque-lowercase-csrf",
		"opaque-lowercase-csrf-timestamp",
		"structured-csrf-secret",
		"structured-csrf-timestamp-secret",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "< csrf: "+secrets[0]+"\n< csrf_ts: "+secrets[1],
		"--actual", `{"csrf":"`+secrets[2]+`","csrf_ts":"`+secrets[3]+`","status":"failed"}`,
		"portal csrf credential redaction probe",
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
		"< csrf: [REDACTED]",
		"< csrf_ts: [REDACTED]",
		`{"csrf":"[REDACTED]","csrf_ts":"[REDACTED]","status":"failed"}`,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
		}
	}
}

func TestSnitchDryRunRedactsWebAuthQueryCredentials(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"widget-query-secret",
		"123456",
		"continuation-query-secret",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", "curl 'https://example.test/auth?widgetKey="+secrets[0]+"&code="+secrets[1]+"&scnt="+secrets[2]+"&flow=login'",
		"web auth query credential redaction probe",
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
	want := "curl 'https://example.test/auth?widgetKey=[REDACTED]&code=[REDACTED]&scnt=[REDACTED]&flow=login'"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want preserved context %q", stderr, want)
	}
}

func TestSnitchDryRunRedactsCurlCookieDataAndSessionCacheValues(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	secrets := []string{
		"curl-cookie-secret",
		"cached-cookie-secret",
		"second-cached-cookie-secret",
		"reordered-cached-cookie-secret",
	}
	stdout, stderr, err := runSnitchCommand(
		t, "9.9.9",
		"--dry-run",
		"--repro", `curl --cookie 'myacinfo=`+secrets[0]+`' --cookie ./cookies.txt https://example.test`,
		"--actual", `{"cookies":{"https://appstoreconnect.apple.com":[{"name":"myacinfo","value":"`+secrets[1]+`","path":"/"},{"name":"dqsid","value":"`+secrets[2]+`"},{"value":"`+secrets[3]+`","name":"itctx"}]},"diagnostic":{"name":"failure","value":"preserve this explanation"},"version":1}`,
		"session cookie redaction probe",
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
		`curl --cookie [REDACTED] --cookie ./cookies.txt https://example.test`,
		`{"cookies":{"https://appstoreconnect.apple.com":[{"name":"myacinfo","value":"[REDACTED]","path":"/"},{"name":"dqsid","value":"[REDACTED]"},{"value":"[REDACTED]","name":"itctx"}]},"diagnostic":{"name":"failure","value":"preserve this explanation"},"version":1}`,
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
