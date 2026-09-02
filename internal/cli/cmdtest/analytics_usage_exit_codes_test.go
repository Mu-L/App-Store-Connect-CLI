package cmdtest

import (
	"path/filepath"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
)

const analyticsUsageExitRequestID = "11111111-1111-1111-1111-111111111111"

// TestAnalyticsInputValidationReturnsUsageExitCode locks the usage-error
// contract for analytics flag validation: every pre-request flag check must
// print "Error: <message>" to stderr and exit with code 2, not the generic
// runtime failure code.
func TestAnalyticsInputValidationReturnsUsageExitCode(t *testing.T) {
	t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))
	t.Setenv("ASC_APP_ID", "")

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "requests limit above maximum",
			args:    []string{"analytics", "requests", "--app", "123456789", "--limit", "201"},
			wantErr: "analytics requests: --limit must be between 1 and 200",
		},
		{
			name:    "requests limit below minimum",
			args:    []string{"analytics", "requests", "--app", "123456789", "--limit", "-1"},
			wantErr: "analytics requests: --limit must be between 1 and 200",
		},
		{
			name:    "requests invalid next",
			args:    []string{"analytics", "requests", "--next", "http://api.appstoreconnect.apple.com/v1/analyticsReportRequests"},
			wantErr: "analytics requests: --next must be an App Store Connect URL",
		},
		{
			name:    "requests invalid request id",
			args:    []string{"analytics", "requests", "--request-id", "not-a-uuid"},
			wantErr: "analytics requests: --request-id must be a valid UUID",
		},
		{
			name:    "requests delete invalid request id",
			args:    []string{"analytics", "requests", "delete", "--request-id", "not-a-uuid", "--confirm"},
			wantErr: "analytics requests delete: --request-id must be a valid UUID",
		},
		{
			name:    "view invalid request id",
			args:    []string{"analytics", "view", "--request-id", "not-a-uuid"},
			wantErr: "analytics view: --request-id must be a valid UUID",
		},
		{
			name:    "view invalid instance id",
			args:    []string{"analytics", "view", "--request-id", analyticsUsageExitRequestID, "--instance-id", "bad/instance"},
			wantErr: "analytics view: --instance-id: resource identifier",
		},
		{
			name:    "view limit above maximum",
			args:    []string{"analytics", "view", "--request-id", analyticsUsageExitRequestID, "--limit", "201"},
			wantErr: "analytics view: --limit must be between 1 and 200",
		},
		{
			name:    "view invalid next",
			args:    []string{"analytics", "view", "--next", "http://api.appstoreconnect.apple.com/v1/analyticsReportRequests/x/reports"},
			wantErr: "analytics view: --next must be an App Store Connect URL",
		},
		{
			name:    "download invalid request id",
			args:    []string{"analytics", "download", "--request-id", "not-a-uuid", "--instance-id", "instance-1"},
			wantErr: "analytics download: --request-id must be a valid UUID",
		},
		{
			name:    "download invalid instance id",
			args:    []string{"analytics", "download", "--request-id", analyticsUsageExitRequestID, "--instance-id", "bad/instance"},
			wantErr: "analytics download: --instance-id: resource identifier",
		},
		{
			name: "download invalid segment id",
			args: []string{
				"analytics", "download",
				"--request-id", analyticsUsageExitRequestID,
				"--instance-id", "instance-1",
				"--segment-id", "bad/segment",
			},
			wantErr: "analytics download: --segment-id: resource identifier",
		},
		{
			name:    "reports links limit above maximum",
			args:    []string{"analytics", "reports", "links", "--report-id", "report-1", "--limit", "201"},
			wantErr: "analytics reports links: --limit must be between 1 and 200",
		},
		{
			name:    "reports links invalid next",
			args:    []string{"analytics", "reports", "links", "--next", "http://api.appstoreconnect.apple.com/v1/analyticsReports/x/instances"},
			wantErr: "analytics reports links: --next must be an App Store Connect URL",
		},
		{
			name:    "instances view invalid instance id",
			args:    []string{"analytics", "instances", "view", "--instance-id", "bad/instance"},
			wantErr: "analytics instances view: --instance-id: resource identifier",
		},
		{
			name:    "instances links limit above maximum",
			args:    []string{"analytics", "instances", "links", "--instance-id", "instance-1", "--limit", "201"},
			wantErr: "analytics instances links: --limit must be between 1 and 200",
		},
		{
			name:    "instances links invalid next",
			args:    []string{"analytics", "instances", "links", "--next", "http://api.appstoreconnect.apple.com/v1/analyticsReportInstances/x/segments"},
			wantErr: "analytics instances links: --next must be an App Store Connect URL",
		},
		{
			name:    "instances links invalid instance id",
			args:    []string{"analytics", "instances", "links", "--instance-id", "bad/instance"},
			wantErr: "analytics instances links: --instance-id: resource identifier",
		},
		{
			name:    "segments view invalid segment id",
			args:    []string{"analytics", "segments", "view", "--segment-id", "bad/segment"},
			wantErr: "analytics segments view: --segment-id: resource identifier",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, runErr := runCommand(t, test.args)

			if runErr == nil {
				t.Fatal("expected error, got nil")
			}
			if got := rootcmd.ExitCodeFromError(runErr); got != rootcmd.ExitUsage {
				t.Fatalf("exit code = %d, want %d (err=%v)", got, rootcmd.ExitUsage, runErr)
			}
			if stdout != "" {
				t.Fatalf("expected empty stdout, got %q", stdout)
			}
			if !strings.Contains(stderr, "Error: "+test.wantErr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, "Error: "+test.wantErr)
			}
		})
	}
}
