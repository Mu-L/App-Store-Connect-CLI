package cmdtest

import (
	"errors"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

// TestGameCenterRelationshipReplacementRequiresConfirm locks the 5.0.0
// contract: replacing Game Center group or leaderboard-set relationships
// without --confirm is a usage error before authentication or HTTP, not a
// warning that continues.
func TestGameCenterRelationshipReplacementRequiresConfirm(t *testing.T) {
	setupUsageExitCodeEnv(t)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "groups achievements set",
			args: []string{"game-center", "groups", "achievements", "set", "--group-id", "group-1", "--ids", "achievement-1"},
		},
		{
			name: "groups leaderboards set",
			args: []string{"game-center", "groups", "leaderboards", "set", "--group-id", "group-1", "--ids", "leaderboard-1"},
		},
		{
			name: "leaderboard-sets members set",
			args: []string{"game-center", "leaderboard-sets", "members", "set", "--set-id", "set-1", "--leaderboard-ids", "leaderboard-1"},
		},
		{
			name: "leaderboard-sets v2 members set",
			args: []string{"game-center", "leaderboard-sets", "v2", "members", "set", "--set-id", "set-1", "--leaderboard-ids", "leaderboard-1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factoryCalled := false
			restore := shared.SetASCClientFactoryForTesting(func() (*asc.Client, error) {
				factoryCalled = true
				return nil, errors.New("poison client factory called")
			})
			t.Cleanup(restore)

			var code int
			stdout, stderr := captureOutput(t, func() {
				code = rootcmd.Run(test.args, "5.0.0")
			})

			if code != rootcmd.ExitUsage {
				t.Fatalf("exit code = %d, want %d", code, rootcmd.ExitUsage)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			assertUsageDiagnosticFirstLine(t, stderr, "--confirm is required")
			if strings.Contains(stderr, "Warning:") {
				t.Fatalf("stderr = %q, must not carry the retired compatibility warning", stderr)
			}
			if factoryCalled {
				t.Fatal("client factory called before --confirm validation")
			}
		})
	}
}
