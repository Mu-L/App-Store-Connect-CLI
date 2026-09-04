package cmdtest

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
)

// TestRemovedHiddenFlagAliasesAreUnknownFlags locks the 5.0.0 removal of the
// hidden compatibility spellings that 4.x accepted behind a deprecation
// warning. Each removed alias now fails as a generic unknown flag before any
// HTTP request, and the canonical spelling stays registered.
func TestRemovedHiddenFlagAliasesAreUnknownFlags(t *testing.T) {
	tests := []struct {
		path      []string
		alias     string
		canonical string
		args      []string
	}{
		{path: []string{"versions", "view"}, alias: "id", canonical: "version-id", args: []string{"versions", "view", "--id", "version-1"}},
		{path: []string{"versions", "update"}, alias: "id", canonical: "version-id", args: []string{"versions", "update", "--id", "version-1", "--copyright", "2026 Example"}},
		{path: []string{"versions", "attach-build"}, alias: "build", canonical: "build-id", args: []string{"versions", "attach-build", "--version-id", "version-1", "--build", "build-1"}},
		{path: []string{"apps", "view"}, alias: "app", canonical: "id", args: []string{"apps", "view", "--app", "app-1"}},
		{path: []string{"apps", "app-encryption-declarations", "list"}, alias: "build", canonical: "build-id", args: []string{"apps", "app-encryption-declarations", "list", "--id", "app-1", "--build", "build-1"}},
		{path: []string{"encryption", "declarations", "list"}, alias: "build", canonical: "build-id", args: []string{"encryption", "declarations", "list", "--app", "app-1", "--build", "build-1"}},
		{path: []string{"encryption", "declarations", "assign-builds"}, alias: "build", canonical: "build-id", args: []string{"encryption", "declarations", "assign-builds", "--id", "decl-1", "--build", "build-1"}},
		{path: []string{"bundle-ids", "capabilities", "list"}, alias: "bundle-id", canonical: "bundle", args: []string{"bundle-ids", "capabilities", "list", "--bundle-id", "bundle-1"}},
		{path: []string{"localizations", "list"}, alias: "version-id", canonical: "version", args: []string{"localizations", "list", "--version-id", "version-1"}},
		{path: []string{"localizations", "update"}, alias: "version-id", canonical: "version", args: []string{"localizations", "update", "--version-id", "version-1", "--locale", "en-US", "--description", "Updated"}},
		{path: []string{"screenshots", "list"}, alias: "localization-id", canonical: "version-localization", args: []string{"screenshots", "list", "--localization-id", "loc-1"}},
	}

	installDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("removed aliases must fail before HTTP: %s %s", req.Method, req.URL.String())
		return nil, errors.New("unexpected request")
	}))

	root := RootCommand("1.2.3")
	for _, test := range tests {
		commandPath := strings.Join(test.path, " ")
		t.Run(commandPath+" --"+test.alias, func(t *testing.T) {
			command := findSubcommand(root, test.path...)
			if command == nil {
				t.Fatalf("command %q not found", commandPath)
			}
			if command.FlagSet.Lookup(test.canonical) == nil {
				t.Fatalf("canonical flag --%s not found on %q", test.canonical, commandPath)
			}
			if command.FlagSet.Lookup(test.alias) != nil {
				t.Fatalf("removed alias --%s is still registered on %q", test.alias, commandPath)
			}

			stdout, stderr := captureOutput(t, func() {
				if code := rootcmd.Run(test.args, "1.2.3"); code != rootcmd.ExitUsage {
					t.Fatalf("exit code = %d, want %d", code, rootcmd.ExitUsage)
				}
			})
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			want := "Error: unknown flag `--" + test.alias + "` for `asc " + commandPath + "`"
			if !strings.Contains(stderr, want) {
				t.Fatalf("stderr = %q, want containing %q", stderr, want)
			}
			if strings.Contains(stderr, "deprecated") {
				t.Fatalf("stderr = %q, want no deprecation guidance for a removed alias", stderr)
			}
		})
	}
}
