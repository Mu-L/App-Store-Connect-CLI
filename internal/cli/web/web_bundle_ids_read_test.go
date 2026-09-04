package web

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"

	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func TestWebBundleIDsCommandHierarchyIncludesReadLeavesFirst(t *testing.T) {
	command := WebBundleIDsCommand()
	want := []string{"list", "view", "capabilities"}
	if len(command.Subcommands) != len(want) {
		t.Fatalf("subcommands = %d, want %d", len(command.Subcommands), len(want))
	}
	for index, name := range want {
		if command.Subcommands[index].Name != name || command.Subcommands[index].UsageFunc == nil {
			t.Fatalf("subcommand %d = %+v, want %q with usage", index, command.Subcommands[index], name)
		}
	}
}

func TestWebBundleIDsReadValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		command func() *ffcli.Command
		args    []string
		wantErr string
	}{
		{name: "list positional", command: WebBundleIDsListCommand, args: []string{"extra"}, wantErr: "web bundle-ids list does not accept positional arguments"},
		{name: "view missing bundle id", command: WebBundleIDsViewCommand, args: nil, wantErr: "--bundle-id is required"},
		{name: "view positional", command: WebBundleIDsViewCommand, args: []string{"--bundle-id", "bundle-1", "extra"}, wantErr: "web bundle-ids view does not accept positional arguments"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.command()
			if err := command.FlagSet.Parse(tc.args); err != nil {
				t.Fatalf("parse error: %v", err)
			}
			stdout, stderr := captureWebCommandOutput(t, func() {
				err := command.Exec(context.Background(), command.FlagSet.Args())
				if !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("expected usage error, got %v", err)
				}
			})
			if stdout != "" {
				t.Fatalf("expected empty stdout, got %q", stdout)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Fatalf("stderr %q does not contain %q", stderr, tc.wantErr)
			}
		})
	}
}

func TestWebBundleIDsListPrintsJSON(t *testing.T) {
	restore := stubWebBundleIDReadDependencies(t)
	defer restore()

	listDeveloperBundleIDsFn = func(context.Context, *webcore.Client) (*webcore.DeveloperBundleIDsListResult, error) {
		return &webcore.DeveloperBundleIDsListResult{
			Data: []webcore.DeveloperBundleID{{
				ID:   "bundle-1",
				Type: "bundleIds",
				Attributes: map[string]any{
					"name":       "Example App",
					"identifier": "com.example.app",
					"platform":   "IOS",
					"wildcard":   false,
				},
			}},
			Raw: json.RawMessage(`{"data":[{"type":"bundleIds","id":"bundle-1","attributes":{"name":"Example App","identifier":"com.example.app","platform":"IOS","wildcard":false}}],"included":[],"links":{},"meta":{},"unknownTopLevel":{"keep":true}}`),
		}, nil
	}

	command := WebBundleIDsListCommand()
	if err := command.FlagSet.Parse([]string{"--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	var result webcore.DeveloperBundleIDsListResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode JSON output %q: %v", stdout, err)
	}
	if len(result.Data) != 1 || result.Data[0].ID != "bundle-1" || result.Data[0].Attributes["identifier"] != "com.example.app" {
		t.Fatalf("unexpected list result: %+v", result)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode raw JSON envelope %q: %v", stdout, err)
	}
	for _, member := range []string{"included", "links", "meta", "unknownTopLevel"} {
		if _, ok := envelope[member]; !ok {
			t.Fatalf("JSON output omitted envelope member %q: %s", member, stdout)
		}
	}
	if got := string(envelope["unknownTopLevel"]); got != `{"keep":true}` {
		t.Fatalf("unknown top-level member = %s, want {\"keep\":true}", got)
	}
}

func TestWebBundleIDsViewPrintsTable(t *testing.T) {
	restore := stubWebBundleIDReadDependencies(t)
	defer restore()

	getDeveloperBundleIDFn = func(_ context.Context, _ *webcore.Client, bundleID string) (*webcore.DeveloperBundleIDGetResult, error) {
		return &webcore.DeveloperBundleIDGetResult{Data: webcore.DeveloperBundleID{
			ID:   bundleID,
			Type: "bundleIds",
			Attributes: map[string]any{
				"name":       "Example App",
				"identifier": "com.example.app",
				"platform":   "IOS",
				"bundleType": "STANDARD",
				"wildcard":   false,
			},
		}}, nil
	}

	command := WebBundleIDsViewCommand()
	if err := command.FlagSet.Parse([]string{"--bundle-id", "bundle-1", "--output", "table"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	for _, want := range []string{"ID", "Name", "Identifier", "Example App", "com.example.app", "STANDARD"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("table output %q does not contain %q", stdout, want)
		}
	}
}

func TestWebBundleIDsViewPrintsRawJSONEnvelope(t *testing.T) {
	restore := stubWebBundleIDReadDependencies(t)
	defer restore()

	getDeveloperBundleIDFn = func(_ context.Context, _ *webcore.Client, bundleID string) (*webcore.DeveloperBundleIDGetResult, error) {
		return &webcore.DeveloperBundleIDGetResult{
			Data: webcore.DeveloperBundleID{
				ID:   bundleID,
				Type: "bundleIds",
				Attributes: map[string]any{
					"name":       "Example App",
					"identifier": "com.example.app",
				},
			},
			Raw: json.RawMessage(`{"data":{"type":"bundleIds","id":"bundle-1","attributes":{"name":"Example App","identifier":"com.example.app"}},"included":[],"links":{},"meta":{},"unknownTopLevel":[]}`),
		}, nil
	}

	command := WebBundleIDsViewCommand()
	if err := command.FlagSet.Parse([]string{"--bundle-id", "bundle-1", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := command.Exec(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("decode raw JSON envelope %q: %v", stdout, err)
	}
	for _, member := range []string{"included", "links", "meta", "unknownTopLevel"} {
		if _, ok := envelope[member]; !ok {
			t.Fatalf("JSON output omitted envelope member %q: %s", member, stdout)
		}
	}
	if got := string(envelope["unknownTopLevel"]); got != `[]` {
		t.Fatalf("unknown top-level member = %s, want []", got)
	}
}

func TestWebBundleIDsGetCompatibilityAliasDispatchesToView(t *testing.T) {
	restore := stubWebBundleIDReadDependencies(t)
	defer restore()

	getDeveloperBundleIDFn = func(_ context.Context, _ *webcore.Client, bundleID string) (*webcore.DeveloperBundleIDGetResult, error) {
		return &webcore.DeveloperBundleIDGetResult{Data: webcore.DeveloperBundleID{
			ID:   bundleID,
			Type: "bundleIds",
			Attributes: map[string]any{
				"name":       "Example App",
				"identifier": "com.example.app",
			},
		}}, nil
	}

	command := WebBundleIDsCommand()
	if err := command.FlagSet.Parse([]string{"get", "--bundle-id", "bundle-1", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := command.Exec(context.Background(), command.FlagSet.Args()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(stderr, "compatibility alias") || !strings.Contains(stderr, "bundle-ids view") {
		t.Fatalf("expected compatibility warning, got %q", stderr)
	}
	var result webcore.DeveloperBundleIDGetResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode JSON output %q: %v", stdout, err)
	}
	if result.Data.ID != "bundle-1" || result.Data.Attributes["identifier"] != "com.example.app" {
		t.Fatalf("unexpected alias result: %+v", result)
	}
}

func stubWebBundleIDReadDependencies(t *testing.T) func() {
	t.Helper()
	origResolveSession := resolveSessionFn
	origNewWebClient := newWebClientFn
	origList := listDeveloperBundleIDsFn
	origGet := getDeveloperBundleIDFn
	origPersist := persistWebSessionFn

	resolveSessionFn = func(context.Context, string, string, string) (*webcore.AuthSession, string, error) {
		return &webcore.AuthSession{}, "cache", nil
	}
	newWebClientFn = func(*webcore.AuthSession) *webcore.Client { return &webcore.Client{} }
	persistWebSessionFn = func(*webcore.AuthSession) error { return nil }

	restore := func() {
		resolveSessionFn = origResolveSession
		newWebClientFn = origNewWebClient
		listDeveloperBundleIDsFn = origList
		getDeveloperBundleIDFn = origGet
		persistWebSessionFn = origPersist
	}
	return restore
}
