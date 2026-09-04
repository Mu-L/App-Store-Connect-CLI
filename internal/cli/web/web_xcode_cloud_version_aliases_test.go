package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func TestWebVersionAliasesHierarchy(t *testing.T) {
	settings := findSub(WebXcodeCloudCommand(), "settings")
	if settings == nil {
		t.Fatal("expected settings subcommand")
	}
	group := findSub(settings, "version-aliases")
	if group == nil {
		t.Fatal("expected version-aliases subcommand")
	}
	for _, name := range []string{"list", "view"} {
		command := findSub(group, name)
		if command == nil || command.UsageFunc == nil {
			t.Fatalf("expected %q subcommand with UsageFunc", name)
		}
	}
}

func TestWebVersionAliasesListJSONOmitsNestedPayloads(t *testing.T) {
	stubNextBuildNumberSession(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/ci/api/teams/team-uuid/products/product-uuid/configuration-options/version-aliases-v3" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.String())
		}
		if got := req.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit = %q, want 100", got)
		}
		body := `{"items":[{"id":"alias-1","name":"Release","type":"CUSTOM","locked":true,"build":{"signed_url":"https://example.invalid/?token=secret"},"build_name":"42","related_workflow_summaries":[{"id":"wf-1","name":"Deploy"}],"build_supported":true}]}`
		return nextBuildNumberResponse(req, http.StatusOK, body), nil
	})

	cmd := webVersionAliasesList()
	if err := cmd.FlagSet.Parse([]string{"--product-id", " product-uuid ", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	stdout, stderr := captureOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode output: %v; output=%q", err, stdout)
	}
	if result["productId"] != "product-uuid" {
		t.Fatalf("productId = %#v", result["productId"])
	}
	if strings.Contains(stdout, "signed_url") || strings.Contains(stdout, "token=secret") || strings.Contains(stdout, "relatedWorkflow") {
		t.Fatalf("nested payload leaked in output: %q", stdout)
	}
	for _, want := range []string{`"id":"alias-1"`, `"name":"Release"`, `"buildName":"42"`, `"buildSupported":true`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("output missing %s: %q", want, stdout)
		}
	}
}

func TestWebVersionAliasViewJSON(t *testing.T) {
	stubNextBuildNumberSession(t, func(req *http.Request) (*http.Response, error) {
		if got := req.URL.EscapedPath(); got != "/ci/api/teams/team-uuid/products/product%2Fone/configuration-options/version-aliases-v3/alias%2Fone" {
			t.Fatalf("escaped path = %q", got)
		}
		return nextBuildNumberResponse(req, http.StatusOK, `{"id":"alias/one","name":"Latest","type":"CUSTOM","locked":false,"build_name":"43","build_supported":true}`), nil
	})
	cmd := webVersionAliasView()
	if err := cmd.FlagSet.Parse([]string{"--product-id", "product/one", "--id", "alias/one", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	stdout, _ := captureOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("Exec() error = %v", err)
		}
	})
	for _, want := range []string{`"productId":"product/one"`, `"id":"alias/one"`, `"name":"Latest"`, `"buildName":"43"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("output missing %s: %q", want, stdout)
		}
	}
}

func TestWebVersionAliasesValidateBeforeSession(t *testing.T) {
	original := resolveSessionFn
	called := false
	resolveSessionFn = func(context.Context, string, string, string) (*webcore.AuthSession, string, error) {
		called = true
		return nil, "", nil
	}
	t.Cleanup(func() { resolveSessionFn = original })

	list := webVersionAliasesList()
	if err := list.Exec(context.Background(), nil); err == nil {
		t.Fatal("expected missing product error")
	}
	view := webVersionAliasView()
	if err := view.FlagSet.Parse([]string{"--product-id", "product"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := view.Exec(context.Background(), nil); err == nil {
		t.Fatal("expected missing alias ID error")
	}
	if called {
		t.Fatal("session resolution must not run for invalid input")
	}
}

func TestWebVersionAliasesRejectPositionalArguments(t *testing.T) {
	for _, command := range []struct {
		name string
		cmd  func() error
	}{
		{name: "list", cmd: func() error { return webVersionAliasesList().Exec(context.Background(), []string{"extra"}) }},
		{name: "view", cmd: func() error { return webVersionAliasView().Exec(context.Background(), []string{"extra"}) }},
	} {
		t.Run(command.name, func(t *testing.T) {
			if err := command.cmd(); err == nil || !strings.Contains(err.Error(), "does not accept positional arguments") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestWebVersionAliasesRequirePublicProviderID(t *testing.T) {
	original := resolveSessionFn
	resolveSessionFn = func(context.Context, string, string, string) (*webcore.AuthSession, string, error) {
		return &webcore.AuthSession{Client: http.DefaultClient}, "cache", nil
	}
	t.Cleanup(func() { resolveSessionFn = original })

	list := webVersionAliasesList()
	if err := list.FlagSet.Parse([]string{"--product-id", "product"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := list.Exec(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "session has no public provider ID") {
		t.Fatalf("list error = %v", err)
	}
	view := webVersionAliasView()
	if err := view.FlagSet.Parse([]string{"--product-id", "product", "--id", "alias"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := view.Exec(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "session has no public provider ID") {
		t.Fatalf("view error = %v", err)
	}
}
