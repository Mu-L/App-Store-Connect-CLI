package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetCIVersionAliases(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/teams/team-uuid/products/product-uuid/configuration-options/version-aliases-v3" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit = %q, want 100", got)
		}
		_, _ = io.WriteString(w, `{"items":[{"id":"alias-1","name":"Release","type":"CUSTOM","locked":true,"build":{"signed_url":"https://example.invalid/?token=secret"},"build_name":"42","related_workflow_summaries":[{"id":"wf-1","name":"Deploy","disabled":false,"locked":false}],"build_supported":true}]}`)
	}))
	defer server.Close()

	result, err := testWebClient(server).GetCIVersionAliases(context.Background(), "team-uuid", "product-uuid")
	if err != nil {
		t.Fatalf("GetCIVersionAliases() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(result.Items))
	}
	item := result.Items[0]
	if item.ID != "alias-1" || item.Name != "Release" || item.Type != "CUSTOM" || !item.Locked || item.BuildName != "42" || !item.BuildSupported {
		t.Fatalf("unexpected item: %+v", item)
	}
	if len(item.RelatedWorkflowSummaries) != 1 || item.RelatedWorkflowSummaries[0].ID != "wf-1" {
		t.Fatalf("unexpected workflow summaries: %+v", item.RelatedWorkflowSummaries)
	}
}

func TestGetCIVersionAlias(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %q, want GET", r.Method)
		}
		if got := r.URL.EscapedPath(); got != "/teams/team%2Fone/products/product%2Fone/configuration-options/version-aliases-v3/alias%2Fone" {
			t.Fatalf("escaped path = %q", got)
		}
		_, _ = io.WriteString(w, `{"id":"alias/one","name":"Latest","type":"CUSTOM","locked":false,"build_name":"43","build_supported":true}`)
	}))
	defer server.Close()

	item, err := testWebClient(server).GetCIVersionAlias(context.Background(), "team/one", "product/one", "alias/one")
	if err != nil {
		t.Fatalf("GetCIVersionAlias() error = %v", err)
	}
	if item.ID != "alias/one" || item.BuildName != "43" {
		t.Fatalf("unexpected item: %+v", item)
	}
}

func TestCIVersionAliasesRejectInvalidInputs(t *testing.T) {
	client := &Client{httpClient: http.DefaultClient, baseURL: "http://localhost"}
	tests := []struct {
		name string
		run  func() error
		want string
	}{
		{name: "list empty team", run: func() error { _, err := client.GetCIVersionAliases(context.Background(), "", "product"); return err }, want: "team id and product id are required"},
		{name: "list empty product", run: func() error { _, err := client.GetCIVersionAliases(context.Background(), "team", " "); return err }, want: "team id and product id are required"},
		{name: "view empty team", run: func() error {
			_, err := client.GetCIVersionAlias(context.Background(), "", "product", "alias")
			return err
		}, want: "team id, product id, and version alias id are required"},
		{name: "view empty product", run: func() error {
			_, err := client.GetCIVersionAlias(context.Background(), "team", "", "alias")
			return err
		}, want: "team id, product id, and version alias id are required"},
		{name: "view empty alias", run: func() error {
			_, err := client.GetCIVersionAlias(context.Background(), "team", "product", " ")
			return err
		}, want: "team id, product id, and version alias id are required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}
