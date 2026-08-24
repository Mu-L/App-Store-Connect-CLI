package cmdtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleIDsListSplitDoesNotFollowPagesWithoutPaginate(t *testing.T) {
	setupAuth(t)
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))
	identifiers := makeLongBundleIDIdentifierFilter()
	requestCount := 0
	setBundleIDPlatformTestServer(t, func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		if req.URL.Query().Get("filter[identifier]") == "" {
			t.Fatalf("request %d unexpectedly followed a continuation URL: %s", requestCount, req.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			_, _ = io.WriteString(w, `{"data":[{"type":"bundleIds","id":"bundle-first"}],"links":{"next":"https://api.appstoreconnect.apple.com/v1/bundleIds?cursor=chunk-one-next"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"type":"bundleIds","id":"bundle-second"}]}`)
	})

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	if err := root.Parse([]string{"bundle-ids", "list", "--identifier", identifiers, "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureOutput(t, func() {
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want one first-page request per chunk", requestCount)
	}
	if !strings.Contains(stdout, `"id":"bundle-first"`) || !strings.Contains(stdout, `"id":"bundle-second"`) {
		t.Fatalf("stdout = %q, want first page from each split chunk", stdout)
	}
}

func TestBundleIDsListSplitPaginatesEveryChunk(t *testing.T) {
	setupAuth(t)
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))
	identifiers := makeLongBundleIDIdentifierFilter()
	requestCount := 0
	setBundleIDPlatformTestServer(t, func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		switch requestCount {
		case 1:
			if req.URL.Query().Get("filter[identifier]") == "" {
				t.Fatalf("first request missing split identifier filter")
			}
			_, _ = io.WriteString(w, `{"data":[{"type":"bundleIds","id":"bundle-first"}],"links":{"next":"https://api.appstoreconnect.apple.com/v1/bundleIds?cursor=chunk-one-next"}}`)
		case 2:
			if req.URL.Query().Get("cursor") != "chunk-one-next" {
				t.Fatalf("second request query = %q, want first chunk continuation", req.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `{"data":[{"type":"bundleIds","id":"bundle-continuation"}]}`)
		case 3:
			if req.URL.Query().Get("filter[identifier]") == "" {
				t.Fatalf("third request missing second split identifier filter")
			}
			_, _ = io.WriteString(w, `{"data":[{"type":"bundleIds","id":"bundle-second"}]}`)
		default:
			t.Fatalf("unexpected extra request %d: %s", requestCount, req.URL.String())
		}
	})

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	if err := root.Parse([]string{"bundle-ids", "list", "--identifier", identifiers, "--paginate", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureOutput(t, func() {
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want every split page, got %q", requestCount, stdout)
	}
	for _, id := range []string{"bundle-first", "bundle-continuation", "bundle-second"} {
		if !strings.Contains(stdout, `"id":"`+id+`"`) {
			t.Fatalf("stdout = %q, missing %s", stdout, id)
		}
	}
}

func makeLongBundleIDIdentifierFilter() string {
	identifiers := make([]string, 0, 250)
	for i := 0; i < 250; i++ {
		identifiers = append(identifiers, fmt.Sprintf("com.example.%012d", i))
	}
	return strings.Join(identifiers, ",")
}
