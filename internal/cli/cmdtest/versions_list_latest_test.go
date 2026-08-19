package cmdtest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
)

func TestVersionsListLatestKeepsNewestVersionPerPlatform(t *testing.T) {
	setupAuth(t)
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	pageTwoPath := "/v1/apps/app-1/appStoreVersions"
	pageTwoQuery := "cursor=page2"
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == pageTwoPath && req.URL.RawQuery == pageTwoQuery:
			return jsonHTTPResponse(http.StatusOK, `{"data":[
				{"type":"appStoreVersions","id":"ver-ios-new","attributes":{"platform":"IOS","versionString":"2.4.1","appStoreState":"READY_FOR_SALE","createdDate":"2026-07-07T14:44:01-07:00"}},
				{"type":"appStoreVersions","id":"ver-mac-old","attributes":{"platform":"MAC_OS","versionString":"1.0.0","appStoreState":"READY_FOR_SALE","createdDate":"2020-01-01T00:00:00-07:00"}}
			],"links":{}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == pageTwoPath:
			return jsonHTTPResponse(http.StatusOK, fmt.Sprintf(`{"data":[
				{"type":"appStoreVersions","id":"ver-ios-old","attributes":{"platform":"IOS","versionString":"2.3.2","appStoreState":"READY_FOR_SALE","createdDate":"2025-11-20T00:00:00-07:00"}},
				{"type":"appStoreVersions","id":"ver-mac-new","attributes":{"platform":"MAC_OS","versionString":"2.6.2","appStoreState":"READY_FOR_SALE","createdDate":"2020-10-26T09:49:56-07:00"}}
			],"links":{"next":"https://api.appstoreconnect.apple.com%s?%s"}}`, pageTwoPath, pageTwoQuery)), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL.String())
		}
	})

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	stdout, _ := captureOutput(t, func() {
		if err := root.Parse([]string{"versions", "list", "--app", "app-1", "--state", "READY_FOR_SALE", "--latest", "--output", "json"}); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})

	var result struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Platform      string `json:"platform"`
				VersionString string `json:"versionString"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal output: %v (%q)", err, stdout)
	}
	if len(result.Data) != 2 {
		t.Fatalf("data length = %d, want 2 (newest per platform)", len(result.Data))
	}
	byPlatform := map[string]string{}
	for _, version := range result.Data {
		byPlatform[version.Attributes.Platform] = version.Attributes.VersionString
	}
	if byPlatform["IOS"] != "2.4.1" {
		t.Fatalf("IOS latest = %q, want 2.4.1 (newest across pages)", byPlatform["IOS"])
	}
	if byPlatform["MAC_OS"] != "2.6.2" {
		t.Fatalf("MAC_OS latest = %q, want 2.6.2", byPlatform["MAC_OS"])
	}
}

func TestVersionsListLatestRejectsNextURL(t *testing.T) {
	stdout, stderr := captureOutput(t, func() {
		if code := rootcmd.Run([]string{"versions", "list", "--app", "app-1", "--latest", "--next", "https://api.appstoreconnect.apple.com/v1/apps/app-1/appStoreVersions?cursor=x"}, "1.2.3"); code != rootcmd.ExitUsage {
			t.Fatalf("exit code = %d, want %d", code, rootcmd.ExitUsage)
		}
	})
	if stdout != "" {
		t.Fatalf("expected empty stdout, got %q", stdout)
	}
	if !strings.Contains(stderr, "--latest") || !strings.Contains(stderr, "--next") {
		t.Fatalf("expected latest/next conflict diagnostic, got %q", stderr)
	}
}
