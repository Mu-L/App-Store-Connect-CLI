package cmdtest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func ageRatingAuditTransport() http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v1/apps":
			return jsonHTTPResponse(http.StatusOK, `{"data":[
				{"type":"apps","id":"app-ready","attributes":{"name":"Ready App","bundleId":"com.example.ready"}},
				{"type":"apps","id":"app-social","attributes":{"name":"Social App","bundleId":"com.example.social"}},
				{"type":"apps","id":"app-unset","attributes":{"name":"Unset App","bundleId":"com.example.unset"}}
			],"links":{}}`), nil
		case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/v1/apps/") && strings.HasSuffix(req.URL.Path, "/appInfos"):
			appID := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, "/v1/apps/"), "/appInfos")
			return jsonHTTPResponse(http.StatusOK, fmt.Sprintf(`{"data":[{"type":"appInfos","id":"info-%s"}],"links":{}}`, appID)), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v1/appInfos/info-app-ready/ageRatingDeclaration":
			return jsonHTTPResponse(http.StatusOK, `{"data":{"type":"ageRatingDeclarations","id":"decl-1","attributes":{"socialMedia":false,"socialMediaAgeRestricted":false,"messagingAndChat":false,"ageAssurance":false}}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v1/appInfos/info-app-social/ageRatingDeclaration":
			return jsonHTTPResponse(http.StatusOK, `{"data":{"type":"ageRatingDeclarations","id":"decl-2","attributes":{"socialMedia":true,"messagingAndChat":true,"ageAssurance":true}}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v1/appInfos/info-app-unset/ageRatingDeclaration":
			return jsonHTTPResponse(http.StatusOK, `{"data":{"type":"ageRatingDeclarations","id":"decl-3","attributes":{}}}`), nil
		default:
			return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL.String())
		}
	})
}

func TestAgeRatingAuditReportsMissingSocialMediaResponses(t *testing.T) {
	setupAuth(t)
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = ageRatingAuditTransport()

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	stdout, stderr := captureOutput(t, func() {
		if err := root.Parse([]string{"age-rating", "audit", "--output", "json"}); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})

	var result struct {
		Apps []struct {
			AppID            string   `json:"appId"`
			SocialMedia      string   `json:"socialMedia"`
			MissingResponses []string `json:"missingResponses"`
			Ready            bool     `json:"ready"`
		} `json:"apps"`
		ReadyCount   int `json:"readyCount"`
		MissingCount int `json:"missingCount"`
		ErrorCount   int `json:"errorCount"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal output: %v (%q)", err, stdout)
	}
	if result.ReadyCount != 1 || result.MissingCount != 2 || result.ErrorCount != 0 {
		t.Fatalf("counts = ready %d missing %d error %d, want 1/2/0", result.ReadyCount, result.MissingCount, result.ErrorCount)
	}
	rows := map[string][]string{}
	for _, row := range result.Apps {
		rows[row.AppID] = row.MissingResponses
	}
	if len(rows["app-ready"]) != 0 {
		t.Fatalf("app-ready missing = %v, want none", rows["app-ready"])
	}
	if got := strings.Join(rows["app-social"], ","); got != "socialMediaAgeRestricted" {
		t.Fatalf("app-social missing = %q, want socialMediaAgeRestricted", got)
	}
	if got := strings.Join(rows["app-unset"], ","); got != "socialMedia,messagingAndChat" {
		t.Fatalf("app-unset missing = %q, want socialMedia,messagingAndChat", got)
	}
	if !strings.Contains(stderr, "September 2026") {
		t.Fatalf("stderr missing deadline notice, got %q", stderr)
	}
}

func TestAgeRatingAuditAppFilterRestrictsSweep(t *testing.T) {
	setupAuth(t)
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = ageRatingAuditTransport()

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	stdout, _ := captureOutput(t, func() {
		if err := root.Parse([]string{"age-rating", "audit", "--app", "app-social", "--output", "json"}); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})

	var result struct {
		Apps []struct {
			AppID string `json:"appId"`
			Name  string `json:"name"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("unmarshal output: %v (%q)", err, stdout)
	}
	if len(result.Apps) != 1 || result.Apps[0].AppID != "app-social" || result.Apps[0].Name != "Social App" {
		t.Fatalf("unexpected filtered rows: %+v", result.Apps)
	}
}
