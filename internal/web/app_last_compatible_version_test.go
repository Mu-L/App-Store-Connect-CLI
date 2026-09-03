package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const lastCompatibleVersionPayload = `{
	"data": {
		"type": "apps",
		"id": "app-123",
		"attributes": {"name": "Example", "bundleId": "com.example.app"},
		"relationships": {
			"appStoreVersions": {"data": [
				{"type": "appStoreVersions", "id": "v-2"},
				{"type": "appStoreVersions", "id": "v-1"}
			]}
		}
	},
	"included": [
		{"type": "appStoreVersions", "id": "v-1", "attributes": {
			"versionString": "1.0",
			"platform": "IOS",
			"appVersionState": "READY_FOR_DISTRIBUTION",
			"downloadable": false,
			"createdDate": "2024-01-02T03:04:05Z",
			"reviewType": "APP_STORE"
		}},
		{"type": "appStoreVersions", "id": "v-2", "attributes": {
			"versionString": "2.0",
			"platform": "IOS",
			"appStoreState": "READY_FOR_SALE",
			"appVersionState": "READY_FOR_DISTRIBUTION",
			"downloadable": true,
			"createdDate": "2025-01-02T03:04:05Z"
		}}
	]
}`

func TestGetAppLastCompatibleVersionsBuildsExpectedRequest(t *testing.T) {
	var gotPath string
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Encode()
		if got := r.URL.Query().Get("include"); got != "appStoreVersions" {
			t.Errorf("include = %q, want appStoreVersions", got)
		}
		if got := r.URL.Query().Get("fields[appStoreVersions]"); !strings.Contains(got, "downloadable") {
			t.Errorf("fields[appStoreVersions] = %q, want downloadable", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(lastCompatibleVersionPayload))
	}))
	defer server.Close()

	got, err := testWebClient(server).GetAppLastCompatibleVersions(context.Background(), "app-123")
	if err != nil {
		t.Fatalf("GetAppLastCompatibleVersions() error = %v", err)
	}
	if gotPath != "/apps/app-123" {
		t.Fatalf("path = %q, want /apps/app-123", gotPath)
	}
	if !strings.Contains(gotQuery, "limit%5BappStoreVersions%5D=2000") {
		t.Fatalf("query = %q, want appStoreVersions limit", gotQuery)
	}
	if got.AppID != "app-123" {
		t.Fatalf("appID = %q, want app-123", got.AppID)
	}
	if len(got.Versions) != 2 {
		t.Fatalf("versions = %d, want 2", len(got.Versions))
	}
	if got.Versions[0].ID != "v-2" || got.Versions[1].ID != "v-1" {
		t.Fatalf("expected Apple relationship ordering, got %+v", got.Versions)
	}
	if got.Versions[0].Downloadable == nil || !*got.Versions[0].Downloadable {
		t.Fatalf("expected v-2 downloadable=true, got %+v", got.Versions[0].Downloadable)
	}
	if got.Versions[1].Downloadable == nil || *got.Versions[1].Downloadable {
		t.Fatalf("expected v-1 downloadable=false, got %+v", got.Versions[1].Downloadable)
	}
	if got.Versions[1].AppStoreState != "" {
		t.Fatalf("expected appStoreState left verbatim/empty, got %q", got.Versions[1].AppStoreState)
	}
	if got.Versions[1].AppVersionState != "READY_FOR_DISTRIBUTION" {
		t.Fatalf("appVersionState = %q, want READY_FOR_DISTRIBUTION", got.Versions[1].AppVersionState)
	}
	if got.Versions[1].VersionString != "1.0" || got.Versions[1].ReviewType != "APP_STORE" {
		t.Fatalf("unexpected version attributes: %+v", got.Versions[1])
	}
}

func TestGetAppLastCompatibleVersionsHandlesNoVersions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": {"type": "apps", "id": "app-9", "attributes": {"name": "Example"}}}`))
	}))
	defer server.Close()

	got, err := testWebClient(server).GetAppLastCompatibleVersions(context.Background(), "app-9")
	if err != nil {
		t.Fatalf("GetAppLastCompatibleVersions() error = %v", err)
	}
	if got.AppID != "app-9" {
		t.Fatalf("appID = %q, want app-9", got.AppID)
	}
	if len(got.Versions) != 0 {
		t.Fatalf("versions = %d, want 0", len(got.Versions))
	}
}

func TestGetAppLastCompatibleVersionsRequiresAppID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL.Path)
	}))
	defer server.Close()

	if _, err := testWebClient(server).GetAppLastCompatibleVersions(context.Background(), " "); err == nil {
		t.Fatal("expected error for empty app id")
	}
}

func TestGetAppLastCompatibleVersionsPropagatesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"status":"404","code":"NOT_FOUND","title":"Not found","detail":"missing app"}]}`))
	}))
	defer server.Close()

	if _, err := testWebClient(server).GetAppLastCompatibleVersions(context.Background(), "app-123"); err == nil {
		t.Fatal("expected error for 404 response")
	}
}
