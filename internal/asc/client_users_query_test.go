package asc

import (
	"context"
	"net/http"
	"testing"
)

func TestGetUsers_WithQueryParityOptions(t *testing.T) {
	response := jsonResponse(http.StatusOK, `{"data":[]}`)
	client := newTestClient(t, func(req *http.Request) {
		if req.URL.Path != "/v1/users" {
			t.Fatalf("path = %q, want /v1/users", req.URL.Path)
		}
		values := req.URL.Query()
		want := map[string]string{
			"filter[visibleApps]": "app-1,app-2",
			"sort":                "-lastName",
			"fields[users]":       "username,lastName,visibleApps",
			"fields[apps]":        "name,bundleId",
			"include":             "visibleApps",
			"limit[visibleApps]":  "25",
		}
		for key, expected := range want {
			if got := values.Get(key); got != expected {
				t.Errorf("%s = %q, want %q", key, got, expected)
			}
		}
	}, response)

	if _, err := client.GetUsers(
		context.Background(),
		WithUsersVisibleAppIDs([]string{"app-1", " app-2 "}),
		WithUsersSort("-lastName"),
		WithUsersFields([]string{"username", "lastName", "visibleApps"}),
		WithUsersAppFields([]string{"name", "bundleId"}),
		WithUsersInclude([]string{"visibleApps"}),
		WithUsersVisibleAppsLimit(25),
	); err != nil {
		t.Fatalf("GetUsers() error: %v", err)
	}
}
