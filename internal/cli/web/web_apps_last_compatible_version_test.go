package web

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func TestWebAppsLastCompatibleVersionViewPrintsVersions(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")
	stubWebAppsDistributionSession(t)

	origGet := getWebAppLastCompatibleVersionsFn
	t.Cleanup(func() { getWebAppLastCompatibleVersionsFn = origGet })

	var gotAppID string
	getWebAppLastCompatibleVersionsFn = func(ctx context.Context, client *webcore.Client, appID string) (*webcore.AppLastCompatibleVersions, error) {
		gotAppID = appID
		return &webcore.AppLastCompatibleVersions{
			AppID: appID,
			Versions: []webcore.AppLastCompatibleVersion{
				{ID: "v-2", VersionString: "2.0", Platform: "IOS", AppVersionState: "READY_FOR_DISTRIBUTION", Downloadable: boolPtr(true), CreatedDate: "2025-01-02T03:04:05Z"},
				{ID: "v-1", VersionString: "1.0", Platform: "IOS", AppVersionState: "READY_FOR_DISTRIBUTION", Downloadable: boolPtr(false), CreatedDate: "2024-01-02T03:04:05Z"},
			},
		}, nil
	}

	cmd := WebAppsLastCompatibleVersionViewCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", "app-1", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	if gotAppID != "app-1" {
		t.Fatalf("appID = %q, want app-1", gotAppID)
	}

	var out struct {
		AppID    string `json:"appId"`
		Versions []struct {
			ID            string `json:"id"`
			VersionString string `json:"versionString"`
			Downloadable  *bool  `json:"downloadable"`
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("expected valid JSON output, got error: %v; stdout=%q", err, stdout)
	}
	if out.AppID != "app-1" || len(out.Versions) != 2 {
		t.Fatalf("unexpected output: %+v", out)
	}
	if out.Versions[0].ID != "v-2" || out.Versions[0].Downloadable == nil || !*out.Versions[0].Downloadable {
		t.Fatalf("unexpected first version: %+v", out.Versions[0])
	}
	if out.Versions[1].Downloadable == nil || *out.Versions[1].Downloadable {
		t.Fatalf("unexpected second version: %+v", out.Versions[1])
	}
}

func TestWebAppsLastCompatibleVersionViewTableRendersRows(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")
	stubWebAppsDistributionSession(t)

	origGet := getWebAppLastCompatibleVersionsFn
	t.Cleanup(func() { getWebAppLastCompatibleVersionsFn = origGet })

	getWebAppLastCompatibleVersionsFn = func(ctx context.Context, client *webcore.Client, appID string) (*webcore.AppLastCompatibleVersions, error) {
		return &webcore.AppLastCompatibleVersions{
			AppID: appID,
			Versions: []webcore.AppLastCompatibleVersion{
				{ID: "v-2", VersionString: "2.0", Platform: "IOS", Downloadable: boolPtr(true)},
				{ID: "v-1", VersionString: "1.0", Platform: "IOS"},
			},
		}, nil
	}

	cmd := WebAppsLastCompatibleVersionViewCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", "app-1", "--output", "table"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	if stderr != "" {
		t.Fatalf("expected empty stderr, got %q", stderr)
	}
	for _, want := range []string{"downloadable", "version", "v-2", "2.0", "true", "unknown"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q; stdout=%q", want, stdout)
		}
	}
}

func TestWebAppsLastCompatibleVersionViewRequiresApp(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")

	cmd := WebAppsLastCompatibleVersionViewCommand()
	if err := cmd.FlagSet.Parse([]string{"--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var err error
	_, stderr := captureWebCommandOutput(t, func() {
		err = cmd.Exec(context.Background(), nil)
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if want := "Error: --app is required (or set ASC_APP_ID)\n"; !strings.HasPrefix(stderr, want) {
		t.Fatalf("stderr = %q, want prefix %q", stderr, want)
	}
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp usage contract", err)
	}
	if kind := shared.ClassifyUsageError(err); kind != shared.UsageErrorMissingRequired {
		t.Fatalf("usage kind = %q, want %q", kind, shared.UsageErrorMissingRequired)
	}
}

func TestWebAppsLastCompatibleVersionViewRejectsPositionalArguments(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")

	cmd := WebAppsLastCompatibleVersionViewCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", "app-1"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	err := cmd.Exec(context.Background(), []string{"extra"})
	if err == nil {
		t.Fatal("expected error for positional argument")
	}
	if !strings.Contains(err.Error(), "unexpected argument") {
		t.Fatalf("error = %v, want unexpected argument", err)
	}
}

func TestWebAppsLastCompatibleVersionGroupIsRegisteredUnderWebApps(t *testing.T) {
	group := WebAppsLastCompatibleVersionCommand()
	if group.Name != "last-compatible-version" {
		t.Fatalf("group name = %q, want last-compatible-version", group.Name)
	}
	if len(group.Subcommands) == 0 {
		t.Fatal("expected last-compatible-version subcommands")
	}

	var registered bool
	for _, sub := range WebAppsCommand().Subcommands {
		if sub.Name == "last-compatible-version" {
			registered = true
		}
	}
	if !registered {
		t.Fatal("expected asc web apps last-compatible-version to be registered")
	}
}
