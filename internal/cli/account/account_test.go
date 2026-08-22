package account

import (
	"path/filepath"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestAuthHealthCheckHonorsRootProfileSelection(t *testing.T) {
	previousProfile := shared.SelectedProfile()
	shared.SetSelectedProfile("work")
	t.Cleanup(func() { shared.SetSelectedProfile(previousProfile) })

	t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("ASC_PROFILE", "")
	t.Setenv("ASC_KEY_ID", "ENVKEY")
	t.Setenv("ASC_ISSUER_ID", "12345678-abcd-1234-abcd-123456789012")
	t.Setenv("ASC_KEY_TYPE", "")
	t.Setenv("ASC_PRIVATE_KEY", "")
	t.Setenv("ASC_PRIVATE_KEY_B64", "")
	t.Setenv("ASC_PRIVATE_KEY_PATH", filepath.Join(t.TempDir(), "ignored-missing.p8"))

	check := authHealthCheck()
	if check.Status == "fail" {
		t.Fatalf("expected root profile selection to suppress ignored environment key failure, got %#v", check)
	}
}

func TestSummarizeAccountChecks(t *testing.T) {
	red := summarizeAccountChecks([]accountCheck{
		{Name: "authentication", Status: "fail", Message: "auth broken"},
		{Name: "api_access", Status: "ok", Message: "ok"},
	})
	if red.Health != "red" {
		t.Fatalf("expected red health, got %q", red.Health)
	}
	if red.ErrorCount != 1 {
		t.Fatalf("expected one error, got %d", red.ErrorCount)
	}
	if red.NextAction != "auth broken" {
		t.Fatalf("unexpected next action %q", red.NextAction)
	}

	yellow := summarizeAccountChecks([]accountCheck{
		{Name: "authentication", Status: "ok", Message: "ok"},
		{Name: "agreements", Status: "unavailable", Message: "not available"},
	})
	if yellow.Health != "yellow" {
		t.Fatalf("expected yellow health, got %q", yellow.Health)
	}
	if yellow.WarningCount != 1 {
		t.Fatalf("expected one warning, got %d", yellow.WarningCount)
	}

	green := summarizeAccountChecks([]accountCheck{
		{Name: "authentication", Status: "ok", Message: "ok"},
		{Name: "api_access", Status: "ok", Message: "ok"},
	})
	if green.Health != "green" {
		t.Fatalf("expected green health, got %q", green.Health)
	}
	if green.NextAction != "No action needed." {
		t.Fatalf("unexpected next action %q", green.NextAction)
	}
}
