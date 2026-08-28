package validate

import (
	"strings"
	"testing"
)

func TestValidateHelpDocumentsDeepCachedSessionContract(t *testing.T) {
	cmd := ValidateCommand()
	for _, want := range []string{"--deep", "--apple-id", "cached Apple web session", "App Privacy", "agreements", "subscription"} {
		if !strings.Contains(cmd.LongHelp, want) {
			t.Fatalf("validate help missing %q:\n%s", want, cmd.LongHelp)
		}
	}
}

func TestValidateDeepFlagsAreTopLevelOnly(t *testing.T) {
	cmd := ValidateCommand()
	err := cmd.ParseAndRun(t.Context(), []string{"--deep", "testflight", "--app", "app-1", "--build", "build-1"})
	if err == nil || !strings.Contains(err.Error(), "--deep is only valid for asc validate") {
		t.Fatalf("error = %v, want top-level-only deep diagnostic", err)
	}
}
