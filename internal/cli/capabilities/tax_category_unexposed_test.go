package capabilities

import (
	"slices"
	"strings"
	"testing"
)

const taxCategoryCapabilityName = "App and In-App Purchase tax category"

// App Information tax category is covered by the experimental web-session
// command, while In-App Purchase tax category remains outside the CLI.
func TestTaxCategoryIsReportedAsPartial(t *testing.T) {
	for _, capability := range capabilityRows() {
		if capability.Capability != taxCategoryCapabilityName {
			continue
		}
		if capability.Status != statusPartial {
			t.Fatalf("expected %q status %q, got %q", taxCategoryCapabilityName, statusPartial, capability.Status)
		}
		if capability.Area != "monetization" {
			t.Fatalf("expected %q area %q, got %q", taxCategoryCapabilityName, "monetization", capability.Area)
		}
		wantCommands := []string{
			"asc web apps tax-category list",
			"asc web apps tax-category view",
			"asc web apps tax-category set",
		}
		if !slices.Equal(capability.Commands, wantCommands) {
			t.Fatalf("expected %q commands %v, got %v", taxCategoryCapabilityName, wantCommands, capability.Commands)
		}
		if strings.TrimSpace(capability.NextAction) == "" {
			t.Fatalf("expected %q to carry a next action", taxCategoryCapabilityName)
		}
		if len(capability.Notes) == 0 {
			t.Fatalf("expected %q to carry explanatory notes", taxCategoryCapabilityName)
		}
		return
	}

	t.Fatalf("capability %q not found", taxCategoryCapabilityName)
}

func TestTaxCategoryCapabilityNotesRemainingIAPGap(t *testing.T) {
	for _, capability := range capabilityRows() {
		if capability.Capability != taxCategoryCapabilityName {
			continue
		}
		joined := strings.ToLower(strings.Join(capability.Notes, " "))
		if !strings.Contains(joined, "in-app purchase") || !strings.Contains(joined, "unimplemented") {
			t.Fatalf("expected %q notes to preserve the In-App Purchase gap, got %v", taxCategoryCapabilityName, capability.Notes)
		}
		return
	}
	t.Fatalf("capability %q not found", taxCategoryCapabilityName)
}
