package capabilities

import (
	"slices"
	"strings"
	"testing"
)

func TestLastCompatibleVersionCapabilityIncludesPublicJSON(t *testing.T) {
	for _, capability := range capabilityRows() {
		if capability.Capability != "Last-compatible version settings inspection" {
			continue
		}
		if capability.Status != statusPartial {
			t.Fatalf("status = %q, want %q", capability.Status, statusPartial)
		}
		if !slices.Contains(capability.Commands, "asc versions list --output json") {
			t.Fatalf("missing public versions JSON command: %+v", capability.Commands)
		}
		for _, note := range capability.Notes {
			if strings.Contains(note, "does not currently request or print") {
				t.Fatalf("stale public-client claim remains: %q", note)
			}
		}
		return
	}
	t.Fatal("last-compatible version capability catalog entry not found")
}
