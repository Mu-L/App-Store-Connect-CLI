package capabilities

import (
	"strings"
	"testing"
)

func TestAPIKeyWebSessionNotesDoNotOverclaimIndividualKeys(t *testing.T) {
	for _, capability := range capabilityRows() {
		if capability.Capability != "App Store Connect API key web-session management" {
			continue
		}
		notes := strings.Join(capability.Notes, " ")
		lower := strings.ToLower(notes)
		if !strings.Contains(lower, "individual") || !strings.Contains(lower, "list") {
			t.Fatalf("expected notes to mention individual-key listing, got %q", notes)
		}
		if strings.Contains(lower, "individual api key list, view, and create") ||
			strings.Contains(lower, "team and individual api key list, view, and create") {
			t.Fatalf("notes overclaim individual-key view/create: %q", notes)
		}
		if !strings.Contains(lower, "team-key-only") {
			t.Fatalf("expected notes to describe view and create as team-key-only, got %q", notes)
		}
		return
	}
	t.Fatal("App Store Connect API key web-session management catalog entry not found")
}
