package shared

import (
	"errors"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestNewTestNotesRecoveryErrorSeparatesHumanAndMachineRecovery(t *testing.T) {
	cause := errors.New("server rejected notes\x1b[31m\nforged line")
	buildID := `build 'quoted' $(touch build)`
	locale := `en-US; touch locale`
	notes := "First line; $(touch notes)\nIt's still quoted\x1b[0m"

	err := NewTestNotesRecoveryError(buildID, locale, notes, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("expected recovery error to wrap cause, got %v", err)
	}
	if asc.HasInterpretedTerminalSequence(err.Error()) {
		t.Fatalf("human recovery error contains terminal controls: %q", err)
	}
	if strings.Contains(err.Error(), "First line") {
		t.Fatalf("human recovery error must not embed notes: %q", err)
	}
	wantHumanParts := []string{
		"retry without uploading the build again",
		"reuse the original notes",
		"asc builds test-notes create --build-id BUILD_ID --locale LOCALE --whats-new NOTES",
	}
	for _, want := range wantHumanParts {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("human recovery error missing %q: %q", want, err)
		}
	}

	recovery := err.Recovery()
	if recovery.BuildID != buildID || recovery.Locale != locale || recovery.SubmittedNotes != notes {
		t.Fatalf("recovery fields lost exact values: %#v", recovery)
	}
	if recovery.Command != "asc" {
		t.Fatalf("recovery command = %q, want asc", recovery.Command)
	}
	want := []string{
		"builds", "test-notes", "create",
		"--build-id", buildID,
		"--locale", locale,
		"--whats-new", notes,
	}
	if len(recovery.Arguments) != len(want) {
		t.Fatalf("retry args = %#v, want %#v", recovery.Arguments, want)
	}
	for i := range want {
		if recovery.Arguments[i] != want[i] {
			t.Fatalf("retry arg %d = %q, want %q; all args=%#v", i, recovery.Arguments[i], want[i], recovery.Arguments)
		}
	}
}
