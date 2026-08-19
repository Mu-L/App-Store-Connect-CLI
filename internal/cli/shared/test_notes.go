package shared

import (
	"context"
	"fmt"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

// UpsertBetaBuildLocalization creates or updates a beta build localization.
func UpsertBetaBuildLocalization(ctx context.Context, client *asc.Client, buildID, locale, notes string) (*asc.BetaBuildLocalizationResponse, error) {
	localeValue := strings.TrimSpace(locale)
	notesValue := strings.TrimSpace(notes)
	if localeValue == "" || notesValue == "" {
		return nil, fmt.Errorf("locale and notes are required")
	}

	resp, err := client.GetBetaBuildLocalizations(
		ctx, buildID,
		asc.WithBetaBuildLocalizationsLimit(200),
	)
	if err != nil {
		return nil, err
	}

	localizationID := ""
	foundLocale := false
	if resp != nil {
		for _, localization := range resp.Data {
			if !strings.EqualFold(strings.TrimSpace(localization.Attributes.Locale), localeValue) {
				continue
			}
			foundLocale = true
			localizationID = strings.TrimSpace(localization.ID)
			break
		}
	}
	if foundLocale {
		if localizationID == "" {
			return nil, fmt.Errorf("missing localization ID for locale %q", localeValue)
		}
		attrs := asc.BetaBuildLocalizationAttributes{
			WhatsNew: notesValue,
		}
		return client.UpdateBetaBuildLocalization(ctx, localizationID, attrs)
	}

	attrs := asc.BetaBuildLocalizationAttributes{
		Locale:   localeValue,
		WhatsNew: notesValue,
	}
	return client.CreateBetaBuildLocalization(ctx, buildID, attrs)
}

// TestNotesRecoveryError preserves a discovered build and the exact retry
// arguments while keeping its human-facing diagnostic terminal-safe.
type TestNotesRecoveryError struct {
	buildID string
	locale  string
	notes   string
	cause   error
}

// NewTestNotesRecoveryError returns recovery context for a failed post-upload
// What to Test request.
func NewTestNotesRecoveryError(buildID, locale, notes string, cause error) *TestNotesRecoveryError {
	return &TestNotesRecoveryError{
		buildID: buildID,
		locale:  locale,
		notes:   notes,
		cause:   cause,
	}
}

func (e *TestNotesRecoveryError) Error() string {
	buildID := asc.SanitizeTerminalText(e.buildID)
	locale := asc.SanitizeTerminalText(e.locale)
	cause := "unknown error"
	if e.cause != nil {
		cause = asc.SanitizeTerminalText(e.cause.Error())
	}
	return fmt.Sprintf(
		"build %q is available, but setting What to Test notes for locale %q failed: %s; retry without uploading the build again and reuse the original notes: asc builds test-notes create --build-id BUILD_ID --locale LOCALE --whats-new NOTES",
		buildID,
		locale,
		cause,
	)
}

// Unwrap preserves API error status and exit classification.
func (e *TestNotesRecoveryError) Unwrap() error {
	return e.cause
}

// Recovery returns exact, shell-neutral retry data for structured output.
func (e *TestNotesRecoveryError) Recovery() *asc.TestNotesRecovery {
	return &asc.TestNotesRecovery{
		BuildID:        e.buildID,
		Locale:         e.locale,
		SubmittedNotes: e.notes,
		Command:        "asc",
		Arguments: []string{
			"builds", "test-notes", "create",
			"--build-id", e.buildID,
			"--locale", e.locale,
			"--whats-new", e.notes,
		},
	}
}
