package validation

import (
	"strings"
	"testing"
)

func TestContentChecksFlagsRejectionPatterns(t *testing.T) {
	tests := []struct {
		name        string
		description string
		wantID      string
		wantQuoted  string
	}{
		{
			name:        "other platform android",
			description: "Also available on Android devices.",
			wantID:      "content.other_platforms",
			wantQuoted:  "Android",
		},
		{
			name:        "other platform google play",
			description: "Download it from Google Play today.",
			wantID:      "content.other_platforms",
			wantQuoted:  "Google Play",
		},
		{
			name:        "other platform play store",
			description: "Rated five stars on the Play Store.",
			wantID:      "content.other_platforms",
			wantQuoted:  "Play Store",
		},
		{
			name:        "other platform blackberry",
			description: "A BlackBerry version is out now.",
			wantID:      "content.other_platforms",
			wantQuoted:  "BlackBerry",
		},
		{
			name:        "other platform windows phone",
			description: "Ported from Windows Phone.",
			wantID:      "content.other_platforms",
			wantQuoted:  "Windows Phone",
		},
		{
			name:        "other platform samsung galaxy",
			description: "Optimized for Samsung Galaxy hardware.",
			wantID:      "content.other_platforms",
			wantQuoted:  "Samsung Galaxy",
		},
		{
			name:        "placeholder lorem ipsum",
			description: "Lorem ipsum dolor sit amet.",
			wantID:      "content.placeholder_text",
			wantQuoted:  "Lorem ipsum",
		},
		{
			name:        "placeholder word",
			description: "This is placeholder copy for the listing.",
			wantID:      "content.placeholder_text",
			wantQuoted:  "placeholder",
		},
		{
			name:        "placeholder text here",
			description: "Your text here.",
			wantID:      "content.placeholder_text",
			wantQuoted:  "Your text here",
		},
		{
			name:        "placeholder todo marker",
			description: "TODO: write the real description.",
			wantID:      "content.placeholder_text",
			wantQuoted:  "TODO",
		},
		{
			name:        "placeholder tbd marker",
			description: "Pricing details TBD.",
			wantID:      "content.placeholder_text",
			wantQuoted:  "TBD",
		},
		{
			name:        "future coming soon",
			description: "Cloud sync coming soon.",
			wantID:      "content.future_functionality",
			wantQuoted:  "coming soon",
		},
		{
			name:        "future next release",
			description: "Widgets arrive in the next release.",
			wantID:      "content.future_functionality",
			wantQuoted:  "in the next release",
		},
		{
			name:        "future will be available",
			description: "Offline mode will be available soon.",
			wantID:      "content.future_functionality",
			wantQuoted:  "will be available soon",
		},
		{
			name:        "future in a future update",
			description: "Themes land in a future update.",
			wantID:      "content.future_functionality",
			wantQuoted:  "in a future update",
		},
		{
			name:        "test words beta test",
			description: "Join the beta test group.",
			wantID:      "content.test_words",
			wantQuoted:  "beta test",
		},
		{
			name:        "test words just a test",
			description: "This is just a test listing.",
			wantID:      "content.test_words",
			wantQuoted:  "just a test",
		},
		{
			name:        "test words for testing purposes",
			description: "Published for testing purposes.",
			wantID:      "content.test_words",
			wantQuoted:  "for testing purposes",
		},
		{
			name:        "test words demo version",
			description: "A demo version of our upcoming product.",
			wantID:      "content.test_words",
			wantQuoted:  "demo version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checks := contentChecks(
				[]VersionLocalization{{ID: "loc-1", Locale: "en-US", Description: test.description}},
				nil,
			)

			if len(checks) != 1 {
				t.Fatalf("expected exactly one check for %q, got %+v", test.description, checks)
			}

			check := checks[0]
			if check.ID != test.wantID {
				t.Fatalf("expected check ID %q, got %q", test.wantID, check.ID)
			}
			if check.Severity != SeverityWarning {
				t.Fatalf("expected warning severity, got %q", check.Severity)
			}
			if !strings.Contains(check.Message, test.wantQuoted) {
				t.Fatalf("expected message to quote %q, got %q", test.wantQuoted, check.Message)
			}
			if check.Remediation == "" {
				t.Fatal("expected remediation guidance")
			}
		})
	}
}

func TestContentChecksIgnoresLegitimateMetadata(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{
			name:        "plural of platform name",
			description: "Androids and other robots are not discussed here.",
		},
		{
			name:        "words containing test",
			description: "Freedom to write your testament, review the latest contest, and protest.",
		},
		{
			name:        "test prep vocabulary",
			description: "Practice tests and test prep for the entrance exam.",
		},
		{
			name:        "beta alone is allowed",
			description: "Join our beta program and share feedback with the team.",
		},
		{
			name:        "non adjacent platform words",
			description: "Play music from your library and browse the store.",
		},
		{
			name:        "galaxy without samsung",
			description: "Track a galaxy of habits through a window of time.",
		},
		{
			name:        "kindle without fire",
			description: "Kindle your motivation and fire up your goals.",
		},
		{
			name:        "windows without phone",
			description: "Windows and doors estimator for contractors.",
		},
		{
			name:        "lowercase todo vocabulary",
			description: "Manage your todo list and keep to-do items in one place.",
		},
		{
			name:        "place is not placeholder",
			description: "Find your place in line and hold it.",
		},
		{
			name:        "citizen is not a platform",
			description: "A citizen registry for civic volunteers.",
		},
		{
			name:        "soon without coming",
			description: "Soon becomes now: log habits the moment they happen.",
		},
		{
			name:        "development without under",
			description: "Development tools for engineers who ship.",
		},
		{
			name:        "free trial is legitimate",
			description: "Start a free trial and subscribe when you are ready.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checks := contentChecks(
				[]VersionLocalization{{ID: "loc-1", Locale: "en-US", Description: test.description}},
				nil,
			)

			if len(checks) != 0 {
				t.Fatalf("expected no content checks for %q, got %+v", test.description, checks)
			}
		})
	}
}

func TestContentChecksAllowlistWinsOverPlatformMatch(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{name: "google analytics", description: "Usage insights powered by Google Analytics."},
		{name: "google drive", description: "Back up your notes to Google Drive."},
		{name: "google maps", description: "Directions come from Google Maps."},
		{name: "google sign-in", description: "Google Sign-In keeps your account portable."},
		{name: "sign in with google", description: "Sign in with Google to sync instantly."},
		{name: "google calendar", description: "Two-way sync with Google Calendar."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checks := contentChecks(
				[]VersionLocalization{{ID: "loc-1", Locale: "en-US", Description: test.description}},
				nil,
			)

			if len(checks) != 0 {
				t.Fatalf("expected allowlisted service name to be ignored for %q, got %+v", test.description, checks)
			}
		})
	}
}

func TestContentChecksAllowlistOnlySuppressesOverlappingMatch(t *testing.T) {
	checks := contentChecks(
		[]VersionLocalization{{ID: "loc-1", Locale: "en-US", Description: "Sync with Google Drive, also on Android."}},
		nil,
	)

	if len(checks) != 1 {
		t.Fatalf("expected one check, got %+v", checks)
	}
	if !strings.Contains(checks[0].Message, "Android") {
		t.Fatalf("expected the platform reference to be reported, got %q", checks[0].Message)
	}
	if strings.Contains(checks[0].Message, "Google Drive") {
		t.Fatalf("expected the allowlisted service to be omitted, got %q", checks[0].Message)
	}
}

func TestContentChecksMatchPhrasesAcrossWhitespace(t *testing.T) {
	tests := []struct {
		name        string
		description string
	}{
		{name: "double space", description: "Sharing is coming  soon."},
		{name: "newline", description: "Sharing is coming\nsoon."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checks := contentChecks(
				[]VersionLocalization{{ID: "loc-1", Locale: "en-US", Description: test.description}},
				nil,
			)

			if len(checks) != 1 || checks[0].ID != "content.future_functionality" {
				t.Fatalf("expected one future functionality check, got %+v", checks)
			}
			if !strings.Contains(checks[0].Message, "coming soon") {
				t.Fatalf("expected normalized phrase in message, got %q", checks[0].Message)
			}
		})
	}
}

func TestContentChecksCoverLocalizedFields(t *testing.T) {
	versionLocs := []VersionLocalization{{
		ID:              "ver-loc-1",
		Locale:          "en-US",
		Description:     "Also on Android.",
		Keywords:        "android,todo,habits",
		WhatsNew:        "Dark mode coming soon.",
		PromotionalText: "TODO",
	}}
	appInfoLocs := []AppInfoLocalization{{
		ID:       "info-loc-1",
		Locale:   "en-US",
		Name:     "Beta Test Timer",
		Subtitle: "Lorem ipsum tracker",
	}}

	checks := contentChecks(versionLocs, appInfoLocs)

	wanted := []struct {
		id           string
		field        string
		resourceType string
		resourceID   string
	}{
		{id: "content.other_platforms", field: "description", resourceType: "appStoreVersionLocalization", resourceID: "ver-loc-1"},
		{id: "content.other_platforms", field: "keywords", resourceType: "appStoreVersionLocalization", resourceID: "ver-loc-1"},
		{id: "content.future_functionality", field: "whatsNew", resourceType: "appStoreVersionLocalization", resourceID: "ver-loc-1"},
		{id: "content.placeholder_text", field: "promotionalText", resourceType: "appStoreVersionLocalization", resourceID: "ver-loc-1"},
		{id: "content.test_words", field: "name", resourceType: "appInfoLocalization", resourceID: "info-loc-1"},
		{id: "content.placeholder_text", field: "subtitle", resourceType: "appInfoLocalization", resourceID: "info-loc-1"},
	}

	for _, want := range wanted {
		found := false
		for _, check := range checks {
			if check.ID != want.id || check.Field != want.field {
				continue
			}
			found = true
			if check.Locale != "en-US" {
				t.Fatalf("expected locale en-US for %s/%s, got %q", want.id, want.field, check.Locale)
			}
			if check.ResourceType != want.resourceType {
				t.Fatalf("expected resource type %q for %s/%s, got %q", want.resourceType, want.id, want.field, check.ResourceType)
			}
			if check.ResourceID != want.resourceID {
				t.Fatalf("expected resource ID %q for %s/%s, got %q", want.resourceID, want.id, want.field, check.ResourceID)
			}
		}
		if !found {
			t.Fatalf("expected %s on field %s, got %+v", want.id, want.field, checks)
		}
	}
}

func TestContentChecksReportOneCheckPerRuleAndField(t *testing.T) {
	checks := contentChecks(
		[]VersionLocalization{{
			ID:          "loc-1",
			Locale:      "en-US",
			Description: "Android first, android second, and Google Play too.",
		}},
		nil,
	)

	if len(checks) != 1 {
		t.Fatalf("expected repeated matches to collapse into one check, got %+v", checks)
	}
	if strings.Count(checks[0].Message, "ndroid") != 1 {
		t.Fatalf("expected duplicate matches to be reported once, got %q", checks[0].Message)
	}
	if !strings.Contains(checks[0].Message, "Google Play") {
		t.Fatalf("expected distinct matches to be listed, got %q", checks[0].Message)
	}
}

func TestContentChecksSkipEmptyFields(t *testing.T) {
	checks := contentChecks([]VersionLocalization{{ID: "loc-1", Locale: "en-US"}}, []AppInfoLocalization{{ID: "info-1", Locale: "en-US"}})

	if len(checks) != 0 {
		t.Fatalf("expected no checks for empty metadata, got %+v", checks)
	}
}

func TestValidate_IncludesContentChecksWithoutBlocking(t *testing.T) {
	report := Validate(Input{
		AppID:         "app-1",
		VersionID:     "ver-1",
		VersionString: "2.0",
		VersionState:  "PREPARE_FOR_SUBMISSION",
		PrimaryLocale: "en-US",
		Copyright:     "2026 Co",
		VersionLocalizations: []VersionLocalization{{
			ID:          "loc-1",
			Locale:      "en-US",
			Description: "Also available on Android. Sync coming soon.",
			Keywords:    "habits",
			WhatsNew:    "Bug fixes",
			SupportURL:  "https://example.com",
		}},
		AppInfoLocalizations: []AppInfoLocalization{{
			ID:               "info-1",
			Locale:           "en-US",
			Name:             "Habit Timer",
			Subtitle:         "Track habits",
			PrivacyPolicyURL: "https://example.com/privacy",
		}},
		PrimaryCategoryID: "cat-1",
	}, false)

	if !hasCheckID(report.Checks, "content.other_platforms") {
		t.Fatalf("expected content.other_platforms in report, got %+v", report.Checks)
	}
	if !hasCheckID(report.Checks, "content.future_functionality") {
		t.Fatalf("expected content.future_functionality in report, got %+v", report.Checks)
	}
	if report.Summary.Blocking != report.Summary.Errors {
		t.Fatalf("expected content warnings to stay non-blocking, got summary %+v", report.Summary)
	}

	foundRemediationStep := false
	for _, step := range report.Remediation.Steps {
		if step.CheckID == "content.other_platforms" {
			foundRemediationStep = true
			if step.Blocking {
				t.Fatalf("expected non-blocking remediation step, got %+v", step)
			}
		}
	}
	if !foundRemediationStep {
		t.Fatal("expected content check to appear in the remediation plan")
	}
}
