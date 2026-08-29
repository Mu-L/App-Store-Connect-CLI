package asc

import (
	"slices"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/validation"
)

func TestValidationRowsAddResolutionColumnsOnlyForDeepReports(t *testing.T) {
	base := &validation.Report{Checks: []validation.CheckResult{{ID: "check-1", Severity: validation.SeverityError, Message: "broken", Remediation: "repair"}}}
	headers, _ := validationCheckRows(base)
	if slices.Contains(headers, "Fixability") {
		t.Fatalf("default validation headers changed: %#v", headers)
	}
	defaultMarkdown := captureStdout(t, func() error { return PrintMarkdown(base) })
	if strings.Contains(defaultMarkdown, "Fixability") || strings.Contains(defaultMarkdown, "App Store Connect URL") {
		t.Fatalf("default Markdown gained deep-only columns:\n%s", defaultMarkdown)
	}

	base.Deep = &validation.DeepReport{}
	base.Checks[0].Resolution = &validation.Resolution{
		Fixability:         validation.FixabilityWebFixable,
		Commands:           []string{"asc web repair --confirm"},
		AppStoreConnectURL: "https://appstoreconnect.apple.com/apps/app-1",
	}
	headers, rows := validationCheckRows(base)
	for _, want := range []string{"Fixability", "Commands", "App Store Connect URL"} {
		if !slices.Contains(headers, want) {
			t.Fatalf("deep headers %#v missing %q", headers, want)
		}
	}
	if got := rows[0][len(rows[0])-3]; got != "web-fixable" {
		t.Fatalf("fixability cell = %q", got)
	}
	deepMarkdown := captureStdout(t, func() error { return PrintMarkdown(base) })
	for _, want := range []string{"Fixability", "Commands", "App Store Connect URL", "web-fixable", "asc web repair --confirm"} {
		if !strings.Contains(deepMarkdown, want) {
			t.Fatalf("deep Markdown missing %q:\n%s", want, deepMarkdown)
		}
	}

	deepHeaders, deepRows := validationDeepRows(base)
	if len(deepHeaders) == 0 || len(deepRows) == 0 {
		t.Fatalf("deep rows were not rendered: headers=%#v rows=%#v", deepHeaders, deepRows)
	}
}
