package asc

import "testing"

func TestPrintHumanOutput_XcodeTestIncludesCasesAndFailures(t *testing.T) {
	result := &XcodeTestResult{
		Action: "test",
		Tests: &XcodeTestSummary{
			Total:  2,
			Passed: 1,
			Failed: 1,
			Cases: []XcodeTestCase{
				{Identifier: "DemoTests/Smoke/testPass", Status: "passed"},
				{Identifier: "DemoTests/Smoke/testFail", Status: "failed"},
			},
			Failures: []XcodeTestFailure{{
				Identifier: "DemoTests/Smoke/testFail",
				Message:    "assertion failed",
			}},
		},
	}

	for _, renderer := range []struct {
		name string
		fn   func(any) error
	}{
		{name: "table", fn: PrintTable},
		{name: "markdown", fn: PrintMarkdown},
	} {
		renderer := renderer
		t.Run(renderer.name, func(t *testing.T) {
			assertRenderedNonJSONContains(t, renderer.fn, result,
				"DemoTests/Smoke/testFail", "failed", "assertion failed")
		})
	}
}
