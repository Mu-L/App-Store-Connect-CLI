package asc

import (
	"strconv"
	"strings"
)

// XcodeTestResult is the stable output receipt for a local Xcode test action.
// It deliberately lives in the output package so JSON and human renderers use
// the same exported camelCase contract as other computed CLI results.
type XcodeTestResult struct {
	Workspace        string            `json:"workspace,omitempty"`
	Project          string            `json:"project,omitempty"`
	Scheme           string            `json:"scheme,omitempty"`
	Action           string            `json:"action"`
	Configuration    string            `json:"configuration,omitempty"`
	Destinations     []string          `json:"destinations,omitempty"`
	TestPlan         string            `json:"testPlan,omitempty"`
	XctestrunPath    string            `json:"xctestrunPath,omitempty"`
	DerivedDataPath  string            `json:"derivedDataPath,omitempty"`
	ResultBundlePath string            `json:"resultBundlePath,omitempty"`
	Tests            *XcodeTestSummary `json:"tests,omitempty"`
	Clean            bool              `json:"clean"`
	NoCodeSigning    bool              `json:"noCodeSigning"`
	Success          bool              `json:"success"`
	DurationMs       int64             `json:"durationMs"`
	ExitStatus       *int              `json:"exitStatus,omitempty"`
}

// XcodeTestSummary is the structured test aggregate in an Xcode result
// receipt.
type XcodeTestSummary struct {
	Total      int                `json:"total"`
	Passed     int                `json:"passed"`
	Failed     int                `json:"failed"`
	Skipped    int                `json:"skipped"`
	DurationMs int64              `json:"durationMs"`
	Cases      []XcodeTestCase    `json:"cases,omitempty"`
	Failures   []XcodeTestFailure `json:"failures,omitempty"`
}

// XcodeTestCase is one parsed Xcode test case.
type XcodeTestCase struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name,omitempty"`
	Classname  string `json:"classname,omitempty"`
	Status     string `json:"status"`
	DurationMs int64  `json:"durationMs,omitempty"`
	Message    string `json:"message,omitempty"`
}

// XcodeTestFailure is bounded structured failure detail from an Xcode result.
type XcodeTestFailure struct {
	Identifier string `json:"identifier"`
	Message    string `json:"message,omitempty"`
}

func xcodeTestResultRows(result *XcodeTestResult) ([]string, [][]string) {
	if result == nil {
		result = &XcodeTestResult{}
	}
	rows := make([][]string, 0, 22)
	if result.Workspace != "" {
		rows = append(rows, []string{"workspace", result.Workspace})
	}
	if result.Project != "" {
		rows = append(rows, []string{"project", result.Project})
	}
	if result.Scheme != "" {
		rows = append(rows, []string{"scheme", result.Scheme})
	}
	rows = append(rows, []string{"action", result.Action})
	if result.Configuration != "" {
		rows = append(rows, []string{"configuration", result.Configuration})
	}
	if len(result.Destinations) > 0 {
		rows = append(rows, []string{"destinations", joinOutputValues(result.Destinations)})
	}
	if result.TestPlan != "" {
		rows = append(rows, []string{"test_plan", result.TestPlan})
	}
	if result.XctestrunPath != "" {
		rows = append(rows, []string{"xctestrun_path", result.XctestrunPath})
	}
	if result.DerivedDataPath != "" {
		rows = append(rows, []string{"derived_data_path", result.DerivedDataPath})
	}
	if result.ResultBundlePath != "" {
		rows = append(rows, []string{"result_bundle_path", result.ResultBundlePath})
	}
	rows = append(
		rows,
		[]string{"clean", formatBool(result.Clean)},
		[]string{"no_code_signing", formatBool(result.NoCodeSigning)},
	)
	if result.Tests != nil {
		rows = append(
			rows,
			[]string{"tests_total", formatInt(result.Tests.Total)},
			[]string{"tests_passed", formatInt(result.Tests.Passed)},
			[]string{"tests_failed", formatInt(result.Tests.Failed)},
			[]string{"tests_skipped", formatInt(result.Tests.Skipped)},
			[]string{"tests_duration_ms", formatInt64(result.Tests.DurationMs)},
		)
	}
	rows = append(
		rows,
		[]string{"success", formatBool(result.Success)},
		[]string{"duration_ms", formatInt64(result.DurationMs)},
	)
	if result.ExitStatus != nil {
		rows = append(rows, []string{"exit_status", formatInt(*result.ExitStatus)})
	}
	return []string{"field", "value"}, rows
}

func joinOutputValues(values []string) string {
	return strings.Join(values, "\n")
}

func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
