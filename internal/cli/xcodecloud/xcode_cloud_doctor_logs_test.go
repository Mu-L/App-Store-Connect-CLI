package xcodecloud

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestAnalyzeDoctorLogBundleFindsITMSDiagnosticsAndExportStatus(t *testing.T) {
	data := doctorLogBundleFixture(t, map[string]string{
		"Export/IDEDistribution.standard.log": "** EXPORT SUCCEEDED **\nerror: ITMS-90478: Invalid Version",
		"Export/duplicate.log":                "error: ITMS-90478: Invalid Version",
		"Export/binary.log":                   "ignored\x00binary",
	})

	analysis, err := analyzeDoctorLogBundle(data)
	if err != nil {
		t.Fatalf("analyzeDoctorLogBundle() error = %v", err)
	}
	if analysis.ExportStatus != "SUCCEEDED" {
		t.Fatalf("ExportStatus = %q, want SUCCEEDED", analysis.ExportStatus)
	}
	if len(analysis.Diagnostics) != 1 {
		t.Fatalf("Diagnostics = %+v, want one deduplicated diagnostic", analysis.Diagnostics)
	}
	if analysis.Diagnostics[0].Code != "ITMS-90478" {
		t.Fatalf("diagnostic code = %q, want ITMS-90478", analysis.Diagnostics[0].Code)
	}
}

func TestAnalyzeDoctorLogTextTruncatesDiagnosticsOnUTF8Boundary(t *testing.T) {
	analysis := doctorLogBundleAnalysis{Diagnostics: make([]asc.XcodeCloudDoctorLogDiagnostic, 0)}
	contents := "ITMS-90000: x" + strings.Repeat("é", maxDoctorDiagnosticLength)

	analyzeDoctorLogText(&analysis, "export.log", contents)

	if len(analysis.Diagnostics) != 1 {
		t.Fatalf("Diagnostics = %+v, want one diagnostic", analysis.Diagnostics)
	}
	if !utf8.ValidString(analysis.Diagnostics[0].Message) {
		t.Fatalf("diagnostic message is not valid UTF-8: %q", analysis.Diagnostics[0].Message)
	}
	if !strings.HasSuffix(analysis.Diagnostics[0].Message, "…") {
		t.Fatalf("diagnostic message = %q, want ellipsis suffix", analysis.Diagnostics[0].Message)
	}
}

func TestFinishXcodeCloudDoctorResultDoesNotInventImportFailure(t *testing.T) {
	result := &asc.XcodeCloudDoctorResult{
		Run: &asc.XcodeCloudStatusResult{
			BuildRunID:        "run-92",
			ExecutionProgress: "COMPLETE",
			CompletionStatus:  "FAILED",
		},
		LogBundles: []asc.XcodeCloudDoctorLogBundle{{
			ArtifactID:   "log-92",
			Inspected:    true,
			ExportStatus: "SUCCEEDED",
			Diagnostics:  []asc.XcodeCloudDoctorLogDiagnostic{},
		}},
		CoverageWarnings: []asc.XcodeCloudDoctorCoverageWarning{},
	}

	finishXcodeCloudDoctorResult(result)

	if !strings.Contains(result.Conclusion, "without an ITMS-level import diagnostic") {
		t.Fatalf("unexpected conclusion %q", result.Conclusion)
	}
	if len(result.CoverageWarnings) != 1 || result.CoverageWarnings[0].ID != "app_store_import_detail_unavailable" {
		t.Fatalf("unexpected coverage warnings: %+v", result.CoverageWarnings)
	}
	if strings.Contains(result.Conclusion, "Invalid Version") || strings.Contains(result.Conclusion, "pre-release train") {
		t.Fatalf("conclusion invented an import root cause: %q", result.Conclusion)
	}
}

func TestFinishXcodeCloudDoctorResultReportsCanceledAndSkippedRuns(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		conclusion string
	}{
		{name: "canceled", status: "CANCELED", conclusion: "was canceled"},
		{name: "skipped", status: "SKIPPED", conclusion: "was skipped"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := &asc.XcodeCloudDoctorResult{
				Run: &asc.XcodeCloudStatusResult{
					BuildRunID:        "run-1",
					ExecutionProgress: "COMPLETE",
					CompletionStatus:  test.status,
				},
			}

			finishXcodeCloudDoctorResult(result)

			if !strings.Contains(strings.ToLower(result.Conclusion), test.conclusion) {
				t.Fatalf("Conclusion = %q, want %q", result.Conclusion, test.conclusion)
			}
			if strings.Contains(strings.ToLower(result.Conclusion), "failed") {
				t.Fatalf("Conclusion = %q, must not describe %s run as failed", result.Conclusion, test.status)
			}
		})
	}
}

func TestShouldInspectDoctorLogsOnlyForFailuresUnlessSaving(t *testing.T) {
	tests := []struct {
		status            string
		executionProgress string
		options           xcodeCloudDoctorOptions
		want              bool
	}{
		{status: "FAILED", want: true},
		{status: "ERRORED", want: true},
		{status: "FAILED", executionProgress: "RUNNING", want: false},
		{status: "SUCCEEDED", want: false},
		{status: "CANCELED", want: false},
		{status: "SKIPPED", want: false},
		{status: "CANCELED", options: xcodeCloudDoctorOptions{SaveLogs: "logs"}, want: true},
		{status: "SKIPPED", options: xcodeCloudDoctorOptions{SaveLogs: "logs"}, want: true},
	}

	for _, test := range tests {
		t.Run(test.status+test.executionProgress+test.options.SaveLogs, func(t *testing.T) {
			executionProgress := test.executionProgress
			if executionProgress == "" {
				executionProgress = "COMPLETE"
			}
			result := &asc.XcodeCloudDoctorResult{
				Run: &asc.XcodeCloudStatusResult{
					ExecutionProgress: executionProgress,
					CompletionStatus:  test.status,
				},
				Summary: asc.XcodeCloudDoctorSummary{LogBundles: 1},
				Actions: []asc.XcodeCloudDoctorAction{{
					CompletionStatus: "FAILED",
					Artifacts:        []asc.XcodeCloudDoctorArtifact{{FileType: "LOG_BUNDLE"}},
				}},
			}

			if got := shouldInspectDoctorLogs(result, test.options); got != test.want {
				t.Fatalf("shouldInspectDoctorLogs(%s, %+v) = %t, want %t", test.status, test.options, got, test.want)
			}
		})
	}
}

func TestDoctorFailureAggregationExcludesCanceledActions(t *testing.T) {
	result := &asc.XcodeCloudDoctorResult{Actions: []asc.XcodeCloudDoctorAction{
		{ID: "failed", CompletionStatus: "FAILED", Artifacts: []asc.XcodeCloudDoctorArtifact{{FileType: "LOG_BUNDLE"}}},
		{ID: "errored", CompletionStatus: "ERRORED", Artifacts: []asc.XcodeCloudDoctorArtifact{{FileType: "LOG_BUNDLE"}}},
		{ID: "canceled", CompletionStatus: "CANCELED", Artifacts: []asc.XcodeCloudDoctorArtifact{{FileType: "LOG_BUNDLE"}}},
	}}

	summarizeXcodeCloudDoctorResult(result)

	if result.Summary.FailedActions != 2 || result.Summary.CanceledActions != 1 {
		t.Fatalf("summary = %+v, want 2 failed and 1 canceled action", result.Summary)
	}
	if got := doctorFailedActionLogBundleCount(result); got != 2 {
		t.Fatalf("doctorFailedActionLogBundleCount() = %d, want 2", got)
	}
}

func TestFinishXcodeCloudDoctorResultIgnoresSuccessfulActionLogBundles(t *testing.T) {
	result := &asc.XcodeCloudDoctorResult{
		Run: &asc.XcodeCloudStatusResult{ExecutionProgress: "COMPLETE", CompletionStatus: "FAILED"},
		Actions: []asc.XcodeCloudDoctorAction{{
			CompletionStatus: "SUCCEEDED",
			Artifacts:        []asc.XcodeCloudDoctorArtifact{{FileType: "LOG_BUNDLE"}},
		}},
		Summary: asc.XcodeCloudDoctorSummary{LogBundles: 1, Errors: 1},
	}

	finishXcodeCloudDoctorResult(result)

	if strings.Contains(result.Conclusion, "not inspected") || strings.Contains(result.NextAction, "--skip-logs") {
		t.Fatalf("successful-action bundle produced misleading remediation: conclusion=%q nextAction=%q", result.Conclusion, result.NextAction)
	}
}

func TestAnalyzeDoctorLogBundleRejectsOversizedTextEntry(t *testing.T) {
	data := doctorLogBundleFixture(t, map[string]string{
		"Export/IDEDistribution.standard.log": strings.Repeat("x", maxDoctorLogEntryBytes+1),
	})

	_, err := analyzeDoctorLogBundle(data)
	if err == nil || !strings.Contains(err.Error(), "IDEDistribution.standard.log") {
		t.Fatalf("analyzeDoctorLogBundle() error = %v, want oversized entry error", err)
	}
}

func TestAnalyzeDoctorLogBundleRejectsUnknownBinary(t *testing.T) {
	if _, err := analyzeDoctorLogBundle([]byte{'P', 'K', 0, 1, 2}); err == nil {
		t.Fatal("analyzeDoctorLogBundle() error = nil, want binary format error")
	}
}

func TestDoctorSavedLogBundleNameSanitizesRemoteComponents(t *testing.T) {
	artifact := asc.XcodeCloudDoctorArtifact{
		ID:       "../../artifact/id",
		FileName: `..\..\Build 92 Logs.zip`,
	}
	name := doctorSavedLogBundleName(artifact)
	if strings.Contains(name, "/") || strings.Contains(name, `\`) || strings.Contains(name, "..") {
		t.Fatalf("unsafe saved name %q", name)
	}
}

func doctorLogBundleFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, contents := range files {
		file, err := archive.Create(name)
		if err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		if _, err := io.WriteString(file, contents); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buffer.Bytes()
}
