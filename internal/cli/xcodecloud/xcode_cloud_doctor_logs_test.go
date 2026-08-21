package xcodecloud

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

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

func TestFinishXcodeCloudDoctorResultDoesNotInventImportFailure(t *testing.T) {
	result := &xcodeCloudDoctorResult{
		Run: &asc.XcodeCloudStatusResult{
			BuildRunID:        "run-92",
			ExecutionProgress: "COMPLETE",
			CompletionStatus:  "FAILED",
		},
		LogBundles: []xcodeCloudDoctorLogBundle{{
			ArtifactID:   "log-92",
			Inspected:    true,
			ExportStatus: "SUCCEEDED",
			Diagnostics:  []xcodeCloudDoctorLogDiagnostic{},
		}},
		CoverageWarnings: []xcodeCloudDoctorCoverageWarning{},
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

func TestAnalyzeDoctorLogBundleRejectsUnknownBinary(t *testing.T) {
	if _, err := analyzeDoctorLogBundle([]byte{'P', 'K', 0, 1, 2}); err == nil {
		t.Fatal("analyzeDoctorLogBundle() error = nil, want binary format error")
	}
}

func TestDoctorSavedLogBundleNameSanitizesRemoteComponents(t *testing.T) {
	artifact := xcodeCloudDoctorArtifact{
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
