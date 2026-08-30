package screenshots

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenReview_DryRun(t *testing.T) {
	outputDir := t.TempDir()
	htmlPath := filepath.Join(outputDir, defaultReviewHTMLName)
	if err := os.WriteFile(htmlPath, []byte("<html></html>"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	result, err := OpenReview(context.Background(), ReviewOpenRequest{
		OutputDir: outputDir,
		DryRun:    true,
	})
	if err != nil {
		t.Fatalf("OpenReview() error: %v", err)
	}
	if result.Opened {
		t.Fatal("expected dry-run open result to be false")
	}
	if result.HTMLPath != htmlPath {
		t.Fatalf("html path = %q, want %q", result.HTMLPath, htmlPath)
	}
}

func TestOpenReviewAllowsOversizedLegacyHTML(t *testing.T) {
	outputDir := t.TempDir()
	html := append([]byte("<!doctype html><html><body>legacy"), bytes.Repeat([]byte{'x'}, maxMatrixReviewBytes)...)
	html = append(html, []byte("</body></html>\n")...)
	if len(html) <= maxMatrixReviewBytes {
		t.Fatalf("legacy HTML length = %d, want over %d", len(html), maxMatrixReviewBytes)
	}
	if err := os.WriteFile(filepath.Join(outputDir, defaultReviewHTMLName), html, 0o644); err != nil {
		t.Fatalf("write oversized legacy HTML: %v", err)
	}

	result, err := OpenReview(context.Background(), ReviewOpenRequest{OutputDir: outputDir, DryRun: true})
	if err != nil {
		t.Fatalf("OpenReview() error = %v, want oversized legacy HTML to remain readable", err)
	}
	if result.Opened {
		t.Fatal("expected dry-run result not to open browser")
	}
}

func TestOpenReviewRejectsOversizedHTMLWithBoundManifest(t *testing.T) {
	outputDir := t.TempDir()
	html := append([]byte("<!doctype html><html><body>legacy"), bytes.Repeat([]byte{'x'}, maxMatrixReviewBytes)...)
	html = append(html, []byte("</body></html>\n")...)
	if len(html) <= maxMatrixReviewBytes {
		t.Fatalf("HTML length = %d, want over %d", len(html), maxMatrixReviewBytes)
	}
	if err := os.WriteFile(filepath.Join(outputDir, defaultReviewHTMLName), html, 0o644); err != nil {
		t.Fatalf("write oversized HTML: %v", err)
	}
	// A readable, digest-bound matrix manifest makes this a matrix pair even
	// when the marker is removed from the HTML. It must not be reclassified as
	// an unbounded legacy report.
	manifest := []byte(`{"htmlSha256":"bound-generation"}`)
	if err := os.WriteFile(filepath.Join(outputDir, defaultReviewManifestName), manifest, 0o644); err != nil {
		t.Fatalf("write bound manifest: %v", err)
	}
	manifestPath := filepath.Join(outputDir, defaultReviewManifestName)
	if _, err := LoadMatrixReviewManifest(manifestPath); !errors.Is(err, errMatrixReviewPairMismatch) {
		t.Fatalf("LoadMatrixReviewManifest() error = %v, want stable pair mismatch", err)
	}
	if _, err := OpenReview(context.Background(), ReviewOpenRequest{OutputDir: outputDir, DryRun: true}); !errors.Is(err, errMatrixReviewPairMismatch) {
		t.Fatalf("OpenReview() error = %v, want stable pair mismatch", err)
	}
}

func TestApproveReview_AllReady(t *testing.T) {
	outputDir := t.TempDir()
	manifestPath := filepath.Join(outputDir, defaultReviewManifestName)
	approvalPath := filepath.Join(outputDir, defaultReviewApprovalsName)

	manifest := ReviewManifest{
		GeneratedAt: "2026-01-01T00:00:00Z",
		FramedDir:   filepath.Join(outputDir, "framed"),
		OutputDir:   outputDir,
		Entries: []ReviewEntry{
			{
				Key:          "en|iPhone_Air|home",
				ScreenshotID: "home",
				Locale:       "en",
				Device:       "iPhone_Air",
				Status:       reviewStatusReady,
			},
			{
				Key:          "en|iPhone_Air|details",
				ScreenshotID: "details",
				Locale:       "en",
				Device:       "iPhone_Air",
				Status:       reviewStatusInvalidSize,
			},
		},
	}
	writeReviewManifest(t, manifestPath, manifest)

	result, err := ApproveReview(context.Background(), ReviewApproveRequest{
		OutputDir: outputDir,
		AllReady:  true,
	})
	if err != nil {
		t.Fatalf("ApproveReview() error: %v", err)
	}

	if result.Matched != 1 {
		t.Fatalf("matched=%d, want 1", result.Matched)
	}
	if result.Added != 1 {
		t.Fatalf("added=%d, want 1", result.Added)
	}
	if result.TotalApproved != 1 {
		t.Fatalf("total_approved=%d, want 1", result.TotalApproved)
	}
	if len(result.Keys) != 1 || result.Keys[0] != "en|iPhone_Air|home" {
		t.Fatalf("unexpected approved keys: %+v", result.Keys)
	}

	approvals, err := loadApprovals(approvalPath)
	if err != nil {
		t.Fatalf("loadApprovals() error: %v", err)
	}
	if !approvals["en|iPhone_Air|home"] {
		t.Fatal("expected home key to be approved")
	}
}

func TestApproveReview_ApprovesByLocaleDeviceSelectors(t *testing.T) {
	outputDir := t.TempDir()
	manifestPath := filepath.Join(outputDir, defaultReviewManifestName)

	manifest := ReviewManifest{
		GeneratedAt: "2026-01-01T00:00:00Z",
		FramedDir:   filepath.Join(outputDir, "framed"),
		OutputDir:   outputDir,
		Entries: []ReviewEntry{
			{
				Key:          "en|iPhone_Air|home",
				ScreenshotID: "home",
				Locale:       "en",
				Device:       "iPhone_Air",
				Status:       reviewStatusInvalidSize,
			},
			{
				Key:          "fr|iPhone_Air|home",
				ScreenshotID: "home",
				Locale:       "fr",
				Device:       "iPhone_Air",
				Status:       reviewStatusReady,
			},
		},
	}
	writeReviewManifest(t, manifestPath, manifest)

	result, err := ApproveReview(context.Background(), ReviewApproveRequest{
		OutputDir: outputDir,
		Locale:    "en",
		Device:    "iPhone_Air",
	})
	if err != nil {
		t.Fatalf("ApproveReview() error: %v", err)
	}
	if result.Matched != 1 || result.Added != 1 || result.TotalApproved != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Keys) != 1 || result.Keys[0] != "en|iPhone_Air|home" {
		t.Fatalf("unexpected approved keys: %+v", result.Keys)
	}
}

func TestApproveReview_RequiresSelector(t *testing.T) {
	outputDir := t.TempDir()
	manifestPath := filepath.Join(outputDir, defaultReviewManifestName)
	writeReviewManifest(t, manifestPath, ReviewManifest{GeneratedAt: "2026-01-01T00:00:00Z"})

	_, err := ApproveReview(context.Background(), ReviewApproveRequest{
		OutputDir: outputDir,
	})
	if err == nil {
		t.Fatal("expected selector error")
	}
	if !strings.Contains(err.Error(), "provide at least one selector") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeReviewManifest(t *testing.T, path string, manifest ReviewManifest) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
}
