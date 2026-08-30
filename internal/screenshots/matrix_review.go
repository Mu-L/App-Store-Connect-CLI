package screenshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

// MatrixReviewRequest describes the local report to write after a matrix run.
type MatrixReviewRequest struct {
	Result    *MatrixResult
	OutputDir string
}

// MatrixReviewManifest is the stable, privacy-safe JSON review artifact.
type MatrixReviewManifest struct {
	GeneratedAt string             `json:"generated_at"`
	PlanPath    string             `json:"plan_path"`
	BundleID    string             `json:"bundle_id"`
	RawDir      string             `json:"raw_dir"`
	FramedDir   string             `json:"framed_dir,omitempty"`
	OutputDir   string             `json:"output_dir"`
	Status      string             `json:"status"`
	TotalCells  int                `json:"total_cells"`
	Succeeded   int                `json:"succeeded"`
	Failed      int                `json:"failed"`
	Canceled    int                `json:"canceled"`
	Retried     int                `json:"retried"`
	Cells       []MatrixCellResult `json:"cells"`
}

// MatrixReviewResult identifies the generated report files.
type MatrixReviewResult struct {
	ManifestPath string `json:"manifest_path"`
	HTMLPath     string `json:"html_path"`
	Total        int    `json:"total"`
	Succeeded    int    `json:"succeeded"`
	Failed       int    `json:"failed"`
	Canceled     int    `json:"canceled"`
}

// GenerateMatrixReview writes an offline HTML report and its JSON manifest.
// It includes every planned cell, including failed and canceled cells.
func GenerateMatrixReview(ctx context.Context, request MatrixReviewRequest) (*MatrixReviewResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Result == nil {
		return nil, errors.New("matrix result is required")
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		return nil, errors.New("matrix review output directory is required")
	}
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve matrix review output directory: %w", err)
	}
	reviewRoot, err := rootfs.New(absOutputDir)
	if err != nil {
		return nil, fmt.Errorf("open matrix review output directory: %w", err)
	}
	defer func() { _ = reviewRoot.Close() }()
	if err := reviewRoot.MkdirAll(".", 0o755); err != nil {
		return nil, fmt.Errorf("create matrix review output directory: %w", err)
	}

	total, succeeded, failed, canceled := matrixReviewCounts(request.Result)
	status := request.Result.Status
	if status == "" {
		status = MatrixCellSuccess
		if failed > 0 || canceled > 0 {
			status = MatrixCellFailed
		}
	}
	manifest := MatrixReviewManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		PlanPath:    request.Result.PlanPath,
		BundleID:    request.Result.BundleID,
		RawDir:      relativeOrCleanPath(absOutputDir, request.Result.RawDir),
		FramedDir:   relativeOrCleanPath(absOutputDir, request.Result.FramedDir),
		OutputDir:   absOutputDir,
		Status:      status,
		TotalCells:  total,
		Succeeded:   succeeded,
		Failed:      failed,
		Canceled:    canceled,
		Retried:     request.Result.Retried,
		Cells:       make([]MatrixCellResult, len(request.Result.Cells)),
	}
	for i, cell := range request.Result.Cells {
		manifest.Cells[i] = cell
		manifest.Cells[i].RawPaths = append([]string(nil), cell.RawPaths...)
		manifest.Cells[i].FramedPaths = append([]string(nil), cell.FramedPaths...)
		manifest.Cells[i].Steps = sanitizeMatrixSteps(cell.Steps)
		manifest.Cells[i].FailureStage, manifest.Cells[i].FailureCode = sanitizeMatrixReviewFailure(cell.FailureStage, cell.FailureCode)
		// Error values are produced by the matrix executor from a fixed set of
		// messages. Keep this defensive check in case a future caller supplies a
		// result directly to the report writer.
		manifest.Cells[i].Error = sanitizeMatrixReviewError(cell.Error)
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal matrix review manifest: %w", err)
	}
	htmlContent := renderMatrixReviewHTML(manifest)
	// Publish HTML before the manifest. The manifest is the report's commit
	// marker, so a failed HTML write cannot leave a new manifest pointing at a
	// report that was not published. Both writes are rooted and atomic.
	if err := reviewRoot.WriteFile("index.html", []byte(htmlContent), 0o644); err != nil {
		return nil, fmt.Errorf("write matrix review HTML: %w", err)
	}
	if err := reviewRoot.WriteFile("manifest.json", append(manifestData, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("write matrix review manifest: %w", err)
	}
	manifestPath := filepath.Join(absOutputDir, "manifest.json")
	htmlPath := filepath.Join(absOutputDir, "index.html")
	return &MatrixReviewResult{
		ManifestPath: manifestPath,
		HTMLPath:     htmlPath,
		Total:        manifest.TotalCells,
		Succeeded:    manifest.Succeeded,
		Failed:       manifest.Failed,
		Canceled:     manifest.Canceled,
	}, nil
}

func matrixReviewCounts(result *MatrixResult) (total, succeeded, failed, canceled int) {
	total = len(result.Cells)
	for _, cell := range result.Cells {
		switch cell.Status {
		case MatrixCellSuccess:
			succeeded++
		case MatrixCellCanceled:
			canceled++
		default:
			failed++
		}
	}
	if result.TotalCells > total {
		total = result.TotalCells
	}
	if result.Total > total {
		total = result.Total
	}
	return total, succeeded, failed, canceled
}

// LoadMatrixReviewManifest parses a generated matrix review manifest.
func LoadMatrixReviewManifest(path string) (*MatrixReviewManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read matrix review manifest: %w", err)
	}
	var manifest MatrixReviewManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse matrix review manifest: %w", err)
	}
	return &manifest, nil
}

func renderMatrixReviewHTML(manifest MatrixReviewManifest) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	b.WriteString("<title>Screenshot matrix review</title>\n<style>")
	b.WriteString("body{font:14px system-ui,sans-serif;margin:2rem;color:#202124;background:#fff}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dadce0;padding:.5rem;text-align:left;vertical-align:top}th{background:#f8f9fa}.success{color:#137333}.failed,.cleanup_failed{color:#b31412}.canceled{color:#8a4b08}.missing{color:#b31412;font-weight:600}ul{margin:.25rem 0;padding-left:1.2rem}a{word-break:break-all}img{display:block;max-width:240px;max-height:420px;margin:.25rem 0;border:1px solid #dadce0}")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<h1>Screenshot matrix review</h1>\n")
	b.WriteString("<p>Total: " + html.EscapeString(fmt.Sprintf("%d", manifest.TotalCells)) + "; succeeded: " + html.EscapeString(fmt.Sprintf("%d", manifest.Succeeded)) + "; failed: " + html.EscapeString(fmt.Sprintf("%d", manifest.Failed)) + "; canceled: " + html.EscapeString(fmt.Sprintf("%d", manifest.Canceled)) + ".</p>\n")
	b.WriteString("<table><thead><tr><th>Cell</th><th>Axes</th><th>Status</th><th>Attempts</th><th>Artifacts</th><th>Failure</th></tr></thead><tbody>\n")
	for _, cell := range manifest.Cells {
		status := html.EscapeString(cell.Status)
		b.WriteString("<tr><td><code>" + html.EscapeString(cell.ID) + "</code></td><td>")
		b.WriteString("device=" + html.EscapeString(cell.Device) + "<br>locale=" + html.EscapeString(cell.Locale) + "<br>appearance=" + html.EscapeString(cell.Appearance) + "<br>content=" + html.EscapeString(cell.Content))
		b.WriteString("</td><td class=\"" + status + "\">" + status + "</td><td>" + html.EscapeString(fmt.Sprintf("%d", cell.Attempts)) + "</td><td>")
		artifactCount := 0
		artifactCount += writeMatrixArtifactLinks(&b, "raw", cell.RawPaths, manifest.OutputDir)
		artifactCount += writeMatrixArtifactLinks(&b, "framed", cell.FramedPaths, manifest.OutputDir)
		if artifactCount == 0 {
			b.WriteString(`<span class="missing">missing image</span><br>`)
		}
		for _, screenshot := range cell.Screenshots {
			b.WriteString(`<span class="screenshot-status">` + html.EscapeString(screenshot.Name) + `: ` + html.EscapeString(screenshot.Status) + `</span><br>`)
		}
		b.WriteString("</td><td>")
		if cell.FailureStage != "" || cell.FailureCode != "" || cell.Error != nil {
			parts := make([]string, 0, 3)
			partsToRender := []string{cell.FailureStage, cell.FailureCode}
			if cell.Error != nil {
				partsToRender = append(partsToRender, cell.Error.Message)
			}
			for _, part := range partsToRender {
				if strings.TrimSpace(part) != "" {
					parts = append(parts, strings.TrimSpace(part))
				}
			}
			b.WriteString(html.EscapeString(strings.Join(parts, ": ")))
		} else {
			b.WriteString("—")
		}
		b.WriteString("</td></tr>\n")
	}
	b.WriteString("</tbody></table>\n</body>\n</html>\n")
	return b.String()
}

func writeMatrixArtifactLinks(b *strings.Builder, label string, paths []string, root string) int {
	count := 0
	for _, path := range paths {
		count++
		path = filepath.ToSlash(relativeOrCleanPath(root, path))
		escapedPath := html.EscapeString(path)
		escapedLabel := html.EscapeString(label)
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		escapedName := html.EscapeString(name)
		b.WriteString("<a href=\"" + escapedPath + "\"><img loading=\"lazy\" src=\"" + escapedPath + "\" alt=\"" + escapedLabel + " " + escapedName + " screenshot\"></a><span>" + escapedLabel + " " + escapedName + "</span><br>")
	}
	return count
}

func relativeOrCleanPath(root, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if relative, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(relative)
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func sanitizeMatrixReviewError(value *MatrixCellError) *MatrixCellError {
	if value == nil {
		return nil
	}
	message := strings.TrimSpace(value.Message)
	switch message {
	case "cell canceled", "screenshot plan execution failed", "screenshot framing failed", "raw screenshot could not be promoted", "framed screenshot could not be promoted", "simulator appearance could not be restored", "simulator blocked after appearance cleanup failure", "appearance state could not be read", "requested appearance could not be applied", "cell execution failed", "target simulator is not ready", "screenshot plan did not produce every requested image", "screenshot plan produced an invalid image", "screenshot framing produced an invalid image":
	default:
		message = "matrix execution failed"
	}
	stage, code := sanitizeMatrixReviewFailure(value.Stage, value.Code)
	return &MatrixCellError{Stage: stage, Code: code, Message: message}
}

func sanitizeMatrixReviewFailure(stage, code string) (string, string) {
	stage = strings.TrimSpace(stage)
	switch stage {
	case "execution", "framing", "appearance", "cleanup", "preflight":
	default:
		stage = "execution"
	}
	code = strings.TrimSpace(code)
	if !isSafeMatrixPathComponent(code) {
		code = "matrix_failure"
	}
	return stage, code
}
