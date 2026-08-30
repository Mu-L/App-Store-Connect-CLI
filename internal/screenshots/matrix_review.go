package screenshots

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

// MatrixReviewRequest describes the local report to write after a matrix run.
type MatrixReviewRequest struct {
	Result      *MatrixResult
	OutputDir   string
	LockContext context.Context
}

// MatrixReviewManifest and MatrixReviewResult are aliases for the governed
// output contracts. The screenshots package keeps execution details private
// while the asc package owns public JSON field naming and renderers.
type (
	MatrixReviewManifest = asc.MatrixReviewManifest
	MatrixReviewResult   = asc.MatrixReviewResult
)

// GenerateMatrixReview writes an offline HTML report and its JSON manifest.
// It includes every planned cell, including failed and canceled cells.
func GenerateMatrixReview(ctx context.Context, request MatrixReviewRequest) (*MatrixReviewResult, error) {
	return generateMatrixReviewWithWriter(ctx, request, func(root rootfs.Root, name string, data []byte, perm os.FileMode) error {
		return root.WriteFilePreservingMode(name, data, perm)
	})
}

// matrixReviewGeneratedFiles lists every file generateMatrixReviewWithWriter
// publishes into the review directory. Plan validation refuses inputs that would
// be overwritten by these names, so this must stay in step with the writer below;
// TestGenerateMatrixReviewWritesOnlyTheDeclaredFiles pins that.
var errMatrixReviewPairMismatch = errors.New("matrix review HTML does not match manifest")

var matrixReviewGeneratedFiles = []string{".asc-matrix-review.lock", "index.html", "manifest.json"}

const matrixReviewLockAfterCancelTimeout = 250 * time.Millisecond

func matrixReviewLockContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	// Report generation is intentionally detached from a canceled matrix run,
	// but lock acquisition must not wait forever behind another process.
	return context.WithTimeout(context.Background(), matrixReviewLockAfterCancelTimeout)
}

type matrixReviewWriter func(rootfs.Root, string, []byte, os.FileMode) error

func generateMatrixReviewWithWriter(ctx context.Context, request MatrixReviewRequest, write matrixReviewWriter) (result *MatrixReviewResult, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if request.Result == nil {
		return nil, errors.New("matrix result is required")
	}
	outputDir := request.OutputDir
	if strings.TrimSpace(outputDir) == "" {
		return nil, errors.New("matrix review output directory is required")
	}
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve matrix review output directory: %w", err)
	}
	reviewRoot, err := openMatrixOutputRoot(absOutputDir)
	if err != nil {
		return nil, fmt.Errorf("create matrix review output directory: %w", err)
	}
	defer func() { _ = reviewRoot.Close() }()
	lockContextSource := request.LockContext
	if lockContextSource == nil {
		lockContextSource = ctx
	}
	lockCtx, cancelLock := matrixReviewLockContext(lockContextSource)
	defer cancelLock()
	releaseReviewLock, err := acquireMatrixReviewLock(lockCtx, reviewRoot)
	if err != nil {
		return nil, fmt.Errorf("lock matrix review output directory: %w", err)
	}
	defer func() {
		if releaseErr := releaseReviewLock(); releaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release matrix review output lock: %w", releaseErr))
		}
	}()
	if write == nil {
		return nil, errors.New("matrix review writer is required")
	}
	if err := reviewRoot.CheckWriteFilePreservingMode("index.html"); err != nil {
		return nil, fmt.Errorf("prepare matrix review HTML: %w", err)
	}
	if err := reviewRoot.CheckWriteFilePreservingMode("manifest.json"); err != nil {
		return nil, fmt.Errorf("prepare matrix review manifest: %w", err)
	}
	previousHTML, hadHTML, err := readMatrixReviewFile(reviewRoot, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read previous matrix review HTML: %w", err)
	}
	previousManifest, hadManifest, err := readMatrixReviewFile(reviewRoot, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read previous matrix review manifest: %w", err)
	}

	total, succeeded, failed, canceled, cleanupFailed := matrixReviewCounts(request.Result)
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

		CleanupFailed: cleanupFailed,
		Cells:         make([]asc.MatrixCellResult, len(request.Result.Cells)),
	}
	for i, cell := range request.Result.Cells {
		manifest.Cells[i] = matrixReviewCellOutput(cell)
		// Error values are produced by the matrix executor from a fixed set of
		// messages. Keep this defensive check in case a future caller supplies a
		// result directly to the report writer.
		if cell.Status != MatrixCellSuccess {
			manifest.Cells[i].Error = matrixReviewErrorOutput(sanitizeMatrixReviewError(cell.Error))
		}
	}
	htmlContent := renderMatrixReviewHTML(manifest)
	htmlDigest := sha256.Sum256([]byte(htmlContent))
	manifest.HTMLSHA256 = fmt.Sprintf("%x", htmlDigest[:])
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal matrix review manifest: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if err := validateMatrixReviewSize("HTML", []byte(htmlContent)); err != nil {
		return nil, err
	}
	if err := validateMatrixReviewSize("manifest", manifestData); err != nil {
		return nil, err
	}
	// Publish HTML before the manifest. The manifest is the report's commit
	// marker. Both writes are rooted and atomic. If the manifest publication
	// fails, restore both files so the old marker and HTML remain a pair.
	if err := write(reviewRoot, "index.html", []byte(htmlContent), 0o644); err != nil {
		rollbackErr := restoreMatrixReviewFile(reviewRoot, "index.html", previousHTML, hadHTML)
		return nil, joinMatrixReviewWriteErrors(fmt.Errorf("write matrix review HTML: %w", err), rollbackErr)
	}
	if err := write(reviewRoot, "manifest.json", manifestData, 0o644); err != nil {
		manifestRollbackErr := restoreMatrixReviewFile(reviewRoot, "manifest.json", previousManifest, hadManifest)
		htmlRollbackErr := restoreMatrixReviewFile(reviewRoot, "index.html", previousHTML, hadHTML)
		return nil, joinMatrixReviewWriteErrors(
			fmt.Errorf("write matrix review manifest: %w", err),
			errors.Join(manifestRollbackErr, htmlRollbackErr),
		)
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

func validateMatrixReviewSize(kind string, data []byte) error {
	if len(data) > maxMatrixReviewBytes {
		return fmt.Errorf("matrix review %s exceeds the %d-byte size limit", kind, maxMatrixReviewBytes)
	}
	return nil
}

func readMatrixReviewFile(root rootfs.Root, name string) ([]byte, bool, error) {
	data, err := root.ReadFileLimited(name, maxMatrixReviewBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func restoreMatrixReviewFile(root rootfs.Root, name string, data []byte, existed bool) error {
	if existed {
		return root.WriteFilePreservingMode(name, data, 0o644)
	}
	rooted, err := root.OpenRoot()
	if err != nil {
		return err
	}
	defer rooted.Close()
	if err := rooted.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func joinMatrixReviewWriteErrors(primary, rollback error) error {
	if rollback == nil {
		return primary
	}
	return errors.Join(primary, fmt.Errorf("rollback matrix review: %w", rollback))
}

// matrixReviewCounts mirrors countMatrixResultStatuses so the persisted review
// agrees with the command result: a cleanup failure counts in both failed and
// cleanupFailed, the latter being a labelled subset rather than a sibling.
func matrixReviewCounts(result *MatrixResult) (total, succeeded, failed, canceled, cleanupFailed int) {
	total = len(result.Cells)
	for _, cell := range result.Cells {
		switch cell.Status {
		case MatrixCellSuccess:
			succeeded++
		case MatrixCellCanceled:
			canceled++
		case MatrixCellCleanupFailed:
			cleanupFailed++
			failed++
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
	return total, succeeded, failed, canceled, cleanupFailed
}

// LoadMatrixReviewManifest parses a generated matrix review manifest.
func LoadMatrixReviewManifest(path string) (*MatrixReviewManifest, error) {
	file, err := rootfs.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("read matrix review manifest: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMatrixReviewBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read matrix review manifest: %w", err)
	}
	if len(data) > maxMatrixReviewBytes {
		return nil, fmt.Errorf("read matrix review manifest: file exceeds the %d-byte size limit", maxMatrixReviewBytes)
	}
	var manifest MatrixReviewManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse matrix review manifest: %w", err)
	}
	if err := validateMatrixReviewPairForHTML(filepath.Join(filepath.Dir(path), "index.html")); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func validateMatrixReviewHTMLDigest(path, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		// Manifests created before the digest contract remain readable.
		return nil
	}
	file, err := rootfs.OpenFile(path)
	if err != nil {
		return errMatrixReviewPairMismatch
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMatrixReviewBytes+1))
	if err != nil || len(data) > maxMatrixReviewBytes {
		return errMatrixReviewPairMismatch
	}
	digest := sha256.Sum256(data)
	if !strings.EqualFold(expected, fmt.Sprintf("%x", digest[:])) {
		return errMatrixReviewPairMismatch
	}
	return nil
}

func validateMatrixReviewPairForHTML(path string) error {
	if filepath.Base(path) != "index.html" {
		return nil
	}
	htmlFile, err := rootfs.OpenFile(path)
	if err != nil {
		return errMatrixReviewPairMismatch
	}
	htmlData, readErr := io.ReadAll(io.LimitReader(htmlFile, maxMatrixReviewBytes+1))
	closeErr := htmlFile.Close()
	if readErr != nil || closeErr != nil || len(htmlData) > maxMatrixReviewBytes {
		return errMatrixReviewPairMismatch
	}
	matrixMarked := bytes.Contains(htmlData, []byte(`<meta name="asc-matrix-review" content="1">`))
	manifestPath := filepath.Join(filepath.Dir(path), "manifest.json")
	file, err := rootfs.OpenFile(manifestPath)
	if err != nil {
		if matrixMarked {
			return errMatrixReviewPairMismatch
		}
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMatrixReviewBytes+1))
	if err != nil || len(data) > maxMatrixReviewBytes {
		if matrixMarked {
			return errMatrixReviewPairMismatch
		}
		return nil
	}
	var binding struct {
		HTMLSHA256 string `json:"htmlSha256"`
	}
	if err := json.Unmarshal(data, &binding); err != nil || strings.TrimSpace(binding.HTMLSHA256) == "" {
		if matrixMarked {
			return errMatrixReviewPairMismatch
		}
		// Non-matrix and pre-binding review pairs remain backward compatible.
		return nil
	}
	return validateMatrixReviewHTMLDigest(path, binding.HTMLSHA256)
}

func renderMatrixReviewHTML(manifest MatrixReviewManifest) string {
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"asc-matrix-review\" content=\"1\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	b.WriteString("<title>Screenshot matrix review</title>\n<style>")
	b.WriteString("body{font:14px system-ui,sans-serif;margin:2rem;color:#202124;background:#fff}table{border-collapse:collapse;width:100%}th,td{border:1px solid #dadce0;padding:.5rem;text-align:left;vertical-align:top}th{background:#f8f9fa}.success{color:#137333}.failed,.cleanup_failed{color:#b31412}.canceled{color:#8a4b08}.missing{color:#b31412;font-weight:600}ul{margin:.25rem 0;padding-left:1.2rem}a{word-break:break-all}img{display:block;max-width:240px;max-height:420px;margin:.25rem 0;border:1px solid #dadce0}")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<h1>Screenshot matrix review</h1>\n")
	b.WriteString("<p>Total: " + html.EscapeString(fmt.Sprintf("%d", manifest.TotalCells)) + "; succeeded: " + html.EscapeString(fmt.Sprintf("%d", manifest.Succeeded)) + "; failed: " + html.EscapeString(fmt.Sprintf("%d", manifest.Failed)))
	// Mirrors the manifest's omitempty aggregate: only surfaced when a cell
	// captured successfully but could not restore simulator state.
	if manifest.CleanupFailed > 0 {
		b.WriteString(" (cleanup failed: " + html.EscapeString(fmt.Sprintf("%d", manifest.CleanupFailed)) + ")")
	}
	b.WriteString("; canceled: " + html.EscapeString(fmt.Sprintf("%d", manifest.Canceled)) + ".</p>\n")
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

func matrixReviewCellOutput(cell MatrixCellResult) asc.MatrixCellResult {
	output := asc.MatrixCellResult{
		ID:           cell.ID,
		Device:       cell.Device,
		Locale:       cell.Locale,
		Appearance:   cell.Appearance,
		Content:      cell.Content,
		Status:       cell.Status,
		Attempts:     cell.Attempts,
		DurationMS:   cell.DurationMS,
		RawPaths:     append([]string(nil), cell.RawPaths...),
		FramedPaths:  append([]string(nil), cell.FramedPaths...),
		FailureStage: "",
		FailureCode:  "",
	}
	output.Screenshots = make([]asc.MatrixScreenshotResult, len(cell.Screenshots))
	for i, screenshot := range cell.Screenshots {
		output.Screenshots[i] = asc.MatrixScreenshotResult{
			Name: screenshot.Name, Status: screenshot.Status, RawPath: screenshot.RawPath,
			FramedPath: screenshot.FramedPath, Width: screenshot.Width, Height: screenshot.Height,
		}
	}
	output.Steps = make([]asc.MatrixStepResult, len(cell.Steps))
	for i, step := range sanitizeMatrixSteps(cell.Steps) {
		output.Steps[i] = asc.MatrixStepResult{
			Index: step.Index, Action: step.Action, Status: step.Status,
			DurationMS: step.DurationMS, Error: step.Error,
		}
	}
	if cell.Status != MatrixCellSuccess {
		output.FailureStage, output.FailureCode = sanitizeMatrixReviewFailure(cell.FailureStage, cell.FailureCode)
	}
	return output
}

func matrixReviewErrorOutput(value *MatrixCellError) *asc.MatrixCellError {
	if value == nil {
		return nil
	}
	return &asc.MatrixCellError{Stage: value.Stage, Code: value.Code, Message: value.Message}
}

func writeMatrixArtifactLinks(b *strings.Builder, label string, paths []string, root string) int {
	count := 0
	for _, path := range paths {
		count++
		path = filepath.ToSlash(relativeOrCleanPath(root, path))
		escapedPath := html.EscapeString(matrixArtifactURLPath(path))
		escapedLabel := html.EscapeString(label)
		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		escapedName := html.EscapeString(name)
		b.WriteString("<a href=\"" + escapedPath + "\"><img loading=\"lazy\" src=\"" + escapedPath + "\" alt=\"" + escapedLabel + " " + escapedName + " screenshot\"></a><span>" + escapedLabel + " " + escapedName + "</span><br>")
	}
	return count
}

func matrixArtifactURLPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func relativeOrCleanPath(root, path string) string {
	if strings.TrimSpace(path) == "" {
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
	case "cell canceled", "screenshot plan execution failed", "screenshot framing failed", "raw screenshot could not be promoted", "framed screenshot could not be promoted", "framed screenshot became unavailable", "simulator appearance could not be restored", "simulator blocked after appearance cleanup failure", "appearance state could not be read", "requested appearance could not be applied", "cell execution failed", "target simulator is not ready", "configured frame does not match simulator family", "simulator family could not be identified", "configured frame mapping is invalid", "screenshot plan did not produce every requested image", "screenshot plan produced an invalid image", "screenshot framing produced an invalid image":
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
