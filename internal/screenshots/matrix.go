package screenshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/tidwall/jsonc"
)

const (
	maxMatrixPlanBytes       = 1 << 20
	maxMatrixReviewBytes     = 8 << 20
	maxMatrixInventoryBytes  = 4 << 20
	maxMatrixCells           = 256
	maxMatrixConcurrency     = 8
	maxMatrixAttempts        = 3
	defaultMatrixConcurrency = 1
	defaultMatrixAttempts    = 1
	defaultMatrixRawDir      = "./screenshots/matrix/raw"
	defaultMatrixFramedDir   = "./screenshots/matrix/framed"
	defaultMatrixReviewDir   = "./screenshots/matrix/review"
)

var matrixPathComponentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

var (
	// ErrMatrixPlanRead indicates that a matrix plan could not be read.
	ErrMatrixPlanRead = errors.New("read matrix plan")
	// ErrMatrixPlanParseJSON indicates that a matrix plan is not valid JSON/JSONC.
	ErrMatrixPlanParseJSON = errors.New("parse matrix plan JSON")
)

// MatrixValidationError marks failures that are deterministic input errors and
// must be reported with CLI usage semantics before any run side effect.
type MatrixValidationError struct {
	Err error
}

func (e *MatrixValidationError) Error() string {
	if e == nil || e.Err == nil {
		return "invalid matrix plan"
	}
	return e.Err.Error()
}

func (e *MatrixValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newMatrixValidationError(err error) error {
	if err == nil {
		return nil
	}
	return &MatrixValidationError{Err: err}
}

// MatrixDevice identifies an already-existing, booted simulator.
type MatrixDevice struct {
	ID   string `json:"id"`
	UDID string `json:"udid"`
}

// MatrixContentVariant supplies literal launch arguments for one content fixture.
type MatrixContentVariant struct {
	ID              string   `json:"id"`
	LaunchArguments []string `json:"launch_arguments,omitempty"`
}

// MatrixExecution controls matrix scheduling and retry behavior.
type MatrixExecution struct {
	MaxConcurrency int    `json:"max_concurrency,omitempty"`
	MaxAttempts    int    `json:"max_attempts,omitempty"`
	RetryBackoffMS int    `json:"retry_backoff_ms,omitempty"`
	RetryBackoff   string `json:"retry_backoff,omitempty"`
}

// MatrixFrame configures optional local framing for matrix artifacts.
type MatrixFrame struct {
	Enabled              bool              `json:"enabled"`
	DeviceByMatrixDevice map[string]string `json:"device_by_matrix_device,omitempty"`
}

// MatrixOutput configures the three local artifact directories.
type MatrixOutput struct {
	RawDir    string      `json:"raw_dir,omitempty"`
	FramedDir string      `json:"framed_dir,omitempty"`
	ReviewDir string      `json:"review_dir,omitempty"`
	Frame     MatrixFrame `json:"frame,omitempty"`
}

// MatrixPlan describes the Cartesian product to execute over a base screenshot plan.
type MatrixPlan struct {
	Version         int                    `json:"version"`
	BasePlan        string                 `json:"base_plan"`
	Devices         []MatrixDevice         `json:"devices"`
	Locales         []string               `json:"locales"`
	Appearances     []string               `json:"appearances"`
	ContentVariants []MatrixContentVariant `json:"content_variants"`
	Execution       MatrixExecution        `json:"execution,omitempty"`
	Output          MatrixOutput           `json:"output,omitempty"`

	sourcePath string
}

// MatrixCell is an expanded matrix invocation. UDID and launch arguments are
// intentionally internal and are never serialized in result or review artifacts.
type MatrixCell struct {
	ID              string
	Device          string
	UDID            string
	Locale          string
	Appearance      string
	Content         string
	LaunchArguments []string
	RawDir          string
	FramedDir       string
	RawPaths        []string
	FramedPaths     []string
}

const (
	MatrixCellSuccess       = "success"
	MatrixCellFailed        = "failed"
	MatrixCellCanceled      = "canceled"
	MatrixCellCleanupFailed = "cleanup_failed"
)

// MatrixCellResult is the privacy-safe result for one cell.
type MatrixCellResult struct {
	ID           string                   `json:"id"`
	Device       string                   `json:"device"`
	Locale       string                   `json:"locale"`
	Appearance   string                   `json:"appearance"`
	Content      string                   `json:"contentVariant"`
	Status       string                   `json:"status"`
	Attempts     int                      `json:"attempts"`
	DurationMS   int64                    `json:"durationMs"`
	RawPaths     []string                 `json:"rawPaths,omitempty"`
	FramedPaths  []string                 `json:"framedPaths,omitempty"`
	Screenshots  []MatrixScreenshotResult `json:"screenshots,omitempty"`
	Steps        []RunStepResult          `json:"steps,omitempty"`
	FailureStage string                   `json:"failureStage,omitempty"`
	FailureCode  string                   `json:"failureCode,omitempty"`
	Error        *MatrixCellError         `json:"error,omitempty"`
}

// MatrixCellError is a sanitized, stable failure contract. It intentionally
// has no raw subprocess output, simulator identifier, or launch arguments.
type MatrixCellError struct {
	Stage   string `json:"stage"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MatrixScreenshotResult describes one screenshot step in a cell review.
type MatrixScreenshotResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	RawPath    string `json:"rawPath,omitempty"`
	FramedPath string `json:"framedPath,omitempty"`
	Width      int    `json:"width,omitempty"`
	Height     int    `json:"height,omitempty"`
}

// MatrixResult is printed after a matrix run and is also the source for review artifacts.
type MatrixResult struct {
	PlanPath      string              `json:"planPath"`
	BundleID      string              `json:"bundleId,omitempty"`
	RawDir        string              `json:"rawDir"`
	FramedDir     string              `json:"framedDir"`
	ReviewDir     string              `json:"reviewDir"`
	Status        string              `json:"status"`
	TotalCells    int                 `json:"totalCells"`
	Succeeded     int                 `json:"succeeded"`
	Failed        int                 `json:"failed"`
	Canceled      int                 `json:"canceled"`
	Retried       int                 `json:"retried"`
	CleanupFailed int                 `json:"cleanupFailed,omitempty"`
	Cells         []MatrixCellResult  `json:"cells"`
	Review        *MatrixReviewResult `json:"review,omitempty"`

	// Total is retained internally for callers that build reports directly;
	// the public output uses totalCells.
	Total int `json:"-"`
}

// MatrixOptions contains command-line overrides. Zero values use plan defaults.
type MatrixOptions struct {
	MaxConcurrency    int
	MaxConcurrencySet bool
	MaxAttempts       int
	MaxAttemptsSet    bool
	RetryBackoff      time.Duration
	RetryBackoffSet   bool
}

// MatrixAppearance controls simulator appearance state around a cell.
type MatrixAppearance interface {
	Snapshot(ctx context.Context, udid string) (state string, err error)
	Set(ctx context.Context, udid, appearance string) error
	Restore(ctx context.Context, udid, state string) error
}

// MatrixDependencies makes external execution replaceable by tests without
// changing the normal command behavior.
type MatrixDependencies struct {
	RunPlan     func(context.Context, *Plan) (*RunResult, error)
	Frame       func(context.Context, FrameRequest) (*FrameResult, error)
	Appearance  MatrixAppearance
	CheckDevice func(context.Context, MatrixDevice) error
}

// matrixOutputRoots keep operator-selected artifact paths anchored for the
// entire run. Paths below these roots are checked and written without
// following symlinks, while the absolute paths remain available to the
// existing simulator and framing adapters.
type matrixOutputRoots struct {
	raw        rootfs.Root
	rawPath    string
	framed     rootfs.Root
	framedPath string
	hasFramed  bool
}

var matrixTemporarySequence atomic.Uint64

// LoadMatrixPlan reads a JSON or JSONC matrix plan without resolving its base plan.
func LoadMatrixPlan(path string) (*MatrixPlan, error) {
	file, err := rootfs.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanRead, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxMatrixPlanBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanRead, err)
	}
	if len(data) > maxMatrixPlanBytes {
		return nil, fmt.Errorf("%w: matrix plan exceeds the %d-byte size limit", ErrMatrixPlanRead, maxMatrixPlanBytes)
	}
	var plan MatrixPlan
	if err := json.Unmarshal(jsonc.ToJSON(data), &plan); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanParseJSON, err)
	}
	if plan.Version == 0 {
		plan.Version = 1
	}
	plan.sourcePath, _ = filepath.Abs(path)
	return &plan, nil
}

func openMatrixOutputRoot(path string) (rootfs.Root, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return rootfs.Root{}, err
	}
	absPath = filepath.Clean(absPath)
	parentPath := filepath.Dir(absPath)
	name := filepath.Base(absPath)
	parent, err := rootfs.New(parentPath)
	if err != nil {
		return rootfs.Root{}, err
	}
	defer func() { _ = parent.Close() }()
	if err := parent.MkdirAll(".", 0o755); err != nil {
		return rootfs.Root{}, err
	}
	if err := parent.CheckContained(name); err != nil {
		return rootfs.Root{}, err
	}
	if err := parent.MkdirAll(name, 0o755); err != nil {
		return rootfs.Root{}, err
	}
	if err := parent.CheckContained(name); err != nil {
		return rootfs.Root{}, err
	}
	root, err := rootfs.New(absPath)
	if err != nil {
		return rootfs.Root{}, err
	}
	if err := root.MkdirAll(".", 0o755); err != nil {
		_ = root.Close()
		return rootfs.Root{}, err
	}
	return root, nil
}

func relativeMatrixOutputPath(rootPath, path string) (string, error) {
	rootPath = filepath.Clean(rootPath)
	path = filepath.Clean(path)
	relative, err := filepath.Rel(rootPath, path)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path %q escapes matrix output root", path)
	}
	return relative, nil
}

func createMatrixTemporaryDir(outputRoot rootfs.Root, outputRootPath, parentPath, prefix string) (string, error) {
	parentRelative, err := relativeMatrixOutputPath(outputRootPath, parentPath)
	if err != nil {
		return "", err
	}
	if err := outputRoot.MkdirAll(parentRelative, 0o755); err != nil {
		return "", err
	}
	rooted, err := outputRoot.OpenRoot()
	if err != nil {
		return "", err
	}
	defer rooted.Close()
	parent := rooted
	if parentRelative != "." {
		parent, err = rooted.OpenRoot(parentRelative)
		if err != nil {
			return "", err
		}
		defer parent.Close()
	}
	for attempt := 0; attempt < 100; attempt++ {
		name := fmt.Sprintf("%s%d", prefix, matrixTemporarySequence.Add(1))
		if err := parent.Mkdir(name, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return "", err
		}
		return filepath.Join(parentPath, name), nil
	}
	return "", errors.New("could not allocate a unique matrix temporary directory")
}

func removeMatrixTemporaryDir(outputRoot rootfs.Root, outputRootPath, path string) error {
	relative, err := relativeMatrixOutputPath(outputRootPath, path)
	if err != nil {
		return err
	}
	rooted, err := outputRoot.OpenRoot()
	if err != nil {
		return err
	}
	defer rooted.Close()
	if err := rooted.RemoveAll(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ValidateMatrixPlan validates all matrix inputs that can be checked without
// executing commands. The base plan must already be loaded and validated.
func ValidateMatrixPlan(plan *MatrixPlan, base *Plan) error {
	if plan == nil {
		return errors.New("matrix plan is required")
	}
	if plan.Version != 1 {
		return fmt.Errorf("unsupported matrix plan version %d (expected 1)", plan.Version)
	}
	if base == nil {
		return errors.New("base screenshot plan is required")
	}
	if err := validatePlan(base); err != nil {
		return fmt.Errorf("base plan: %w", err)
	}
	if err := validateMatrixBaseScreenshots(base); err != nil {
		return err
	}
	if len(plan.Devices) == 0 || len(plan.Locales) == 0 || len(plan.Appearances) == 0 || len(plan.ContentVariants) == 0 {
		return errors.New("devices, locales, appearances, and content_variants must each contain at least one item")
	}

	seenIDs := make(map[string]struct{}, len(plan.Devices))
	seenUDIDs := make(map[string]struct{}, len(plan.Devices))
	for i := range plan.Devices {
		device := &plan.Devices[i]
		device.ID = strings.TrimSpace(device.ID)
		device.UDID = strings.TrimSpace(device.UDID)
		if !isSafeMatrixPathComponent(device.ID) {
			return fmt.Errorf("device id %q must be a unique safe path component", device.ID)
		}
		if _, exists := seenIDs[device.ID]; exists {
			return fmt.Errorf("device id %q must be unique", device.ID)
		}
		seenIDs[device.ID] = struct{}{}
		if device.UDID == "" {
			return fmt.Errorf("device %q udid is required", device.ID)
		}
		if _, exists := seenUDIDs[device.UDID]; exists {
			return fmt.Errorf("device udid values must be unique")
		}
		seenUDIDs[device.UDID] = struct{}{}
	}

	seenLocales := make(map[string]struct{}, len(plan.Locales))
	for i, locale := range plan.Locales {
		normalized, err := normalizeMatrixLocale(locale)
		if err != nil {
			return fmt.Errorf("locales[%d]: %w", i, err)
		}
		if _, exists := seenLocales[normalized]; exists {
			return fmt.Errorf("locale %q must be unique after normalization", normalized)
		}
		seenLocales[normalized] = struct{}{}
		plan.Locales[i] = normalized
	}

	seenAppearances := make(map[string]struct{}, len(plan.Appearances))
	for i, appearance := range plan.Appearances {
		normalized := strings.ToLower(strings.TrimSpace(appearance))
		if normalized != "light" && normalized != "dark" {
			return fmt.Errorf("appearances[%d] must be light or dark", i)
		}
		if _, exists := seenAppearances[normalized]; exists {
			return fmt.Errorf("appearance %q must be unique", normalized)
		}
		seenAppearances[normalized] = struct{}{}
		plan.Appearances[i] = normalized
	}

	seenContent := make(map[string]struct{}, len(plan.ContentVariants))
	for i := range plan.ContentVariants {
		variant := &plan.ContentVariants[i]
		variant.ID = strings.TrimSpace(variant.ID)
		if !isSafeMatrixPathComponent(variant.ID) {
			return fmt.Errorf("content variant id %q must be a unique safe path component", variant.ID)
		}
		if _, exists := seenContent[variant.ID]; exists {
			return fmt.Errorf("content variant id %q must be unique", variant.ID)
		}
		seenContent[variant.ID] = struct{}{}
		if err := validateLiteralLaunchArguments(variant.LaunchArguments); err != nil {
			return fmt.Errorf("content variant %q: %w", variant.ID, err)
		}
	}

	cellCount := len(plan.Devices) * len(plan.Locales) * len(plan.Appearances) * len(plan.ContentVariants)
	if cellCount > maxMatrixCells {
		return fmt.Errorf("matrix expands to %d cells; maximum is %d", cellCount, maxMatrixCells)
	}
	if plan.Execution.MaxConcurrency < 0 || plan.Execution.MaxConcurrency > maxMatrixConcurrency {
		return fmt.Errorf("execution.max_concurrency must be between 1 and %d when set", maxMatrixConcurrency)
	}
	if plan.Execution.MaxAttempts < 0 || plan.Execution.MaxAttempts > maxMatrixAttempts {
		return fmt.Errorf("execution.max_attempts must be between 1 and %d when set", maxMatrixAttempts)
	}
	if plan.Execution.RetryBackoffMS < 0 {
		return errors.New("execution.retry_backoff_ms must be >= 0")
	}
	if strings.TrimSpace(plan.Execution.RetryBackoff) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(plan.Execution.RetryBackoff))
		if err != nil || parsed < 0 {
			return errors.New("execution.retry_backoff must be a non-negative duration")
		}
		if plan.Execution.RetryBackoffMS != 0 {
			return errors.New("set only one of execution.retry_backoff or execution.retry_backoff_ms")
		}
	}
	if err := validateMatrixOutputPaths(plan.Output); err != nil {
		return err
	}
	if plan.Output.Frame.Enabled {
		for _, device := range plan.Devices {
			frame, ok := plan.Output.Frame.DeviceByMatrixDevice[device.ID]
			if !ok || strings.TrimSpace(frame) == "" {
				return fmt.Errorf("framing requires a frame mapping for device %q", device.ID)
			}
			if err := validateMatrixFrameMapping(device.ID, frame); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateMatrixOutputPaths(output MatrixOutput) error {
	rawDir := strings.TrimSpace(output.RawDir)
	if rawDir == "" {
		rawDir = defaultMatrixRawDir
	}
	framedDir := strings.TrimSpace(output.FramedDir)
	if framedDir == "" {
		framedDir = defaultMatrixFramedDir
	}
	reviewDir := strings.TrimSpace(output.ReviewDir)
	if reviewDir == "" {
		reviewDir = defaultMatrixReviewDir
	}
	paths := []struct {
		name string
		path string
	}{
		{name: "raw_dir", path: rawDir}, {name: "framed_dir", path: framedDir}, {name: "review_dir", path: reviewDir},
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			left, _ := filepath.Abs(paths[i].path)
			right, _ := filepath.Abs(paths[j].path)
			if filepath.Clean(left) == filepath.Clean(right) {
				return fmt.Errorf("output.%s and output.%s must be different directories", paths[i].name, paths[j].name)
			}
		}
	}
	return nil
}

func validateMatrixBaseScreenshots(base *Plan) error {
	seen := make(map[string]struct{})
	for i, step := range base.Steps {
		if step.Action != ActionScreenshot {
			continue
		}
		name := strings.TrimSpace(stringValue(step.Name))
		if !isSafeMatrixPathComponent(name) {
			return fmt.Errorf("base plan screenshot at steps[%d] has unsafe name %q", i+1, name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("base plan screenshot name %q must be unique", name)
		}
		seen[name] = struct{}{}
	}
	if len(seen) == 0 {
		return errors.New("base plan must contain at least one screenshot step")
	}
	if err := validateLiteralLaunchArguments(base.App.LaunchArguments); err != nil {
		return fmt.Errorf("base plan app.launch_arguments: %w", err)
	}
	return nil
}

// ExpandMatrix returns cells in declaration order: device, locale, appearance,
// then content variant. Paths are logical paths until RunMatrix resolves them.
func ExpandMatrix(plan *MatrixPlan, base *Plan) ([]MatrixCell, error) {
	if err := ValidateMatrixPlan(plan, base); err != nil {
		return nil, err
	}
	rawDir := strings.TrimSpace(plan.Output.RawDir)
	if rawDir == "" {
		rawDir = defaultMatrixRawDir
	}
	framedDir := strings.TrimSpace(plan.Output.FramedDir)
	if framedDir == "" {
		framedDir = defaultMatrixFramedDir
	}
	cells := make([]MatrixCell, 0, len(plan.Devices)*len(plan.Locales)*len(plan.Appearances)*len(plan.ContentVariants))
	for _, device := range plan.Devices {
		for _, locale := range plan.Locales {
			for _, appearance := range plan.Appearances {
				for _, variant := range plan.ContentVariants {
					id := strings.Join([]string{device.ID, locale, appearance, variant.ID}, "|")
					launchArguments, err := BuildLocaleLaunchArguments(locale)
					if err != nil {
						return nil, err
					}
					launchArguments = append(launchArguments, variant.LaunchArguments...)
					cell := MatrixCell{
						ID:              id,
						Device:          device.ID,
						UDID:            device.UDID,
						Locale:          locale,
						Appearance:      appearance,
						Content:         variant.ID,
						LaunchArguments: append([]string(nil), launchArguments...),
						RawDir:          filepath.Join(rawDir, locale, device.ID, appearance, variant.ID),
						FramedDir:       filepath.Join(framedDir, locale, device.ID, appearance, variant.ID),
					}
					for _, step := range base.Steps {
						if step.Action != ActionScreenshot {
							continue
						}
						name := strings.TrimSpace(stringValue(step.Name))
						cell.RawPaths = append(cell.RawPaths, filepath.Join(cell.RawDir, name+".png"))
						cell.FramedPaths = append(cell.FramedPaths, filepath.Join(cell.FramedDir, name+".png"))
					}
					cells = append(cells, cell)
				}
			}
		}
	}
	return cells, nil
}

// BuildLocaleLaunchArguments returns arguments accepted by simctl launch.
func BuildLocaleLaunchArguments(locale string) ([]string, error) {
	normalized, err := normalizeMatrixLocale(locale)
	if err != nil {
		return nil, err
	}
	language := strings.Split(normalized, "-")[0]
	return []string{"-AppleLanguages", "(" + language + ")", "-AppleLocale", strings.ReplaceAll(normalized, "-", "_")}, nil
}

// RunMatrix loads the base plan, validates the complete matrix, executes local
// cells, and writes a report even when execution is partially unsuccessful.
func RunMatrix(ctx context.Context, matrixPath string, matrixPlan *MatrixPlan, options MatrixOptions) (*MatrixResult, error) {
	return RunMatrixWithDependencies(ctx, matrixPath, matrixPlan, options, MatrixDependencies{})
}

// RunMatrixWithDependencies is the testable implementation of RunMatrix.
func RunMatrixWithDependencies(ctx context.Context, matrixPath string, matrixPlan *MatrixPlan, options MatrixOptions, dependencies MatrixDependencies) (*MatrixResult, error) {
	if matrixPlan == nil {
		return nil, newMatrixValidationError(errors.New("matrix plan is required"))
	}
	basePath := strings.TrimSpace(matrixPlan.BasePlan)
	if basePath == "" {
		return nil, newMatrixValidationError(errors.New("base_plan is required"))
	}
	if !filepath.IsAbs(basePath) {
		basePath = filepath.Join(matrixPlanSourceDir(matrixPath, matrixPlan.sourcePath), basePath)
	}
	base, err := LoadPlan(basePath)
	if err != nil {
		return nil, newMatrixValidationError(fmt.Errorf("load base plan: %w", err))
	}
	if err := ValidateMatrixPlan(matrixPlan, base); err != nil {
		return nil, newMatrixValidationError(err)
	}
	concurrency, attempts, backoff, err := resolveMatrixExecution(matrixPlan.Execution, options)
	if err != nil {
		return nil, newMatrixValidationError(err)
	}
	cells, err := ExpandMatrix(matrixPlan, base)
	if err != nil {
		return nil, newMatrixValidationError(err)
	}
	baseDir := matrixPlanSourceDir(matrixPath, matrixPlan.sourcePath)
	for i := range cells {
		cells[i].RawDir = resolveMatrixArtifactPath(baseDir, cells[i].RawDir)
		cells[i].FramedDir = resolveMatrixArtifactPath(baseDir, cells[i].FramedDir)
		for j := range cells[i].RawPaths {
			cells[i].RawPaths[j] = resolveMatrixArtifactPath(baseDir, cells[i].RawPaths[j])
			cells[i].FramedPaths[j] = resolveMatrixArtifactPath(baseDir, cells[i].FramedPaths[j])
		}
	}
	rawDir := resolveMatrixArtifactPath(baseDir, matrixPlan.Output.RawDir)
	if strings.TrimSpace(matrixPlan.Output.RawDir) == "" {
		rawDir = resolveMatrixArtifactPath(baseDir, defaultMatrixRawDir)
	}
	framedDir := resolveMatrixArtifactPath(baseDir, matrixPlan.Output.FramedDir)
	if strings.TrimSpace(matrixPlan.Output.FramedDir) == "" {
		framedDir = resolveMatrixArtifactPath(baseDir, defaultMatrixFramedDir)
	}
	reviewDir := resolveMatrixArtifactPath(baseDir, matrixPlan.Output.ReviewDir)
	if strings.TrimSpace(matrixPlan.Output.ReviewDir) == "" {
		reviewDir = resolveMatrixArtifactPath(baseDir, defaultMatrixReviewDir)
	}

	planPath := strings.TrimSpace(matrixPath)
	if planPath == "" {
		planPath = matrixPlan.sourcePath
	}
	if absolutePlanPath, pathErr := filepath.Abs(planPath); pathErr == nil {
		planPath = absolutePlanPath
	}
	result := &MatrixResult{
		PlanPath:   planPath,
		BundleID:   base.App.BundleID,
		RawDir:     rawDir,
		FramedDir:  framedDir,
		ReviewDir:  reviewDir,
		Total:      len(cells),
		TotalCells: len(cells),
		Cells:      make([]MatrixCellResult, len(cells)),
	}
	for i, cell := range cells {
		result.Cells[i] = newMatrixCellResult(cell)
	}

	deps := dependencies
	useDefaultDeviceCheck := deps.RunPlan == nil && deps.Frame == nil && deps.Appearance == nil && deps.CheckDevice == nil
	if deps.RunPlan == nil {
		deps.RunPlan = RunPlan
	}
	if deps.Frame == nil {
		deps.Frame = Frame
	}
	if deps.Appearance == nil {
		deps.Appearance = &simctlMatrixAppearance{}
	}
	if deps.CheckDevice == nil && useDefaultDeviceCheck {
		deps.CheckDevice = checkMatrixDevice
	}
	deviceFailures := make(map[string]struct{})
	if deps.CheckDevice != nil {
		for _, device := range matrixPlan.Devices {
			if err := deps.CheckDevice(ctx, device); err != nil {
				deviceFailures[device.ID] = struct{}{}
			}
		}
	}
	for index, cell := range cells {
		if _, failed := deviceFailures[cell.Device]; !failed {
			continue
		}
		result.Cells[index].Status = MatrixCellFailed
		result.Cells[index].FailureStage = "preflight"
		result.Cells[index].FailureCode = "simulator_not_ready"
		result.Cells[index].Error = newMatrixCellError("preflight", "simulator_not_ready", "target simulator is not ready")
		setMatrixScreenshotStatuses(&result.Cells[index])
	}
	rawRoot, err := openMatrixOutputRoot(rawDir)
	if err != nil {
		return nil, fmt.Errorf("create raw output directory: %w", err)
	}
	defer func() { _ = rawRoot.Close() }()
	outputRoots := matrixOutputRoots{raw: rawRoot, rawPath: rawDir}
	if matrixPlan.Output.Frame.Enabled {
		framedRoot, rootErr := openMatrixOutputRoot(framedDir)
		if rootErr != nil {
			return nil, fmt.Errorf("create framed output directory: %w", rootErr)
		}
		defer func() { _ = framedRoot.Close() }()
		outputRoots.framed = framedRoot
		outputRoots.framedPath = framedDir
		outputRoots.hasFramed = true
	}
	runErr := executeMatrixCells(ctx, cells, deviceFailures, base, matrixPlan, concurrency, attempts, backoff, deps, outputRoots, result)
	countMatrixResultStatuses(result)
	reviewCtx := context.WithoutCancel(ctx)
	review, reviewErr := GenerateMatrixReview(reviewCtx, MatrixReviewRequest{Result: result, OutputDir: reviewDir})
	if reviewErr == nil {
		result.Review = review
	} else if runErr == nil {
		result.Status = MatrixCellFailed
		runErr = fmt.Errorf("write matrix review: %w", reviewErr)
	} else {
		result.Status = MatrixCellFailed
		runErr = errors.Join(runErr, fmt.Errorf("write matrix review: %w", reviewErr))
	}
	return result, runErr
}

func resolveMatrixExecution(execution MatrixExecution, options MatrixOptions) (int, int, time.Duration, error) {
	concurrency := execution.MaxConcurrency
	if options.MaxConcurrencySet || options.MaxConcurrency != 0 {
		concurrency = options.MaxConcurrency
	}
	if concurrency == 0 && !options.MaxConcurrencySet {
		concurrency = defaultMatrixConcurrency
	}
	if concurrency < 1 || concurrency > maxMatrixConcurrency {
		return 0, 0, 0, fmt.Errorf("max concurrency must be between 1 and %d", maxMatrixConcurrency)
	}
	attempts := execution.MaxAttempts
	if options.MaxAttemptsSet || options.MaxAttempts != 0 {
		attempts = options.MaxAttempts
	}
	if attempts == 0 && !options.MaxAttemptsSet {
		attempts = defaultMatrixAttempts
	}
	if attempts < 1 || attempts > maxMatrixAttempts {
		return 0, 0, 0, fmt.Errorf("max attempts must be between 1 and %d", maxMatrixAttempts)
	}
	backoff := time.Duration(execution.RetryBackoffMS) * time.Millisecond
	if strings.TrimSpace(execution.RetryBackoff) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(execution.RetryBackoff))
		if err != nil {
			return 0, 0, 0, errors.New("retry backoff must be a valid duration")
		}
		backoff = parsed
	}
	if options.RetryBackoffSet || options.RetryBackoff != 0 {
		backoff = options.RetryBackoff
	}
	if backoff < 0 {
		return 0, 0, 0, errors.New("retry backoff must be >= 0")
	}
	return concurrency, attempts, backoff, nil
}

func executeMatrixCells(ctx context.Context, cells []MatrixCell, deviceFailures map[string]struct{}, base *Plan, matrixPlan *MatrixPlan, concurrency, attempts int, backoff time.Duration, deps MatrixDependencies, outputRoots matrixOutputRoots, result *MatrixResult) error {
	jobs := make(chan int)
	var workers sync.WaitGroup
	guards := make(map[string]*matrixSimulatorGuard)
	for _, cell := range cells {
		if _, ok := guards[cell.UDID]; !ok {
			guards[cell.UDID] = &matrixSimulatorGuard{}
		}
	}
	workerCount := concurrency
	if workerCount > len(cells) {
		workerCount = len(cells)
	}
	if workerCount == 0 {
		return nil
	}
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if _, failed := deviceFailures[cells[index].Device]; failed {
					continue
				}
				cellResult := executeMatrixCell(ctx, cells[index], base, matrixPlan, attempts, backoff, deps, outputRoots, guards[cells[index].UDID])
				result.Cells[index] = cellResult
			}
		}()
	}
	for index := range cells {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	workers.Wait()
	if ctx.Err() != nil {
		for i := range result.Cells {
			if result.Cells[i].Status == MatrixCellCanceled && result.Cells[i].Attempts == 0 {
				result.Cells[i].FailureStage = "execution"
				result.Cells[i].FailureCode = "canceled"
				result.Cells[i].Error = newMatrixCellError("execution", "canceled", "cell canceled")
			}
		}
		return ctx.Err()
	}
	for _, cell := range result.Cells {
		if cell.Status == MatrixCellFailed || cell.Status == MatrixCellCleanupFailed {
			return errors.New("one or more matrix cells failed")
		}
	}
	return nil
}

type matrixSimulatorGuard struct {
	mu      sync.Mutex
	blocked bool
}

func executeMatrixCell(ctx context.Context, cell MatrixCell, base *Plan, matrixPlan *MatrixPlan, maxAttempts int, backoff time.Duration, deps MatrixDependencies, outputRoots matrixOutputRoots, guard *matrixSimulatorGuard) MatrixCellResult {
	started := time.Now()
	result := newMatrixCellResult(cell)
	result.Status = MatrixCellFailed
	if guard == nil {
		guard = &matrixSimulatorGuard{}
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.blocked {
		result.FailureStage = "appearance"
		result.FailureCode = "simulator_blocked_after_cleanup_failure"
		result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "simulator blocked after appearance cleanup failure")
		setMatrixScreenshotStatuses(&result)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}

	if err := ctx.Err(); err != nil {
		return finishMatrixCellFailure(result, started, "execution", "canceled", "cell canceled")
	}
	state, err := deps.Appearance.Snapshot(ctx, cell.UDID)
	if err != nil {
		if ctx.Err() != nil {
			return finishMatrixCellFailure(result, started, "execution", "canceled", "cell canceled")
		}
		return finishMatrixCellFailure(result, started, "appearance", "snapshot_failed", "appearance state could not be read")
	}
	if err := deps.Appearance.Set(ctx, cell.UDID, cell.Appearance); err != nil {
		if ctx.Err() != nil {
			result = finishMatrixCellFailure(result, started, "execution", "canceled", "cell canceled")
		} else {
			result = finishMatrixCellFailure(result, started, "appearance", "set_failed", "requested appearance could not be applied")
		}
		if restoreErr := restoreMatrixAppearance(deps.Appearance, cell.UDID, state); restoreErr != nil {
			guard.blocked = true
			result.Status = MatrixCellCleanupFailed
			result.FailureStage = "cleanup"
			result.FailureCode = "appearance_restore_failed"
			result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "simulator appearance could not be restored")
		}
		setMatrixScreenshotStatuses(&result)
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result.Attempts = attempt
		if err := ctx.Err(); err != nil {
			result.Status = MatrixCellCanceled
			result.FailureStage = "execution"
			result.FailureCode = "canceled"
			result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "cell canceled")
			break
		}
		attemptResult, attemptErr := executeMatrixCellAttempt(ctx, cell, base, matrixPlan, deps, outputRoots)
		result.Steps = attemptResult.Steps
		if len(attemptResult.RawPaths) > 0 {
			result.RawPaths = append([]string(nil), attemptResult.RawPaths...)
			result.Screenshots = append([]MatrixScreenshotResult(nil), attemptResult.Screenshots...)
		}
		if attemptErr == nil {
			result.Status = MatrixCellSuccess
			result.FramedPaths = append([]string(nil), attemptResult.FramedPaths...)
			break
		}
		if ctx.Err() != nil {
			result.Status = MatrixCellCanceled
			result.FailureStage = "execution"
			result.FailureCode = "canceled"
			result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "cell canceled")
			break
		}
		result.FailureStage = attemptResult.FailureStage
		result.FailureCode = attemptResult.FailureCode
		result.Error = newMatrixCellError(attemptResult.FailureStage, attemptResult.FailureCode, attemptResult.Error)
		if attempt == maxAttempts || (attemptResult.FailureStage != "execution" && attemptResult.FailureStage != "framing") {
			break
		}
		if err := waitContext(ctx, backoff); err != nil {
			result.Status = MatrixCellCanceled
			result.FailureStage = "execution"
			result.FailureCode = "canceled"
			result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "cell canceled")
			break
		}
	}

	restoreErr := restoreMatrixAppearance(deps.Appearance, cell.UDID, state)
	if restoreErr != nil {
		guard.blocked = true
		result.Status = MatrixCellCleanupFailed
		result.FailureStage = "cleanup"
		result.FailureCode = "appearance_restore_failed"
		result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "simulator appearance could not be restored")
	} else if result.Status == MatrixCellFailed && result.FailureCode == "" {
		result.FailureStage = "execution"
		result.FailureCode = "execution_failed"
		result.Error = newMatrixCellError(result.FailureStage, result.FailureCode, "cell execution failed")
	}
	setMatrixScreenshotStatuses(&result)
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func restoreMatrixAppearance(appearance MatrixAppearance, udid, state string) error {
	restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return appearance.Restore(restoreCtx, udid, state)
}

type matrixAttemptResult struct {
	RawPaths     []string
	FramedPaths  []string
	Screenshots  []MatrixScreenshotResult
	Steps        []RunStepResult
	FailureStage string
	FailureCode  string
	Error        string
}

func executeMatrixCellAttempt(ctx context.Context, cell MatrixCell, base *Plan, matrixPlan *MatrixPlan, deps MatrixDependencies, outputRoots matrixOutputRoots) (matrixAttemptResult, error) {
	rawRelative, err := relativeMatrixOutputPath(outputRoots.rawPath, cell.RawDir)
	if err != nil {
		return matrixAttemptResult{FailureStage: "execution", FailureCode: "temporary_output_failed", Error: "temporary output directory could not be created"}, err
	}
	if err := outputRoots.raw.MkdirAll(rawRelative, 0o755); err != nil {
		return matrixAttemptResult{FailureStage: "execution", FailureCode: "temporary_output_failed", Error: "temporary output directory could not be created"}, err
	}
	attemptDir, err := createMatrixTemporaryDir(outputRoots.raw, outputRoots.rawPath, filepath.Dir(cell.RawDir), ".asc-matrix-attempt-")
	if err != nil {
		return matrixAttemptResult{FailureStage: "execution", FailureCode: "temporary_output_failed", Error: "temporary output directory could not be created"}, err
	}
	defer func() { _ = removeMatrixTemporaryDir(outputRoots.raw, outputRoots.rawPath, attemptDir) }()
	plan, err := cloneScreenshotPlan(base)
	if err != nil {
		return matrixAttemptResult{FailureStage: "execution", FailureCode: "plan_clone_failed", Error: "base plan could not be prepared"}, err
	}
	plan.App.UDID = cell.UDID
	plan.App.OutputDir = attemptDir
	plan.App.LaunchArguments = append(append([]string(nil), base.App.LaunchArguments...), cell.LaunchArguments...)
	ensureMatrixLaunchStep(plan)
	runResult, err := deps.RunPlan(ctx, plan)
	attempt := matrixAttemptResult{}
	if runResult != nil {
		attempt.Steps = sanitizeMatrixSteps(runResult.Steps)
	}
	if err != nil {
		attempt.FailureStage = "execution"
		attempt.FailureCode = "plan_failed"
		attempt.Error = "screenshot plan execution failed"
		return attempt, err
	}
	if runResult == nil {
		attempt.FailureStage = "execution"
		attempt.FailureCode = "empty_result"
		attempt.Error = "screenshot plan returned no result"
		return attempt, errors.New("empty screenshot result")
	}
	sources := make([]string, 0, len(cell.RawPaths))
	names := make([]string, 0, len(cell.RawPaths))
	dimensionsList := make([]asc.ImageDimensions, 0, len(cell.RawPaths))
	for _, rawPath := range cell.RawPaths {
		name := filepath.Base(rawPath)
		source := filepath.Join(attemptDir, name)
		sourceRelative, relativeErr := relativeMatrixOutputPath(outputRoots.rawPath, source)
		if relativeErr != nil {
			attempt.FailureStage = "execution"
			attempt.FailureCode = "missing_screenshot"
			attempt.Error = "screenshot plan did not produce every requested image"
			return attempt, relativeErr
		}
		sourceFile, openErr := outputRoots.raw.OpenFile(sourceRelative)
		if openErr != nil {
			attempt.FailureStage = "execution"
			attempt.FailureCode = "missing_screenshot"
			attempt.Error = "screenshot plan did not produce every requested image"
			return attempt, openErr
		}
		dimensions, imageErr := readMatrixImageDimensions(sourceFile, source)
		closeErr := sourceFile.Close()
		if imageErr != nil || closeErr != nil {
			attempt.FailureStage = "execution"
			attempt.FailureCode = "invalid_screenshot"
			attempt.Error = "screenshot plan produced an invalid image"
			if imageErr != nil {
				return attempt, imageErr
			}
			return attempt, closeErr
		}
		sources = append(sources, source)
		names = append(names, strings.TrimSuffix(name, filepath.Ext(name)))
		dimensionsList = append(dimensionsList, dimensions)
	}
	for index, rawPath := range cell.RawPaths {
		source := sources[index]
		destination := rawPath
		if err := promoteMatrixArtifact(outputRoots.raw, outputRoots.rawPath, source, destination); err != nil {
			attempt.FailureStage = "execution"
			attempt.FailureCode = "raw_output_failed"
			attempt.Error = "raw screenshot could not be promoted"
			return attempt, err
		}
		attempt.RawPaths = append(attempt.RawPaths, destination)
		attempt.Screenshots = append(attempt.Screenshots, MatrixScreenshotResult{
			Name: names[index], Status: MatrixCellSuccess,
			RawPath: destination, Width: dimensionsList[index].Width, Height: dimensionsList[index].Height,
		})
	}

	if !matrixPlan.Output.Frame.Enabled {
		return attempt, nil
	}
	framedRelative, err := relativeMatrixOutputPath(outputRoots.framedPath, cell.FramedDir)
	if err != nil {
		attempt.FailureStage = "framing"
		attempt.FailureCode = "framed_output_failed"
		attempt.Error = "framed output directory could not be created"
		return attempt, err
	}
	if err := outputRoots.framed.MkdirAll(framedRelative, 0o755); err != nil {
		attempt.FailureStage = "framing"
		attempt.FailureCode = "framed_output_failed"
		attempt.Error = "framed output directory could not be created"
		return attempt, err
	}
	frameAttemptDir, err := createMatrixTemporaryDir(outputRoots.framed, outputRoots.framedPath, filepath.Dir(cell.FramedDir), ".asc-matrix-frame-attempt-")
	if err != nil {
		attempt.FailureStage = "framing"
		attempt.FailureCode = "temporary_output_failed"
		attempt.Error = "temporary frame output directory could not be created"
		return attempt, err
	}
	defer func() { _ = removeMatrixTemporaryDir(outputRoots.framed, outputRoots.framedPath, frameAttemptDir) }()
	frameDevice := strings.TrimSpace(matrixPlan.Output.Frame.DeviceByMatrixDevice[cell.Device])
	frameSources := make([]string, 0, len(attempt.RawPaths))
	for index, inputPath := range attempt.RawPaths {
		tempFrame := filepath.Join(frameAttemptDir, filepath.Base(cell.FramedPaths[index]))
		frameResult, frameErr := deps.Frame(ctx, FrameRequest{InputPath: inputPath, OutputPath: tempFrame, Device: frameDevice})
		if frameErr != nil || frameResult == nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "frame_failed"
			attempt.Error = "screenshot framing failed"
			return attempt, errors.New("frame failed")
		}
		tempFrameRelative, relativeErr := relativeMatrixOutputPath(outputRoots.framedPath, tempFrame)
		if relativeErr != nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "invalid_frame"
			attempt.Error = "screenshot framing produced an invalid image"
			return attempt, relativeErr
		}
		tempFrameFile, openErr := outputRoots.framed.OpenFile(tempFrameRelative)
		if openErr != nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "invalid_frame"
			attempt.Error = "screenshot framing produced an invalid image"
			return attempt, openErr
		}
		_, imageErr := readMatrixImageDimensions(tempFrameFile, tempFrame)
		closeErr := tempFrameFile.Close()
		if imageErr != nil || closeErr != nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "invalid_frame"
			attempt.Error = "screenshot framing produced an invalid image"
			if imageErr != nil {
				return attempt, imageErr
			}
			return attempt, closeErr
		}
		frameSources = append(frameSources, tempFrame)
	}
	for index, tempFrame := range frameSources {
		if err := promoteMatrixArtifact(outputRoots.framed, outputRoots.framedPath, tempFrame, cell.FramedPaths[index]); err != nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "framed_output_failed"
			attempt.Error = "framed screenshot could not be promoted"
			return attempt, err
		}
		attempt.FramedPaths = append(attempt.FramedPaths, cell.FramedPaths[index])
		attempt.Screenshots[index].FramedPath = cell.FramedPaths[index]
	}
	return attempt, nil
}

func sanitizeMatrixSteps(steps []RunStepResult) []RunStepResult {
	if len(steps) == 0 {
		return nil
	}
	sanitized := make([]RunStepResult, len(steps))
	for index, step := range steps {
		sanitized[index] = RunStepResult{
			Index: step.Index, Action: step.Action, Status: step.Status, DurationMS: step.DurationMS,
		}
		if strings.TrimSpace(step.Error) != "" {
			sanitized[index].Error = "step execution failed"
		}
	}
	return sanitized
}

func ensureMatrixLaunchStep(plan *Plan) {
	for _, step := range plan.Steps {
		if step.Action == ActionLaunch {
			return
		}
	}
	plan.Steps = append([]PlanStep{{Action: ActionLaunch}}, plan.Steps...)
}

func cloneScreenshotPlan(base *Plan) (*Plan, error) {
	data, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	var clone Plan
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func promoteMatrixArtifact(outputRoot rootfs.Root, outputRootPath, source, destination string) error {
	sourceRelative, err := relativeMatrixOutputPath(outputRootPath, source)
	if err != nil {
		return err
	}
	sourceFile, err := outputRoot.OpenFile(sourceRelative)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	destinationRelative, err := relativeMatrixOutputPath(outputRootPath, destination)
	if err != nil {
		return err
	}
	_, err = outputRoot.WriteFrom(destinationRelative, sourceFile, 0o644)
	return err
}

func readMatrixImageDimensions(file *os.File, path string) (asc.ImageDimensions, error) {
	if file == nil {
		return asc.ImageDimensions{}, errors.New("image file is required")
	}
	info, err := file.Stat()
	if err != nil {
		return asc.ImageDimensions{}, err
	}
	if !info.Mode().IsRegular() {
		return asc.ImageDimensions{}, fmt.Errorf("expected regular image file %q", path)
	}
	if info.Size() <= 0 {
		return asc.ImageDimensions{}, fmt.Errorf("image file %q is empty", path)
	}
	if info.Size() > 1<<30 {
		return asc.ImageDimensions{}, fmt.Errorf("image file %q exceeds the size limit", path)
	}
	config, _, err := image.DecodeConfig(file)
	if err != nil {
		return asc.ImageDimensions{}, fmt.Errorf("decode image dimensions: %w", err)
	}
	if config.Width <= 0 || config.Height <= 0 {
		return asc.ImageDimensions{}, fmt.Errorf("image %q has invalid dimensions", path)
	}
	return asc.ImageDimensions{Width: config.Width, Height: config.Height}, nil
}

func finishMatrixCellFailure(result MatrixCellResult, started time.Time, stage, code, message string) MatrixCellResult {
	result.Status = MatrixCellFailed
	if code == "canceled" {
		result.Status = MatrixCellCanceled
	}
	result.FailureStage = stage
	result.FailureCode = code
	result.Error = newMatrixCellError(stage, code, message)
	setMatrixScreenshotStatuses(&result)
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func setMatrixScreenshotStatuses(result *MatrixCellResult) {
	for i := range result.Screenshots {
		switch result.Status {
		case MatrixCellSuccess:
			result.Screenshots[i].Status = MatrixCellSuccess
		case MatrixCellCanceled:
			result.Screenshots[i].Status = MatrixCellCanceled
		default:
			result.Screenshots[i].Status = MatrixCellFailed
		}
	}
}

func newMatrixCellResult(cell MatrixCell) MatrixCellResult {
	result := MatrixCellResult{
		ID: cell.ID, Device: cell.Device, Locale: cell.Locale, Appearance: cell.Appearance,
		Content: cell.Content, Status: MatrixCellCanceled,
		Screenshots: make([]MatrixScreenshotResult, 0, len(cell.RawPaths)),
	}
	for _, rawPath := range cell.RawPaths {
		name := strings.TrimSuffix(filepath.Base(rawPath), filepath.Ext(rawPath))
		result.Screenshots = append(result.Screenshots, MatrixScreenshotResult{Name: name, Status: MatrixCellCanceled})
	}
	return result
}

func newMatrixCellError(stage, code, message string) *MatrixCellError {
	return &MatrixCellError{Stage: stage, Code: code, Message: message}
}

func countMatrixResultStatuses(result *MatrixResult) {
	result.Succeeded, result.Failed, result.Canceled, result.CleanupFailed = 0, 0, 0, 0
	result.Retried = 0
	for _, cell := range result.Cells {
		if cell.Attempts > 1 {
			result.Retried += cell.Attempts - 1
		}
		switch cell.Status {
		case MatrixCellSuccess:
			result.Succeeded++
		case MatrixCellCanceled:
			result.Canceled++
		case MatrixCellCleanupFailed:
			result.CleanupFailed++
			result.Failed++
		default:
			result.Failed++
		}
	}
	result.Status = MatrixCellSuccess
	if result.Failed > 0 || result.Canceled > 0 {
		result.Status = MatrixCellFailed
	}
	result.TotalCells = result.Total
}

func resolveMatrixArtifactPath(baseDir, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	abs, err := filepath.Abs(filepath.Join(baseDir, path))
	if err != nil {
		return filepath.Clean(filepath.Join(baseDir, path))
	}
	return abs
}

func matrixPlanSourceDir(matrixPath, sourcePath string) string {
	path := strings.TrimSpace(matrixPath)
	if path == "" {
		path = strings.TrimSpace(sourcePath)
	}
	if path == "" {
		return "."
	}
	return filepath.Dir(path)
}

func isSafeMatrixPathComponent(value string) bool {
	return value != "." && value != ".." && matrixPathComponentPattern.MatchString(strings.TrimSpace(value))
}

func validateLiteralLaunchArguments(arguments []string) error {
	for _, argument := range arguments {
		trimmed := strings.TrimSpace(argument)
		if trimmed == "-AppleLocale" || trimmed == "-AppleLanguages" || strings.HasPrefix(trimmed, "-AppleLocale=") || strings.HasPrefix(trimmed, "-AppleLanguages=") {
			return errors.New("launch arguments must not override AppleLocale or AppleLanguages")
		}
	}
	return nil
}

func normalizeMatrixLocale(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "_", "-"))
	if value == "" {
		return "", errors.New("locale is required")
	}
	parts := strings.Split(value, "-")
	if len(parts) == 0 || len(parts[0]) < 2 || len(parts[0]) > 3 || !isASCIIAlpha(parts[0]) {
		return "", fmt.Errorf("locale %q must start with a language code such as en or en-US", value)
	}
	parts[0] = strings.ToLower(parts[0])
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" || len(parts[i]) < 2 || len(parts[i]) > 4 || !isASCIIAlphaNumeric(parts[i]) {
			return "", fmt.Errorf("locale %q contains an invalid region or script", value)
		}
		if len(parts[i]) == 2 || len(parts[i]) == 3 && isASCIIDigit(parts[i]) {
			parts[i] = strings.ToUpper(parts[i])
		} else {
			part := strings.ToLower(parts[i])
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "-"), nil
}

func isASCIIAlpha(value string) bool {
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func isASCIIDigit(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value string) bool {
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validateMatrixFrameMapping(matrixDevice, frame string) error {
	parsed, err := ParseFrameDevice(frame)
	if err != nil {
		return fmt.Errorf("device %q: %w", matrixDevice, err)
	}
	matrixFamily := matrixDeviceFamily(matrixDevice)
	frameFamily := frameDeviceFamily(parsed)
	if matrixFamily == "unknown" {
		return fmt.Errorf("device %q family is unknown; use a device label containing iphone or mac before enabling framing", matrixDevice)
	}
	if matrixFamily != "unknown" && frameFamily != "unknown" && matrixFamily != frameFamily {
		return fmt.Errorf("device %q cannot use %q frame: device families must match", matrixDevice, parsed)
	}
	if matrixFamily == "ipad" {
		return fmt.Errorf("device %q has no supported same-device frame mapping", matrixDevice)
	}
	return nil
}

func matrixDeviceFamily(value string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "ipad"), strings.Contains(value, "tablet"):
		return "ipad"
	case strings.Contains(value, "mac"):
		return "mac"
	case strings.Contains(value, "iphone"), strings.Contains(value, "phone"):
		return "iphone"
	default:
		return "unknown"
	}
}

func frameDeviceFamily(device FrameDevice) string {
	if device == FrameDeviceMac {
		return "mac"
	}
	return "iphone"
}

func checkMatrixDevice(ctx context.Context, device MatrixDevice) error {
	command := exec.CommandContext(ctx, "xcrun", "simctl", "list", "devices", "--json")
	var output cappedMatrixBuffer
	output.limit = maxMatrixInventoryBytes
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	if err != nil {
		return errors.New("simulator inventory could not be read")
	}
	if output.exceeded {
		return errors.New("simulator inventory exceeded the output size limit")
	}
	out := output.Bytes()
	var inventory struct {
		Devices map[string][]struct {
			UDID        string `json:"udid"`
			State       string `json:"state"`
			IsAvailable bool   `json:"isAvailable"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(out, &inventory); err != nil {
		return errors.New("simulator inventory was invalid")
	}
	wanted := strings.TrimSpace(device.UDID)
	for _, devices := range inventory.Devices {
		for _, candidate := range devices {
			if !strings.EqualFold(strings.TrimSpace(candidate.UDID), wanted) {
				continue
			}
			if !candidate.IsAvailable {
				return errors.New("simulator is unavailable")
			}
			if !strings.EqualFold(strings.TrimSpace(candidate.State), "booted") {
				return errors.New("simulator is not booted")
			}
			return nil
		}
	}
	return errors.New("simulator was not found")
}

type cappedMatrixBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *cappedMatrixBuffer) Write(data []byte) (int, error) {
	if b.limit < 0 {
		return 0, errors.New("output limit must not be negative")
	}
	if b.exceeded {
		return len(data), nil
	}
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		b.exceeded = len(data) > 0
		return len(data), nil
	}
	if len(data) > remaining {
		b.data = append(b.data, data[:remaining]...)
		b.exceeded = true
		return len(data), nil
	}
	b.data = append(b.data, data...)
	return len(data), nil
}

func (b *cappedMatrixBuffer) Bytes() []byte { return b.data }

type simctlMatrixAppearance struct{}

func (simctlMatrixAppearance) Snapshot(ctx context.Context, udid string) (string, error) {
	out, err := runExternalOutput(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "read", "-g", "AppleInterfaceStyle")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") || strings.Contains(strings.ToLower(err.Error()), "domain/default pair") {
			return "light", nil
		}
		return "", err
	}
	if strings.Contains(strings.ToLower(out), "dark") {
		return "dark", nil
	}
	if strings.Contains(strings.ToLower(out), "light") {
		return "light_explicit", nil
	}
	return "light", nil
}

func (simctlMatrixAppearance) Set(ctx context.Context, udid, appearance string) error {
	if appearance == "dark" {
		return runExternal(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "write", "-g", "AppleInterfaceStyle", "-string", "Dark")
	}
	err := runExternal(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "delete", "-g", "AppleInterfaceStyle")
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "does not exist") || strings.Contains(strings.ToLower(err.Error()), "domain/default pair")) {
		return nil
	}
	return err
}

func (simctlMatrixAppearance) Restore(ctx context.Context, udid, state string) error {
	if strings.EqualFold(strings.TrimSpace(state), "dark") {
		return runExternal(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "write", "-g", "AppleInterfaceStyle", "-string", "Dark")
	}
	if strings.EqualFold(strings.TrimSpace(state), "light_explicit") {
		return runExternal(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "write", "-g", "AppleInterfaceStyle", "-string", "Light")
	}
	err := runExternal(ctx, "xcrun", "simctl", "spawn", udid, "defaults", "delete", "-g", "AppleInterfaceStyle")
	if err != nil && (strings.Contains(strings.ToLower(err.Error()), "does not exist") || strings.Contains(strings.ToLower(err.Error()), "domain/default pair")) {
		return nil
	}
	return err
}
