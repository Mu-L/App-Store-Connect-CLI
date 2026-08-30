package screenshots

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	maxMatrixAppearanceBytes = 64 << 10
	maxMatrixReviewBytes     = 8 << 20
	maxMatrixInventoryBytes  = 4 << 20
	maxMatrixCells           = 256
	maxMatrixConcurrency     = 8
	maxMatrixAttempts        = 3
	// Keep millisecond retry values within time.Duration's nanosecond range
	// before converting them to a duration for scheduling.
	maxMatrixRetryBackoffMS  = (1<<63 - 1) / int64(time.Millisecond)
	matrixSubprocessTimeout  = 30 * time.Second
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
	// ErrMatrixInventoryTimeout indicates that the bounded simulator inventory
	// command reached its own deadline without caller cancellation.
	ErrMatrixInventoryTimeout = errors.New("simulator inventory timed out")
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

	// maxConcurrencySet and maxAttemptsSet record whether the operator stated
	// the bounded limit explicitly, so an omitted field can default while an
	// explicit zero is rejected as out of the documented 1-N range.
	maxConcurrencySet bool
	maxAttemptsSet    bool

	// retryBackoffMSSet and retryBackoffSet record which retry-backoff encoding
	// was stated. Zero milliseconds and an empty duration are both meaningful
	// values, so only presence can tell that both encodings were supplied.
	retryBackoffMSSet bool
	retryBackoffSet   bool
}

// UnmarshalJSON decodes execution settings while recording which bounded limits
// were stated explicitly. encoding/json cannot otherwise distinguish
// "max_concurrency": 0 from an omitted field, so a mistaken zero would silently
// run with the default instead of being reported. Unknown-field strictness is
// preserved here because a custom unmarshaler bypasses the outer decoder's
// DisallowUnknownFields.
func (e *MatrixExecution) UnmarshalJSON(data []byte) error {
	type executionFields MatrixExecution
	var decoded executionFields
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*e = MatrixExecution(decoded)
	var present map[string]json.RawMessage
	if err := json.Unmarshal(data, &present); err != nil {
		return err
	}
	_, e.maxConcurrencySet = present["max_concurrency"]
	_, e.maxAttemptsSet = present["max_attempts"]
	_, e.retryBackoffMSSet = present["retry_backoff_ms"]
	_, e.retryBackoffSet = present["retry_backoff"]
	return nil
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

	framedArtifacts map[string]matrixArtifactInfo
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
	jsonData := jsonc.ToJSON(data)
	if err := validateMatrixPlanJSONFields(jsonData); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanParseJSON, err)
	}
	var plan MatrixPlan
	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanParseJSON, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: multiple JSON values", ErrMatrixPlanParseJSON)
		}
		return nil, fmt.Errorf("%w: %w", ErrMatrixPlanParseJSON, err)
	}
	plan.sourcePath, _ = filepath.Abs(path)
	return &plan, nil
}

type matrixJSONScope string

const (
	matrixJSONScopePlan           matrixJSONScope = "plan"
	matrixJSONScopeDevice         matrixJSONScope = "device"
	matrixJSONScopeContentVariant matrixJSONScope = "content_variant"
	matrixJSONScopeExecution      matrixJSONScope = "execution"
	matrixJSONScopeOutput         matrixJSONScope = "output"
	matrixJSONScopeFrame          matrixJSONScope = "frame"
	matrixJSONScopeGeneric        matrixJSONScope = "generic"
)

var matrixJSONFieldScopes = map[matrixJSONScope]map[string]matrixJSONScope{
	matrixJSONScopePlan: {
		"version":          matrixJSONScopeGeneric,
		"base_plan":        matrixJSONScopeGeneric,
		"devices":          matrixJSONScopeDevice,
		"locales":          matrixJSONScopeGeneric,
		"appearances":      matrixJSONScopeGeneric,
		"content_variants": matrixJSONScopeContentVariant,
		"execution":        matrixJSONScopeExecution,
		"output":           matrixJSONScopeOutput,
	},
	matrixJSONScopeDevice: {
		"id":   matrixJSONScopeGeneric,
		"udid": matrixJSONScopeGeneric,
	},
	matrixJSONScopeContentVariant: {
		"id":               matrixJSONScopeGeneric,
		"launch_arguments": matrixJSONScopeGeneric,
	},
	matrixJSONScopeExecution: {
		"max_concurrency":  matrixJSONScopeGeneric,
		"max_attempts":     matrixJSONScopeGeneric,
		"retry_backoff_ms": matrixJSONScopeGeneric,
		"retry_backoff":    matrixJSONScopeGeneric,
	},
	matrixJSONScopeOutput: {
		"raw_dir":    matrixJSONScopeGeneric,
		"framed_dir": matrixJSONScopeGeneric,
		"review_dir": matrixJSONScopeGeneric,
		"frame":      matrixJSONScopeFrame,
	},
	matrixJSONScopeFrame: {
		"enabled":                 matrixJSONScopeGeneric,
		"device_by_matrix_device": matrixJSONScopeGeneric,
	},
}

// validateMatrixPlanJSONFields rejects duplicate keys and accepts only the
// exact snake_case spelling of matrix-plan fields. encoding/json otherwise
// accepts case-insensitive field matches and silently keeps the last duplicate
// value, which makes operator typos and ambiguous plans unsafe to review.
func validateMatrixPlanJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkMatrixJSONValue(decoder, matrixJSONScopePlan); err != nil {
		return err
	}
	return nil
}

func walkMatrixJSONValue(decoder *json.Decoder, scope matrixJSONScope) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		return walkMatrixJSONObject(decoder, scope)
	case '[':
		for decoder.More() {
			if err := walkMatrixJSONValue(decoder, scope); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("matrix plan JSON array is malformed")
		}
		return nil
	default:
		return fmt.Errorf("matrix plan JSON value is malformed")
	}
}

func walkMatrixJSONObject(decoder *json.Decoder, scope matrixJSONScope) error {
	allowed := matrixJSONFieldScopes[scope]
	seen := make(map[string]string)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("matrix plan JSON object key is malformed")
		}
		keyFolded := strings.ToLower(key)
		if previous, exists := seen[keyFolded]; exists {
			return fmt.Errorf("matrix plan contains duplicate fields %q and %q", previous, key)
		}
		childScope, exact := allowed[key]
		if len(allowed) > 0 && !exact {
			for expected := range allowed {
				if strings.EqualFold(expected, key) {
					return fmt.Errorf("matrix plan field %q must use exact spelling %q", key, expected)
				}
			}
			return fmt.Errorf("matrix plan contains unknown field %q", key)
		}
		seen[keyFolded] = key
		if err := walkMatrixJSONValue(decoder, childScope); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != json.Delim('}') {
		return fmt.Errorf("matrix plan JSON object is malformed")
	}
	return nil
}

// loadMatrixBasePlan loads a base screenshot plan from the matrix plan's
// directory. Matrix plans intentionally do not permit absolute or escaping
// references: the directory is the operator-selected trust boundary for all
// matrix inputs. Rooted reads reject symlinks, non-regular files, and files
// larger than the bounded plan limit.
func loadMatrixBasePlan(matrixPath string, matrixPlan *MatrixPlan) (*Plan, error) {
	if matrixPlan == nil {
		return nil, fmt.Errorf("%w: matrix plan is required", ErrPlanRead)
	}
	baseReference := matrixPlan.BasePlan
	if strings.TrimSpace(baseReference) == "" {
		return nil, fmt.Errorf("%w: base_plan is required", ErrPlanRead)
	}
	if filepath.IsAbs(baseReference) || filepath.VolumeName(baseReference) != "" {
		return nil, fmt.Errorf("%w: base_plan must be relative to the matrix plan", ErrPlanRead)
	}
	baseRelative := filepath.Clean(baseReference)
	if baseRelative == ".." || strings.HasPrefix(baseRelative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: base_plan must stay below the matrix plan directory", ErrPlanRead)
	}
	baseRoot, err := rootfs.New(matrixPlanSourceDir(matrixPath, matrixPlan.sourcePath))
	if err != nil {
		return nil, fmt.Errorf("%w: open matrix plan directory: %w", ErrPlanRead, err)
	}
	defer func() { _ = baseRoot.Close() }()
	data, err := baseRoot.ReadFileLimited(baseRelative, maxMatrixPlanBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPlanRead, err)
	}
	var plan Plan
	data = jsonc.ToJSON(data)
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPlanParseJSON, err)
	}
	// Keep the existing base-plan compatibility contract: omitted version
	// fields are treated as v1. The matrix envelope itself remains strict and
	// must explicitly declare version 1.
	if plan.Version == 0 {
		plan.Version = 1
	}
	if err := validatePlan(&plan); err != nil {
		return nil, err
	}
	return &plan, nil
}

func openMatrixOutputRoot(path string) (rootfs.Root, error) {
	if strings.TrimSpace(path) == "" {
		return rootfs.Root{}, errors.New("matrix output path is required")
	}
	absPath, err := filepath.Abs(path)
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
	return validateMatrixPlan(plan, base, "")
}

func validateMatrixPlan(plan *MatrixPlan, base *Plan, outputBaseDir string) error {
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
		idKey := strings.ToLower(device.ID)
		if _, exists := seenIDs[idKey]; exists {
			return fmt.Errorf("device id %q must be unique", device.ID)
		}
		seenIDs[idKey] = struct{}{}
		if device.UDID == "" {
			return fmt.Errorf("device %q udid is required", device.ID)
		}
		udidKey := normalizeMatrixUDID(device.UDID)
		if _, exists := seenUDIDs[udidKey]; exists {
			return fmt.Errorf("device udid values must be unique")
		}
		seenUDIDs[udidKey] = struct{}{}
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
		contentKey := strings.ToLower(variant.ID)
		if _, exists := seenContent[contentKey]; exists {
			return fmt.Errorf("content variant id %q must be unique", variant.ID)
		}
		seenContent[contentKey] = struct{}{}
		if err := validateLiteralLaunchArguments(variant.LaunchArguments); err != nil {
			return fmt.Errorf("content variant %q: %w", variant.ID, err)
		}
	}

	cellCount := len(plan.Devices) * len(plan.Locales) * len(plan.Appearances) * len(plan.ContentVariants)
	if cellCount > maxMatrixCells {
		return fmt.Errorf("matrix expands to %d cells; maximum is %d", cellCount, maxMatrixCells)
	}
	// An omitted limit defaults; an explicitly configured value must fall inside
	// the documented range, so a stated zero is rejected rather than silently
	// replaced by the default.
	if plan.Execution.MaxConcurrency < 0 || plan.Execution.MaxConcurrency > maxMatrixConcurrency ||
		(plan.Execution.maxConcurrencySet && plan.Execution.MaxConcurrency < 1) {
		return fmt.Errorf("execution.max_concurrency must be between 1 and %d when set", maxMatrixConcurrency)
	}
	if plan.Execution.MaxAttempts < 0 || plan.Execution.MaxAttempts > maxMatrixAttempts ||
		(plan.Execution.maxAttemptsSet && plan.Execution.MaxAttempts < 1) {
		return fmt.Errorf("execution.max_attempts must be between 1 and %d when set", maxMatrixAttempts)
	}
	if plan.Execution.RetryBackoffMS < 0 {
		return errors.New("execution.retry_backoff_ms must be >= 0")
	}
	if int64(plan.Execution.RetryBackoffMS) > maxMatrixRetryBackoffMS {
		return errors.New("execution.retry_backoff_ms exceeds maximum duration")
	}
	retryBackoffText := strings.TrimSpace(plan.Execution.RetryBackoff)
	if retryBackoffText != "" {
		parsed, err := time.ParseDuration(retryBackoffText)
		if err != nil || parsed < 0 {
			return errors.New("execution.retry_backoff must be a non-negative duration")
		}
	}
	// Zero milliseconds is a valid explicit no-delay value, so a nonzero test
	// cannot tell "omitted" from "stated as 0". Presence decides when the plan
	// came from a document; the value comparison still covers plans built in Go,
	// which carry no presence information.
	if (plan.Execution.retryBackoffMSSet && plan.Execution.retryBackoffSet) ||
		(retryBackoffText != "" && plan.Execution.RetryBackoffMS != 0) {
		return errors.New("set only one of execution.retry_backoff or execution.retry_backoff_ms")
	}
	if err := validateMatrixOutputPaths(plan.Output, outputBaseDir); err != nil {
		return err
	}
	if err := validateMatrixReviewDoesNotOverwritePlans(plan, outputBaseDir); err != nil {
		return err
	}
	if plan.Output.Frame.Enabled {
		frameMappings := make(map[string]string, len(plan.Output.Frame.DeviceByMatrixDevice))
		for matrixDevice := range plan.Output.Frame.DeviceByMatrixDevice {
			key := normalizeMatrixDeviceID(matrixDevice)
			if _, declared := seenIDs[key]; !declared {
				return fmt.Errorf("framing mapping references undeclared device %q", matrixDevice)
			}
			if _, duplicate := frameMappings[key]; duplicate {
				return fmt.Errorf("framing mapping device %q must be unique", matrixDevice)
			}
			frameMappings[key] = plan.Output.Frame.DeviceByMatrixDevice[matrixDevice]
		}
		for _, device := range plan.Devices {
			frame, ok := frameMappings[normalizeMatrixDeviceID(device.ID)]
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

func validateMatrixOutputPaths(output MatrixOutput, baseDir string) error {
	rawDir := output.RawDir
	if strings.TrimSpace(rawDir) == "" {
		rawDir = defaultMatrixRawDir
	}
	framedDir := output.FramedDir
	if strings.TrimSpace(framedDir) == "" {
		framedDir = defaultMatrixFramedDir
	}
	reviewDir := output.ReviewDir
	if strings.TrimSpace(reviewDir) == "" {
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
			left := resolveMatrixValidationPath(baseDir, paths[i].path)
			right := resolveMatrixValidationPath(baseDir, paths[j].path)
			if sameMatrixDirectory(left, right) {
				return fmt.Errorf("output.%s and output.%s must be different directories", paths[i].name, paths[j].name)
			}
		}
	}
	return nil
}

// sameMatrixDirectory reports whether two output paths resolve to the same
// directory, including when one path reaches the other through a symlinked
// ancestor or a platform alias such as /tmp versus /private/tmp. Output roots
// do not need to exist yet, so the comparison resolves the nearest existing
// ancestor and appends the not-yet-created suffix without creating anything.
func sameMatrixDirectory(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if strings.EqualFold(left, right) {
		return true
	}
	if leftInfo, leftErr := os.Stat(left); leftErr == nil {
		if rightInfo, rightErr := os.Stat(right); rightErr == nil && os.SameFile(leftInfo, rightInfo) {
			return true
		}
	}
	leftPhysical, leftOK := resolveMatrixPhysicalPath(left)
	rightPhysical, rightOK := resolveMatrixPhysicalPath(right)
	return leftOK && rightOK && strings.EqualFold(leftPhysical, rightPhysical)
}

// resolveMatrixPhysicalPath resolves the existing prefix of a possibly
// missing path. This is intentionally a read-only identity check: it does not
// create output directories or follow a final path during publication. The
// rooted writers still enforce their no-follow contract when they open roots
// and files.
func resolveMatrixPhysicalPath(path string) (string, bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	absPath = filepath.Clean(absPath)
	missing := make([]string, 0, 4)
	current := absPath
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", false
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), true
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

// validateMatrixReviewDoesNotOverwritePlans refuses a review directory whose
// generated files would atomically replace one of the plan documents that
// produced them.
//
// Comparing only the three output directories is not enough: GenerateMatrixReview
// always publishes fixed filenames into review_dir, so a matrix plan at
// config/manifest.json with review_dir "." is structurally valid yet destroys its
// own input on the first run, and every later run then fails to parse it. The
// comparison is case-folded to match the case-insensitive filesystems this runs
// on, consistent with validateMatrixOutputPaths.
func validateMatrixReviewDoesNotOverwritePlans(plan *MatrixPlan, baseDir string) error {
	planPath := strings.TrimSpace(plan.sourcePath)
	if planPath == "" {
		// A programmatically constructed plan has no on-disk source to protect.
		return nil
	}
	planDir := filepath.Dir(planPath)
	if strings.TrimSpace(baseDir) == "" {
		baseDir = planDir
	}
	reviewDir := plan.Output.ReviewDir
	if strings.TrimSpace(reviewDir) == "" {
		reviewDir = defaultMatrixReviewDir
	}
	resolvedReviewDir := filepath.Clean(resolveMatrixValidationPath(baseDir, reviewDir))

	type matrixPlanInput struct {
		label string
		path  string
	}
	inputs := []matrixPlanInput{{label: "matrix plan", path: filepath.Clean(planPath)}}
	if reference := strings.TrimSpace(plan.BasePlan); reference != "" && !filepath.IsAbs(reference) {
		inputs = append(inputs, matrixPlanInput{
			label: "base plan",
			path:  filepath.Clean(resolveMatrixArtifactPath(planDir, reference)),
		})
	}
	for _, generated := range matrixReviewGeneratedFiles {
		generatedPath := filepath.Clean(filepath.Join(resolvedReviewDir, generated))
		for _, input := range inputs {
			if strings.EqualFold(generatedPath, input.path) || sameMatrixFile(generatedPath, input.path) {
				return fmt.Errorf(
					"output.review_dir would overwrite the %s at %q with the generated %s; use a different review_dir or plan filename",
					input.label, input.path, generated,
				)
			}
		}
	}
	return nil
}

// sameMatrixFile reports whether two paths name the same existing file.
//
// Cleaned strings cannot see through a symlinked ancestor or a platform alias
// such as /tmp versus /private/tmp, and openMatrixOutputRoot resolves the review
// directory's parent physically, so filesystem identity is what actually decides
// whether publishing would land on a plan input. If the generated path does not
// exist yet it cannot already be the plan, so a failed stat is not a collision.
//
// Lstat rather than Stat is deliberate: a symlink sitting at the generated path
// is refused by the rooted, no-follow writer instead of being followed to the
// plan, so comparing the link itself is the accurate test.
func sameMatrixFile(left, right string) bool {
	leftInfo, err := os.Lstat(left)
	if err != nil {
		return false
	}
	rightInfo, err := os.Lstat(right)
	if err != nil {
		return false
	}
	return os.SameFile(leftInfo, rightInfo)
}

// validateMatrixArtifactPathsDoNotOverwritePlans checks every expanded raw
// and framed artifact path before any execution or output-root creation. Plan
// and base-plan files are inputs to the run, so allowing a generated artifact
// to alias either one would turn the first run into a destructive rewrite.
func validateMatrixArtifactPathsDoNotOverwritePlans(plan *MatrixPlan, matrixPath, baseDir string, cells []MatrixCell) error {
	if plan == nil {
		return errors.New("matrix plan is required")
	}
	planPath := strings.TrimSpace(plan.sourcePath)
	if planPath == "" {
		planPath = strings.TrimSpace(matrixPath)
	}
	planDir := strings.TrimSpace(baseDir)
	if planPath != "" {
		if absolute, err := filepath.Abs(planPath); err == nil {
			planPath = filepath.Clean(absolute)
		}
		planDir = filepath.Dir(planPath)
	}
	if planDir == "" {
		planDir = "."
	}

	type matrixPlanInput struct {
		label string
		path  string
	}
	inputs := make([]matrixPlanInput, 0, 2)
	if planPath != "" {
		inputs = append(inputs, matrixPlanInput{label: "matrix plan", path: filepath.Clean(planPath)})
	}
	if reference := strings.TrimSpace(plan.BasePlan); reference != "" && !filepath.IsAbs(reference) {
		inputs = append(inputs, matrixPlanInput{
			label: "base plan",
			path:  filepath.Clean(resolveMatrixArtifactPath(planDir, reference)),
		})
	}
	if len(inputs) == 0 {
		return nil
	}

	for _, cell := range cells {
		artifacts := []struct {
			kind  string
			paths []string
		}{
			{kind: "raw", paths: cell.RawPaths},
			{kind: "framed", paths: cell.FramedPaths},
		}
		for _, artifact := range artifacts {
			for _, path := range artifact.paths {
				resolvedPath := filepath.Clean(resolveMatrixArtifactPath(baseDir, path))
				for _, input := range inputs {
					if sameMatrixPath(resolvedPath, input.path) {
						return fmt.Errorf(
							"output %s artifact %q would overwrite the %s at %q; choose distinct output paths",
							artifact.kind, resolvedPath, input.label, input.path,
						)
					}
				}
			}
		}
	}
	return nil
}

// sameMatrixPath reports whether two paths identify the same existing input,
// or resolve to the same physical path when the destination does not exist
// yet. The latter matters for aliases such as /tmp versus /private/tmp and
// symlinked ancestors: a future artifact must not be allowed to replace a
// plan simply because its final directory entry has not been created.
func sameMatrixPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if strings.EqualFold(left, right) || sameMatrixFile(left, right) {
		return true
	}
	leftPhysical, leftOK := resolveMatrixPhysicalPath(left)
	rightPhysical, rightOK := resolveMatrixPhysicalPath(right)
	return leftOK && rightOK && strings.EqualFold(leftPhysical, rightPhysical)
}

func resolveMatrixValidationPath(baseDir, path string) string {
	if baseDir != "" {
		return resolveMatrixArtifactPath(baseDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
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
		nameKey := strings.ToLower(name)
		if _, exists := seen[nameKey]; exists {
			return fmt.Errorf("base plan screenshot name %q must be unique", name)
		}
		seen[nameKey] = struct{}{}
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
	return expandMatrix(plan, base, "")
}

func expandMatrix(plan *MatrixPlan, base *Plan, outputBaseDir string) ([]MatrixCell, error) {
	if err := validateMatrixPlan(plan, base, outputBaseDir); err != nil {
		return nil, err
	}
	rawDir := plan.Output.RawDir
	if strings.TrimSpace(rawDir) == "" {
		rawDir = defaultMatrixRawDir
	}
	framedDir := plan.Output.FramedDir
	if strings.TrimSpace(framedDir) == "" {
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
	if matrixPlan.Version != 1 {
		return nil, newMatrixValidationError(fmt.Errorf("unsupported matrix plan version %d (expected 1)", matrixPlan.Version))
	}
	if strings.TrimSpace(matrixPlan.BasePlan) == "" {
		return nil, newMatrixValidationError(errors.New("base_plan is required"))
	}
	baseDir := matrixPlanSourceDir(matrixPath, matrixPlan.sourcePath)
	base, err := loadMatrixBasePlan(matrixPath, matrixPlan)
	if err != nil {
		return nil, newMatrixValidationError(fmt.Errorf("load base plan: %w", err))
	}
	if err := validateMatrixPlan(matrixPlan, base, baseDir); err != nil {
		return nil, newMatrixValidationError(err)
	}
	concurrency, attempts, backoff, err := resolveMatrixExecution(matrixPlan.Execution, options)
	if err != nil {
		return nil, newMatrixValidationError(err)
	}
	cells, err := expandMatrix(matrixPlan, base, baseDir)
	if err != nil {
		return nil, newMatrixValidationError(err)
	}
	if err := validateMatrixArtifactPathsDoNotOverwritePlans(matrixPlan, matrixPath, baseDir, cells); err != nil {
		return nil, newMatrixValidationError(err)
	}
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

	planPath := matrixPath
	if strings.TrimSpace(planPath) == "" {
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
	deviceFailures := make(map[string]struct{})
	var preflightErr error
	if deps.CheckDevice == nil && useDefaultDeviceCheck {
		deviceFailures, preflightErr = checkMatrixDevices(ctx, matrixPlan)
	} else if deps.CheckDevice != nil {
		for _, device := range matrixPlan.Devices {
			if err := deps.CheckDevice(ctx, device); err != nil {
				if isMatrixContextTermination(err) {
					preflightErr = err
					break
				}
				deviceFailures[device.ID] = struct{}{}
			}
		}
	}
	if preflightErr != nil {
		markMatrixCellsCanceled(result)
	} else {
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
	}
	runErr := preflightErr
	var outputRoots matrixOutputRoots
	var outputRootErr error
	rawRoot, rawRootErr := openMatrixOutputRoot(rawDir)
	if rawRootErr != nil {
		outputRootErr = fmt.Errorf("create raw output directory: %w", rawRootErr)
	} else {
		defer func() { _ = rawRoot.Close() }()
		outputRoots = matrixOutputRoots{raw: rawRoot, rawPath: rawDir}
		if matrixPlan.Output.Frame.Enabled {
			framedRoot, rootErr := openMatrixOutputRoot(framedDir)
			if rootErr != nil {
				outputRootErr = fmt.Errorf("create framed output directory: %w", rootErr)
			} else {
				defer func() { _ = framedRoot.Close() }()
				outputRoots.framed = framedRoot
				outputRoots.framedPath = framedDir
				outputRoots.hasFramed = true
			}
		}
	}
	if outputRootErr != nil {
		markMatrixOutputFailure(result)
		if runErr == nil {
			runErr = outputRootErr
		} else {
			runErr = errors.Join(runErr, outputRootErr)
		}
	}
	if runErr == nil {
		runErr = executeMatrixCells(ctx, cells, deviceFailures, base, matrixPlan, concurrency, attempts, backoff, deps, outputRoots, result)
	}
	if framedErr := revalidateMatrixFramedPaths(result); framedErr != nil {
		if runErr == nil {
			runErr = framedErr
		} else {
			runErr = errors.Join(runErr, framedErr)
		}
	}
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
	if int64(execution.RetryBackoffMS) > maxMatrixRetryBackoffMS {
		return 0, 0, 0, errors.New("retry backoff milliseconds exceeds maximum duration")
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
		guardKey := normalizeMatrixUDID(cell.UDID)
		if _, ok := guards[guardKey]; !ok {
			guards[guardKey] = &matrixSimulatorGuard{}
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
				cellResult := executeMatrixCell(ctx, cells[index], base, matrixPlan, attempts, backoff, deps, outputRoots, guards[normalizeMatrixUDID(cells[index].UDID)])
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
		mergeMatrixAttemptResult(&result, cell, attemptResult)
		if attemptErr == nil {
			result.Status = MatrixCellSuccess
			result.FailureStage = ""
			result.FailureCode = ""
			result.Error = nil
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
	restoreCtx, cancel := context.WithTimeout(context.Background(), matrixSubprocessTimeout)
	defer cancel()
	return appearance.Restore(restoreCtx, udid, state)
}

type matrixAttemptResult struct {
	RawPaths        []string
	FramedPaths     []string
	FramedArtifacts map[string]matrixArtifactInfo
	Screenshots     []MatrixScreenshotResult
	Steps           []RunStepResult
	FailureStage    string
	FailureCode     string
	Error           string
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
	frameDevice, frameMappingFound := matrixFrameMappingForDevice(matrixPlan.Output.Frame.DeviceByMatrixDevice, cell.Device)
	if !frameMappingFound || strings.TrimSpace(frameDevice) == "" {
		attempt.FailureStage = "framing"
		attempt.FailureCode = "framing_mapping_missing"
		attempt.Error = "framing device mapping could not be resolved"
		return attempt, errors.New("framing device mapping is missing")
	}
	frameDevice = strings.TrimSpace(frameDevice)
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
		artifact, err := promoteMatrixArtifactWithInfo(outputRoots.framed, outputRoots.framedPath, tempFrame, cell.FramedPaths[index])
		if err != nil {
			attempt.FailureStage = "framing"
			attempt.FailureCode = "framed_output_failed"
			attempt.Error = "framed screenshot could not be promoted"
			return attempt, err
		}
		if attempt.FramedArtifacts == nil {
			attempt.FramedArtifacts = make(map[string]matrixArtifactInfo)
		}
		attempt.FramedPaths = append(attempt.FramedPaths, cell.FramedPaths[index])
		attempt.FramedArtifacts[cell.FramedPaths[index]] = artifact
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

// ensureMatrixLaunchStep guarantees the cell's app session is established with
// this cell's locale and content-variant launch arguments before any step that
// observes or drives the app runs.
//
// A plain "does the plan launch anywhere" check is not sufficient: a valid base
// plan may place a screenshot or interaction before a later launch, and those
// early steps would then run against whatever session the simulator already had,
// producing artifacts mislabeled for the requested axes. Only leading
// app-independent steps may precede the launch.
func ensureMatrixLaunchStep(plan *Plan) {
	for _, step := range plan.Steps {
		if matrixStepIsAppIndependent(step.Action) {
			continue
		}
		if step.Action == ActionLaunch {
			return
		}
		break
	}
	plan.Steps = append([]PlanStep{{Action: ActionLaunch}}, plan.Steps...)
}

// matrixStepIsAppIndependent reports whether a step neither observes nor drives
// the app under test, and may therefore precede the matrix launch. Only an
// unconditional delay qualifies; every other action reads or manipulates app
// state. ActionWaitFor is excluded because it polls for on-screen content.
func matrixStepIsAppIndependent(action StepAction) bool {
	return action == ActionWait
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
	_, err = outputRoot.WriteFromPreservingMode(destinationRelative, sourceFile, 0o644)
	return err
}

type matrixArtifactInfo struct {
	identity os.FileInfo
	size     int64
	digest   [sha256.Size]byte
}

func promoteMatrixArtifactWithInfo(outputRoot rootfs.Root, outputRootPath, source, destination string) (matrixArtifactInfo, error) {
	if err := promoteMatrixArtifact(outputRoot, outputRootPath, source, destination); err != nil {
		return matrixArtifactInfo{}, err
	}
	return inspectMatrixArtifact(outputRoot, outputRootPath, destination)
}

func inspectMatrixArtifact(outputRoot rootfs.Root, outputRootPath, path string) (matrixArtifactInfo, error) {
	relative, err := relativeMatrixOutputPath(outputRootPath, path)
	if err != nil {
		return matrixArtifactInfo{}, err
	}
	file, err := outputRoot.OpenFile(relative)
	if err != nil {
		return matrixArtifactInfo{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return matrixArtifactInfo{}, err
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return matrixArtifactInfo{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return matrixArtifactInfo{identity: info, size: size, digest: digest}, nil
}

func mergeMatrixFramedArtifacts(result *MatrixCellResult, attempt matrixAttemptResult) {
	if len(attempt.FramedArtifacts) == 0 {
		return
	}
	if result.framedArtifacts == nil {
		result.framedArtifacts = make(map[string]matrixArtifactInfo, len(attempt.FramedArtifacts))
	}
	for path, artifact := range attempt.FramedArtifacts {
		result.framedArtifacts[path] = artifact
	}
}

func revalidateMatrixFramedPaths(result *MatrixResult) error {
	if result == nil {
		return nil
	}
	hasFramedPaths := false
	for _, cell := range result.Cells {
		if len(cell.FramedPaths) > 0 {
			hasFramedPaths = true
			break
		}
	}
	if !hasFramedPaths {
		return nil
	}
	framedRoot, rootErr := rootfs.New(result.FramedDir)
	if rootErr == nil {
		defer framedRoot.Close()
	}
	invalid := false
	for cellIndex := range result.Cells {
		cell := &result.Cells[cellIndex]
		validPaths := make([]string, 0, len(cell.FramedPaths))
		validSet := make(map[string]struct{}, len(cell.FramedPaths))
		for _, path := range cell.FramedPaths {
			expected, known := cell.framedArtifacts[path]
			if rootErr != nil || !known {
				invalid = true
				continue
			}
			current, err := inspectMatrixArtifact(framedRoot, result.FramedDir, path)
			if err != nil || !matrixArtifactMatches(expected, current) {
				invalid = true
				continue
			}
			validPaths = append(validPaths, path)
			validSet[path] = struct{}{}
		}
		if len(validPaths) != len(cell.FramedPaths) {
			cell.FramedPaths = validPaths
			if cell.Status == MatrixCellSuccess {
				cell.Status = MatrixCellFailed
				cell.FailureStage = "framing"
				cell.FailureCode = "framed_output_unavailable"
				cell.Error = newMatrixCellError(cell.FailureStage, cell.FailureCode, "framed screenshot became unavailable")
			}
		}
		for screenshotIndex := range cell.Screenshots {
			path := cell.Screenshots[screenshotIndex].FramedPath
			if path == "" {
				continue
			}
			if _, ok := validSet[path]; !ok {
				cell.Screenshots[screenshotIndex].FramedPath = ""
			}
		}
	}
	if invalid {
		return errors.New("one or more framed screenshots became unavailable")
	}
	return nil
}

func matrixArtifactMatches(expected, current matrixArtifactInfo) bool {
	if expected.identity == nil || current.identity == nil {
		return false
	}
	return os.SameFile(expected.identity, current.identity) && expected.size == current.size && expected.digest == current.digest
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

func markMatrixCellsCanceled(result *MatrixResult) {
	if result == nil {
		return
	}
	for i := range result.Cells {
		if result.Cells[i].Status == MatrixCellSuccess {
			continue
		}
		result.Cells[i].Status = MatrixCellCanceled
		result.Cells[i].FailureStage = "execution"
		result.Cells[i].FailureCode = "canceled"
		result.Cells[i].Error = newMatrixCellError("execution", "canceled", "cell canceled")
		setMatrixScreenshotStatuses(&result.Cells[i])
	}
}

func markMatrixOutputFailure(result *MatrixResult) {
	if result == nil {
		return
	}
	for i := range result.Cells {
		// Preserve a more specific preflight or cancellation result already known
		// for this cell; output-root setup is an additional run-level failure.
		if result.Cells[i].FailureCode != "" {
			continue
		}
		result.Cells[i].Status = MatrixCellFailed
		result.Cells[i].FailureStage = "execution"
		result.Cells[i].FailureCode = "output_root_failed"
		result.Cells[i].Error = newMatrixCellError("execution", "output_root_failed", "matrix output root could not be prepared")
		setMatrixScreenshotStatuses(&result.Cells[i])
	}
}

func setMatrixScreenshotStatuses(result *MatrixCellResult) {
	for i := range result.Screenshots {
		switch result.Status {
		case MatrixCellSuccess:
			result.Screenshots[i].Status = MatrixCellSuccess
		case MatrixCellCanceled:
			if result.Screenshots[i].RawPath == "" {
				result.Screenshots[i].Status = MatrixCellCanceled
			} else {
				result.Screenshots[i].Status = MatrixCellSuccess
			}
		default:
			if result.Screenshots[i].RawPath == "" {
				result.Screenshots[i].Status = MatrixCellFailed
			} else {
				result.Screenshots[i].Status = MatrixCellSuccess
			}
		}
	}
}

func mergeMatrixAttemptResult(result *MatrixCellResult, cell MatrixCell, attempt matrixAttemptResult) {
	if result == nil {
		return
	}
	result.RawPaths = mergeMatrixPaths(result.RawPaths, attempt.RawPaths, cell.RawPaths)
	result.FramedPaths = mergeMatrixPaths(result.FramedPaths, attempt.FramedPaths, cell.FramedPaths)
	mergeMatrixFramedArtifacts(result, attempt)
	mergeMatrixScreenshots(result, cell, attempt.Screenshots)
}

func mergeMatrixPaths(existing, incoming, canonical []string) []string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	merged := make([]string, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	appendUnique := func(paths []string) {
		for _, path := range paths {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			merged = append(merged, path)
		}
	}
	appendUnique(existing)
	appendUnique(incoming)
	if len(canonical) == 0 {
		return merged
	}
	ordered := make([]string, 0, len(merged))
	for _, path := range canonical {
		if _, ok := seen[path]; !ok {
			continue
		}
		ordered = append(ordered, path)
		delete(seen, path)
	}
	for _, path := range merged {
		if _, ok := seen[path]; !ok {
			continue
		}
		ordered = append(ordered, path)
		delete(seen, path)
	}
	return ordered
}

func mergeMatrixScreenshots(result *MatrixCellResult, cell MatrixCell, incoming []MatrixScreenshotResult) {
	if len(result.Screenshots) == 0 && len(cell.RawPaths) == 0 && len(incoming) == 0 {
		return
	}
	existing := make(map[string]MatrixScreenshotResult, len(result.Screenshots))
	for _, screenshot := range result.Screenshots {
		key := strings.ToLower(strings.TrimSpace(screenshot.Name))
		if key == "" {
			continue
		}
		existing[key] = screenshot
	}
	ordered := make([]MatrixScreenshotResult, 0, len(cell.RawPaths)+len(incoming))
	seen := make(map[string]struct{}, len(cell.RawPaths)+len(incoming))
	for _, rawPath := range cell.RawPaths {
		name := strings.TrimSuffix(filepath.Base(rawPath), filepath.Ext(rawPath))
		key := strings.ToLower(strings.TrimSpace(name))
		screenshot, ok := existing[key]
		if !ok {
			screenshot = MatrixScreenshotResult{Name: name, Status: MatrixCellCanceled}
		}
		ordered = append(ordered, screenshot)
		seen[key] = struct{}{}
	}
	for _, screenshot := range result.Screenshots {
		key := strings.ToLower(strings.TrimSpace(screenshot.Name))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		ordered = append(ordered, screenshot)
		seen[key] = struct{}{}
	}
	for _, screenshot := range incoming {
		key := strings.ToLower(strings.TrimSpace(screenshot.Name))
		if key == "" {
			continue
		}
		index := -1
		for candidate := range ordered {
			if strings.EqualFold(strings.TrimSpace(ordered[candidate].Name), strings.TrimSpace(screenshot.Name)) {
				index = candidate
				break
			}
		}
		if index < 0 {
			ordered = append(ordered, screenshot)
			continue
		}
		current := &ordered[index]
		if screenshot.Name != "" {
			current.Name = screenshot.Name
		}
		if screenshot.Status != "" {
			current.Status = screenshot.Status
		}
		if screenshot.RawPath != "" {
			current.RawPath = screenshot.RawPath
		}
		if screenshot.FramedPath != "" {
			current.FramedPath = screenshot.FramedPath
		}
		if screenshot.Width > 0 {
			current.Width = screenshot.Width
		}
		if screenshot.Height > 0 {
			current.Height = screenshot.Height
		}
	}
	result.Screenshots = ordered
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
	if strings.TrimSpace(path) == "" {
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
	path := matrixPath
	if strings.TrimSpace(path) == "" {
		path = sourcePath
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
	// Device-family compatibility is checked after simulator inventory is read;
	// a matrix ID is only a logical label and must not determine the family.
	if _, err := ParseFrameDevice(frame); err != nil {
		return fmt.Errorf("device %q: %w", matrixDevice, err)
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

type matrixSimulatorDevice struct {
	UDID                 string `json:"udid"`
	State                string `json:"state"`
	IsAvailable          bool   `json:"isAvailable"`
	Name                 string `json:"name"`
	DeviceTypeIdentifier string `json:"deviceTypeIdentifier"`
}

func readMatrixSimulatorInventory(ctx context.Context) ([]matrixSimulatorDevice, error) {
	return readMatrixSimulatorInventoryWithTimeout(ctx, matrixSubprocessTimeout)
}

func readMatrixSimulatorInventoryWithTimeout(ctx context.Context, timeout time.Duration) ([]matrixSimulatorDevice, error) {
	inventoryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(inventoryCtx, "xcrun", "simctl", "list", "devices", "--json")
	var output cappedMatrixBuffer
	output.limit = maxMatrixInventoryBytes
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	if parentErr := ctx.Err(); parentErr != nil {
		return nil, parentErr
	}
	if errors.Is(inventoryCtx.Err(), context.DeadlineExceeded) {
		return nil, ErrMatrixInventoryTimeout
	}
	if output.exceeded {
		return nil, errors.New("simulator inventory exceeded the output size limit")
	}
	if err != nil {
		return nil, errors.New("simulator inventory could not be read")
	}
	out := output.Bytes()
	var inventory struct {
		Devices map[string][]matrixSimulatorDevice `json:"devices"`
	}
	if err := json.Unmarshal(out, &inventory); err != nil {
		return nil, errors.New("simulator inventory was invalid")
	}
	devices := make([]matrixSimulatorDevice, 0)
	for _, runtimeDevices := range inventory.Devices {
		devices = append(devices, runtimeDevices...)
	}
	return devices, nil
}

func checkMatrixDevice(ctx context.Context, device MatrixDevice) error {
	devices, err := readMatrixSimulatorInventory(ctx)
	if err != nil {
		return err
	}
	wanted := normalizeMatrixUDID(device.UDID)
	for _, candidate := range devices {
		if normalizeMatrixUDID(candidate.UDID) != wanted {
			continue
		}
		return validateMatrixSimulatorDevice(candidate)
	}
	return errors.New("simulator was not found")
}

func checkMatrixDevices(ctx context.Context, plan *MatrixPlan) (map[string]struct{}, error) {
	failures := make(map[string]struct{})
	devices, inventoryErr := readMatrixSimulatorInventory(ctx)
	if inventoryErr != nil && isMatrixContextTermination(inventoryErr) {
		return nil, inventoryErr
	}
	for _, device := range plan.Devices {
		if inventoryErr != nil {
			failures[device.ID] = struct{}{}
			continue
		}
		candidate, found := findMatrixSimulatorDevice(devices, device.UDID)
		if !found || validateMatrixSimulatorDevice(candidate) != nil {
			failures[device.ID] = struct{}{}
			continue
		}
		if plan.Output.Frame.Enabled {
			frame, _ := matrixFrameMappingForDevice(plan.Output.Frame.DeviceByMatrixDevice, device.ID)
			if validateMatrixFrameMappingForSimulator(device.ID, frame, candidate) != nil {
				failures[device.ID] = struct{}{}
			}
		}
	}
	return failures, nil
}

func isMatrixContextTermination(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func findMatrixSimulatorDevice(devices []matrixSimulatorDevice, udid string) (matrixSimulatorDevice, bool) {
	wanted := normalizeMatrixUDID(udid)
	for _, device := range devices {
		if normalizeMatrixUDID(device.UDID) == wanted {
			return device, true
		}
	}
	return matrixSimulatorDevice{}, false
}

func validateMatrixSimulatorDevice(device matrixSimulatorDevice) error {
	if !device.IsAvailable {
		return errors.New("simulator is unavailable")
	}
	if !strings.EqualFold(strings.TrimSpace(device.State), "booted") {
		return errors.New("simulator is not booted")
	}
	return nil
}

func validateMatrixFrameMappingForSimulator(matrixDevice, frame string, simulator matrixSimulatorDevice) error {
	parsed, err := ParseFrameDevice(frame)
	if err != nil {
		return fmt.Errorf("device %q: %w", matrixDevice, err)
	}
	actualFamily := matrixSimulatorFamily(simulator)
	if actualFamily == "unknown" {
		return fmt.Errorf("device %q simulator family is unknown", matrixDevice)
	}
	if actualFamily == "ipad" {
		return fmt.Errorf("device %q has no supported same-device frame mapping", matrixDevice)
	}
	if actualFamily != frameDeviceFamily(parsed) {
		return fmt.Errorf("device %q frame family does not match simulator model", matrixDevice)
	}
	return nil
}

func matrixSimulatorFamily(device matrixSimulatorDevice) string {
	return matrixDeviceFamily(device.Name + " " + device.DeviceTypeIdentifier)
}

func normalizeMatrixUDID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeMatrixDeviceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func matrixFrameMappingForDevice(mapping map[string]string, deviceID string) (string, bool) {
	wanted := normalizeMatrixDeviceID(deviceID)
	if wanted == "" {
		return "", false
	}
	var value string
	found := false
	for candidate, frame := range mapping {
		if normalizeMatrixDeviceID(candidate) != wanted {
			continue
		}
		if found {
			return "", false
		}
		found = true
		value = frame
	}
	return value, found
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
	out, err := runMatrixAppearanceOutput(ctx, "xcrun", "simctl", "ui", udid, "appearance")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "dark":
		return "dark", nil
	case "light":
		return "light", nil
	default:
		return "", errors.New("simulator appearance state was invalid")
	}
}

func (simctlMatrixAppearance) Set(ctx context.Context, udid, appearance string) error {
	appearance = strings.ToLower(strings.TrimSpace(appearance))
	if appearance != "light" && appearance != "dark" {
		return errors.New("simulator appearance must be light or dark")
	}
	return runMatrixAppearance(ctx, "xcrun", "simctl", "ui", udid, "appearance", appearance)
}

func (simctlMatrixAppearance) Restore(ctx context.Context, udid, state string) error {
	state = strings.ToLower(strings.TrimSpace(state))
	if state != "light" && state != "dark" {
		return errors.New("simulator appearance state must be light or dark")
	}
	return runMatrixAppearance(ctx, "xcrun", "simctl", "ui", udid, "appearance", state)
}

func runMatrixAppearance(ctx context.Context, name string, args ...string) error {
	_, err := runMatrixAppearanceOutput(ctx, name, args...)
	return err
}

func runMatrixAppearanceOutput(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdout := &cappedMatrixBuffer{limit: maxMatrixAppearanceBytes}
	stderr := &cappedMatrixBuffer{limit: maxMatrixAppearanceBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return "", errors.New("simulator appearance command exceeded the output size limit")
	}
	if err != nil {
		return "", fmt.Errorf("%s failed", name)
	}
	return string(stdout.Bytes()), nil
}
