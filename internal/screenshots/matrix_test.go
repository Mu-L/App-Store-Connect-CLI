package screenshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestLoadMatrixPlanAndExpand_UsesStableAxisOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.jsonc")
	writeMatrixTestFile(t, basePath, `{
  "version": 1,
  "app": {"bundle_id": "com.example.app"},
  "steps": [{"action": "launch"}, {"action": "screenshot", "name": "home"}]
}`)
	writeMatrixTestFile(t, matrixPath, `{
  // Matrix plans accept JSONC comments.
  "version": 1,
  "base_plan": "base.json",
  "devices": [
    {"id": "phone", "udid": "PHONE-UDID"},
    {"id": "tablet", "udid": "TABLET-UDID"}
  ],
  "locales": ["en-US", "ja-JP"],
  "appearances": ["light", "dark"],
  "content_variants": [{"id": "default"}, {"id": "empty", "launch_arguments": ["--fixture", "empty"]}],
  "execution": {"max_concurrency": 2, "max_attempts": 2, "retry_backoff_ms": 1},
  "output": {"raw_dir": "raw", "framed_dir": "framed", "review_dir": "review", "frame": {"enabled": false}}
}`)

	matrix, err := LoadMatrixPlan(matrixPath)
	if err != nil {
		t.Fatalf("LoadMatrixPlan() error = %v", err)
	}
	base, err := LoadPlan(filepath.Join(dir, matrix.BasePlan))
	if err != nil {
		t.Fatalf("LoadPlan() error = %v", err)
	}
	cells, err := ExpandMatrix(matrix, base)
	if err != nil {
		t.Fatalf("ExpandMatrix() error = %v", err)
	}
	if len(cells) != 16 {
		t.Fatalf("got %d cells, want 16", len(cells))
	}
	got := make([]string, 0, len(cells))
	for _, cell := range cells {
		got = append(got, cell.ID)
	}
	want := []string{
		"phone|en-US|light|default", "phone|en-US|light|empty",
		"phone|en-US|dark|default", "phone|en-US|dark|empty",
		"phone|ja-JP|light|default", "phone|ja-JP|light|empty",
		"phone|ja-JP|dark|default", "phone|ja-JP|dark|empty",
		"tablet|en-US|light|default", "tablet|en-US|light|empty",
		"tablet|en-US|dark|default", "tablet|en-US|dark|empty",
		"tablet|ja-JP|light|default", "tablet|ja-JP|light|empty",
		"tablet|ja-JP|dark|default", "tablet|ja-JP|dark|empty",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cell order = %v, want %v", got, want)
	}
	if len(cells[1].RawPaths) != 1 || cells[1].RawPaths[0] != filepath.Join("raw", "en-US", "phone", "light", "empty", "home.png") {
		t.Fatalf("raw paths = %q", cells[1].RawPaths)
	}
	if got := cells[1].LaunchArguments; !reflect.DeepEqual(got, []string{"-AppleLanguages", "(en)", "-AppleLocale", "en_US", "--fixture", "empty"}) {
		t.Fatalf("launch arguments = %v", got)
	}
}

func TestLoadMatrixPlan_RejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matrix.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxMatrixPlanBytes+1)), 0o644); err != nil {
		t.Fatalf("write oversized matrix plan: %v", err)
	}
	_, err := LoadMatrixPlan(path)
	if err == nil || !errors.Is(err, ErrMatrixPlanRead) || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("LoadMatrixPlan() error = %v, want bounded-size read error", err)
	}
}

func TestLoadMatrixPlan_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "matrix.json")
	if err := os.WriteFile(target, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatalf("write target matrix plan: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create matrix plan symlink: %v", err)
	}
	_, err := LoadMatrixPlan(link)
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("LoadMatrixPlan() error = %v, want symlink rejection", err)
	}
}

func TestLoadMatrixPlanDoesNotDefaultMissingVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matrix.json")
	writeMatrixTestFile(t, path, `{"devices":[]}`)
	plan, err := LoadMatrixPlan(path)
	if err != nil {
		t.Fatalf("LoadMatrixPlan() error = %v", err)
	}
	if plan.Version != 0 {
		t.Fatalf("matrix plan version = %d, want missing version to remain invalid", plan.Version)
	}
}

func TestLoadMatrixPlanRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matrix.json")
	writeMatrixTestFile(t, path, `{"version":1,"unknown_axis":true}`)
	_, err := LoadMatrixPlan(path)
	if err == nil || !errors.Is(err, ErrMatrixPlanParseJSON) || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadMatrixPlan() error = %v, want unknown-field parse error", err)
	}
}

func TestLoadMatrixPlanRejectsDuplicateAndMisCasedFields(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "duplicate", data: `{"version":1,"version":1}`, want: "duplicate fields"},
		{name: "mis-cased", data: `{"Version":1}`, want: "exact spelling"},
		{name: "nested mis-cased", data: `{"version":1,"execution":{"Max_Attempts":2}}`, want: "exact spelling"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "matrix.json")
			writeMatrixTestFile(t, path, tc.data)
			_, err := LoadMatrixPlan(path)
			if err == nil || !errors.Is(err, ErrMatrixPlanParseJSON) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadMatrixPlan() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunMatrixRejectsMissingVersionBeforeLoadingBasePlan(t *testing.T) {
	plan := &MatrixPlan{BasePlan: "missing.json", sourcePath: filepath.Join(t.TempDir(), "matrix.json")}
	_, err := RunMatrixWithDependencies(context.Background(), plan.sourcePath, plan, MatrixOptions{}, MatrixDependencies{})
	var validationErr *MatrixValidationError
	if err == nil || !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "expected 1") {
		t.Fatalf("RunMatrixWithDependencies() error = %v, want matrix version validation", err)
	}
}

func TestLoadMatrixBasePlanIsRootedBoundedAndNoFollow(t *testing.T) {
	t.Parallel()

	testPlan := `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`
	tests := []struct {
		name      string
		basePlan  string
		setup     func(t *testing.T, dir string) string
		wantError string
	}{
		{
			name:      "absolute reference",
			basePlan:  "",
			setup:     func(t *testing.T, dir string) string { return filepath.Join(dir, "outside.json") },
			wantError: "must be relative",
		},
		{
			name:      "parent traversal",
			basePlan:  "../outside.json",
			setup:     func(*testing.T, string) string { return "" },
			wantError: "must stay below",
		},
		{
			name:     "symlink",
			basePlan: "base.json",
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "target.json")
				writeMatrixTestFile(t, target, testPlan)
				if err := os.Symlink(target, filepath.Join(dir, "base.json")); err != nil {
					t.Fatalf("create base plan symlink: %v", err)
				}
				return target
			},
			wantError: "symlink",
		},
		{
			name:     "oversized",
			basePlan: "base.json",
			setup: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "base.json")
				writeMatrixTestFile(t, path, strings.Repeat(" ", maxMatrixPlanBytes+1))
				return path
			},
			wantError: "size limit",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			outside := tc.setup(t, dir)
			basePlan := tc.basePlan
			if basePlan == "" {
				basePlan = outside
			}
			matrixPath := filepath.Join(dir, "matrix.json")
			plan := &MatrixPlan{BasePlan: basePlan, sourcePath: matrixPath}
			_, err := loadMatrixBasePlan(matrixPath, plan)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantError)) {
				t.Fatalf("loadMatrixBasePlan() error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestLoadMatrixBasePlanPreservesLiteralFilename(t *testing.T) {
	dir := t.TempDir()
	baseName := "base plan .json "
	basePath := filepath.Join(dir, baseName)
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	matrixPath := filepath.Join(dir, "matrix.json")
	plan := &MatrixPlan{BasePlan: baseName, sourcePath: matrixPath}
	loaded, err := loadMatrixBasePlan(matrixPath, plan)
	if err != nil {
		t.Fatalf("loadMatrixBasePlan() error = %v", err)
	}
	if loaded.App.BundleID != "com.example.app" {
		t.Fatalf("loaded base plan = %+v", loaded)
	}
}

func TestLoadMatrixBasePlanRetainsVersionZeroCompatibility(t *testing.T) {
	dir := t.TempDir()
	baseName := "base.json"
	writeMatrixTestFile(t, filepath.Join(dir, baseName), `{"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	plan := &MatrixPlan{BasePlan: baseName, sourcePath: filepath.Join(dir, "matrix.json")}
	loaded, err := loadMatrixBasePlan(plan.sourcePath, plan)
	if err != nil {
		t.Fatalf("loadMatrixBasePlan() error = %v", err)
	}
	if loaded.Version != 1 {
		t.Fatalf("loaded base plan version = %d, want compatibility default 1", loaded.Version)
	}
}

func TestExpandMatrixPreservesLiteralOutputDirectorySpelling(t *testing.T) {
	base := &Plan{
		Version: 1,
		App:     PlanApp{BundleID: "com.example.app"},
		Steps:   []PlanStep{{Action: ActionScreenshot, Name: stringPtr("home")}},
	}
	plan := &MatrixPlan{
		Version:         1,
		Devices:         []MatrixDevice{{ID: "phone", UDID: "SIM-UDID"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
		Output:          MatrixOutput{RawDir: "raw screenshots ", FramedDir: "framed screenshots ", ReviewDir: "review screenshots "},
	}
	cells, err := ExpandMatrix(plan, base)
	if err != nil {
		t.Fatalf("ExpandMatrix() error = %v", err)
	}
	if got, want := cells[0].RawDir, filepath.Join("raw screenshots ", "en-US", "phone", "light", "default"); got != want {
		t.Fatalf("raw directory = %q, want %q", got, want)
	}
}

func TestRunMatrixRejectsOutputAliasesResolvedFromMatrixPlanDirectory(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	plan := &MatrixPlan{
		Version:         1,
		BasePlan:        "base.json",
		Devices:         []MatrixDevice{{ID: "phone", UDID: "SIM-UDID"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
		Output: MatrixOutput{
			RawDir:    "raw",
			FramedDir: filepath.Join(dir, "raw"),
			ReviewDir: "review",
		},
		sourcePath: matrixPath,
	}
	_, err := RunMatrixWithDependencies(context.Background(), matrixPath, plan, MatrixOptions{}, MatrixDependencies{})
	var validationErr *MatrixValidationError
	if err == nil || !errors.As(err, &validationErr) || !strings.Contains(err.Error(), "must be different directories") {
		t.Fatalf("RunMatrixWithDependencies() error = %v, want plan-directory output collision", err)
	}
}

func TestRunMatrixDoesNotComparePlanRelativeOutputsAgainstWorkingDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	plan := &MatrixPlan{
		Version:         1,
		BasePlan:        "base.json",
		Devices:         []MatrixDevice{{ID: "phone", UDID: "SIM-UDID"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
		Output: MatrixOutput{
			RawDir:    "raw",
			FramedDir: filepath.Join(cwd, "raw"),
			ReviewDir: "review",
		},
		sourcePath: matrixPath,
	}
	runPlan := func(_ context.Context, screenshotPlan *Plan) (*RunResult, error) {
		writeMatrixPNG(t, filepath.Join(screenshotPlan.App.OutputDir, "home.png"))
		return &RunResult{Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "ok"}}}, nil
	}
	_, err = RunMatrixWithDependencies(context.Background(), matrixPath, plan, MatrixOptions{}, MatrixDependencies{
		RunPlan: runPlan, Appearance: &matrixTestAppearance{},
	})
	if err != nil {
		t.Fatalf("RunMatrixWithDependencies() error = %v, want distinct plan-relative outputs", err)
	}
}

func TestValidateMatrixPlan_RejectsUnsafeAndConflictingValues(t *testing.T) {
	t.Parallel()

	base := &Plan{
		Version: 1,
		App:     PlanApp{BundleID: "com.example.app"},
		Steps:   []PlanStep{{Action: ActionScreenshot, Name: stringPtr("home")}},
	}
	cases := []struct {
		name string
		plan MatrixPlan
		want string
	}{
		{
			name: "path device id",
			plan: MatrixPlan{Version: 1, Devices: []MatrixDevice{{ID: "../phone", UDID: "u"}}, Locales: []string{"en-US"}, Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default"}}},
			want: "device id",
		},
		{
			name: "duplicate udid",
			plan: MatrixPlan{Version: 1, Devices: []MatrixDevice{{ID: "one", UDID: "same"}, {ID: "two", UDID: " SAME "}}, Locales: []string{"en-US"}, Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default"}}},
			want: "unique",
		},
		{
			name: "case-insensitive device id",
			plan: MatrixPlan{Version: 1, Devices: []MatrixDevice{{ID: "Phone", UDID: "one"}, {ID: "phone", UDID: "two"}}, Locales: []string{"en-US"}, Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default"}}},
			want: "unique",
		},
		{
			name: "content locale override",
			plan: MatrixPlan{Version: 1, Devices: []MatrixDevice{{ID: "phone", UDID: "u"}}, Locales: []string{"en-US"}, Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default", LaunchArguments: []string{"-AppleLocale", "fr_FR"}}}},
			want: "AppleLocale",
		},
		{
			name: "too many cells",
			plan: MatrixPlan{Version: 1, Devices: makeMatrixDevices(17), Locales: makeStrings(16, "en-US"), Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default"}}},
			want: "256",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMatrixPlan(&tc.plan, base)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateMatrixPlan() error = %v, want substring %q", err, tc.want)
			}
		})
	}
	caseInsensitiveScreenshots := *base
	caseInsensitiveScreenshots.Steps = []PlanStep{
		{Action: ActionScreenshot, Name: stringPtr("Home")},
		{Action: ActionScreenshot, Name: stringPtr("home")},
	}
	if err := ValidateMatrixPlan(&MatrixPlan{
		Version:         1,
		Devices:         []MatrixDevice{{ID: "phone", UDID: "u"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
	}, &caseInsensitiveScreenshots); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("ValidateMatrixPlan() error = %v, want case-insensitive screenshot-name collision", err)
	}
}

func TestBuildLocaleLaunchArguments_NormalizesLocale(t *testing.T) {
	args, err := BuildLocaleLaunchArguments("pt-BR")
	if err != nil {
		t.Fatalf("BuildLocaleLaunchArguments() error = %v", err)
	}
	want := []string{"-AppleLanguages", "(pt)", "-AppleLocale", "pt_BR"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestValidateMatrixPlanDefersFrameFamilyToSimulator(t *testing.T) {
	base := &Plan{Version: 1, App: PlanApp{BundleID: "com.example.app"}, Steps: []PlanStep{{Action: ActionScreenshot, Name: stringPtr("home")}}}
	plan := &MatrixPlan{
		Version:         1,
		Devices:         []MatrixDevice{{ID: "ipad-pro-13", UDID: "IPAD-UDID"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
		Output:          MatrixOutput{Frame: MatrixFrame{Enabled: true, DeviceByMatrixDevice: map[string]string{"ipad-pro-13": "iphone-17-pro"}}},
	}
	if err := ValidateMatrixPlan(plan, base); err != nil {
		t.Fatalf("ValidateMatrixPlan() error = %v, want syntax-only frame validation", err)
	}
}

func TestValidateMatrixFrameMappingForSimulatorUsesActualFamily(t *testing.T) {
	tests := []struct {
		name      string
		matrixID  string
		simulator matrixSimulatorDevice
		wantError bool
	}{
		{
			name:     "iPhone actual and logical phone",
			matrixID: "sim-a",
			simulator: matrixSimulatorDevice{
				Name:                 "iPhone 16 Pro",
				DeviceTypeIdentifier: "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro",
			},
		},
		{
			name:     "iPhone actual despite iPad logical label",
			matrixID: "ipad-demo",
			simulator: matrixSimulatorDevice{
				Name:                 "iPhone 16 Pro",
				DeviceTypeIdentifier: "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro",
			},
		},
		{
			name:     "iPad actual",
			matrixID: "sim-a",
			simulator: matrixSimulatorDevice{
				Name:                 "iPad Pro (13-inch)",
				DeviceTypeIdentifier: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M4",
			},
			wantError: true,
		},
		{
			name:     "unknown actual type",
			matrixID: "sim-a",
			simulator: matrixSimulatorDevice{
				Name:                 "Test Device",
				DeviceTypeIdentifier: "com.apple.CoreSimulator.SimDeviceType.Unknown",
			},
			wantError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMatrixFrameMappingForSimulator(tc.matrixID, "iphone-17-pro", tc.simulator)
			if (err != nil) != tc.wantError {
				t.Fatalf("validateMatrixFrameMappingForSimulator() error = %v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestCheckMatrixDeviceRejectsOversizedInventory(t *testing.T) {
	binDir := t.TempDir()
	xcrunPath := filepath.Join(binDir, "xcrun")
	script := "#!/bin/sh\nexec /usr/bin/head -c 4194305 /dev/zero\n"
	if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	err := checkMatrixDevice(context.Background(), MatrixDevice{ID: "phone", UDID: "SIM"})
	if err == nil || !strings.Contains(err.Error(), "exceeded the output size limit") {
		t.Fatalf("checkMatrixDevice() error = %v, want bounded-output error", err)
	}
}

func TestCheckMatrixDevicesUsesSimulatorModelForFrameFamily(t *testing.T) {
	binDir := t.TempDir()
	xcrunPath := filepath.Join(binDir, "xcrun")
	script := `#!/bin/sh
set -eu
printf '%s\n' '{"devices":{"runtime":[{"udid":"SIM-UDID","state":"Booted","isAvailable":true,"name":"iPad Pro (13-inch)","deviceTypeIdentifier":"com.apple.CoreSimulator.SimDeviceType.iPad-Pro"}]}}'
`
	if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	plan := &MatrixPlan{
		Devices: []MatrixDevice{{ID: "iphone-demo", UDID: "SIM-UDID"}},
		Output: MatrixOutput{
			Frame: MatrixFrame{Enabled: true, DeviceByMatrixDevice: map[string]string{"iphone-demo": "iphone-17-pro"}},
		},
	}
	failures, err := checkMatrixDevices(context.Background(), plan)
	if err != nil {
		t.Fatalf("checkMatrixDevices() error = %v", err)
	}
	if _, failed := failures["iphone-demo"]; !failed {
		t.Fatalf("checkMatrixDevices() failures = %v, want model/frame mismatch", failures)
	}
}

func TestReadMatrixSimulatorInventoryUsesBoundedTimeout(t *testing.T) {
	binDir := t.TempDir()
	xcrunPath := filepath.Join(binDir, "xcrun")
	script := "#!/bin/sh\nwhile :; do :; done\n"
	if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	parentCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err := readMatrixSimulatorInventoryWithTimeout(parentCtx, 50*time.Millisecond)
	if !errors.Is(err, ErrMatrixInventoryTimeout) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("readMatrixSimulatorInventoryWithTimeout() error = %v, want non-context inventory timeout", err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("inventory command took %s, want derived timeout before caller deadline", elapsed)
	}
}

func TestReadMatrixSimulatorInventoryWithTimeoutPreservesParentContext(t *testing.T) {
	tests := []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		wantError  error
	}{
		{
			name: "caller canceled",
			newContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			wantError: context.Canceled,
		},
		{
			name: "caller deadline exceeded",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 50*time.Millisecond)
			},
			wantError: context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			binDir := t.TempDir()
			xcrunPath := filepath.Join(binDir, "xcrun")
			script := "#!/bin/sh\nwhile :; do :; done\n"
			if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
				t.Fatalf("write xcrun fixture: %v", err)
			}
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			ctx, cancel := tc.newContext()
			defer cancel()
			_, err := readMatrixSimulatorInventoryWithTimeout(ctx, time.Second)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("readMatrixSimulatorInventoryWithTimeout() error = %v, want %v", err, tc.wantError)
			}
			if errors.Is(err, ErrMatrixInventoryTimeout) {
				t.Fatalf("readMatrixSimulatorInventoryWithTimeout() error = %v, want parent context error", err)
			}
		})
	}
}

func TestSimctlMatrixAppearanceUsesSupportedUIContractAndRestores(t *testing.T) {
	binDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "xcrun.log")
	xcrunPath := filepath.Join(binDir, "xcrun")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$XCRUN_LOG"
if [ "$#" -eq 4 ] && [ "$1" = "simctl" ] && [ "$2" = "ui" ] && [ "$4" = "appearance" ]; then
  printf '%s\n' dark
fi
`
	if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XCRUN_LOG", logPath)

	appearance := simctlMatrixAppearance{}
	state, err := appearance.Snapshot(context.Background(), "SIM-UDID")
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if state != "dark" {
		t.Fatalf("Snapshot() state = %q, want dark", state)
	}
	if err := appearance.Set(context.Background(), "SIM-UDID", "light"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := appearance.Restore(context.Background(), "SIM-UDID", "dark"); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read xcrun log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{
		"simctl ui SIM-UDID appearance",
		"simctl ui SIM-UDID appearance light",
		"simctl ui SIM-UDID appearance dark",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("xcrun argv = %v, want %v", got, want)
	}
	if strings.Contains(string(data), "spawn") || strings.Contains(string(data), "defaults") || strings.Contains(string(data), "AppleInterfaceStyle") {
		t.Fatalf("appearance used unsupported command: %s", data)
	}
}

func TestSimctlMatrixAppearanceBoundsCapturedOutput(t *testing.T) {
	binDir := t.TempDir()
	xcrunPath := filepath.Join(binDir, "xcrun")
	script := "#!/bin/sh\nexec /usr/bin/head -c " + fmt.Sprint(maxMatrixAppearanceBytes+1) + " /dev/zero\n"
	if err := os.WriteFile(xcrunPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write xcrun fixture: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := (simctlMatrixAppearance{}).Snapshot(context.Background(), "SIM-UDID")
	if err == nil || !strings.Contains(err.Error(), "output size limit") {
		t.Fatalf("Snapshot() error = %v, want bounded-output error", err)
	}
}

func TestMatrixReviewSanitizerClearsSuccessfulCellFailureMetadata(t *testing.T) {
	dir := t.TempDir()
	result := &MatrixResult{Cells: []MatrixCellResult{{
		ID: "phone|en-US|light|default", Status: MatrixCellSuccess,
		FailureStage: "execution", FailureCode: "stale_failure",
		Error: &MatrixCellError{Stage: "execution", Code: "stale_failure", Message: "capture failed"},
	}}}
	if _, err := GenerateMatrixReview(context.Background(), MatrixReviewRequest{Result: result, OutputDir: dir}); err != nil {
		t.Fatalf("GenerateMatrixReview() error = %v", err)
	}
	manifest, err := LoadMatrixReviewManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("LoadMatrixReviewManifest() error = %v", err)
	}
	cell := manifest.Cells[0]
	if cell.FailureStage != "" || cell.FailureCode != "" || cell.Error != nil {
		t.Fatalf("successful cell retained failure metadata: %+v", cell)
	}
}

func TestRenderMatrixReviewURLEncodesArtifactPaths(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw screenshots", "home image#1?.png")
	result := &MatrixResult{RawDir: filepath.Join(dir, "raw screenshots"), Cells: []MatrixCellResult{{
		ID: "phone|en-US|light|default", Status: MatrixCellSuccess,
		RawPaths: []string{rawPath},
	}}}
	if _, err := GenerateMatrixReview(context.Background(), MatrixReviewRequest{Result: result, OutputDir: dir}); err != nil {
		t.Fatalf("GenerateMatrixReview() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	html := string(data)
	for _, want := range []string{`href="raw%20screenshots/home%20image%231%3F.png"`, `src="raw%20screenshots/home%20image%231%3F.png"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing URL-encoded artifact path %q: %s", want, html)
		}
	}
	if strings.Contains(html, `href="raw screenshots/home image#1?.png"`) {
		t.Fatalf("HTML contains unescaped artifact path: %s", html)
	}
}

func TestRenderMatrixReview_ContainsFailedCellsAndEscapesLabels(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result := &MatrixResult{
		Cells: []MatrixCellResult{{
			ID:         "phone|en-US|light|default",
			Device:     "phone",
			Locale:     "en-US",
			Appearance: "light",
			Content:    "<default>",
			Status:     MatrixCellSuccess,
		}, {
			ID:           "phone|ja-JP|dark|empty",
			Device:       "phone",
			Locale:       "ja-JP",
			Appearance:   "dark",
			Content:      "empty",
			Status:       MatrixCellFailed,
			FailureStage: "raw command output /private/keychain",
			FailureCode:  "raw command output /private/keychain",
			Error:        &MatrixCellError{Stage: "execution", Code: "plan_failed", Message: "capture failed"},
		}},
	}
	if _, err := GenerateMatrixReview(context.Background(), MatrixReviewRequest{Result: result, OutputDir: dir}); err != nil {
		t.Fatalf("GenerateMatrixReview() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "phone|ja-JP|dark|empty") || !strings.Contains(html, "matrix execution failed") || !strings.Contains(html, "missing image") {
		t.Fatalf("HTML omitted cell status: %s", html)
	}
	if strings.Contains(html, "<default>") || !strings.Contains(html, "&lt;default&gt;") {
		t.Fatalf("HTML did not escape content label: %s", html)
	}
	manifest, err := LoadMatrixReviewManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("LoadMatrixReviewManifest() error = %v", err)
	}
	if len(manifest.Cells) != 2 || manifest.Cells[1].Status != MatrixCellFailed {
		t.Fatalf("manifest cells = %+v", manifest.Cells)
	}
	manifestData, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	for _, field := range []string{`"generatedAt"`, `"planPath"`, `"totalCells"`, `"contentVariant"`} {
		if !strings.Contains(string(manifestData), field) {
			t.Fatalf("manifest missing governed camelCase field %s: %s", field, manifestData)
		}
	}
	for _, field := range []string{`"generated_at"`, `"plan_path"`, `"total_cells"`, `"content_variant"`} {
		if strings.Contains(string(manifestData), field) {
			t.Fatalf("manifest contains legacy snake_case field %s: %s", field, manifestData)
		}
	}
	if strings.Contains(string(manifestData), "/private/keychain") {
		t.Fatalf("manifest leaked unsanitized failure fields: %s", manifestData)
	}
}

func TestGenerateMatrixReview_DoesNotReplaceManifestWhenHTMLPublishFails(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	oldManifest := []byte(`{"status":"previous"}
`)
	if err := os.WriteFile(manifestPath, oldManifest, 0o644); err != nil {
		t.Fatalf("write previous manifest: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "index.html"), 0o755); err != nil {
		t.Fatalf("create blocked HTML destination: %v", err)
	}

	_, err := GenerateMatrixReview(context.Background(), MatrixReviewRequest{
		Result:    &MatrixResult{Cells: []MatrixCellResult{{ID: "phone|en-US|light|default", Status: MatrixCellSuccess}}},
		OutputDir: dir,
	})
	if err == nil || !strings.Contains(err.Error(), "matrix review HTML") {
		t.Fatalf("GenerateMatrixReview() error = %v, want HTML write failure", err)
	}
	got, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read previous manifest: %v", err)
	}
	if string(got) != string(oldManifest) {
		t.Fatalf("manifest changed after HTML publish failure: %q", got)
	}
}

func TestGenerateMatrixReviewPreservesExistingFileModes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"index.html", "manifest.json"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
			t.Fatalf("write previous %s: %v", name, err)
		}
	}

	_, err := GenerateMatrixReview(context.Background(), MatrixReviewRequest{
		Result:    &MatrixResult{Cells: []MatrixCellResult{{ID: "phone|en-US|light|default", Status: MatrixCellSuccess}}},
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("GenerateMatrixReview() error = %v", err)
	}
	for _, name := range []string{"index.html", "manifest.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat generated %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("generated %s mode = %o, want preserved 600", name, got)
		}
	}
}

func TestGenerateMatrixReview_RollsBackPairWhenManifestPublishFails(t *testing.T) {
	dir := t.TempDir()
	oldHTML := []byte("<html>previous</html>\n")
	oldManifest := []byte("{\"status\":\"previous\"}\n")
	if err := os.WriteFile(filepath.Join(dir, "index.html"), oldHTML, 0o600); err != nil {
		t.Fatalf("write previous HTML: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), oldManifest, 0o600); err != nil {
		t.Fatalf("write previous manifest: %v", err)
	}

	write := func(root rootfs.Root, name string, data []byte, perm os.FileMode) error {
		if name == "manifest.json" {
			return errors.New("injected manifest publication failure")
		}
		return root.WriteFilePreservingMode(name, data, perm)
	}
	_, err := generateMatrixReviewWithWriter(context.Background(), MatrixReviewRequest{
		Result:    &MatrixResult{Cells: []MatrixCellResult{{ID: "phone|en-US|light|default", Status: MatrixCellSuccess}}},
		OutputDir: dir,
	}, write)
	if err == nil || !strings.Contains(err.Error(), "injected manifest publication failure") {
		t.Fatalf("generateMatrixReviewWithWriter() error = %v, want injected manifest failure", err)
	}
	gotHTML, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		t.Fatalf("read HTML after rollback: %v", err)
	}
	gotManifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest after rollback: %v", err)
	}
	if string(gotHTML) != string(oldHTML) || string(gotManifest) != string(oldManifest) {
		t.Fatalf("review pair changed after rollback: HTML=%q manifest=%q", gotHTML, gotManifest)
	}
	for _, name := range []string{"index.html", "manifest.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat rolled-back %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("rolled-back %s mode = %o, want preserved 600", name, got)
		}
	}
}

func TestLoadMatrixReviewManifestRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxMatrixReviewBytes+1)), 0o644); err != nil {
		t.Fatalf("write oversized matrix review manifest: %v", err)
	}
	_, err := LoadMatrixReviewManifest(path)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("LoadMatrixReviewManifest() error = %v, want bounded-size read error", err)
	}
}

func TestLoadMatrixReviewManifestRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(target, []byte(`{"status":"success"}`), 0o644); err != nil {
		t.Fatalf("write target matrix review manifest: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create matrix review manifest symlink: %v", err)
	}
	_, err := LoadMatrixReviewManifest(link)
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("LoadMatrixReviewManifest() error = %v, want symlink rejection", err)
	}
}

func TestPromoteMatrixArtifactRejectsParentSymlink(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "raw")
	outsideDir := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("create outside directory: %v", err)
	}
	source := filepath.Join(outputDir, "source.png")
	writeMatrixPNG(t, source)
	parentLink := filepath.Join(outputDir, "nested")
	if err := os.Symlink(outsideDir, parentLink); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}
	root, err := rootfs.New(outputDir)
	if err != nil {
		t.Fatalf("open output root: %v", err)
	}
	defer root.Close()

	err = promoteMatrixArtifact(root, outputDir, source, filepath.Join(parentLink, "result.png"))
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("promoteMatrixArtifact() error = %v, want parent symlink rejection", err)
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "result.png")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside destination was touched: %v", err)
	}
}

func TestPromoteMatrixArtifactRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	outputDir := filepath.Join(dir, "raw")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	source := filepath.Join(outputDir, "source.png")
	writeMatrixPNG(t, source)
	target := filepath.Join(dir, "outside.png")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	destination := filepath.Join(outputDir, "result.png")
	if err := os.Symlink(target, destination); err != nil {
		t.Fatalf("create final symlink: %v", err)
	}
	root, err := rootfs.New(outputDir)
	if err != nil {
		t.Fatalf("open output root: %v", err)
	}
	defer root.Close()

	err = promoteMatrixArtifact(root, outputDir, source, destination)
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("promoteMatrixArtifact() error = %v, want final symlink rejection", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read outside target: %v", err)
	}
	if string(got) != "outside" {
		t.Fatalf("outside target changed: %q", got)
	}
}

func TestMatrixResultJSONDoesNotPersistSimulatorSecrets(t *testing.T) {
	data, err := json.Marshal(MatrixResult{
		BundleID: "com.example.app",
		Cells:    []MatrixCellResult{{ID: "phone|en-US|light|default", Device: "phone", Status: MatrixCellSuccess}},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(data)
	for _, forbidden := range []string{"UDID", "udid", "launch_arguments", "PRIVATE_KEY"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("result JSON contains %q: %s", forbidden, encoded)
		}
	}
}

func TestRunMatrix_BoundsConcurrencyAndWritesPartialSafeResult(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"launch"},{"action":"screenshot","name":"home"}]}`)
	writeMatrixTestFile(t, matrixPath, `{
  "version":1,"base_plan":"base.json",
  "devices":[{"id":"phone-a","udid":"UDID-A"},{"id":"phone-b","udid":"UDID-B"}],
  "locales":["en-US","ja-JP"],"appearances":["light"],"content_variants":[{"id":"default"}],
  "output":{"raw_dir":"raw","review_dir":"review"}
}`)
	matrixPlan, err := LoadMatrixPlan(matrixPath)
	if err != nil {
		t.Fatalf("LoadMatrixPlan() error = %v", err)
	}
	appearance := &matrixTestAppearance{}
	var mu sync.Mutex
	active, maxActive := 0, 0
	runPlan := func(ctx context.Context, plan *Plan) (*RunResult, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		if err := waitContext(ctx, 5*time.Millisecond); err != nil {
			return nil, err
		}
		writeMatrixPNG(t, filepath.Join(plan.App.OutputDir, "home.png"))
		return &RunResult{BundleID: plan.App.BundleID, UDID: plan.App.UDID, OutputDir: plan.App.OutputDir, Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "ok"}}}, nil
	}
	result, runErr := RunMatrixWithDependencies(context.Background(), matrixPath, matrixPlan, MatrixOptions{MaxConcurrency: 2}, MatrixDependencies{RunPlan: runPlan, Appearance: appearance})
	if runErr != nil {
		t.Fatalf("RunMatrixWithDependencies() error = %v", runErr)
	}
	if maxActive > 2 {
		t.Fatalf("max concurrent runs = %d, want <= 2", maxActive)
	}
	if result.Succeeded != 4 || result.Failed != 0 || len(result.Cells) != 4 {
		t.Fatalf("unexpected result summary: %+v", result)
	}
	if appearance.setCount != 4 || appearance.restoreCount != 4 {
		t.Fatalf("appearance calls = set %d restore %d", appearance.setCount, appearance.restoreCount)
	}
	if _, err := os.Stat(filepath.Join(dir, "review", "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
}

func TestRunMatrix_RetriesExecutionButNotValidation(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	writeMatrixTestFile(t, matrixPath, `{"version":1,"base_plan":"base.json","devices":[{"id":"phone","udid":"UDID"}],"locales":["en-US"],"appearances":["light"],"content_variants":[{"id":"default","launch_arguments":["--fixture","value with spaces;$(touch should-not-run)"]}],"execution":{"max_attempts":2},"output":{"raw_dir":"raw","review_dir":"review"}}`)
	matrixPlan, _ := LoadMatrixPlan(matrixPath)
	appearance := &matrixTestAppearance{}
	var mu sync.Mutex
	attempts := 0
	runPlan := func(_ context.Context, plan *Plan) (*RunResult, error) {
		mu.Lock()
		attempts++
		current := attempts
		mu.Unlock()
		if got, want := plan.App.LaunchArguments, []string{"-AppleLanguages", "(en)", "-AppleLocale", "en_US", "--fixture", "value with spaces;$(touch should-not-run)"}; !reflect.DeepEqual(got, want) {
			t.Errorf("launch arguments = %v, want %v", got, want)
		}
		if len(plan.Steps) == 0 || plan.Steps[0].Action != ActionLaunch {
			t.Errorf("matrix plan did not ensure an explicit launch step: %+v", plan.Steps)
		}
		if current == 1 {
			return &RunResult{Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "error"}}}, errors.New("injected failure")
		}
		writeMatrixPNG(t, filepath.Join(plan.App.OutputDir, "home.png"))
		return &RunResult{Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "ok"}}}, nil
	}
	result, runErr := RunMatrixWithDependencies(context.Background(), matrixPath, matrixPlan, MatrixOptions{}, MatrixDependencies{RunPlan: runPlan, Appearance: appearance})
	if runErr != nil {
		t.Fatalf("RunMatrixWithDependencies() error = %v", runErr)
	}
	if attempts != 2 || result.Cells[0].Attempts != 2 || result.Cells[0].Status != MatrixCellSuccess {
		t.Fatalf("attempts=%d cell=%+v", attempts, result.Cells[0])
	}
	if result.Cells[0].FailureStage != "" || result.Cells[0].FailureCode != "" || result.Cells[0].Error != nil {
		t.Fatalf("successful retry retained failure metadata: %+v", result.Cells[0])
	}
}

func TestRunMatrix_PreflightFailureDoesNotSuppressReadyDevices(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	writeMatrixTestFile(t, matrixPath, `{"version":1,"base_plan":"base.json","devices":[{"id":"phone-a","udid":"READY"},{"id":"phone-b","udid":"NOT-READY"}],"locales":["en-US"],"appearances":["light"],"content_variants":[{"id":"default"}],"output":{"raw_dir":"raw","review_dir":"review"}}`)
	matrixPlan, _ := LoadMatrixPlan(matrixPath)
	appearance := &matrixTestAppearance{}
	var ran sync.Mutex
	readyRuns := 0
	runPlan := func(_ context.Context, plan *Plan) (*RunResult, error) {
		ran.Lock()
		readyRuns++
		ran.Unlock()
		writeMatrixPNG(t, filepath.Join(plan.App.OutputDir, "home.png"))
		return &RunResult{Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "ok"}}}, nil
	}
	checkDevice := func(_ context.Context, device MatrixDevice) error {
		if device.ID == "phone-b" {
			return errors.New("not ready")
		}
		return nil
	}
	result, runErr := RunMatrixWithDependencies(context.Background(), matrixPath, matrixPlan, MatrixOptions{}, MatrixDependencies{RunPlan: runPlan, Appearance: appearance, CheckDevice: checkDevice})
	if runErr == nil {
		t.Fatal("expected preflight failure")
	}
	if readyRuns != 1 || result.Succeeded != 1 || result.Failed != 1 || result.Status != MatrixCellFailed {
		t.Fatalf("unexpected preflight result: runs=%d result=%+v", readyRuns, result)
	}
	if result.Cells[1].FailureCode != "simulator_not_ready" || result.Cells[1].Error == nil {
		t.Fatalf("missing sanitized preflight error: %+v", result.Cells[1])
	}
	if _, err := os.Stat(filepath.Join(dir, "review", "manifest.json")); err != nil {
		t.Fatalf("manifest missing after preflight failure: %v", err)
	}
}

func TestRunMatrix_InventoryCancellationMarksAllCellsCanceled(t *testing.T) {
	tests := []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		wantError  error
	}{
		{
			name: "caller canceled",
			newContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			wantError: context.Canceled,
		},
		{
			name: "caller deadline exceeded",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			wantError: context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			basePath := filepath.Join(dir, "base.json")
			matrixPath := filepath.Join(dir, "matrix.json")
			writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
			writeMatrixTestFile(t, matrixPath, `{"version":1,"base_plan":"base.json","devices":[{"id":"sim-a","udid":"SIM-A"},{"id":"sim-b","udid":"SIM-B"}],"locales":["en-US"],"appearances":["light"],"content_variants":[{"id":"default"}],"output":{"raw_dir":"raw","review_dir":"review"}}`)
			matrixPlan, err := LoadMatrixPlan(matrixPath)
			if err != nil {
				t.Fatalf("LoadMatrixPlan() error = %v", err)
			}
			ctx, cancel := tc.newContext()
			defer cancel()

			result, runErr := RunMatrixWithDependencies(ctx, matrixPath, matrixPlan, MatrixOptions{}, MatrixDependencies{})
			if !errors.Is(runErr, tc.wantError) {
				t.Fatalf("RunMatrixWithDependencies() error = %v, want %v", runErr, tc.wantError)
			}
			if result == nil {
				t.Fatal("RunMatrixWithDependencies() result = nil, want partial canceled result")
			}
			if result.Succeeded != 0 || result.Failed != 0 || result.Canceled != len(result.Cells) {
				t.Fatalf("unexpected cancellation summary: %+v", result)
			}
			if result.Review == nil || result.Review.Canceled != len(result.Cells) || result.Review.Failed != 0 {
				t.Fatalf("unexpected cancellation review: %+v", result.Review)
			}
			for _, cell := range result.Cells {
				if cell.Status != MatrixCellCanceled {
					t.Errorf("cell %q status = %q, want canceled", cell.ID, cell.Status)
				}
				if cell.FailureCode == "simulator_not_ready" {
					t.Errorf("cell %q reported simulator_not_ready for inventory cancellation", cell.ID)
				}
			}
		})
	}
}

func TestRunMatrix_InventoryTimeoutMarksCellsFailed(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	writeMatrixTestFile(t, matrixPath, `{"version":1,"base_plan":"base.json","devices":[{"id":"sim-a","udid":"SIM-A"},{"id":"sim-b","udid":"SIM-B"}],"locales":["en-US"],"appearances":["light"],"content_variants":[{"id":"default"}],"output":{"raw_dir":"raw","review_dir":"review"}}`)
	matrixPlan, err := LoadMatrixPlan(matrixPath)
	if err != nil {
		t.Fatalf("LoadMatrixPlan() error = %v", err)
	}
	checkDevice := func(context.Context, MatrixDevice) error {
		return ErrMatrixInventoryTimeout
	}
	result, runErr := RunMatrixWithDependencies(context.Background(), matrixPath, matrixPlan, MatrixOptions{}, MatrixDependencies{CheckDevice: checkDevice})
	if runErr == nil {
		t.Fatal("RunMatrixWithDependencies() error = nil, want preflight failure")
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		t.Fatalf("RunMatrixWithDependencies() error = %v, want non-context preflight failure", runErr)
	}
	if result.Succeeded != 0 || result.Failed != len(result.Cells) || result.Canceled != 0 || result.Status != MatrixCellFailed {
		t.Fatalf("unexpected inventory-timeout result: %+v", result)
	}
	if result.Review == nil || result.Review.Failed != len(result.Cells) || result.Review.Canceled != 0 {
		t.Fatalf("unexpected inventory-timeout review: %+v", result.Review)
	}
	for _, cell := range result.Cells {
		if cell.Status != MatrixCellFailed || cell.FailureStage != "preflight" || cell.FailureCode != "simulator_not_ready" {
			t.Errorf("cell %q = %+v, want preflight simulator_not_ready failure", cell.ID, cell)
		}
	}
}

func TestRunMatrix_CleanupFailureBlocksLaterCellsOnSameSimulator(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	matrixPath := filepath.Join(dir, "matrix.json")
	writeMatrixTestFile(t, basePath, `{"version":1,"app":{"bundle_id":"com.example.app"},"steps":[{"action":"screenshot","name":"home"}]}`)
	writeMatrixTestFile(t, matrixPath, `{"version":1,"base_plan":"base.json","devices":[{"id":"phone","udid":"SIM"}],"locales":["en-US","ja-JP"],"appearances":["light"],"content_variants":[{"id":"default"}],"output":{"raw_dir":"raw","review_dir":"review"}}`)
	matrixPlan, _ := LoadMatrixPlan(matrixPath)
	appearance := &matrixTestAppearance{restoreErr: true}
	runPlan := func(_ context.Context, plan *Plan) (*RunResult, error) {
		writeMatrixPNG(t, filepath.Join(plan.App.OutputDir, "home.png"))
		return &RunResult{Steps: []RunStepResult{{Index: 1, Action: "screenshot", Status: "ok"}}}, nil
	}
	result, runErr := RunMatrixWithDependencies(context.Background(), matrixPath, matrixPlan, MatrixOptions{}, MatrixDependencies{RunPlan: runPlan, Appearance: appearance})
	if runErr == nil {
		t.Fatal("expected cleanup failure")
	}
	if result.Cells[0].Status != MatrixCellCleanupFailed || result.Cells[1].FailureCode != "simulator_blocked_after_cleanup_failure" {
		t.Fatalf("unexpected cleanup result: %+v", result.Cells)
	}
	if appearance.restoreCount != 1 {
		t.Fatalf("restore count = %d, want one before simulator was blocked", appearance.restoreCount)
	}
}

type matrixTestAppearance struct {
	mu           sync.Mutex
	setCount     int
	restoreCount int
	setErr       bool
	restoreErr   bool
}

func (*matrixTestAppearance) Snapshot(context.Context, string) (string, error) { return "light", nil }

func (a *matrixTestAppearance) Set(context.Context, string, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setCount++
	if a.setErr {
		return errors.New("set failed")
	}
	return nil
}

func (a *matrixTestAppearance) Restore(context.Context, string, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.restoreCount++
	if a.restoreErr {
		return errors.New("restore failed")
	}
	return nil
}

func writeMatrixTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func stringPtr(value string) *string { return &value }

func makeMatrixDevices(count int) []MatrixDevice {
	devices := make([]MatrixDevice, count)
	for i := range devices {
		devices[i] = MatrixDevice{ID: "device-" + string(rune('a'+i)), UDID: "udid-" + string(rune('a'+i))}
	}
	return devices
}

func makeStrings(count int, value string) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value + "-" + string([]rune{'A' + rune(i/26), 'A' + rune(i%26)})
	}
	return values
}

func writeMatrixPNG(t *testing.T, path string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fake screenshot: %v", err)
	}
	defer file.Close()
	if err := png.Encode(file, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatalf("encode fake screenshot: %v", err)
	}
}
