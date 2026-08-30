package screenshots

import (
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
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
			plan: MatrixPlan{Version: 1, Devices: []MatrixDevice{{ID: "one", UDID: "same"}, {ID: "two", UDID: "same"}}, Locales: []string{"en-US"}, Appearances: []string{"light"}, ContentVariants: []MatrixContentVariant{{ID: "default"}}},
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

func TestValidateMatrixPlan_RejectsCrossFamilyFrameMapping(t *testing.T) {
	base := &Plan{Version: 1, App: PlanApp{BundleID: "com.example.app"}, Steps: []PlanStep{{Action: ActionScreenshot, Name: stringPtr("home")}}}
	plan := &MatrixPlan{
		Version:         1,
		Devices:         []MatrixDevice{{ID: "ipad-pro-13", UDID: "IPAD-UDID"}},
		Locales:         []string{"en-US"},
		Appearances:     []string{"light"},
		ContentVariants: []MatrixContentVariant{{ID: "default"}},
		Output:          MatrixOutput{Frame: MatrixFrame{Enabled: true, DeviceByMatrixDevice: map[string]string{"ipad-pro-13": "iphone-17-pro"}}},
	}
	if err := ValidateMatrixPlan(plan, base); err == nil || !strings.Contains(err.Error(), "families") {
		t.Fatalf("ValidateMatrixPlan() error = %v, want family mismatch", err)
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
	if err == nil || !strings.Contains(err.Error(), "write matrix review HTML") {
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
