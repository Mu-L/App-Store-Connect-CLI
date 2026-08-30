package xcode

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateTestOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    TestOptions
		wantErr string
	}{
		{
			name: "project test",
			opts: TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}},
		},
		{
			name: "workspace build for testing",
			opts: TestOptions{WorkspacePath: "Demo.xcworkspace", Scheme: "Demo", Action: string(TestActionBuildForTesting), Destinations: []string{"generic/platform=iOS"}},
		},
		{
			name: "test without building",
			opts: TestOptions{Action: string(TestActionTestWithoutBuilding), XctestrunPath: "Demo.xctestrun", Destinations: []string{"generic/platform=iOS"}},
		},
		{
			name:    "missing selector",
			opts:    TestOptions{Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "exactly one of --workspace or --project",
		},
		{
			name:    "both selectors",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", WorkspacePath: "Demo.xcworkspace", Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "exactly one of --workspace or --project",
		},
		{
			name:    "missing destination",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo"},
			wantErr: "--destination is required",
		},
		{
			name:    "invalid action",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", Action: "archive", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--action must be one of",
		},
		{
			name:    "without building requires xctestrun",
			opts:    TestOptions{Action: string(TestActionTestWithoutBuilding), Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--xctestrun is required",
		},
		{
			name:    "without building rejects project",
			opts:    TestOptions{Action: string(TestActionTestWithoutBuilding), ProjectPath: "Demo.xcodeproj", XctestrunPath: "Demo.xctestrun", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--project and --workspace cannot be used",
		},
		{
			name:    "without building rejects clean",
			opts:    TestOptions{Action: string(TestActionTestWithoutBuilding), XctestrunPath: "Demo.xctestrun", Clean: true, Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--clean cannot be used",
		},
		{
			name:    "test action rejects xctestrun",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", XctestrunPath: "Demo.xctestrun", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--xctestrun is only valid",
		},
		{
			name:    "test plan conflicts with xctestrun",
			opts:    TestOptions{Action: string(TestActionTestWithoutBuilding), TestPlan: "Demo", XctestrunPath: "Demo.xctestrun", Destinations: []string{"generic/platform=iOS"}},
			wantErr: "--test-plan cannot be used",
		},
		{
			name:    "reserved result flag",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}, XcodebuildArgs: []string{"-resultBundlePath", "/tmp/other.xcresult"}},
			wantErr: "cannot override asc-managed argument",
		},
		{
			name:    "reserved test filter",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}, XcodebuildArgs: []string{"-only-testing:DemoTests/Smoke"}},
			wantErr: "cannot override asc-managed argument",
		},
		{
			name:    "empty raw flag",
			opts:    TestOptions{ProjectPath: "Demo.xcodeproj", Scheme: "Demo", Destinations: []string{"generic/platform=iOS"}, XcodebuildArgs: []string{" "}},
			wantErr: "--xcodebuild-flag cannot be empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTestOptions(test.opts)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateTestOptions() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateTestOptions() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestBuildTestCommandUsesTypedOptionsAndPreservesOrder(t *testing.T) {
	opts := TestOptions{
		WorkspacePath:    "Demo App.xcworkspace",
		Scheme:           "Demo App",
		Action:           string(TestActionTest),
		Configuration:    "Release Candidate",
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro", "platform=iOS Simulator,name=iPad Pro"},
		TestPlan:         "DemoTests",
		OnlyTesting:      []string{"DemoTests/LoginTests", "DemoTests/SmokeTests"},
		SkipTesting:      []string{"DemoTests/FlakyTests"},
		DerivedDataPath:  "/tmp/Derived Data/Demo",
		ResultBundlePath: "/tmp/Results/Demo.xcresult",
		Clean:            true,
		NoCodeSigning:    true,
		XcodebuildArgs:   []string{"-quiet", "OTHER_SWIFT_FLAGS=-D ASC_TEST"},
	}

	want := []string{
		"-workspace", "Demo App.xcworkspace",
		"-scheme", "Demo App",
		"-configuration", "Release Candidate",
		"-destination", "platform=iOS Simulator,name=iPhone 17 Pro",
		"-destination", "platform=iOS Simulator,name=iPad Pro",
		"-testPlan", "DemoTests",
		"-derivedDataPath", "/tmp/Derived Data/Demo",
		"-resultBundlePath", "/tmp/Results/Demo.xcresult",
		"-only-testing:DemoTests/LoginTests",
		"-only-testing:DemoTests/SmokeTests",
		"-skip-testing:DemoTests/FlakyTests",
		"-quiet", "OTHER_SWIFT_FLAGS=-D ASC_TEST",
		"CODE_SIGNING_ALLOWED=NO",
		"clean",
		"test",
	}
	if got := buildTestCommand(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildTestCommand() = %#v\nwant %#v", got, want)
	}
}

func TestBuildTestCommandSupportsWithoutBuilding(t *testing.T) {
	opts := TestOptions{
		Action:           string(TestActionTestWithoutBuilding),
		XctestrunPath:    "/tmp/App.xctestrun",
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro"},
		ResultBundlePath: "/tmp/App-tests.xcresult",
		OnlyTesting:      []string{"AppTests/Smoke"},
	}
	want := []string{
		"-destination", "platform=iOS Simulator,name=iPhone 17 Pro",
		"-xctestrun", "/tmp/App.xctestrun",
		"-resultBundlePath", "/tmp/App-tests.xcresult",
		"-only-testing:AppTests/Smoke",
		"test-without-building",
	}
	if got := buildTestCommand(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildTestCommand() = %#v\nwant %#v", got, want)
	}
}

func TestParseTestResultSummaryWithCases(t *testing.T) {
	data := []byte(`{
  "tests": [
    {"testIdentifier":"DemoTests/Login/testValid","status":"Passed","duration":0.25},
    {"testIdentifier":"DemoTests/Login/testInvalid","status":"Failed","durationMs":125,"failureMessage":"assertion failed"},
    {"testIdentifier":"DemoTests/Login/testSkipped","status":"Skipped"}
  ],
  "testDuration": 1.25,
  "testFailures": [{"testIdentifier":"DemoTests/Login/testInvalid","message":"assertion failed"}]
}`)

	got, err := ParseTestResultSummary(data)
	if err != nil {
		t.Fatalf("ParseTestResultSummary() error = %v", err)
	}
	if got.Total != 3 || got.Passed != 1 || got.Failed != 1 || got.Skipped != 1 || got.DurationMS != 1250 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if len(got.Cases) != 3 || got.Cases[1].Status != "failed" || got.Cases[0].DurationMS != 250 {
		t.Fatalf("unexpected cases: %+v", got.Cases)
	}
	if len(got.Failures) != 1 || got.Failures[0].Identifier != "DemoTests/Login/testInvalid" {
		t.Fatalf("unexpected failures: %+v", got.Failures)
	}
}

func TestParseTestResultSummaryWithCounts(t *testing.T) {
	data := []byte(`{"tests":4,"passedTests":3,"failedTests":1,"skippedTests":0,"testDuration":2.5}`)
	got, err := ParseTestResultSummary(data)
	if err != nil {
		t.Fatalf("ParseTestResultSummary() error = %v", err)
	}
	if got.Total != 4 || got.Passed != 3 || got.Failed != 1 || got.Skipped != 0 || got.DurationMS != 2500 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if len(got.Cases) != 0 {
		t.Fatalf("expected no cases in count-only summary, got %+v", got.Cases)
	}
}

func TestParseTestResultSummaryUsesCurrentXcodeFields(t *testing.T) {
	data := []byte(`{
  "result":"Failed",
  "totalTestCount":3,
  "passedTests":1,
  "failedTests":1,
  "skippedTests":1,
  "startTime":10.25,
  "finishTime":12.5,
  "testFailures":[{
    "testIdentifier":14,
    "testIdentifierString":"DemoTests/Login/testInvalid",
    "testName":"testInvalid",
    "targetName":"DemoTests",
    "failureText":"assertion failed"
  }]
}`)
	got, err := ParseTestResultSummary(data)
	if err != nil {
		t.Fatalf("ParseTestResultSummary() error = %v", err)
	}
	if got.Total != 3 || got.Passed != 1 || got.Failed != 1 || got.Skipped != 1 || got.DurationMS != 2250 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if len(got.Failures) != 1 || got.Failures[0].Identifier != "DemoTests/Login/testInvalid" || got.Failures[0].Message != "assertion failed" {
		t.Fatalf("unexpected failures: %+v", got.Failures)
	}
}

func TestParseTestResultCasesWalksCurrentXcodeTree(t *testing.T) {
	data := []byte(`{
  "testNodes":[{
    "nodeType":"Test Plan",
    "children":[{
      "nodeType":"Unit test bundle",
      "children":[{
        "nodeType":"Test Suite",
        "children":[
          {"nodeType":"Test Case","nodeIdentifier":"DemoTests/Login/testValid","name":"testValid","result":"Passed","duration":"0.25"},
          {"nodeType":"Test Case","nodeIdentifier":"DemoTests/Login/testInvalid","name":"testInvalid","result":"Failed","children":[{"nodeType":"Failure Message","name":"assertion failed"}]},
          {"nodeType":"Test Case","nodeIdentifier":"DemoTests/Login/testSkipped","name":"testSkipped","result":"Skipped"}
        ]
      }]
    }]
  }]
}`)
	cases, err := ParseTestResultCases(data)
	if err != nil {
		t.Fatalf("ParseTestResultCases() error = %v", err)
	}
	if len(cases) != 3 {
		t.Fatalf("len(cases) = %d, want 3", len(cases))
	}
	if cases[0].Identifier != "DemoTests/Login/testValid" || cases[0].Classname != "DemoTests" || cases[0].DurationMS != 250 {
		t.Fatalf("unexpected passing case: %+v", cases[0])
	}
	if cases[1].Status != "failed" || cases[1].Message != "assertion failed" {
		t.Fatalf("unexpected failing case: %+v", cases[1])
	}
	if cases[2].Status != "skipped" {
		t.Fatalf("unexpected skipped case: %+v", cases[2])
	}
}

func TestParseTestResultSummaryRejectsInvalidCountsAndMissingCount(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"tests":2,"passedTests":2,"failedTests":1}`),
		[]byte(`{"totalTestCount":2}`),
		[]byte(`{"result":"Passed"}`),
	} {
		if _, err := ParseTestResultSummary(data); err == nil {
			t.Fatalf("ParseTestResultSummary(%s) succeeded, want error", data)
		}
	}
}

func TestParseTestResultSummaryBoundsFailureMessage(t *testing.T) {
	message := strings.Repeat("x", maxTestFailureMessage+100)
	data, err := json.Marshal(map[string]any{
		"tests":        1,
		"passedTests":  0,
		"failedTests":  1,
		"skippedTests": 0,
		"testFailures": []map[string]string{{"testIdentifier": "Demo/test", "message": message}},
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got, err := ParseTestResultSummary(data)
	if err != nil {
		t.Fatalf("ParseTestResultSummary() error = %v", err)
	}
	if len(got.Failures) != 1 || len(got.Failures[0].Message) != maxTestFailureMessage {
		t.Fatalf("failure message length = %d, want %d", len(got.Failures[0].Message), maxTestFailureMessage)
	}
}

func TestResolveTestPaths(t *testing.T) {
	originalCache := userCacheDirFn
	originalNow := testNowFn
	t.Cleanup(func() {
		userCacheDirFn = originalCache
		testNowFn = originalNow
	})
	userCacheDirFn = func() (string, error) { return "/tmp/asc-cache", nil }
	testNowFn = func() time.Time { return time.Unix(1700000000, 1234) }

	opts := TestOptions{
		ProjectPath:  "Demo.xcodeproj",
		Scheme:       "Demo App",
		Action:       string(TestActionTest),
		Destinations: []string{"generic/platform=iOS"},
	}
	derived, err := resolveTestDerivedDataPath(opts)
	if err != nil {
		t.Fatalf("resolveTestDerivedDataPath() error = %v", err)
	}
	if !strings.HasPrefix(derived, filepath.Join("/tmp/asc-cache", "asc", "xcode-test", "demo-app-")) {
		t.Fatalf("derived path = %q, want cache prefix", derived)
	}
	result, err := resolveTestResultBundlePath(opts)
	if err != nil {
		t.Fatalf("resolveTestResultBundlePath() error = %v", err)
	}
	if !strings.HasSuffix(result, ".xcresult") || !strings.Contains(result, "1700000000000001234") {
		t.Fatalf("result path = %q, want timestamped xcresult", result)
	}
}

func TestFindXctestrunPathRequiresExactlyOneRegularCandidate(t *testing.T) {
	derived := t.TempDir()
	products := filepath.Join(derived, "Build", "Products")
	if err := os.MkdirAll(products, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	path := filepath.Join(products, "Demo.xctestrun")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if got := findXctestrunPath(derived); got != path {
		t.Fatalf("findXctestrunPath() = %q, want %q", got, path)
	}
	if err := os.WriteFile(filepath.Join(products, "Other.xctestrun"), []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if got := findXctestrunPath(derived); got != "" {
		t.Fatalf("findXctestrunPath() = %q, want empty for ambiguous candidates", got)
	}
}

func TestValidateTestResultBundleDestination(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{name: "regular file", setup: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
		}},
		{name: "directory", setup: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
		}},
		{name: "dangling symlink", setup: func(t *testing.T, path string) {
			if runtime.GOOS == "windows" {
				t.Skip("Windows symlink creation requires elevated privileges")
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(path), "missing-target"), path); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing.xcresult")
			test.setup(t, path)
			if err := validateTestResultBundleDestination(path); err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("validateTestResultBundleDestination() error = %v, want existing-path error", err)
			}
		})
	}

	if err := validateTestResultBundleDestination(filepath.Join(t.TempDir(), "new.xcresult")); err != nil {
		t.Fatalf("validateTestResultBundleDestination() error = %v", err)
	}
}

func TestSetTestExitStatusLeavesSignalsWithoutStatus(t *testing.T) {
	result := &TestResult{}
	setTestExitStatus(result, errors.New("not an exit error"))
	if result.ExitStatus != nil {
		t.Fatalf("ExitStatus = %v, want nil", result.ExitStatus)
	}
}

func TestReadTestResultSummaryUsesCurrentXcodeOperations(t *testing.T) {
	originalLookPath := lookPathFn
	originalCommandContext := commandContextFn
	t.Cleanup(func() {
		lookPathFn = originalLookPath
		commandContextFn = originalCommandContext
	})
	lookPathFn = func(string) (string, error) { return "/usr/bin/xcrun", nil }
	var commands [][]string
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commands = append(commands, append([]string{name}, args...))
		output := `{"totalTestCount":1,"passedTests":1,"failedTests":0,"skippedTests":0}`
		if len(args) > 3 && args[3] == "tests" {
			output = `{"testNodes":[{"nodeType":"Test Plan","children":[{"nodeType":"Unit test bundle","children":[{"nodeType":"Test Suite","children":[{"nodeType":"Test Case","nodeIdentifier":"DemoTests/Smoke/testPass","name":"testPass","result":"Passed"}]}]}]}]}`
		}
		return exec.CommandContext(ctx, "printf", "%s", output)
	}

	got, err := readTestResultSummary(context.Background(), "/tmp/Demo.xcresult")
	if err != nil {
		t.Fatalf("readTestResultSummary() error = %v", err)
	}
	if got.Total != 1 || got.Passed != 1 || len(got.Cases) != 1 || got.Cases[0].Identifier != "DemoTests/Smoke/testPass" {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if len(commands) != 2 {
		t.Fatalf("xcresulttool command count = %d, want 2", len(commands))
	}
	wantPrefix := []string{"xcrun", "xcresulttool", "get", "test-results", "summary", "--path", "/tmp/Demo.xcresult", "--compact"}
	if !reflect.DeepEqual(commands[0], wantPrefix) {
		t.Fatalf("summary command = %#v, want %#v", commands[0], wantPrefix)
	}
	if commands[1][4] != "tests" || commands[1][len(commands[1])-1] != "--compact" {
		t.Fatalf("tests command = %#v, want tests operation with compact output", commands[1])
	}
}

func TestTestRunsActionAndParsesResult(t *testing.T) {
	originalRuntimeGOOS := runtimeGOOS
	originalLookPath := lookPathFn
	originalCommandContext := commandContextFn
	originalRun := runXcodeTestCommand
	originalRead := readTestResultSummaryFn
	t.Cleanup(func() {
		runtimeGOOS = originalRuntimeGOOS
		lookPathFn = originalLookPath
		commandContextFn = originalCommandContext
		runXcodeTestCommand = originalRun
		readTestResultSummaryFn = originalRead
	})
	runtimeGOOS = "darwin"
	lookPathFn = func(string) (string, error) { return "/usr/bin/xcodebuild", nil }
	commandContextFn = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	projectPath := filepath.Join(t.TempDir(), "Demo.xcodeproj")
	if err := os.Mkdir(projectPath, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	resultPath := filepath.Join(t.TempDir(), "Demo-tests.xcresult")
	var gotArgs []string
	runXcodeTestCommand = func(_ context.Context, args []string, _ io.Writer) error {
		gotArgs = append([]string(nil), args...)
		for index, arg := range args {
			if arg == "-resultBundlePath" && index+1 < len(args) {
				if err := os.Mkdir(args[index+1], 0o755); err != nil {
					return err
				}
			}
		}
		return nil
	}
	readTestResultSummaryFn = func(context.Context, string) (*TestSummary, error) {
		return &TestSummary{Total: 1, Passed: 1, DurationMS: 250}, nil
	}

	result, err := Test(context.Background(), TestOptions{
		ProjectPath:      projectPath,
		Scheme:           "Demo",
		Action:           string(TestActionTest),
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro"},
		DerivedDataPath:  filepath.Join(t.TempDir(), "DerivedData"),
		ResultBundlePath: resultPath,
	})
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if !result.Success || result.Tests == nil || result.Tests.Total != 1 || result.ExitStatus == nil || *result.ExitStatus != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.ResultBundlePath != resultPath || len(gotArgs) == 0 || gotArgs[len(gotArgs)-1] != "test" {
		t.Fatalf("result path/argv = %q/%#v, want explicit result path and test action", result.ResultBundlePath, gotArgs)
	}
}

func TestTestPreservesProcessFailureAndPartialSummary(t *testing.T) {
	originalRuntimeGOOS := runtimeGOOS
	originalLookPath := lookPathFn
	originalCommandContext := commandContextFn
	originalRun := runXcodeTestCommand
	originalRead := readTestResultSummaryFn
	t.Cleanup(func() {
		runtimeGOOS = originalRuntimeGOOS
		lookPathFn = originalLookPath
		commandContextFn = originalCommandContext
		runXcodeTestCommand = originalRun
		readTestResultSummaryFn = originalRead
	})
	runtimeGOOS = "darwin"
	lookPathFn = func(string) (string, error) { return "/usr/bin/xcodebuild", nil }
	commandContextFn = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	projectPath := filepath.Join(t.TempDir(), "Demo.xcodeproj")
	if err := os.Mkdir(projectPath, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	resultPath := filepath.Join(t.TempDir(), "Demo-tests.xcresult")
	processErr := exec.Command("sh", "-c", "exit 65").Run()
	runXcodeTestCommand = func(_ context.Context, _ []string, _ io.Writer) error {
		if err := os.Mkdir(resultPath, 0o755); err != nil {
			return err
		}
		return processErr
	}
	readTestResultSummaryFn = func(context.Context, string) (*TestSummary, error) {
		return &TestSummary{Total: 1, Failed: 1}, nil
	}
	result, err := Test(context.Background(), TestOptions{
		ProjectPath:      projectPath,
		Scheme:           "Demo",
		Action:           string(TestActionTest),
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro"},
		DerivedDataPath:  filepath.Join(t.TempDir(), "DerivedData"),
		ResultBundlePath: resultPath,
	})
	if !errors.Is(err, processErr) {
		t.Fatalf("Test() error = %v, want process error %v", err, processErr)
	}
	if result.Success || result.Tests == nil || result.Tests.Failed != 1 || result.ExitStatus == nil || *result.ExitStatus != 65 {
		t.Fatalf("unexpected failure result: %+v", result)
	}
}

func TestTestOmitsExitStatusForContextCancellation(t *testing.T) {
	originalRuntimeGOOS := runtimeGOOS
	originalLookPath := lookPathFn
	originalCommandContext := commandContextFn
	originalRun := runXcodeTestCommand
	t.Cleanup(func() {
		runtimeGOOS = originalRuntimeGOOS
		lookPathFn = originalLookPath
		commandContextFn = originalCommandContext
		runXcodeTestCommand = originalRun
	})
	runtimeGOOS = "darwin"
	lookPathFn = func(string) (string, error) { return "/usr/bin/xcodebuild", nil }
	commandContextFn = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	projectPath := filepath.Join(t.TempDir(), "Demo.xcodeproj")
	if err := os.Mkdir(projectPath, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	resultPath := filepath.Join(t.TempDir(), "Demo-tests.xcresult")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runXcodeTestCommand = func(ctx context.Context, _ []string, _ io.Writer) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}

	result, err := Test(ctx, TestOptions{
		ProjectPath:      projectPath,
		Scheme:           "Demo",
		Action:           string(TestActionTest),
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro"},
		DerivedDataPath:  filepath.Join(t.TempDir(), "DerivedData"),
		ResultBundlePath: resultPath,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Test() error = %v, want context cancellation", err)
	}
	if result == nil || result.Success {
		t.Fatalf("Test() result = %+v, want canceled failure", result)
	}
	if result.ExitStatus != nil {
		t.Fatalf("ExitStatus = %v, want nil for cancellation", result.ExitStatus)
	}
}

func TestTestOmitsExitStatusForResultPostProcessingFailure(t *testing.T) {
	originalRuntimeGOOS := runtimeGOOS
	originalLookPath := lookPathFn
	originalCommandContext := commandContextFn
	originalRun := runXcodeTestCommand
	originalRead := readTestResultSummaryFn
	t.Cleanup(func() {
		runtimeGOOS = originalRuntimeGOOS
		lookPathFn = originalLookPath
		commandContextFn = originalCommandContext
		runXcodeTestCommand = originalRun
		readTestResultSummaryFn = originalRead
	})
	runtimeGOOS = "darwin"
	lookPathFn = func(string) (string, error) { return "/usr/bin/xcodebuild", nil }
	commandContextFn = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}
	projectPath := filepath.Join(t.TempDir(), "Demo.xcodeproj")
	if err := os.Mkdir(projectPath, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	resultPath := filepath.Join(t.TempDir(), "Demo-tests.xcresult")
	runXcodeTestCommand = func(_ context.Context, _ []string, _ io.Writer) error {
		return os.Mkdir(resultPath, 0o755)
	}
	readTestResultSummaryFn = func(context.Context, string) (*TestSummary, error) {
		return nil, errors.New("unsupported result summary")
	}
	result, err := Test(context.Background(), TestOptions{
		ProjectPath:      projectPath,
		Scheme:           "Demo",
		Action:           string(TestActionTest),
		Destinations:     []string{"platform=iOS Simulator,name=iPhone 17 Pro"},
		DerivedDataPath:  filepath.Join(t.TempDir(), "DerivedData"),
		ResultBundlePath: resultPath,
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported result summary") {
		t.Fatalf("Test() error = %v, want post-processing failure", err)
	}
	if result.Success || result.ExitStatus != nil {
		t.Fatalf("unexpected post-processing result: %+v", result)
	}
}
