package xcode

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

func TestXcodeTestPassesTypedOptionsAndPrintsJSON(t *testing.T) {
	originalRunTest := runTest
	t.Cleanup(func() { runTest = originalRunTest })

	var gotOpts localxcode.TestOptions
	runTest = func(_ context.Context, opts localxcode.TestOptions) (*localxcode.TestResult, error) {
		gotOpts = opts
		exitStatus := 0
		return &localxcode.TestResult{
			ProjectPath:      opts.ProjectPath,
			Scheme:           opts.Scheme,
			Action:           opts.Action,
			Configuration:    opts.Configuration,
			Destinations:     opts.Destinations,
			TestPlan:         opts.TestPlan,
			DerivedDataPath:  opts.DerivedDataPath,
			ResultBundlePath: opts.ResultBundlePath,
			Tests: &localxcode.TestSummary{
				Total:      2,
				Passed:     1,
				Failed:     1,
				DurationMS: 1250,
				Failures: []localxcode.TestFailure{{
					Identifier: "DemoTests/LoginTests/testInvalidPassword",
					Message:    "assertion failed",
				}},
			},
			Success:    true,
			DurationMS: 1400,
			ExitStatus: &exitStatus,
		}, nil
	}

	cmd := XcodeTestCommand()
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.FlagSet.Parse([]string{
		"--project", "Demo App.xcodeproj",
		"--scheme", "Demo App",
		"--action", "test",
		"--configuration", "Debug",
		"--destination", "platform=iOS Simulator,name=iPhone 17 Pro",
		"--destination", "platform=iOS Simulator,name=iPad Pro",
		"--test-plan", "DemoTests",
		"--only-testing", "DemoTests/LoginTests",
		"--skip-testing", "DemoTests/FlakyTests",
		"--derived-data-path", "/tmp/Derived Data",
		"--result-bundle-path", "/tmp/Results/Demo.xcresult",
		"--clean",
		"--no-code-signing",
		"--xcodebuild-flag=-quiet",
		"--xcodebuild-flag=OTHER_SWIFT_FLAGS=-D ASC_TEST",
		"--output", "json",
	}); err != nil {
		t.Fatalf("FlagSet.Parse() error = %v", err)
	}

	var runErr error
	stdout, stderr := captureCommandOutput(t, func() error {
		runErr = cmd.Exec(context.Background(), nil)
		return runErr
	})
	if runErr != nil {
		t.Fatalf("Exec() error = %v", runErr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if gotOpts.ProjectPath != "Demo App.xcodeproj" || gotOpts.WorkspacePath != "" || gotOpts.Scheme != "Demo App" {
		t.Fatalf("unexpected selector options: %+v", gotOpts)
	}
	if gotOpts.Action != "test" || gotOpts.Configuration != "Debug" || gotOpts.TestPlan != "DemoTests" {
		t.Fatalf("unexpected action options: %+v", gotOpts)
	}
	if len(gotOpts.Destinations) != 2 || gotOpts.Destinations[1] != "platform=iOS Simulator,name=iPad Pro" {
		t.Fatalf("unexpected destinations: %#v", gotOpts.Destinations)
	}
	if len(gotOpts.OnlyTesting) != 1 || gotOpts.OnlyTesting[0] != "DemoTests/LoginTests" || len(gotOpts.SkipTesting) != 1 {
		t.Fatalf("unexpected test filters: %+v", gotOpts)
	}
	if !gotOpts.Clean || !gotOpts.NoCodeSigning {
		t.Fatalf("expected clean and no-code-signing: %+v", gotOpts)
	}
	wantRaw := []string{"-quiet", "OTHER_SWIFT_FLAGS=-D ASC_TEST"}
	if len(gotOpts.XcodebuildArgs) != len(wantRaw) || gotOpts.XcodebuildArgs[0] != wantRaw[0] || gotOpts.XcodebuildArgs[1] != wantRaw[1] {
		t.Fatalf("XcodebuildArgs = %#v, want %#v", gotOpts.XcodebuildArgs, wantRaw)
	}

	var payload localxcode.TestResult
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout=%s", err, stdout)
	}
	if payload.Action != "test" || payload.Tests == nil || payload.Tests.Total != 2 || payload.Tests.Failed != 1 || payload.DurationMS != 1400 {
		t.Fatalf("unexpected JSON payload: %+v", payload)
	}
}

func TestXcodeTestValidationErrorsAreUsageErrors(t *testing.T) {
	originalRunTest := runTest
	t.Cleanup(func() { runTest = originalRunTest })
	runTest = func(context.Context, localxcode.TestOptions) (*localxcode.TestResult, error) {
		t.Fatal("runTest must not be called for invalid input")
		return nil, nil
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing selector", args: []string{"--scheme", "Demo", "--destination", "generic/platform=iOS"}, want: "exactly one of --workspace or --project"},
		{name: "both selectors", args: []string{"--project", "Demo.xcodeproj", "--workspace", "Demo.xcworkspace", "--scheme", "Demo", "--destination", "generic/platform=iOS"}, want: "exactly one of --workspace or --project"},
		{name: "missing scheme", args: []string{"--project", "Demo.xcodeproj", "--destination", "generic/platform=iOS"}, want: "--scheme is required"},
		{name: "missing destination", args: []string{"--project", "Demo.xcodeproj", "--scheme", "Demo"}, want: "--destination is required"},
		{name: "invalid action", args: []string{"--project", "Demo.xcodeproj", "--scheme", "Demo", "--destination", "generic/platform=iOS", "--action", "archive"}, want: "--action must be one of"},
		{name: "without building missing xctestrun", args: []string{"--action", "test-without-building", "--destination", "generic/platform=iOS"}, want: "--xctestrun is required"},
		{name: "reserved raw action", args: []string{"--project", "Demo.xcodeproj", "--scheme", "Demo", "--destination", "generic/platform=iOS", "--xcodebuild-flag=test"}, want: "cannot override asc-managed argument"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := XcodeTestCommand()
			cmd.FlagSet.SetOutput(io.Discard)
			if err := cmd.FlagSet.Parse(test.args); err != nil {
				t.Fatalf("FlagSet.Parse() error = %v", err)
			}
			var runErr error
			stdout, stderr := captureCommandOutput(t, func() error {
				runErr = cmd.Exec(context.Background(), nil)
				return runErr
			})
			if !errors.Is(runErr, flag.ErrHelp) {
				t.Fatalf("Exec() error = %v, want usage error", runErr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, test.want) {
				t.Fatalf("stderr = %q, want %q", stderr, test.want)
			}
		})
	}
}

func TestXcodeTestRendersTableAndMarkdown(t *testing.T) {
	originalRunTest := runTest
	t.Cleanup(func() { runTest = originalRunTest })
	runTest = func(_ context.Context, opts localxcode.TestOptions) (*localxcode.TestResult, error) {
		exitStatus := 0
		return &localxcode.TestResult{
			WorkspacePath: opts.WorkspacePath,
			Scheme:        opts.Scheme,
			Action:        opts.Action,
			Destinations:  opts.Destinations,
			Tests:         &localxcode.TestSummary{Total: 1, Passed: 1, DurationMS: 10},
			Success:       true,
			ExitStatus:    &exitStatus,
		}, nil
	}

	for _, format := range []string{"table", "markdown"} {
		t.Run(format, func(t *testing.T) {
			cmd := XcodeTestCommand()
			cmd.FlagSet.SetOutput(io.Discard)
			if err := cmd.FlagSet.Parse([]string{
				"--workspace", "Demo.xcworkspace", "--scheme", "Demo",
				"--destination", "generic/platform=iOS", "--output", format,
			}); err != nil {
				t.Fatalf("FlagSet.Parse() error = %v", err)
			}
			var runErr error
			stdout, stderr := captureCommandOutput(t, func() error {
				runErr = cmd.Exec(context.Background(), nil)
				return runErr
			})
			if runErr != nil {
				t.Fatalf("Exec() error = %v", runErr)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			for _, want := range []string{"workspace", "Demo.xcworkspace", "destination", "generic/platform=iOS", "tests", "success", "exit_status", "0"} {
				if !strings.Contains(stdout, want) {
					t.Fatalf("%s output = %q, want %q", format, stdout, want)
				}
			}
		})
	}
}

func TestXcodeTestPrintsStructuredFailureBeforeReturningError(t *testing.T) {
	originalRunTest := runTest
	t.Cleanup(func() { runTest = originalRunTest })
	runTest = func(_ context.Context, opts localxcode.TestOptions) (*localxcode.TestResult, error) {
		_, _ = io.WriteString(opts.LogWriter, "test failed\n")
		exitStatus := 65
		return &localxcode.TestResult{
			ProjectPath:  opts.ProjectPath,
			Scheme:       opts.Scheme,
			Action:       opts.Action,
			Destinations: opts.Destinations,
			Tests:        &localxcode.TestSummary{Total: 1, Failed: 1, DurationMS: 400},
			Success:      false,
			DurationMS:   400,
			ExitStatus:   &exitStatus,
		}, errors.New("xcodebuild test failed: test failed")
	}

	cmd := XcodeTestCommand()
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.FlagSet.Parse([]string{
		"--project", "Demo.xcodeproj", "--scheme", "Demo",
		"--destination", "generic/platform=iOS", "--output", "json",
	}); err != nil {
		t.Fatalf("FlagSet.Parse() error = %v", err)
	}
	var runErr error
	stdout, stderr := captureCommandOutput(t, func() error {
		runErr = cmd.Exec(context.Background(), nil)
		return runErr
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "xcodebuild test failed: test failed") {
		t.Fatalf("Exec() error = %v, want wrapped test failure", runErr)
	}
	var reportedErr shared.ReportedError
	if !errors.As(runErr, &reportedErr) {
		t.Fatalf("Exec() error = %T %v, want ReportedError", runErr, runErr)
	}
	if got := strings.Count(stderr, "test failed"); got != 2 {
		t.Fatalf("stderr = %q, test diagnostic count = %d, want stream and concise error", stderr, got)
	}
	if !strings.Contains(stderr, "Error: xcode test failed with exit status 65") {
		t.Fatalf("stderr = %q, want concise final test error", stderr)
	}
	var payload localxcode.TestResult
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\nstdout=%s", err, stdout)
	}
	if payload.Success || payload.ExitStatus == nil || *payload.ExitStatus != 65 || payload.Tests == nil || payload.Tests.Failed != 1 {
		t.Fatalf("unexpected failure payload: %+v", payload)
	}
}

func TestXcodeTestJUnitIncludesStructuredCases(t *testing.T) {
	report := testResultJUnitReport(&localxcode.TestResult{
		Success: true,
		Tests: &localxcode.TestSummary{
			Total:  3,
			Passed: 1,
			Failed: 1,
			Cases: []localxcode.TestCase{
				{Identifier: "DemoTests/Smoke/testPass", Name: "testPass", Classname: "DemoTests", Status: "passed", DurationMS: 250},
				{Identifier: "DemoTests/Smoke/testFail", Name: "testFail", Classname: "DemoTests", Status: "failed", Message: "assertion failed", DurationMS: 400},
				{Identifier: "DemoTests/Smoke/testSkip", Name: "testSkip", Classname: "DemoTests", Status: "skipped"},
			},
		},
	})
	data, err := report.Marshal()
	if err != nil {
		t.Fatalf("JUnit Marshal() error = %v", err)
	}
	if got := strings.Count(string(data), "<testcase "); got != 3 {
		t.Fatalf("JUnit testcase count = %d, want 3\n%s", got, data)
	}
	for _, want := range []string{"testPass", "testFail", "testSkip", "FAILURE", "assertion failed", "<skipped></skipped>"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("JUnit output = %s, want %q", data, want)
		}
	}
}

func TestXcodeTestJUnitFallbackMarksSummaryFailure(t *testing.T) {
	report := testResultJUnitReport(&localxcode.TestResult{
		Success: true,
		Tests:   &localxcode.TestSummary{Total: 1, Failed: 1, DurationMS: 600},
	})
	data, err := report.Marshal()
	if err != nil {
		t.Fatalf("JUnit Marshal() error = %v", err)
	}
	if !strings.Contains(string(data), `failures="1"`) || !strings.Contains(string(data), "FAILURE") {
		t.Fatalf("JUnit output = %s, want one failure", data)
	}
}
