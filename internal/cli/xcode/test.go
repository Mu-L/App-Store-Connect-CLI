package xcode

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

var runTest = localxcode.Test

// XcodeTestCommand returns the local Xcode test command.
func XcodeTestCommand() *ffcli.Command {
	fs := flag.NewFlagSet("xcode test", flag.ExitOnError)

	workspacePath := fs.String("workspace", "", "Path to .xcworkspace directory")
	projectPath := fs.String("project", "", "Path to .xcodeproj directory")
	scheme := fs.String("scheme", "", "Xcode scheme name (required except for test-without-building)")
	action := fs.String("action", string(localxcode.TestActionTest), "Xcode test action: test, build-for-testing, or test-without-building")
	configuration := fs.String("configuration", "", "Build configuration (for example Debug or Release)")
	var destinations shared.MultiStringFlag
	fs.Var(&destinations, "destination", "Xcode destination specifier (repeatable; required)")
	testPlan := fs.String("test-plan", "", "Xcode test plan name")
	xctestrunPath := fs.String("xctestrun", "", "Path to an existing .xctestrun file for test-without-building")
	var onlyTesting shared.MultiStringFlag
	fs.Var(&onlyTesting, "only-testing", "Run only the selected test target or identifier (repeatable)")
	var skipTesting shared.MultiStringFlag
	fs.Var(&skipTesting, "skip-testing", "Skip the selected test target or identifier (repeatable)")
	derivedDataPath := fs.String("derived-data-path", "", "DerivedData directory (defaults to a stable asc cache path)")
	resultBundlePath := fs.String("result-bundle-path", "", "Destination for a new Xcode result bundle")
	clean := fs.Bool("clean", false, "Run clean before the selected Xcode action")
	noCodeSigning := fs.Bool("no-code-signing", false, "Set CODE_SIGNING_ALLOWED=NO explicitly")
	var xcodebuildFlags shared.MultiStringFlag
	fs.Var(&xcodebuildFlags, "xcodebuild-flag", "Pass a raw argument through to xcodebuild (repeatable)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "test",
		ShortUsage: "asc xcode test [flags]",
		ShortHelp:  "[experimental] Run local Xcode tests and report structured results.",
		LongHelp: `[experimental] Run a local Xcode test action and report structured results.

For test and build-for-testing, provide exactly one of --workspace or --project,
plus --scheme and at least one --destination. The default action is test. Use
--action build-for-testing to produce test products, or use
--action test-without-building with an existing --xctestrun file. Test actions
write a new .xcresult bundle automatically when --result-bundle-path is omitted.

Xcode diagnostics are written to stderr and the selected structured result
format is written to stdout. This command never calls App Store Connect or
changes project files.

Examples:
  asc xcode test --project App.xcodeproj --scheme App --destination 'platform=iOS Simulator,name=iPhone 17 Pro' --output json
  asc xcode test --workspace App.xcworkspace --scheme App --destination 'platform=iOS Simulator,name=iPhone 17 Pro' --destination 'platform=iOS Simulator,name=iPad Pro (13-inch)'
  asc xcode test --project App.xcodeproj --scheme App --action build-for-testing --destination 'platform=iOS Simulator,name=iPhone 17 Pro'
  asc xcode test --action test-without-building --xctestrun App_iphonesimulator.xctestrun --destination 'platform=iOS Simulator,name=iPhone 17 Pro'`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				fmt.Fprintln(os.Stderr, "Error: xcode test does not accept positional arguments")
				return flag.ErrHelp
			}
			if emptyFlag := firstExplicitlyEmptyFlag(fs, "workspace", "project", "scheme", "action", "configuration", "test-plan", "xctestrun", "derived-data-path", "result-bundle-path"); emptyFlag != "" {
				return shared.UsageErrorf("--%s must not be empty", emptyFlag)
			}
			opts := localxcode.TestOptions{
				WorkspacePath:    strings.TrimSpace(*workspacePath),
				ProjectPath:      strings.TrimSpace(*projectPath),
				Scheme:           strings.TrimSpace(*scheme),
				Action:           strings.TrimSpace(*action),
				Configuration:    strings.TrimSpace(*configuration),
				Destinations:     []string(destinations),
				TestPlan:         strings.TrimSpace(*testPlan),
				XctestrunPath:    strings.TrimSpace(*xctestrunPath),
				OnlyTesting:      []string(onlyTesting),
				SkipTesting:      []string(skipTesting),
				DerivedDataPath:  strings.TrimSpace(*derivedDataPath),
				ResultBundlePath: strings.TrimSpace(*resultBundlePath),
				Clean:            *clean,
				NoCodeSigning:    *noCodeSigning,
				XcodebuildArgs:   []string(xcodebuildFlags),
				LogWriter:        os.Stderr,
			}
			if err := localxcode.ValidateTestOptions(opts); err != nil {
				return shared.UsageError(err.Error())
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}

			result, testErr := runTest(ctx, opts)
			if result != nil {
				if outputErr := printTestResult(result, *output.Output, *output.Pretty); outputErr != nil {
					if testErr != nil {
						return shared.NewErrorWithCause(outputErr, testErr)
					}
					return outputErr
				}
				if result.Tests != nil && shared.ReportFormat() == shared.ReportFormatJUnit && shared.ReportFile() != "" {
					shared.SetJUnitReport(testResultJUnitReport(result))
				}
			}
			if testErr != nil {
				if result == nil {
					return fmt.Errorf("xcode test: %w", testErr)
				}
				reportTestFailure(result, testErr)
				return shared.NewReportedError(fmt.Errorf("xcode test: %w", testErr))
			}
			if result == nil {
				return fmt.Errorf("xcode test: tester returned no result")
			}
			return nil
		},
	}
}

func reportTestFailure(result *localxcode.TestResult, testErr error) {
	message := "xcode test failed"
	if result.ExitStatus != nil {
		message = fmt.Sprintf("%s with exit status %d", message, *result.ExitStatus)
	} else {
		message = fmt.Sprintf("%s: %v", message, testInterruptionReason(testErr))
	}
	fmt.Fprintf(os.Stderr, "Error: %s\n", message)
}

func testInterruptionReason(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() < 0 {
		return exitErr
	}
	return err
}

func printTestResult(result *localxcode.TestResult, output string, pretty bool) error {
	return shared.PrintOutputWithRenderers(
		result,
		output,
		pretty,
		func() error {
			asc.RenderTable([]string{"field", "value"}, testResultRows(result))
			return nil
		},
		func() error {
			asc.RenderMarkdown([]string{"field", "value"}, testResultRows(result))
			return nil
		},
	)
}

func testResultRows(result *localxcode.TestResult) [][]string {
	rows := make([][]string, 0, 22)
	if result.WorkspacePath != "" {
		rows = append(rows, []string{"workspace", result.WorkspacePath})
	}
	if result.ProjectPath != "" {
		rows = append(rows, []string{"project", result.ProjectPath})
	}
	if result.Scheme != "" {
		rows = append(rows, []string{"scheme", result.Scheme})
	}
	rows = append(rows, []string{"action", result.Action})
	if result.Configuration != "" {
		rows = append(rows, []string{"configuration", result.Configuration})
	}
	if len(result.Destinations) > 0 {
		rows = append(rows, []string{"destinations", strings.Join(result.Destinations, "\n")})
	}
	if result.TestPlan != "" {
		rows = append(rows, []string{"test_plan", result.TestPlan})
	}
	if result.XctestrunPath != "" {
		rows = append(rows, []string{"xctestrun_path", result.XctestrunPath})
	}
	if result.DerivedDataPath != "" {
		rows = append(rows, []string{"derived_data_path", result.DerivedDataPath})
	}
	if result.ResultBundlePath != "" {
		rows = append(rows, []string{"result_bundle_path", result.ResultBundlePath})
	}
	rows = append(
		rows,
		[]string{"clean", fmt.Sprintf("%t", result.Clean)},
		[]string{"no_code_signing", fmt.Sprintf("%t", result.NoCodeSigning)},
	)
	if result.Tests != nil {
		rows = append(
			rows,
			[]string{"tests_total", fmt.Sprintf("%d", result.Tests.Total)},
			[]string{"tests_passed", fmt.Sprintf("%d", result.Tests.Passed)},
			[]string{"tests_failed", fmt.Sprintf("%d", result.Tests.Failed)},
			[]string{"tests_skipped", fmt.Sprintf("%d", result.Tests.Skipped)},
			[]string{"tests_duration_ms", fmt.Sprintf("%d", result.Tests.DurationMS)},
		)
	}
	rows = append(
		rows,
		[]string{"success", fmt.Sprintf("%t", result.Success)},
		[]string{"duration_ms", fmt.Sprintf("%d", result.DurationMS)},
	)
	if result.ExitStatus != nil {
		rows = append(rows, []string{"exit_status", fmt.Sprintf("%d", *result.ExitStatus)})
	}
	return rows
}

func testResultJUnitReport(result *localxcode.TestResult) *shared.JUnitReport {
	tests := make([]shared.JUnitTestCase, 0, len(result.Tests.Cases))
	for _, testCase := range result.Tests.Cases {
		name := testCase.Name
		if name == "" {
			name = testCase.Identifier
		}
		if name == "" {
			name = "unnamed-test"
		}
		failure := ""
		message := ""
		skipped := strings.EqualFold(testCase.Status, "skipped")
		if strings.EqualFold(testCase.Status, "failed") {
			failure = "FAILURE"
			message = testCase.Message
			if strings.TrimSpace(message) == "" {
				message = testFailureMessage(result.Tests, testCase.Identifier)
			}
		}
		tests = append(tests, shared.JUnitTestCase{
			Name:      name,
			Classname: testCase.Classname,
			Time:      durationFromMilliseconds(testCase.DurationMS),
			Skipped:   skipped,
			Failure:   failure,
			Message:   message,
		})
	}
	if len(tests) == 0 {
		name := "asc xcode test"
		failure := ""
		message := ""
		if !result.Success || result.Tests.Failed > 0 {
			failure = "FAILURE"
			message = "test action reported failure"
		}
		tests = append(tests, shared.JUnitTestCase{
			Name:    name,
			Failure: failure,
			Message: message,
			Time:    durationFromMilliseconds(result.Tests.DurationMS),
		})
	}
	return &shared.JUnitReport{Tests: tests, Timestamp: time.Now(), Name: "asc xcode test"}
}

func testFailureMessage(summary *localxcode.TestSummary, identifier string) string {
	if summary == nil {
		return ""
	}
	for _, failure := range summary.Failures {
		if failure.Identifier == identifier {
			return failure.Message
		}
	}
	return ""
}

func durationFromMilliseconds(value int64) time.Duration {
	return time.Duration(value) * time.Millisecond
}
