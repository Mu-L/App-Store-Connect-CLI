package xcode

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStapleRunsResolutionThenStapleThenValidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App;$(touch should-not-run).dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")

	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_STAPLE_STDOUT", "staple stdout\n")
	t.Setenv("ASC_STAPLER_STAPLE_STDERR", "staple stderr\n")
	t.Setenv("ASC_STAPLER_VALIDATE_STDOUT", "validate stdout\n")
	t.Setenv("ASC_STAPLER_VALIDATE_STDERR", "validate stderr\n")

	var diagnostics bytes.Buffer
	result, err := Staple(context.Background(), target, &diagnostics)
	if err != nil {
		t.Fatalf("Staple() error = %v", err)
	}
	if result == nil || result.Path != target || result.Operation != string(StaplerOperationStaple) || !result.Stapled || !result.Validated {
		t.Fatalf("Staple() result = %#v, want a verified staple result", result)
	}
	if !strings.Contains(diagnostics.String(), "staple stdout") ||
		!strings.Contains(diagnostics.String(), "staple stderr") ||
		!strings.Contains(diagnostics.String(), "validate stdout") ||
		!strings.Contains(diagnostics.String(), "validate stderr") {
		t.Fatalf("diagnostics = %q, want child stdout/stderr", diagnostics.String())
	}

	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
		"xcrun|stapler|validate|" + target,
	})
}

func TestStapleRunsStageVerifierAroundEachOperation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	var stages []string
	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		position := "after"
		if before {
			position = "before"
		}
		stages = append(stages, position+" "+string(operation))
		return nil
	})
	if err != nil {
		t.Fatalf("StapleWithVerifier() error = %v", err)
	}
	if result == nil || !result.Stapled || !result.Validated {
		t.Fatalf("StapleWithVerifier() result = %#v, want verified result", result)
	}
	want := []string{"before staple", "after staple", "before validate", "after validate"}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("verified stages = %#v, want %#v", stages, want)
	}
}

func TestValidateStapleRunsOnlyValidationAfterResolution(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	result, err := ValidateStaple(context.Background(), target, ioDiscardForStaplerTest{})
	if err != nil {
		t.Fatalf("ValidateStaple() error = %v", err)
	}
	if result == nil || result.Path != target || result.Operation != string(StaplerOperationValidate) || result.Stapled || !result.Validated {
		t.Fatalf("ValidateStaple() result = %#v, want a validation-only result", result)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|validate|" + target,
	})
}

func TestStapleStopsBeforeValidationWhenStapleFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_STAPLE_EXIT_CODE", "66")
	t.Setenv("ASC_STAPLER_STAPLE_STDERR", "not a supported artifact\n")

	var diagnostics bytes.Buffer
	result, err := Staple(context.Background(), target, &diagnostics)
	if result != nil {
		t.Fatalf("Staple() result = %#v, want nil on staple failure", result)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("Staple() error = %T %v, want StaplerCommandError", err, err)
	}
	if commandErr.Operation != string(StaplerOperationStaple) || commandErr.ExitCode != 66 {
		t.Fatalf("Staple() command error = %#v, want staple/66", commandErr)
	}
	if !strings.Contains(diagnostics.String(), "not a supported artifact") {
		t.Fatalf("diagnostics = %q, want child diagnostic", diagnostics.String())
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleReturnsValidationFailureAfterMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_VALIDATE_EXIT_CODE", "65")
	t.Setenv("ASC_STAPLER_VALIDATE_STDERR", "ticket mismatch\n")

	var diagnostics bytes.Buffer
	result, err := Staple(context.Background(), target, &diagnostics)
	if result != nil {
		t.Fatalf("Staple() result = %#v, want nil when follow-up validation fails", result)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("Staple() error = %T %v, want StaplerCommandError", err, err)
	}
	if commandErr.Operation != string(StaplerOperationValidate) || commandErr.ExitCode != 65 {
		t.Fatalf("Staple() command error = %#v, want validate/65", commandErr)
	}
	if !strings.Contains(diagnostics.String(), "ticket mismatch") {
		t.Fatalf("diagnostics = %q, want validation diagnostic", diagnostics.String())
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
		"xcrun|stapler|validate|" + target,
	})
}

func TestStaplerRejectsUnsupportedPlatformBeforeToolLookup(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "linux"
	t.Cleanup(func() { runtimeGOOS = previousOS })
	previousLookPath := lookPathFn
	lookPathFn = func(string) (string, error) {
		t.Fatal("lookPathFn called on unsupported platform")
		return "", nil
	}
	t.Cleanup(func() { lookPathFn = previousLookPath })

	result, err := Staple(context.Background(), "/tmp/MyApp.dmg", nil)
	if result != nil {
		t.Fatalf("Staple() result = %#v, want nil", result)
	}
	if err == nil || !strings.Contains(err.Error(), "macOS only") {
		t.Fatalf("Staple() error = %v, want macOS-only failure", err)
	}
}

func TestStaplerReportsMissingXcrunWithoutStartingChild(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "darwin"
	t.Cleanup(func() { runtimeGOOS = previousOS })
	previousLookPath := lookPathFn
	lookPathFn = func(file string) (string, error) {
		if file == "xcrun" {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/" + file, nil
	}
	t.Cleanup(func() { lookPathFn = previousLookPath })
	previousCommandContext := commandContextFn
	commandContextFn = func(context.Context, string, ...string) *exec.Cmd {
		t.Fatal("commandContextFn called when xcrun is missing")
		return nil
	}
	t.Cleanup(func() { commandContextFn = previousCommandContext })

	_, err := Staple(context.Background(), "/tmp/MyApp.dmg", nil)
	if err == nil || !strings.Contains(err.Error(), "xcrun not available") {
		t.Fatalf("Staple() error = %v, want missing-xcrun failure", err)
	}
}

func TestStaplerPreservesResolutionExitStatus(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_FIND_EXIT_CODE", "64")

	_, err := Staple(context.Background(), target, nil)
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("Staple() error = %T %v, want StaplerCommandError", err, err)
	}
	if commandErr.Operation != string(StaplerOperationResolve) || commandErr.ExitCode != 64 {
		t.Fatalf("Staple() command error = %#v, want resolve/64", commandErr)
	}
}

func TestStaplerPropagatesCancellationWithoutSuccess(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_WAIT", "1")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	result, err := Staple(ctx, target, nil)
	if result != nil {
		t.Fatalf("Staple() result = %#v, want nil after cancellation", result)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Staple() error = %v, want context deadline", err)
	}
}

func configureStaplerTestEnvironment(t *testing.T, logPath string) {
	t.Helper()
	previousOS := runtimeGOOS
	runtimeGOOS = "darwin"
	t.Cleanup(func() { runtimeGOOS = previousOS })
	previousLookPath := lookPathFn
	lookPathFn = func(file string) (string, error) {
		if file != "xcrun" {
			return "", fmt.Errorf("unexpected lookup %q", file)
		}
		return "/usr/bin/xcrun", nil
	}
	t.Cleanup(func() { lookPathFn = previousLookPath })
	previousCommandContext := commandContextFn
	commandContextFn = staplerHelperCommandContext(t, logPath)
	t.Cleanup(func() { commandContextFn = previousCommandContext })
	t.Setenv("GO_WANT_STAPLER_HELPER", "1")
}

func staplerHelperCommandContext(t *testing.T, logPath string) func(context.Context, string, ...string) *exec.Cmd {
	t.Helper()
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commandArgs := []string{"-test.run=TestStaplerHelperProcess", "--", name}
		commandArgs = append(commandArgs, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], commandArgs...)
		cmd.Env = append(os.Environ(), "GO_WANT_STAPLER_HELPER=1", "ASC_STAPLER_HELPER_LOG="+logPath)
		return cmd
	}
}

func TestStaplerHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_STAPLER_HELPER") != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing helper arguments")
		os.Exit(2)
	}
	args := os.Args[separator+1:]
	if err := appendStaplerHelperLog(os.Getenv("ASC_STAPLER_HELPER_LOG"), args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if len(args) == 3 && args[0] == "xcrun" && args[1] == "--find" && args[2] == "stapler" {
		if code := staplerHelperExitCode("ASC_STAPLER_FIND_EXIT_CODE"); code >= 0 {
			fmt.Fprintln(os.Stderr, "stapler lookup failed")
			os.Exit(code)
		}
		fmt.Fprintln(os.Stdout, "/usr/bin/stapler")
		os.Exit(0)
	}
	if len(args) >= 4 && args[0] == "xcrun" && args[1] == "stapler" {
		operation := strings.ToUpper(args[2][:1]) + args[2][1:]
		if output := os.Getenv("ASC_STAPLER_" + strings.ToUpper(args[2]) + "_STDOUT"); output != "" {
			fmt.Fprint(os.Stdout, output)
		}
		if output := os.Getenv("ASC_STAPLER_" + strings.ToUpper(args[2]) + "_STDERR"); output != "" {
			fmt.Fprint(os.Stderr, output)
		}
		if os.Getenv("ASC_STAPLER_WAIT") == "1" {
			for {
				time.Sleep(time.Second)
			}
		}
		if code := staplerHelperExitCode("ASC_STAPLER_" + strings.ToUpper(args[2]) + "_EXIT_CODE"); code >= 0 {
			fmt.Fprintf(os.Stderr, "%s failed\n", operation)
			os.Exit(code)
		}
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "unexpected helper invocation: %v\n", args)
	os.Exit(2)
}

func staplerHelperExitCode(name string) int {
	value := os.Getenv(name)
	if value == "" {
		return -1
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		return 2
	}
	return code
}

func appendStaplerHelperLog(path string, args []string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, strings.Join(args, "|"))
	return err
}

type ioDiscardForStaplerTest struct{}

func (ioDiscardForStaplerTest) Write(p []byte) (int, error) { return len(p), nil }

func assertStaplerCommands(t *testing.T, logPath string, want []string) {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(got) != len(want) {
		t.Fatalf("commands = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("command %d = %q, want %q", index, got[index], want[index])
		}
	}
}
