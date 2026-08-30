package notarization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

func TestNotarizationStapleCommandPrintsComputedJSON(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer) (*localxcode.StaplerResult, error) {
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json", "--pretty"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr != nil {
		t.Fatalf("staple command error = %v", runErr)
	}
	var result asc.NotarizationStapleResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode stdout: %v; stdout=%q", err, stdout)
	}
	if result.FilePath != target || result.Operation != "staple" || !result.Stapled || !result.Validated {
		t.Fatalf("result = %#v, want verified staple output", result)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty for fake successful runner", stderr)
	}
	if !strings.Contains(stdout, "\n  \"filePath\"") {
		t.Fatalf("stdout = %q, want pretty JSON", stdout)
	}
}

func TestNotarizationStapleRequiresConfirmationBeforeTargetOrRunner(t *testing.T) {
	previous := runStaplerStaple
	calls := 0
	runStaplerStaple = func(context.Context, string, io.Writer) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("runner should not be called")
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	missingTarget := filepath.Join(t.TempDir(), "missing.dmg")
	if err := cmd.FlagSet.Parse([]string{"--file", missingTarget}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("command error = %v, want usage error", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "--confirm is required") {
		t.Fatalf("stderr = %q, want missing-confirm diagnostic", stderr)
	}
	if strings.Contains(stderr, "does not exist") {
		t.Fatalf("stderr = %q, target validation ran before confirmation", stderr)
	}
	if calls != 0 {
		t.Fatalf("runner calls = %d, want 0 without confirmation", calls)
	}
}

func TestNotarizationStapleHelpRequiresConfirmation(t *testing.T) {
	cmd := stapleCommand()
	if cmd.FlagSet.Lookup("confirm") == nil {
		t.Fatal("staple command is missing --confirm")
	}
	if !strings.Contains(cmd.ShortUsage, "--confirm") {
		t.Fatalf("short usage = %q, want --confirm", cmd.ShortUsage)
	}
	if !strings.Contains(cmd.LongHelp, "--confirm") {
		t.Fatalf("long help = %q, want --confirm guidance", cmd.LongHelp)
	}
}

func TestNotarizationLocalCommandsAreExperimental(t *testing.T) {
	for _, test := range []struct {
		name  string
		cmd   *ffcli.Command
		flags []string
	}{
		{name: "staple", cmd: stapleCommand(), flags: []string{"file", "confirm"}},
		{name: "validate", cmd: validateStapleCommand(), flags: []string{"file"}},
	} {
		if !strings.HasPrefix(test.cmd.ShortHelp, "[experimental] ") {
			t.Errorf("%s short help = %q, want experimental marker", test.name, test.cmd.ShortHelp)
		}
		if !strings.HasPrefix(test.cmd.LongHelp, "[experimental] ") {
			t.Errorf("%s long help = %q, want experimental marker", test.name, test.cmd.LongHelp)
		}
		for _, flagName := range test.flags {
			flagValue := test.cmd.FlagSet.Lookup(flagName)
			usage := "<missing>"
			if flagValue != nil {
				usage = flagValue.Usage
			}
			if flagValue == nil || !strings.HasPrefix(usage, "[experimental] ") {
				t.Errorf("%s --%s usage = %q, want experimental marker", test.name, flagName, usage)
			}
		}
	}
}

func TestNotarizationFileFlagRejectsRepeatedUse(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	value := bindSingleStringFlag(fs, "file", "artifact path")
	if err := fs.Parse([]string{"--file", "first", "--file", "second"}); err == nil {
		t.Fatal("repeated --file should fail")
	}
	if value.String() != "first" {
		t.Fatalf("value = %q, want first value preserved", value.String())
	}
}

func TestValidateStaplerTargetPreservesTrailingWhitespace(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg ")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	got, err := validateStaplerTarget(target)
	if err != nil {
		t.Fatalf("validateStaplerTarget() error = %v", err)
	}
	if got != target {
		t.Fatalf("validateStaplerTarget() = %q, want %q", got, target)
	}
}

func TestNotarizationValidateCommandPrintsComputedJSONWithoutStapling(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer) (*localxcode.StaplerResult, error) {
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationValidate),
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr != nil {
		t.Fatalf("validate command error = %v", runErr)
	}
	var result asc.NotarizationValidateResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode stdout: %v; stdout=%q", err, stdout)
	}
	if result.FilePath != target || result.Operation != "validate" || !result.Validated {
		t.Fatalf("result = %#v, want validated output", result)
	}
	if strings.Contains(stdout, "stapled") {
		t.Fatalf("stdout = %q, validate output must not claim stapling", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty for fake successful runner", stderr)
	}
}

func TestNotarizationStapleRejectsInvalidTargetsBeforeRunner(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid.dmg")
	if err := os.WriteFile(valid, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write valid target: %v", err)
	}
	empty := filepath.Join(root, "empty.pkg")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty target: %v", err)
	}
	zipPath := filepath.Join(root, "archive.zip")
	if err := os.WriteFile(zipPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write zip target: %v", err)
	}
	symlinkPath := filepath.Join(root, "link.dmg")
	if err := os.Symlink(valid, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	parentTarget := filepath.Join(root, "real", "target.dmg")
	if err := os.MkdirAll(filepath.Dir(parentTarget), 0o755); err != nil {
		t.Fatalf("create parent target: %v", err)
	}
	if err := os.WriteFile(parentTarget, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write parent target: %v", err)
	}
	parentLink := filepath.Join(root, "linked-parent")
	if err := os.Symlink(filepath.Dir(parentTarget), parentLink); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}

	previous := runStaplerStaple
	calls := 0
	runStaplerStaple = func(context.Context, string, io.Writer) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("runner should not be called")
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "missing", path: filepath.Join(root, "missing.dmg"), want: "does not exist"},
		{name: "empty", path: empty, want: "must not be empty"},
		{name: "zip", path: zipPath, want: "directly"},
		{name: "final symlink", path: symlinkPath, want: "symlink"},
		{name: "parent symlink", path: filepath.Join(parentLink, "target.dmg"), want: "symlink"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := stapleCommand()
			if err := cmd.FlagSet.Parse([]string{"--file", test.path, "--confirm"}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			var runErr error
			_, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
			if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
				t.Fatalf("command error = %v, want usage error", runErr)
			}
			if !strings.Contains(stderr, test.want) {
				t.Fatalf("stderr = %q, want %q", stderr, test.want)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("runner calls = %d, want 0 for invalid targets", calls)
	}
}

func TestNotarizationStapleRejectsPositionalArgumentsBeforeRunner(t *testing.T) {
	previous := runStaplerStaple
	runStaplerStaple = func(context.Context, string, io.Writer) (*localxcode.StaplerResult, error) {
		t.Fatal("runner should not be called")
		return nil, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", "artifact.dmg", "--confirm", "unexpected"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	_, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args()) })
	if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("command error = %v, want usage error", runErr)
	}
	if !strings.Contains(stderr, "does not accept positional arguments") {
		t.Fatalf("stderr = %q, want positional-argument diagnostic", stderr)
	}
}

func TestNotarizationStapleRejectsInvalidOutputBeforeRunner(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	calls := 0
	runStaplerStaple = func(context.Context, string, io.Writer) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("runner should not be called")
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	for _, args := range [][]string{
		{"--file", target, "--confirm", "--output", "yaml"},
		{"--file", target, "--confirm", "--output", "table", "--pretty"},
		{"--file", "", "--confirm"},
	} {
		cmd := stapleCommand()
		if err := cmd.FlagSet.Parse(args); err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		var runErr error
		_, stderr := captureNotarizationOutput(t, func() {
			runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
		})
		if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
			t.Fatalf("args %v: command error = %v, want usage error", args, runErr)
		}
		if stderr == "" {
			t.Fatalf("args %v: stderr is empty, want preflight diagnostic", args)
		}
	}
	if calls != 0 {
		t.Fatalf("runner calls = %d, want 0 for invalid invocation", calls)
	}
}

func TestNotarizationStapleRejectsUnverifiedRunnerResult(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer) (*localxcode.StaplerResult, error) {
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationStaple)}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want unverified-result failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "did not report a verified ticket") {
		t.Fatalf("stderr = %q, want unverified-result diagnostic", stderr)
	}
}

func TestNotarizationStapleFailurePreservesChildExitStatusAndDoesNotPrintJSON(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(context.Context, string, io.Writer) (*localxcode.StaplerResult, error) {
		return nil, &localxcode.StaplerCommandError{
			Operation: string(localxcode.StaplerOperationStaple),
			ExitCode:  66,
			Err:       errors.New("child command exited with status 66"),
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("command error = nil, want child failure")
	}
	if code, ok := sharedProcessExitCodeForTest(runErr); !ok || code != 66 {
		t.Fatalf("command error = %v, process code = %d/%v, want 66", runErr, code, ok)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple failed") {
		t.Fatalf("stderr = %q, want failure stage", stderr)
	}
}

func captureNotarizationOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	outC := make(chan string, 1)
	errC := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		_ = rOut.Close()
		outC <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		_ = rErr.Close()
		errC <- buf.String()
	}()
	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	return <-outC, <-errC
}

func sharedProcessExitCodeForTest(err error) (int, bool) {
	return shared.ProcessExitCode(err)
}
