package notarization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

type staplerModeFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info staplerModeFileInfo) Mode() os.FileMode {
	return info.mode
}

func TestNotarizationStapleCommandPrintsComputedJSON(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if verifier == nil {
			t.Fatal("staple runner received no stage verifier")
		}
		if err := invokeStapleVerifier(verifier); err != nil {
			return nil, err
		}
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
	runStaplerStaple = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
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

func TestStaplerRegularFileFingerprintBindsSameSizeBytes(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(targetPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	expected, err := target.captureRegularFileFingerprintAtStage(context.Background(), "after stapling")
	if err != nil {
		t.Fatalf("capture regular-file fingerprint: %v", err)
	}
	if err := os.WriteFile(targetPath, []byte("changed!"), 0o600); err != nil {
		t.Fatalf("rewrite target: %v", err)
	}
	err = target.verifyRegularFileFingerprint(context.Background(), expected, "before validation")
	if err == nil {
		t.Fatal("verifyRegularFileFingerprint() = nil, want same-size byte mismatch")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("verifyRegularFileFingerprint() error = %T %v, want identity error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) {
		t.Fatalf("verification error = %q, must not expose target path", err.Error())
	}
}

func TestNotarizationStapleRejectsSameInodeRegularFileRewriteBeforeValidation(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(targetPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	validationChildCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, false); err != nil {
			return nil, err
		}
		if err := os.WriteFile(targetPath, []byte("changed!"), 0o600); err != nil {
			t.Fatalf("rewrite target: %v", err)
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		validationChildCalls++
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationStaple), Stapled: true, Validated: true}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want same-inode rewrite failure")
	}
	if validationChildCalls != 0 {
		t.Fatalf("validation child calls = %d, want zero after fingerprint mismatch", validationChildCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed before validate") {
		t.Fatalf("stderr = %q, want regular-file fingerprint stage diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationValidateRejectsSameInodeRegularFileRewriteAfterValidation(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(targetPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		if err := os.WriteFile(targetPath, []byte("changed!"), 0o600); err != nil {
			t.Fatalf("rewrite target: %v", err)
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationValidate), Validated: true}, nil
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("validate command error = nil, want same-inode rewrite failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed after validation") {
		t.Fatalf("stderr = %q, want regular-file fingerprint stage diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationStapleRejectsOversizedRegularFileBeforeRunner(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "oversized.dmg")
	if err := os.WriteFile(targetPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Truncate(targetPath, staplerInventoryMaxBytes+1); err != nil {
		t.Fatalf("sparsely grow target: %v", err)
	}

	previous := runStaplerStaple
	runnerCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, _ localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		runnerCalls++
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want preflight size rejection")
	}
	if runnerCalls != 0 {
		t.Fatalf("stapler runner calls = %d, want zero before fingerprint-size validation", runnerCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want stable filesystem diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) || strings.Contains(stderr, strconv.FormatInt(staplerInventoryMaxBytes, 10)) {
		t.Fatalf("stderr = %q, must not expose target path or private size cap", stderr)
	}
}

func TestNotarizationStapleRejectsRegularFileGrowthBeforeChild(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "growing.dmg")
	if err := os.WriteFile(targetPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	previous := runStaplerStaple
	childCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := os.Truncate(targetPath, staplerInventoryMaxBytes+1); err != nil {
			t.Fatalf("grow target before staple: %v", err)
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		childCalls++
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want growth rejection before child")
	}
	if childCalls != 0 {
		t.Fatalf("stapler child calls = %d, want zero after pre-child growth rejection", childCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want stable filesystem diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) || strings.Contains(stderr, strconv.FormatInt(staplerInventoryMaxBytes, 10)) {
		t.Fatalf("stderr = %q, must not expose target path or private size cap", stderr)
	}
}

func TestNotarizationStapleRejectsOversizedDirectoryBeforeRunner(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	oversizedPath := filepath.Join(targetPath, "Contents", "Oversized.bin")
	if err := os.MkdirAll(filepath.Dir(oversizedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(oversizedPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	if err := os.Truncate(oversizedPath, staplerInventoryMaxBytes+1); err != nil {
		t.Fatalf("sparsely grow oversized fixture: %v", err)
	}

	previous := runStaplerStaple
	runnerCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, _ localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		runnerCalls++
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want preflight inventory-size rejection")
	}
	if runnerCalls != 0 {
		t.Fatalf("stapler runner calls = %d, want zero before inventory-size validation", runnerCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want stable filesystem diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) || strings.Contains(stderr, strconv.FormatInt(staplerInventoryMaxBytes, 10)) {
		t.Fatalf("stderr = %q, must not expose target path or private size cap", stderr)
	}
}

func TestNotarizationStapleRejectsDirectoryOverEntryCapBeforeRunner(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}

	previousNames := readdirStaplerInventoryNamesFn
	readdirStaplerInventoryNamesFn = func(_ *os.File, _ int) ([]string, error) {
		return make([]string, staplerInventoryMaxEntries), io.EOF
	}
	t.Cleanup(func() { readdirStaplerInventoryNamesFn = previousNames })

	previous := runStaplerStaple
	runnerCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, _ localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		runnerCalls++
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", targetPath, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want preflight entry-cap rejection")
	}
	if runnerCalls != 0 {
		t.Fatalf("stapler runner calls = %d, want zero before entry-cap validation", runnerCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed before stapling") {
		t.Fatalf("stderr = %q, want stable entry-cap diagnostic", stderr)
	}
	if strings.Contains(stderr, targetPath) || strings.Contains(stderr, strconv.Itoa(staplerInventoryMaxEntries)) {
		t.Fatalf("stderr = %q, must not expose target path or private entry cap", stderr)
	}
}

func TestValidateStaplerTargetResolvesRelativeParentFromPhysicalWorkingDirectory(t *testing.T) {
	workspace := t.TempDir()
	physical := filepath.Join(workspace, "physical")
	physicalCWD := filepath.Join(physical, "nested")
	if err := os.MkdirAll(physicalCWD, 0o755); err != nil {
		t.Fatalf("create physical cwd: %v", err)
	}
	target := filepath.Join(physical, "target.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logicalCWD := filepath.Join(workspace, "logical-cwd")
	if err := os.Symlink(physicalCWD, logicalCWD); err != nil {
		t.Fatalf("create logical cwd symlink: %v", err)
	}
	originalCWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	if err := os.Chdir(logicalCWD); err != nil {
		t.Fatalf("change to logical cwd: %v", err)
	}
	t.Setenv("PWD", logicalCWD)
	t.Cleanup(func() {
		if err := os.Chdir(originalCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
	if got, err := os.Getwd(); err != nil || got != logicalCWD {
		t.Skipf("platform does not expose a logical symlinked cwd (got %q, err %v)", got, err)
	}

	validated, err := validateStaplerTargetDetails("../target.pkg")
	if err != nil {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want target relative to physical cwd", err)
	}
	defer validated.close()
	physicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("resolve physical target: %v", err)
	}
	if validated.path != physicalTarget {
		t.Fatalf("validated path = %q, want physical target %q", validated.path, physicalTarget)
	}
}

func TestValidateStaplerTargetRejectsRelativeTargetAfterCWDReplacement(t *testing.T) {
	workspace := t.TempDir()
	physicalCWD := filepath.Join(workspace, "physical")
	if err := os.Mkdir(physicalCWD, 0o755); err != nil {
		t.Fatalf("create physical cwd: %v", err)
	}
	targetPath := filepath.Join(physicalCWD, "target.dmg")
	if err := os.WriteFile(targetPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write original target: %v", err)
	}
	originalCWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	if err := os.Chdir(physicalCWD); err != nil {
		t.Fatalf("change cwd: %v", err)
	}
	previousHook := afterStaplerPathResolutionFn
	replaced := false
	afterStaplerPathResolutionFn = func() {
		if replaced {
			return
		}
		replaced = true
		if err := os.Rename(physicalCWD, physicalCWD+".original"); err != nil {
			t.Fatalf("rename original cwd: %v", err)
		}
		if err := os.Mkdir(physicalCWD, 0o755); err != nil {
			t.Fatalf("create replacement cwd: %v", err)
		}
		if err := os.WriteFile(filepath.Join(physicalCWD, "target.dmg"), []byte("replacement"), 0o600); err != nil {
			t.Fatalf("write replacement target: %v", err)
		}
	}
	t.Cleanup(func() {
		afterStaplerPathResolutionFn = previousHook
		if err := os.Chdir(originalCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
		if replaced {
			if err := os.RemoveAll(physicalCWD); err != nil {
				t.Errorf("remove replacement cwd: %v", err)
			}
			if err := os.Rename(physicalCWD+".original", physicalCWD); err != nil {
				t.Errorf("restore original cwd: %v", err)
			}
		}
	})

	validated, err := validateStaplerTargetDetails("target.dmg")
	if validated != nil {
		validated.close()
	}
	if err == nil {
		t.Fatal("validateStaplerTargetDetails() = nil, want cwd replacement rejection")
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want closed operational cwd identity failure", err)
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("validateStaplerTargetDetails() error = %T %v, want proven cwd identity error", err, err)
	}
	var verifyErr *staplerTargetVerifyError
	if errors.As(err, &verifyErr) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, cwd replacement must not be operational verification", err)
	}
}

func TestStaplerTargetRetainedWorkingDirectoryHandleFailureIsOperational(t *testing.T) {
	target := newRelativeStaplerTargetForTest(t)
	if err := target.workingDirectory.Close(); err != nil {
		t.Fatalf("close retained working directory: %v", err)
	}

	err := target.verifyIdentity("before validation")
	if err == nil {
		t.Fatal("verifyIdentity() = nil, want retained-cwd stat failure")
	}
	var verifyErr *staplerTargetVerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("verifyIdentity() error = %T %v, want operational verification error", err, err)
	}
	var identityErr *staplerTargetIdentityError
	if errors.As(err, &identityErr) {
		t.Fatalf("verifyIdentity() error = %v, closed retained handle must not imply cwd replacement", err)
	}
}

func TestStaplerTargetRetainedWorkingDirectoryPathFailureIsOperational(t *testing.T) {
	target := newRelativeStaplerTargetForTest(t)
	previous := statStaplerWorkingDirectoryPathFn
	statStaplerWorkingDirectoryPathFn = func(string) (os.FileInfo, error) {
		return nil, syscall.EACCES
	}
	t.Cleanup(func() { statStaplerWorkingDirectoryPathFn = previous })

	err := target.verifyIdentity("before validation")
	if err == nil {
		t.Fatal("verifyIdentity() = nil, want retained-cwd path stat failure")
	}
	var verifyErr *staplerTargetVerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("verifyIdentity() error = %T %v, want operational verification error", err, err)
	}
	var identityErr *staplerTargetIdentityError
	if errors.As(err, &identityErr) {
		t.Fatalf("verifyIdentity() error = %v, EACCES must not imply cwd replacement", err)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("verifyIdentity() error = %v, want retained EACCES cause", err)
	}
}

func newRelativeStaplerTargetForTest(t *testing.T) *validatedStaplerTarget {
	t.Helper()
	directory := t.TempDir()
	pathValue := filepath.Join(directory, "target.dmg")
	if err := os.WriteFile(pathValue, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write relative target: %v", err)
	}
	originalCWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original cwd: %v", err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatalf("change cwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
	target, err := validateStaplerTargetDetails("target.dmg")
	if err != nil {
		t.Fatalf("validate relative target: %v", err)
	}
	t.Cleanup(target.close)
	if target.workingDirectory == nil {
		t.Fatal("validated target retained no working-directory handle")
	}
	return target
}

func TestNotarizationValidateRejectsDirectoryQualifiedRegularFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	previousOpenFile := openStaplerTargetFileFn
	previousRunner := runStaplerValidate
	fileOpenCalls := 0
	runnerCalls := 0
	openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
		fileOpenCalls++
		return nil, errors.New("regular-file fallback must not run")
	}
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		runnerCalls++
		return nil, errors.New("stapler runner must not run")
	}
	t.Cleanup(func() {
		openStaplerTargetFileFn = previousOpenFile
		runStaplerValidate = previousRunner
	})

	for _, suffix := range []string{string(filepath.Separator), string(filepath.Separator) + "."} {
		t.Run(fmt.Sprintf("suffix-%q", suffix), func(t *testing.T) {
			cmd := validateStapleCommand()
			if err := cmd.FlagSet.Parse([]string{"--file", target + suffix, "--output", "json"}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			var runErr error
			stdout, stderr := captureNotarizationOutput(t, func() {
				runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
			})
			if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
				t.Fatalf("command error = %v, want usage rejection", runErr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty before stapler", stdout)
			}
			if !strings.Contains(stderr, "directory bundle") {
				t.Fatalf("stderr = %q, want directory-qualified target diagnostic", stderr)
			}
		})
	}
	if fileOpenCalls != 0 {
		t.Fatalf("regular file open calls = %d, want no fallback for directory-qualified path", fileOpenCalls)
	}
	if runnerCalls != 0 {
		t.Fatalf("stapler runner calls = %d, want no child invocation", runnerCalls)
	}
}

func TestValidateStaplerTargetAcceptsDirectoryQualifiedBundle(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}

	for _, suffix := range []string{string(filepath.Separator), string(filepath.Separator) + "."} {
		t.Run(fmt.Sprintf("suffix-%q", suffix), func(t *testing.T) {
			validated, err := validateStaplerTargetDetails(target + suffix)
			if err != nil {
				t.Fatalf("validateStaplerTargetDetails() error = %v", err)
			}
			if !validated.directory {
				t.Fatalf("validated target = %#v, want directory target", validated)
			}
			validated.close()
		})
	}
}

func TestNotarizationValidateRejectsSymlinkParentBeforeLexicalParentTraversal(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	// Build this path without filepath.Join: Join/Clean would erase the
	// lexical parent traversal that the command must inspect first.
	pathValue := link + string(filepath.Separator) + ".." + string(filepath.Separator) + "target.pkg"

	previous := runStaplerValidate
	calls := 0
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("stapler runner must not be called")
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", pathValue, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("command error = %v, want usage error before traversal", runErr)
	}
	if calls != 0 {
		t.Fatalf("stapler runner calls = %d, want 0", calls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty on rejected path", stdout)
	}
	if !strings.Contains(stderr, "symlink") {
		t.Fatalf("stderr = %q, want symlink diagnostic", stderr)
	}
}

func TestNotarizationValidateRejectsMissingParentBeforeLexicalParentTraversal(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	pathValue := filepath.Join(root, "missing") + string(filepath.Separator) + ".." + string(filepath.Separator) + "target.pkg"

	previous := runStaplerValidate
	calls := 0
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("stapler runner must not be called")
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", pathValue, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("command error = %v, want usage error before traversal", runErr)
	}
	if calls != 0 {
		t.Fatalf("stapler runner calls = %d, want 0", calls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty on rejected path", stdout)
	}
	if !strings.Contains(stderr, "missing component") {
		t.Fatalf("stderr = %q, want missing-component diagnostic", stderr)
	}
}

func TestNotarizationValidateRejectsNonDirectoryParentBeforeLexicalParentTraversal(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "regular-parent")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write regular parent: %v", err)
	}
	target := filepath.Join(root, "target.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	pathValue := parent + string(filepath.Separator) + ".." + string(filepath.Separator) + "target.pkg"

	previous := runStaplerValidate
	calls := 0
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("stapler runner must not be called")
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", pathValue, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil || !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("command error = %v, want usage error before traversal", runErr)
	}
	if calls != 0 {
		t.Fatalf("stapler runner calls = %d, want 0", calls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty on rejected path", stdout)
	}
	if !strings.Contains(stderr, "non-directory component") {
		t.Fatalf("stderr = %q, want non-directory diagnostic", stderr)
	}
}

func TestValidateStaplerTargetAllowsCleanParentTraversal(t *testing.T) {
	root := t.TempDir()
	normal := filepath.Join(root, "normal")
	if err := os.Mkdir(normal, 0o755); err != nil {
		t.Fatalf("create normal parent: %v", err)
	}
	target := filepath.Join(root, "target.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	pathValue := normal + string(filepath.Separator) + ".." + string(filepath.Separator) + "target.pkg"

	validated, err := validateStaplerTargetDetails(pathValue)
	if err != nil {
		t.Fatalf("validateStaplerTargetDetails() error = %v, clean parent traversal should remain valid", err)
	}
	validated.close()
}

func TestRejectSymlinkedLexicalParentTraversalAllowsSymlinkAncestorWhenPoppingChild(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "child"), 0o755); err != nil {
		t.Fatalf("create child: %v", err)
	}

	pathValue := link + string(filepath.Separator) + "child" + string(filepath.Separator) + ".." + string(filepath.Separator) + "artifact"
	if err := rejectSymlinkedLexicalParentTraversal(pathValue); err != nil {
		t.Fatalf("rejectSymlinkedLexicalParentTraversal() = %v, want clean traversal after popping child", err)
	}
}

func TestRejectSymlinkedLexicalParentTraversalChecksPoppedMacOSAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("/var alias behavior is specific to macOS")
	}

	pathValue := "/var" + string(filepath.Separator) + ".." + string(filepath.Separator) + "tmp"
	if err := rejectSymlinkedLexicalParentTraversal(pathValue); !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("rejectSymlinkedLexicalParentTraversal() = %v, want /var alias symlink rejection", err)
	}
}

func TestValidateStaplerTargetAcceptsDirectoryBundle(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	got, err := validateStaplerTarget(target)
	if err != nil {
		t.Fatalf("validateStaplerTarget() error = %v", err)
	}
	if got != target {
		t.Fatalf("validateStaplerTarget() = %q, want %q", got, target)
	}
}

func TestValidateStaplerTargetDetailsPreservesDirectoryOpenFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	wantErr := errors.New("directory open failed")
	previous := openStaplerTargetDirFn
	openStaplerTargetDirFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, wantErr
	}
	t.Cleanup(func() { openStaplerTargetDirFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want directory-open error", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, operational failure must not be usage", err)
	}
}

func TestValidateStaplerTargetDetailsDoesNotClassifyDirectoryPhraseAsWrongKind(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	wantErr := errors.New("directory probe failed: is not a directory")
	previous := openStaplerTargetDirFn
	openStaplerTargetDirFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, wantErr
	}
	t.Cleanup(func() { openStaplerTargetDirFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want injected error", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, phrase-bearing operational failure must not be usage", err)
	}
}

func TestValidateStaplerTargetDetailsDoesNotFallbackDirectoryOpenRace(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	previous := openStaplerTargetDirFn
	openStaplerTargetDirFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, &staplerTargetDirectoryOpenError{err: fmt.Errorf("target changed: %w", syscall.ENOTDIR)}
	}
	t.Cleanup(func() { openStaplerTargetDirFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want wrapped ENOTDIR", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, directory-open race must remain operational", err)
	}
}

func TestValidateStaplerTargetDetailsDoesNotClassifyRegularFilePhraseInPathAsUsage(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "is not a regular file")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	target := filepath.Join(parent, "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := openStaplerTargetFileFn
	openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
		// Real rooted opens embed the pathname in the message, so an
		// operational failure on this artifact carries the wrong-kind phrase.
		return nil, fmt.Errorf("open %s: %w", target, syscall.EACCES)
	}
	t.Cleanup(func() { openStaplerTargetFileFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want EACCES", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, pathname text must not make it usage", err)
	}
}

func TestValidateStaplerTargetDetailsRejectsSpecialFileWithoutPathnameMatching(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	baseInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	previousProbe := probeStaplerTargetKindFn
	probeStaplerTargetKindFn = func(rootfs.Root, string) (os.FileInfo, error) {
		return staplerModeFileInfo{FileInfo: baseInfo, mode: os.ModeNamedPipe | 0o600}, nil
	}
	t.Cleanup(func() { probeStaplerTargetKindFn = previousProbe })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want usage error for a special file", err)
	}
	if !strings.Contains(err.Error(), "is not a regular file or directory bundle") {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want stable special-file diagnostic", err)
	}
}

func TestValidateStaplerTargetDetailsRejectsSameKindReplacementAfterProbe(t *testing.T) {
	tests := []struct {
		name      string
		directory bool
	}{
		{name: "regular file", directory: false},
		{name: "directory bundle", directory: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			target := filepath.Join(parent, "MyApp.pkg")
			replacement := filepath.Join(parent, "replacement")
			preserved := filepath.Join(parent, "preserved-original")
			if test.directory {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("create target directory: %v", err)
				}
				if err := os.Mkdir(replacement, 0o700); err != nil {
					t.Fatalf("create replacement directory: %v", err)
				}
				previousOpen := openStaplerTargetDirectoryFn
				openStaplerTargetDirectoryFn = func(root rootfs.Root, relative string) (*os.File, error) {
					if err := os.Rename(target, preserved); err != nil {
						t.Fatalf("preserve target: %v", err)
					}
					if err := os.Rename(replacement, target); err != nil {
						t.Fatalf("replace target: %v", err)
					}
					return root.OpenDir(relative)
				}
				t.Cleanup(func() { openStaplerTargetDirectoryFn = previousOpen })
			} else {
				if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
				if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
					t.Fatalf("write replacement: %v", err)
				}
				previousOpen := openStaplerTargetFileFn
				openStaplerTargetFileFn = func(root rootfs.Root, relative string) (*os.File, error) {
					if err := os.Rename(target, preserved); err != nil {
						t.Fatalf("preserve target: %v", err)
					}
					if err := os.Rename(replacement, target); err != nil {
						t.Fatalf("replace target: %v", err)
					}
					return root.OpenFile(relative)
				}
				t.Cleanup(func() { openStaplerTargetFileFn = previousOpen })
			}

			validated, err := validateStaplerTargetDetails(target)
			if validated != nil {
				validated.close()
				t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
			}
			if !errors.Is(err, errStaplerTargetRaced) {
				t.Fatalf("validateStaplerTargetDetails() error = %v, want replacement race", err)
			}
			if isStaplerTargetUsageError(err) {
				t.Fatalf("validateStaplerTargetDetails() error = %v, replacement race must remain operational", err)
			}
		})
	}
}

func TestValidateStaplerTargetDetailsKeepsPostProbeReplacementOperational(t *testing.T) {
	tests := []struct {
		name    string
		failure error
	}{
		{name: "removed after probe", failure: syscall.ENOENT},
		{name: "replaced by symlink after probe", failure: rootfs.ErrSymlink},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "MyApp.pkg")
			if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
				t.Fatalf("write target: %v", err)
			}
			previous := openStaplerTargetFileFn
			openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
				return nil, test.failure
			}
			t.Cleanup(func() { openStaplerTargetFileFn = previous })

			validated, err := validateStaplerTargetDetails(target)
			if validated != nil {
				validated.close()
				t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
			}
			if !errors.Is(err, test.failure) {
				t.Fatalf("validateStaplerTargetDetails() error = %v, want %v", err, test.failure)
			}
			// The probe already proved the target existed and was not a
			// symlink, so a later disagreement is a race, not operator input.
			if isStaplerTargetUsageError(err) {
				t.Fatalf("validateStaplerTargetDetails() error = %v, post-probe race must stay operational", err)
			}
			if strings.Contains(err.Error(), target) && isStaplerTargetUsageError(err) {
				t.Fatalf("validateStaplerTargetDetails() error = %v, must not expose the path as usage", err)
			}
		})
	}
}

func TestNotarizationValidateReportsPostProbeReplacementAsRuntimeFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previousOpen := openStaplerTargetFileFn
	previousRunner := runStaplerValidate
	openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, syscall.ENOENT
	}
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		t.Fatal("validation runner should not be called after a post-probe race")
		return nil, nil
	}
	t.Cleanup(func() {
		openStaplerTargetFileFn = previousOpen
		runStaplerValidate = previousRunner
	})

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want runtime failure")
	}
	if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
		t.Fatalf("command error = %v, post-probe race must not be usage", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want sanitized filesystem failure", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestValidateStaplerTargetDetailsTreatsPostOpenKindFlipAsRace(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	swapped := filepath.Join(root, "swapped")
	if err := os.Mkdir(swapped, 0o755); err != nil {
		t.Fatalf("create swapped directory: %v", err)
	}
	previous := openStaplerTargetFileFn
	openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
		// The probe saw a regular file; hand back a handle that no longer is
		// one, as a replacement between probe and open would.
		return os.Open(swapped)
	}
	t.Cleanup(func() { openStaplerTargetFileFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, errStaplerTargetRaced) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want the race sentinel", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, a race must not be usage", err)
	}
}

func TestValidateStaplerTargetDetailsPinsArtifactInodeForTheOperation(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "regular file"
		if directory {
			name = "directory bundle"
		}
		t.Run(name, func(t *testing.T) {
			var target string
			if directory {
				target = filepath.Join(t.TempDir(), "MyApp.app")
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatalf("create target: %v", err)
				}
			} else {
				target = filepath.Join(t.TempDir(), "MyApp.pkg")
				if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
			}

			validated, err := validateStaplerTargetDetails(target)
			if err != nil {
				t.Fatalf("validateStaplerTargetDetails() error = %v", err)
			}
			t.Cleanup(validated.close)

			// Unlink the artifact. A retained descriptor keeps the inode
			// allocated, so a replacement cannot receive the recycled file ID
			// and satisfy os.SameFile against the recorded identity.
			if err := os.Remove(target); err != nil {
				t.Fatalf("remove target: %v", err)
			}

			pinned, statErr := validated.pinnedIdentity()
			if statErr != nil {
				t.Fatalf("pinnedIdentity() error = %v, want the artifact descriptor retained", statErr)
			}
			if !os.SameFile(validated.identity, pinned) {
				t.Fatalf("pinnedIdentity() = %#v, want the originally validated artifact", pinned)
			}
		})
	}
}

func TestNotarizationValidateReportsFilesystemFailureWhenIdentityReopenFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previousOpenFile := openStaplerTargetFileFn
	previousDetails := validateStaplerDetailsFn
	previousRunner := runStaplerValidate
	calls := 0
	// Validate the real target first, then revoke reopen so only the stage
	// boundary fails. The artifact itself is never replaced.
	validateStaplerDetailsFn = func(pathValue string) (*validatedStaplerTarget, error) {
		validated, err := validateStaplerTargetDetails(pathValue)
		if err == nil {
			openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
				return nil, syscall.EACCES
			}
		}
		return validated, err
	}
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		calls++
		return nil, errors.New("runner should not be called")
	}
	t.Cleanup(func() {
		openStaplerTargetFileFn = previousOpenFile
		validateStaplerDetailsFn = previousDetails
		runStaplerValidate = previousRunner
	})

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want operational stage failure")
	}
	if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
		t.Fatalf("command error = %v, reopen failure must not be usage", runErr)
	}
	if calls != 0 {
		t.Fatalf("validation runner calls = %d, want 0", calls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want filesystem diagnostic", stderr)
	}
	if strings.Contains(stderr, "artifact target changed") {
		t.Fatalf("stderr = %q, unchanged artifact must not be reported as replaced", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestNotarizationValidateReportsNonRegularReplacementAtStage(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	baseInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	previousOpenFile := openStaplerTargetFileFn
	previousProbe := probeStaplerTargetKindFn
	previousDetails := validateStaplerDetailsFn
	previousRunner := runStaplerValidate
	validateStaplerDetailsFn = func(pathValue string) (*validatedStaplerTarget, error) {
		validated, err := validateStaplerTargetDetails(pathValue)
		if err == nil {
			// Model a FIFO/device/socket replacement through the probe seam without
			// creating a blocking special file on the test filesystem.
			probeStaplerTargetKindFn = func(rootfs.Root, string) (os.FileInfo, error) {
				return staplerModeFileInfo{FileInfo: baseInfo, mode: os.ModeNamedPipe | 0o600}, nil
			}
			openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
				return nil, syscall.EACCES
			}
		}
		return validated, err
	}
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		t.Fatal("validation runner should not be called after stage identity failure")
		return nil, nil
	}
	t.Cleanup(func() {
		openStaplerTargetFileFn = previousOpenFile
		probeStaplerTargetKindFn = previousProbe
		validateStaplerDetailsFn = previousDetails
		runStaplerValidate = previousRunner
	})

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want stage identity failure")
	}
	if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
		t.Fatalf("command error = %v, stage replacement must not be usage", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty on stage identity failure", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed before validation") {
		t.Fatalf("stderr = %q, want stable stage-specific identity diagnostic", stderr)
	}
	if strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, non-regular replacement must not be generic filesystem failure", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestNotarizationValidateReportsParentKindSwapAtStage(t *testing.T) {
	rootDir := t.TempDir()
	parent := filepath.Join(rootDir, "artifact-parent")
	preservedParent := filepath.Join(rootDir, "preserved-parent")
	target := filepath.Join(parent, "MyApp.pkg")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("create target parent: %v", err)
	}
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	previousDetails := validateStaplerDetailsFn
	previousRunner := runStaplerValidate
	validateStaplerDetailsFn = func(pathValue string) (*validatedStaplerTarget, error) {
		validated, err := validateStaplerTargetDetails(pathValue)
		if err != nil {
			return nil, err
		}
		if err := os.Rename(parent, preservedParent); err != nil {
			validated.close()
			return nil, fmt.Errorf("preserve target parent: %w", err)
		}
		if err := os.WriteFile(parent, []byte("replacement"), 0o600); err != nil {
			validated.close()
			return nil, fmt.Errorf("replace parent with regular file: %w", err)
		}
		return validated, nil
	}
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		t.Fatal("validation runner should not be called after parent kind swap")
		return nil, nil
	}
	t.Cleanup(func() {
		validateStaplerDetailsFn = previousDetails
		runStaplerValidate = previousRunner
	})

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want parent kind-swap identity failure")
	}
	if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
		t.Fatalf("command error = %v, stage parent replacement must not be usage", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty on stage identity failure", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed before validation") {
		t.Fatalf("stderr = %q, want stable stage-specific identity diagnostic", stderr)
	}
	if strings.Contains(stderr, "could not inspect artifact filesystem") || strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, want redacted identity diagnostic", stderr)
	}
}

func TestNotarizationValidateChildAndPostVerifierFailurePreservesExitAndStage(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	childErr := errors.New("validation child failed")
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		return nil, errors.Join(
			&localxcode.StaplerCommandError{
				Operation: string(localxcode.StaplerOperationValidate),
				ExitCode:  65,
				Err:       childErr,
			},
			&localxcode.StaplerStageVerificationError{
				Operation: localxcode.StaplerOperationValidate,
				Before:    false,
				Err:       &staplerTargetIdentityError{stage: "after validation"},
			},
		)
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, childErr) {
		t.Fatalf("command error = %v, want child cause", runErr)
	}
	if code, ok := sharedProcessExitCodeForTest(runErr); !ok || code != 65 {
		t.Fatalf("command error = %v, process code = %d/%v, want 65", runErr, code, ok)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed after validation") || !strings.Contains(stderr, "exit status 65") {
		t.Fatalf("stderr = %q, want stage diagnostic and child exit", stderr)
	}
	if strings.Contains(stderr, "staple completed") || strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, validate-only failure must not claim partial staple mutation", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationValidateChildAndOuterStageFailurePreservesExitAndStage(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	childErr := errors.New("validation child failed")
	previous := runStaplerValidate
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := replaceStaplerTargetForTest(target); err != nil {
			t.Fatalf("replace target: %v", err)
		}
		return nil, &localxcode.StaplerCommandError{
			Operation: string(localxcode.StaplerOperationValidate),
			ExitCode:  65,
			Err:       childErr,
		}
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, childErr) {
		t.Fatalf("command error = %v, want child cause", runErr)
	}
	if code, ok := sharedProcessExitCodeForTest(runErr); !ok || code != 65 {
		t.Fatalf("command error = %v, process code = %d/%v, want 65", runErr, code, ok)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed after validation") || !strings.Contains(stderr, "exit status 65") {
		t.Fatalf("stderr = %q, want outer stage diagnostic and child exit", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationStapleCancellationAndOuterStageFailurePreservesBoth(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := replaceStaplerTargetForTest(target); err != nil {
			t.Fatalf("replace target: %v", err)
		}
		return nil, context.Canceled
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("command error = %v, want cancellation cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed after stapling") {
		t.Fatalf("stderr = %q, want outer stage diagnostic", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestVerifyIdentityStillReportsRealReplacementWhenReopenSucceeds(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	validated, err := validateStaplerTargetDetails(target)
	if err != nil {
		t.Fatalf("validateStaplerTargetDetails() error = %v", err)
	}
	t.Cleanup(validated.close)

	if err := replaceStaplerTargetForTest(target); err != nil {
		t.Fatalf("replace target: %v", err)
	}
	stageErr := validated.verifyIdentity("before validation")
	var identityErr *staplerTargetIdentityError
	if !errors.As(stageErr, &identityErr) {
		t.Fatalf("verifyIdentity() error = %T %v, want identity error", stageErr, stageErr)
	}
	var verifyErr *staplerTargetVerifyError
	if errors.As(stageErr, &verifyErr) {
		t.Fatalf("verifyIdentity() error = %v, a real replacement must not be operational", stageErr)
	}
}

func TestNotarizationValidateCommandPrintsComputedJSONWithoutStapling(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if verifier == nil {
			t.Fatal("validation runner received no stage verifier")
		}
		if err := verifier(localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		result := &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationValidate),
			Validated: true,
		}
		if err := verifier(localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return result, nil
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

func TestNotarizationStapleRejectsTargetIdentityChangeAfterRunner(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, false); err != nil {
			return nil, err
		}
		if err := replaceStaplerTargetForTest(path); err != nil {
			t.Fatalf("replace target: %v", err)
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationStaple),
			Stapled:   true,
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want identity-drift failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed") {
		t.Fatalf("stderr = %q, want identity-drift diagnostic", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestNotarizationStapleRejectsNestedReplacementBeforeValidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	nested := filepath.Join(target, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nested, []byte("original"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	previous := runStaplerStaple
	validationChildCalls := 0
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := verifier(localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		if err := verifier(localxcode.StaplerOperationStaple, false); err != nil {
			return nil, err
		}
		if err := os.WriteFile(nested, []byte("replacement"), 0o600); err != nil {
			t.Fatalf("replace nested file: %v", err)
		}
		if err := verifier(localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		validationChildCalls++
		if err := verifier(localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationStaple), Stapled: true, Validated: true}, nil
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("command error = nil, want nested replacement failure")
	}
	if validationChildCalls != 0 {
		t.Fatalf("validation child calls = %d, want zero after nested preflight mismatch", validationChildCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed") || !strings.Contains(stderr, "before validation") {
		t.Fatalf("stderr = %q, want stable nested-mismatch stage", stderr)
	}
	if strings.Contains(stderr, target) || strings.Contains(stderr, "Info.plist") {
		t.Fatalf("stderr = %q, must not expose nested path", stderr)
	}
}

func TestNotarizationValidateRejectsTargetIdentityChangeAfterRunner(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if verifier != nil {
			if err := verifier(localxcode.StaplerOperationValidate, true); err != nil {
				return nil, err
			}
		}
		if err := replaceStaplerTargetForTest(path); err != nil {
			t.Fatalf("replace target: %v", err)
		}
		if verifier != nil {
			if err := verifier(localxcode.StaplerOperationValidate, false); err != nil {
				return nil, err
			}
		}
		return &localxcode.StaplerResult{
			Path:      path,
			Operation: string(localxcode.StaplerOperationValidate),
			Validated: true,
		}, nil
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want identity-drift failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed") {
		t.Fatalf("stderr = %q, want identity-drift diagnostic", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestValidateStaplerTargetDetailsPreservesEACCESWithoutFileFallback(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	previous := openStaplerTargetDirFn
	openStaplerTargetDirFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, syscall.EACCES
	}
	t.Cleanup(func() { openStaplerTargetDirFn = previous })

	validated, err := validateStaplerTargetDetails(target)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want EACCES", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, EACCES must remain operational", err)
	}
}

func TestNotarizationValidateCommandReportsEACCESWithoutFallbackOrSuccess(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	previousOpen := openStaplerTargetDirFn
	openStaplerTargetDirFn = func(rootfs.Root, string) (*os.File, error) {
		return nil, syscall.EACCES
	}
	previousRunner := runStaplerValidate
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		t.Fatal("validation runner should not be called after EACCES")
		return nil, nil
	}
	t.Cleanup(func() {
		openStaplerTargetDirFn = previousOpen
		runStaplerValidate = previousRunner
	})

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil {
		t.Fatal("command error = nil, want operational EACCES failure")
	}
	if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
		t.Fatalf("command error = %v, EACCES must not be usage", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if !strings.Contains(stderr, "could not inspect artifact filesystem") {
		t.Fatalf("stderr = %q, want stable filesystem failure", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose artifact path", stderr)
	}
}

func TestNotarizationValidateDefaultTargetHelperDoesNotFallbackTraversalFailures(t *testing.T) {
	tests := []struct {
		name      string
		directory bool
		configure func()
	}{
		{
			name: "contained traversal ENOTDIR",
			configure: func() {
				checkStaplerTargetContainedFn = func(rootfs.Root, string) error {
					return fmt.Errorf("parent traversal failed: %w", syscall.ENOTDIR)
				}
			},
		},
		{
			name: "kind probe traversal ENOTDIR",
			configure: func() {
				probeStaplerTargetKindFn = func(rootfs.Root, string) (os.FileInfo, error) {
					return nil, fmt.Errorf("kind probe traversal failed: %w", syscall.ENOTDIR)
				}
			},
		},
		{
			name: "kind probe EACCES",
			configure: func() {
				probeStaplerTargetKindFn = func(rootfs.Root, string) (os.FileInfo, error) {
					return nil, syscall.EACCES
				}
			},
		},
		{
			name: "kind probe phrase",
			configure: func() {
				probeStaplerTargetKindFn = func(rootfs.Root, string) (os.FileInfo, error) {
					return nil, errors.New("kind probe failed: is not a directory")
				}
			},
		},
		{
			name:      "directory open race ENOTDIR",
			directory: true,
			configure: func() {
				openStaplerTargetDirectoryFn = func(rootfs.Root, string) (*os.File, error) {
					return nil, fmt.Errorf("directory changed during open: %w", syscall.ENOTDIR)
				}
			},
		},
		{
			name: "file open race ENOTDIR",
			configure: func() {
				openStaplerTargetFileFn = func(rootfs.Root, string) (*os.File, error) {
					return nil, fmt.Errorf("target changed during file open: %w", syscall.ENOTDIR)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var target string
			if test.directory {
				target = filepath.Join(t.TempDir(), "MyApp.app")
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatalf("create target: %v", err)
				}
			} else {
				target = filepath.Join(t.TempDir(), "MyApp.pkg")
				if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
			}

			previousContained := checkStaplerTargetContainedFn
			previousProbe := probeStaplerTargetKindFn
			previousOpenDirectory := openStaplerTargetDirectoryFn
			previousOpenFile := openStaplerTargetFileFn
			previousRunner := runStaplerValidate
			calls := 0
			// Install only the case-specific failure. Each subtest restores every
			// wrapper seam in Cleanup, and the outer openStaplerTargetDirFn stays
			// on its default so the real classification path is exercised.
			test.configure()
			runStaplerValidate = func(_ context.Context, path string, _ io.Writer, _ localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
				calls++
				return &localxcode.StaplerResult{
					Path:      path,
					Operation: string(localxcode.StaplerOperationValidate),
					Validated: true,
				}, nil
			}
			t.Cleanup(func() {
				checkStaplerTargetContainedFn = previousContained
				probeStaplerTargetKindFn = previousProbe
				openStaplerTargetDirectoryFn = previousOpenDirectory
				openStaplerTargetFileFn = previousOpenFile
				runStaplerValidate = previousRunner
			})

			cmd := validateStapleCommand()
			if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			var runErr error
			stdout, stderr := captureNotarizationOutput(t, func() {
				runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
			})
			if runErr == nil {
				t.Fatal("command error = nil, want operational filesystem failure")
			}
			if errors.Is(runErr, flag.ErrHelp) || shared.IsReportedUsageError(runErr) {
				t.Fatalf("command error = %v, traversal/runtime failure must not be usage", runErr)
			}
			if calls != 0 {
				t.Fatalf("validation runner calls = %d, want no fallback invocation", calls)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want no success output", stdout)
			}
			if !strings.Contains(stderr, "could not inspect artifact filesystem") {
				t.Fatalf("stderr = %q, want stable filesystem failure", stderr)
			}
			if strings.Contains(stderr, target) {
				t.Fatalf("stderr = %q, must not expose artifact path", stderr)
			}
		})
	}
}

func replaceStaplerTargetForTest(path string) error {
	if err := os.Rename(path, path+".original"); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("replacement"), 0o600)
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
	runStaplerStaple = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
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
	runStaplerStaple = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
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
	runStaplerStaple = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
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
	runStaplerStaple = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStapleVerifier(verifier); err != nil {
			return nil, err
		}
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
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStapleVerifier(verifier); err != nil {
			return nil, err
		}
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
	var commandErr *localxcode.StaplerCommandError
	if !errors.As(runErr, &commandErr) || commandErr.ExitCode != 66 {
		t.Fatalf("command error = %T %v, want preserved stapler command cause", runErr, runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple failed") {
		t.Fatalf("stderr = %q, want failure stage", stderr)
	}
}

func TestNotarizationStapleCancellationAfterMutationReportsUnverified(t *testing.T) {
	for _, test := range []struct {
		name                 string
		cancelDuringValidate bool
		cause                error
		deadline             bool
	}{
		{name: "cancellation before follow-up validation", cause: context.Canceled},
		{name: "cancellation during follow-up validation", cancelDuringValidate: true, cause: context.Canceled},
		{name: "deadline before follow-up validation", cause: context.DeadlineExceeded, deadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "MyApp.dmg")
			if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
				t.Fatalf("write target: %v", err)
			}
			previous := runStaplerStaple
			ctx, cancel := context.WithCancel(context.Background())
			if test.deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
				if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
					return nil, err
				}
				if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, false); err != nil {
					return nil, err
				}
				if test.cancelDuringValidate {
					if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
						return nil, err
					}
				}
				if test.deadline {
					<-ctx.Done()
					return nil, &localxcode.StaplerPartialMutationError{
						Operation: localxcode.StaplerOperationValidate,
						Err:       ctx.Err(),
					}
				}
				cancel()
				return nil, &localxcode.StaplerPartialMutationError{
					Operation: localxcode.StaplerOperationValidate,
					Err:       test.cause,
				}
			}
			t.Cleanup(func() {
				cancel()
				runStaplerStaple = previous
			})

			cmd := stapleCommand()
			if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
				t.Fatalf("parse: %v", err)
			}
			var runErr error
			stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(ctx, nil) })
			if runErr == nil || !errors.Is(runErr, test.cause) {
				t.Fatalf("command error = %v, want %v", runErr, test.cause)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want no success JSON", stdout)
			}
			if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
				t.Fatalf("stderr = %q, want post-staple verification warning", stderr)
			}
			if strings.Contains(stderr, target) {
				t.Fatalf("stderr = %q, must not expose target path", stderr)
			}
		})
	}
}

func TestNotarizationStapleInterruptedDuringInitialChildDoesNotClaimCompletion(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation:   localxcode.StaplerOperationStaple,
			Interrupted: true,
			Err:         context.Canceled,
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("command error = %v, want cancellation cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple was interrupted") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want interrupted-staple warning", stderr)
	}
	if strings.Contains(stderr, "staple completed") || strings.Contains(stderr, "follow-up validation") || strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not claim completion or expose target path", stderr)
	}
}

func TestNotarizationStapleSignalDuringInitialChildReportsUnverified(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt is not implemented for child processes on Windows")
	}
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation:   localxcode.StaplerOperationStaple,
			Interrupted: true,
			Err: &localxcode.StaplerCommandError{
				Operation: string(localxcode.StaplerOperationStaple),
				ExitCode:  -1,
				Err:       errors.New("stapler child terminated by signal"),
			},
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
		t.Fatal("command error = nil, want signaled staple failure")
	}
	var partialErr *localxcode.StaplerPartialMutationError
	if !errors.As(runErr, &partialErr) || !partialErr.Interrupted {
		t.Fatalf("command error = %T %v, want interrupted partial marker", runErr, runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple was interrupted") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want interrupted-staple warning", stderr)
	}
	if strings.Contains(stderr, "staple completed") || strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not claim completion or expose target path", stderr)
	}
}

func TestNotarizationStaplePostStapleVerifierFailureReportsUnverified(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	wantErr := errors.New("target changed after staple")
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		stageErr := &localxcode.StaplerStageVerificationError{
			Operation: localxcode.StaplerOperationStaple,
			Before:    false,
			Err:       wantErr,
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation: localxcode.StaplerOperationStaple,
			Err:       stageErr,
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, wantErr) {
		t.Fatalf("command error = %v, want preserved verifier cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want post-staple verification warning", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationValidateRejectsNestedReplacementAfterChild(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	nested := filepath.Join(target, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nested, []byte("original"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := verifier(localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		if err := os.WriteFile(nested, []byte("replacement"), 0o600); err != nil {
			t.Fatalf("replace nested file: %v", err)
		}
		if err := verifier(localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationValidate), Validated: true}, nil
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("command error = nil, want nested replacement failure")
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "artifact target changed") || !strings.Contains(stderr, "after validation") {
		t.Fatalf("stderr = %q, want stable nested-mismatch stage", stderr)
	}
	if strings.Contains(stderr, target) || strings.Contains(stderr, "Info.plist") {
		t.Fatalf("stderr = %q, must not expose nested path", stderr)
	}
}

func TestNotarizationValidateDirectoryBundleWithStableNestedInventorySucceeds(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.app")
	nested := filepath.Join(target, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nested), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nested, []byte("original"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, path string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := verifier(localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		if err := verifier(localxcode.StaplerOperationValidate, false); err != nil {
			return nil, err
		}
		return &localxcode.StaplerResult{Path: path, Operation: string(localxcode.StaplerOperationValidate), Validated: true}, nil
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr != nil {
		t.Fatalf("command error = %v, want unchanged nested inventory success", runErr)
	}
	if stdout == "" || !strings.Contains(stdout, `"validated":true`) {
		t.Fatalf("stdout = %q, want validated JSON", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestNotarizationStapleJoinedChildAndPostStapleVerifierFailureReportsUnverified(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	wantErr := errors.New("target changed after staple")
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation: localxcode.StaplerOperationStaple,
			Err: errors.Join(
				&localxcode.StaplerCommandError{
					Operation: string(localxcode.StaplerOperationStaple),
					ExitCode:  66,
					Err:       errors.New("stapler child failed"),
				},
				&localxcode.StaplerStageVerificationError{
					Operation: localxcode.StaplerOperationStaple,
					Before:    false,
					Err:       &staplerTargetVerifyError{stage: "after stapling", err: wantErr},
				},
			),
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, wantErr) {
		t.Fatalf("command error = %v, want preserved verifier cause", runErr)
	}
	if code, ok := sharedProcessExitCodeForTest(runErr); !ok || code != 66 {
		t.Fatalf("command error = %v, process code = %d/%v, want 66", runErr, code, ok)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want post-staple warning", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationStaplePrioritizesPostStaplePartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	wantErr := errors.New("target changed after staple")
	stageErr := &localxcode.StaplerStageVerificationError{
		Operation: localxcode.StaplerOperationStaple,
		Before:    false,
		Err:       &staplerTargetVerifyError{stage: "after stapling", err: wantErr},
	}
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationStaple, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation: localxcode.StaplerOperationStaple,
			Err:       stageErr,
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, wantErr) {
		t.Fatalf("command error = %v, want preserved partial verifier cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want post-staple warning", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationStaplePostValidationVerifierFailureReportsUnverified(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	wantErr := errors.New("target changed after validation")
	previous := runStaplerStaple
	runStaplerStaple = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStapleVerifier(verifier); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerPartialMutationError{
			Operation: localxcode.StaplerOperationValidate,
			Err: &localxcode.StaplerStageVerificationError{
				Operation: localxcode.StaplerOperationValidate,
				Before:    false,
				Err:       &staplerTargetVerifyError{stage: "after validation", err: wantErr},
			},
		}
	}
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, wantErr) {
		t.Fatalf("command error = %v, want preserved verifier cause", runErr)
	}
	var partialErr *localxcode.StaplerPartialMutationError
	if !errors.As(runErr, &partialErr) || partialErr.Operation != localxcode.StaplerOperationValidate {
		t.Fatalf("command error = %T %v, want post-validation partial marker", runErr, runErr)
	}
	var verifyErr *staplerTargetVerifyError
	if !errors.As(runErr, &verifyErr) {
		t.Fatalf("command error = %T %v, want typed target verification cause", runErr, runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want post-validation warning", stderr)
	}
	if strings.Contains(stderr, target) {
		t.Fatalf("stderr = %q, must not expose target path", stderr)
	}
}

func TestNotarizationStapleProductionRunnerProjectsInventoryMismatchAsPartialMutation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("local stapler is macOS-only")
	}
	target := filepath.Join(t.TempDir(), "MyApp.app")
	nestedPath := filepath.Join(target, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}

	// Use a real localxcode.StapleWithVerifier invocation. The temporary xcrun
	// changes the nested file during validate, after the staple-stage inventory
	// was captured, so the command must take the production partial-mutation
	// projection rather than a test-only runner shortcut.
	fakeBin := t.TempDir()
	fakeXcrun := filepath.Join(fakeBin, "xcrun")
	const canary = "STAPLER_INVENTORY_DIGEST_CANARY_2242"
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--find\" ] && [ \"$2\" = \"stapler\" ]; then\n" +
		"  printf '%s\\n' /usr/bin/stapler\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"stapler\" ] && [ \"$2\" = \"staple\" ]; then\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"stapler\" ] && [ \"$2\" = \"validate\" ]; then\n" +
		"  printf '%s' '" + canary + "' > \"$3/Contents/Info.plist\"\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 2\n"
	if err := os.WriteFile(fakeXcrun, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake xcrun: %v", err)
	}
	oldPath, hadPath := os.LookupEnv("PATH")
	pathValue := fakeBin
	if hadPath {
		pathValue += string(os.PathListSeparator) + oldPath
	}
	t.Setenv("PATH", pathValue)

	previous := runStaplerStaple
	runStaplerStaple = localxcode.StapleWithVerifier
	t.Cleanup(func() { runStaplerStaple = previous })

	cmd := stapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("staple command error = nil, want partial-mutation failure")
	}
	var partialErr *localxcode.StaplerPartialMutationError
	if !errors.As(runErr, &partialErr) || partialErr.Operation != localxcode.StaplerOperationValidate {
		t.Fatalf("staple command error = %T %v, want production post-validation partial marker", runErr, runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if !strings.Contains(stderr, "staple completed") || !strings.Contains(stderr, "not verified") {
		t.Fatalf("stderr = %q, want generic unverified warning", stderr)
	}
	for _, secret := range []string{target, nestedPath, canary} {
		if strings.Contains(stderr, secret) {
			t.Fatalf("stderr = %q, must not expose %q", stderr, secret)
		}
	}
	contents, err := os.ReadFile(nestedPath)
	if err != nil {
		t.Fatalf("read mutated nested file: %v", err)
	}
	if string(contents) != canary {
		t.Fatalf("nested file = %q, want fake validator mutation", contents)
	}
}

func TestNotarizationValidateStartFailureRedactsUnderlyingDiagnostic(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	const canary = "START_PATH_CANARY_2242"
	underlying := errors.New("start /private/tmp/" + canary + "/xcrun: permission denied")
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerCommandError{
			Operation: string(localxcode.StaplerOperationValidate),
			ExitCode:  -1,
			Err:       underlying,
		}
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil {
		t.Fatal("command error = nil, want start failure")
	}
	if !errors.Is(runErr, underlying) {
		t.Fatalf("command error = %v, want preserved underlying cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success JSON", stdout)
	}
	if strings.Contains(stderr, canary) || strings.Contains(stderr, "/private/tmp/") {
		t.Fatalf("stderr = %q, must redact underlying start diagnostic", stderr)
	}
	if !strings.Contains(stderr, "failed during validate before a usable exit status") {
		t.Fatalf("stderr = %q, want stable start-failure diagnostic", stderr)
	}
}

func TestNotarizationValidateResolutionFailureRedactsLookupPath(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	const canary = "RESOLUTION_PATH_CANARY_2242"
	underlying := errors.New("lookpath /private/tmp/" + canary + "/xcrun: permission denied")
	previous := runStaplerValidate
	runStaplerValidate = func(_ context.Context, _ string, _ io.Writer, verifier localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		if err := invokeStaplerStage(verifier, localxcode.StaplerOperationValidate, true); err != nil {
			return nil, err
		}
		return nil, &localxcode.StaplerResolutionError{Err: underlying}
	}
	t.Cleanup(func() { runStaplerValidate = previous })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", target, "--output", "json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var runErr error
	stdout, stderr := captureNotarizationOutput(t, func() { runErr = cmd.Exec(context.Background(), nil) })
	if runErr == nil || !errors.Is(runErr, underlying) {
		t.Fatalf("command error = %v, want lookup cause", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no success output", stdout)
	}
	if strings.Contains(stderr, canary) || strings.Contains(stderr, "/private/tmp/") {
		t.Fatalf("stderr = %q, must redact lookup path", stderr)
	}
	if !strings.Contains(stderr, "stapler tool resolution failed") {
		t.Fatalf("stderr = %q, want stable resolution diagnostic", stderr)
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

func invokeStapleVerifier(verifier localxcode.StaplerStageVerifier) error {
	for _, stage := range []struct {
		operation localxcode.StaplerOperation
		before    bool
	}{
		{operation: localxcode.StaplerOperationStaple, before: true},
		{operation: localxcode.StaplerOperationStaple, before: false},
		{operation: localxcode.StaplerOperationValidate, before: true},
		{operation: localxcode.StaplerOperationValidate, before: false},
	} {
		if err := invokeStaplerStage(verifier, stage.operation, stage.before); err != nil {
			return err
		}
	}
	return nil
}

func invokeStaplerStage(verifier localxcode.StaplerStageVerifier, operation localxcode.StaplerOperation, before bool) error {
	if verifier == nil {
		return nil
	}
	return verifier(operation, before)
}

func sharedProcessExitCodeForTest(err error) (int, bool) {
	return shared.ProcessExitCode(err)
}

func TestValidateStaplerTargetRejectsUnsearchableLexicalParentBeforeClean(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatalf("create blocked parent: %v", err)
	}
	target := filepath.Join(root, "App.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	pathValue := blocked + string(filepath.Separator) + ".." + string(filepath.Separator) + "App.dmg"

	previous := openStaplerLexicalDirectoryFn
	calls := 0
	openStaplerLexicalDirectoryFn = func(path string) (*os.File, error) {
		calls++
		if filepath.Clean(path) != blocked {
			t.Fatalf("lexical directory path = %q, want %q", path, blocked)
		}
		return nil, syscall.EACCES
	}
	t.Cleanup(func() { openStaplerLexicalDirectoryFn = previous })

	validated, err := validateStaplerTargetDetails(pathValue)
	if validated != nil {
		validated.close()
		t.Fatalf("validateStaplerTargetDetails() target = %#v, want nil", validated)
	}
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, want EACCES", err)
	}
	if isStaplerTargetUsageError(err) {
		t.Fatalf("validateStaplerTargetDetails() error = %v, search failure must remain operational", err)
	}
	if calls != 1 {
		t.Fatalf("lexical directory opens = %d, want one searchability check before cleaning", calls)
	}

	previousRunner := runStaplerValidate
	runnerCalls := 0
	runStaplerValidate = func(context.Context, string, io.Writer, localxcode.StaplerStageVerifier) (*localxcode.StaplerResult, error) {
		runnerCalls++
		return nil, errors.New("stapler child must not start")
	}
	t.Cleanup(func() { runStaplerValidate = previousRunner })

	cmd := validateStapleCommand()
	if err := cmd.FlagSet.Parse([]string{"--file", pathValue, "--output", "json"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	var runErr error
	stdout, _ := captureNotarizationOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})
	if runErr == nil || isStaplerTargetUsageError(runErr) {
		t.Fatalf("validate command error = %v, want operational filesystem failure", runErr)
	}
	if runnerCalls != 0 {
		t.Fatalf("stapler child calls = %d, want zero", runnerCalls)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if calls != 2 {
		t.Fatalf("lexical directory opens = %d, want one per validation", calls)
	}
}

func TestRejectSymlinkedLexicalParentTraversalChecksSearchPermissionWithoutRequiringRead(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("search-only directory semantics are covered on Darwin and Linux")
	}
	skipIfDACOverrideForStaplerTest(t)
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatalf("create lexical parent: %v", err)
	}
	pathValue := blocked + string(filepath.Separator) + ".." + string(filepath.Separator) + "App.dmg"

	if err := os.Chmod(blocked, 0o444); err != nil {
		t.Fatalf("remove lexical parent search permission: %v", err)
	}
	if err := rejectSymlinkedLexicalParentTraversal(pathValue); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("unsearchable lexical parent error = %v, want EACCES", err)
	}

	if err := os.Chmod(blocked, 0o111); err != nil {
		t.Fatalf("grant search-only lexical parent permission: %v", err)
	}
	if err := rejectSymlinkedLexicalParentTraversal(pathValue); err != nil {
		t.Fatalf("search-only lexical parent rejected: %v", err)
	}
}

func skipIfDACOverrideForStaplerTest(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("mode-bit permission assertions are not deterministic for root")
	}
	if runtime.GOOS != "linux" {
		return
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			continue
		}
		capabilities, err := strconv.ParseUint(fields[1], 16, 64)
		if err == nil && capabilities&((1<<1)|(1<<2)) != 0 { // CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH
			t.Skip("mode-bit permission assertions are not deterministic with DAC override/search capability")
		}
	}
}

func TestRejectSymlinkedLexicalParentTraversalRejectsOpenedDirectoryIdentityChange(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	replacement := filepath.Join(root, "replacement")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatalf("create original directory: %v", err)
	}
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatalf("create replacement directory: %v", err)
	}
	pathValue := original + string(filepath.Separator) + ".." + string(filepath.Separator) + "App.dmg"

	previous := openStaplerLexicalDirectoryFn
	openStaplerLexicalDirectoryFn = func(string) (*os.File, error) {
		return os.Open(replacement)
	}
	t.Cleanup(func() { openStaplerLexicalDirectoryFn = previous })

	if err := rejectSymlinkedLexicalParentTraversal(pathValue); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("directory identity change error = %v, want fail-closed race error", err)
	}
}
