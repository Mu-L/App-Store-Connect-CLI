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
	"strings"
	"syscall"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

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
