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

func TestStapleWithVerifierMarksPostStapleVerifierFailureAsPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	wantErr := errors.New("target changed after staple")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationStaple && !before {
			return wantErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after verifier failure", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationStaple {
		t.Fatalf("StapleWithVerifier() error = %T %v, want post-staple partial marker", err, err)
	}
	if !strings.Contains(err.Error(), "post-staple") {
		t.Fatalf("StapleWithVerifier() error = %v, want post-staple phase", err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleWithVerifierJoinsStapleChildAndPostStapleVerifierFailures(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_STAPLE_EXIT_CODE", "66")
	verifierErr := errors.New("target changed after staple")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationStaple && !before {
			return verifierErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after post-staple verification failure", result)
	}
	if !errors.Is(err, verifierErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationStaple {
		t.Fatalf("StapleWithVerifier() error = %T %v, want staple partial marker", err, err)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) || commandErr.Operation != string(StaplerOperationStaple) || commandErr.ExitCode != 66 {
		t.Fatalf("StapleWithVerifier() error = %T %v, want joined staple/66 child error", err, err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) || stageErr.Before {
		t.Fatalf("StapleWithVerifier() error = %T %v, want post-staple stage error", err, err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleWithVerifierMarksPreValidationVerifierFailureAsPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	verifierErr := errors.New("target changed before validation")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationValidate && before {
			return verifierErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after post-staple verification failure", result)
	}
	if !errors.Is(err, verifierErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationStaple {
		t.Fatalf("StapleWithVerifier() error = %T %v, want staple partial marker", err, err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) || !stageErr.Before || stageErr.Operation != StaplerOperationValidate {
		t.Fatalf("StapleWithVerifier() error = %T %v, want pre-validation stage error", err, err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleWithVerifierMarksPostValidationVerifierFailureAsPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	wantErr := errors.New("target changed after validation")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationValidate && !before {
			return wantErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after verifier failure", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationValidate {
		t.Fatalf("StapleWithVerifier() error = %T %v, want post-validation partial marker", err, err)
	}
	if !strings.Contains(err.Error(), "after staple") {
		t.Fatalf("StapleWithVerifier() error = %v, want post-staple phase", err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
		"xcrun|stapler|validate|" + target,
	})
}

func TestStapleWithVerifierJoinsPostValidationChildAndVerifierFailures(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_VALIDATE_EXIT_CODE", "65")
	verifierErr := errors.New("target changed after validation")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationValidate && !before {
			return verifierErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after verifier failure", result)
	}
	if !errors.Is(err, verifierErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationValidate {
		t.Fatalf("StapleWithVerifier() error = %T %v, want post-validation partial marker", err, err)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) || commandErr.Operation != string(StaplerOperationValidate) || commandErr.ExitCode != 65 {
		t.Fatalf("StapleWithVerifier() error = %T %v, want joined validate/65 child error", err, err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
		"xcrun|stapler|validate|" + target,
	})
}

func TestStapleWithVerifierKeepsPreStapleVerifierFailureOrdinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	wantErr := errors.New("target unavailable before staple")

	result, err := StapleWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationStaple && before {
			return wantErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil before verifier failure", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("StapleWithVerifier() error = %v, want verifier cause", err)
	}
	var partialErr *StaplerPartialMutationError
	if errors.As(err, &partialErr) {
		t.Fatalf("StapleWithVerifier() error = %v, pre-staple failure must not be partial mutation", err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) || !stageErr.Before {
		t.Fatalf("StapleWithVerifier() error = %T %v, want pre-staple stage error", err, err)
	}
	assertStaplerCommands(t, logPath, []string{"xcrun|--find|stapler"})
}

func TestStapleWithVerifierMarksCancellationBeforeFollowUpValidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stages []string
	result, err := StapleWithVerifier(ctx, target, nil, func(operation StaplerOperation, before bool) error {
		position := "after"
		if before {
			position = "before"
		}
		stages = append(stages, position+" "+string(operation))
		if operation == StaplerOperationStaple && !before {
			cancel()
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil after cancellation", result)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StapleWithVerifier() error = %v, want context cancellation", err)
	}
	if !strings.Contains(err.Error(), "after staple") {
		t.Fatalf("StapleWithVerifier() error = %v, want post-staple validation phase", err)
	}
	if want := []string{"before staple", "after staple", "before validate", "after validate"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("verified stages = %#v, want %#v", stages, want)
	}
}

func TestStapleWithVerifierMarksCancellationDuringFollowUpValidation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	readyPath := filepath.Join(t.TempDir(), "validate-ready")
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_VALIDATE_WAIT", "1")
	t.Setenv("ASC_STAPLER_VALIDATE_READY_PATH", readyPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result *StaplerResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := StapleWithVerifier(ctx, target, nil, func(StaplerOperation, bool) error {
			return nil
		})
		done <- outcome{result: result, err: err}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			cancel()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("validation helper did not report readiness")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("StapleWithVerifier() result = %#v, want nil after cancellation", got.result)
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("StapleWithVerifier() error = %v, want context cancellation", got.err)
		}
		if !strings.Contains(got.err.Error(), "after staple") {
			t.Fatalf("StapleWithVerifier() error = %v, want post-staple validation phase", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StapleWithVerifier() did not return after cancellation")
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

func TestValidateWithVerifierRunsVerifierAroundValidationChild(t *testing.T) {
	target := filepath.Join(t.TempDir(), "My App.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	var stages []string
	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		position := "after"
		if before {
			position = "before"
		}
		stages = append(stages, position+" "+string(operation))
		return nil
	})
	if err != nil {
		t.Fatalf("ValidateWithVerifier() error = %v", err)
	}
	if result == nil || result.Path != target || result.Operation != string(StaplerOperationValidate) || result.Stapled || !result.Validated {
		t.Fatalf("ValidateWithVerifier() result = %#v, want a validation-only result", result)
	}
	if want := []string{"before validate", "after validate"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("verified stages = %#v, want %#v", stages, want)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|validate|" + target,
	})
}

func TestValidateWithVerifierWrapsStageErrorsAndSkipsValidationChild(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	wantErr := errors.New("target identity mismatch")

	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation != StaplerOperationValidate || !before {
			t.Fatalf("verifier called for %s before=%t, want validate before", operation, before)
		}
		return wantErr
	})
	if result != nil {
		t.Fatalf("ValidateWithVerifier() result = %#v, want nil on verifier failure", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("ValidateWithVerifier() error = %v, want wrapped verifier error", err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) {
		t.Fatalf("ValidateWithVerifier() error = %T %v, want stage verification error", err, err)
	}
	if stageErr.Operation != StaplerOperationValidate || !stageErr.Before {
		t.Fatalf("stage verification error = %#v, want validate/before", stageErr)
	}
	assertStaplerCommands(t, logPath, []string{"xcrun|--find|stapler"})
}

func TestValidateWithVerifierRunsAfterVerifierWhenValidationFails(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_VALIDATE_EXIT_CODE", "65")

	var stages []string
	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		position := "after"
		if before {
			position = "before"
		}
		stages = append(stages, position+" "+string(operation))
		return nil
	})
	if result != nil {
		t.Fatalf("ValidateWithVerifier() result = %#v, want nil on child failure", result)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) || commandErr.Operation != string(StaplerOperationValidate) || commandErr.ExitCode != 65 {
		t.Fatalf("ValidateWithVerifier() error = %#v, want validate/65 command error", err)
	}
	if want := []string{"before validate", "after validate"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("verified stages = %#v, want %#v", stages, want)
	}
}

func TestValidateWithVerifierJoinsChildAndPostValidationVerifierFailures(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_VALIDATE_EXIT_CODE", "65")
	verifierErr := errors.New("target changed after validation")

	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationValidate && !before {
			return verifierErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("ValidateWithVerifier() result = %#v, want nil after post-validation verifier failure", result)
	}
	if !errors.Is(err, verifierErr) {
		t.Fatalf("ValidateWithVerifier() error = %v, want verifier cause", err)
	}
	var commandErr *StaplerCommandError
	if !errors.As(err, &commandErr) || commandErr.Operation != string(StaplerOperationValidate) || commandErr.ExitCode != 65 {
		t.Fatalf("ValidateWithVerifier() error = %T %v, want joined validate/65 child error", err, err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) || stageErr.Before || stageErr.Operation != StaplerOperationValidate {
		t.Fatalf("ValidateWithVerifier() error = %T %v, want post-validation stage error", err, err)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|validate|" + target,
	})
}

func TestValidateWithVerifierRejectsReplacementDetectedAfterLookup(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	originalInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_SWAP_ON_FIND", target)
	restored := false
	t.Cleanup(func() {
		if restored {
			return
		}
		replacementPath := target + ".replacement"
		if _, statErr := os.Stat(target); statErr == nil {
			_ = os.Rename(target, replacementPath)
		}
		_ = os.Rename(target+".original", target)
		_ = os.Remove(replacementPath)
	})

	wantErr := errors.New("target identity changed")
	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		if operation != StaplerOperationValidate || !before {
			t.Fatalf("verifier called for %s before=%t, want validate before", operation, before)
		}
		current, statErr := os.Stat(target)
		if statErr != nil {
			return statErr
		}
		if !os.SameFile(originalInfo, current) {
			return wantErr
		}
		return nil
	})
	if result != nil {
		t.Fatalf("ValidateWithVerifier() result = %#v, want nil on replacement", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("ValidateWithVerifier() error = %v, want replacement failure", err)
	}
	assertStaplerCommands(t, logPath, []string{"xcrun|--find|stapler"})

	if err := os.Rename(target, target+".replacement"); err != nil {
		t.Fatalf("move replacement: %v", err)
	}
	if err := os.Rename(target+".original", target); err != nil {
		t.Fatalf("restore original target: %v", err)
	}
	restored = true
}

func TestValidateWithVerifierRestoresLookupSwapBeforeValidationChild(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	original := []byte("original")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	observedPath := filepath.Join(t.TempDir(), "observed-by-child")
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_SWAP_AND_RESTORE_ON_FIND", target)
	t.Setenv("ASC_STAPLER_VALIDATE_OBSERVED_PATH", observedPath)

	var stages []string
	result, err := ValidateWithVerifier(context.Background(), target, nil, func(operation StaplerOperation, before bool) error {
		position := "after"
		if before {
			position = "before"
		}
		stages = append(stages, position+" "+string(operation))
		if operation == StaplerOperationValidate && before {
			current, readErr := os.ReadFile(target)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(current, original) {
				return fmt.Errorf("pre-child target = %q, want original", current)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ValidateWithVerifier() error = %v, want success after lookup restoration", err)
	}
	if result == nil || result.Path != target || result.Operation != string(StaplerOperationValidate) || !result.Validated {
		t.Fatalf("ValidateWithVerifier() result = %#v, want truthful validation result", result)
	}
	observed, err := os.ReadFile(observedPath)
	if err != nil {
		t.Fatalf("read child observation: %v", err)
	}
	if !bytes.Equal(observed, original) {
		t.Fatalf("validation child observed %q, want original bytes", observed)
	}
	if want := []string{"before validate", "after validate"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("verified stages = %#v, want %#v", stages, want)
	}
	final, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read final target: %v", err)
	}
	if !bytes.Equal(final, original) {
		t.Fatalf("final target = %q, want original bytes", final)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|validate|" + target,
	})
}

func TestValidateWithVerifierRejectsReplacementByValidationHelper(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.pkg")
	original := []byte("original")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	originalInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	observedPath := filepath.Join(t.TempDir(), "observed-by-child")
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_REPLACE_AFTER_VALIDATE", target)
	t.Setenv("ASC_STAPLER_VALIDATE_OBSERVED_PATH", observedPath)
	restored := false
	t.Cleanup(func() {
		if restored {
			return
		}
		replacementPath := target + ".replacement"
		if _, statErr := os.Stat(target); statErr == nil {
			_ = os.Rename(target, replacementPath)
		}
		_ = os.Rename(target+".original", target)
		_ = os.Remove(replacementPath)
	})

	wantErr := errors.New("target identity changed after validation child")
	var diagnostics bytes.Buffer
	result, err := ValidateWithVerifier(context.Background(), target, &diagnostics, func(operation StaplerOperation, before bool) error {
		if operation != StaplerOperationValidate {
			return nil
		}
		current, statErr := os.Stat(target)
		if statErr != nil {
			return statErr
		}
		if before {
			if !os.SameFile(originalInfo, current) {
				return wantErr
			}
			return nil
		}
		if os.SameFile(originalInfo, current) {
			return nil
		}
		return wantErr
	})
	if result != nil {
		t.Fatalf("ValidateWithVerifier() result = %#v, want nil after helper replacement", result)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("ValidateWithVerifier() error = %v, want post-child identity failure", err)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("child diagnostics = %q, want no success output or diagnostics", diagnostics.String())
	}
	observed, err := os.ReadFile(observedPath)
	if err != nil {
		t.Fatalf("read child observation: %v", err)
	}
	if !bytes.Equal(observed, original) {
		t.Fatalf("validation helper observed %q, want original bytes before replacement", observed)
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|validate|" + target,
	})

	if err := os.Rename(target, target+".replacement"); err != nil {
		t.Fatalf("move replacement: %v", err)
	}
	if err := os.Rename(target+".original", target); err != nil {
		t.Fatalf("restore original target: %v", err)
	}
	if err := os.Remove(target + ".replacement"); err != nil {
		t.Fatalf("remove replacement: %v", err)
	}
	restored = true
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
	var partialErr *StaplerPartialMutationError
	if !errors.As(err, &partialErr) || partialErr.Operation != StaplerOperationValidate {
		t.Fatalf("Staple() error = %#v, want post-staple validation marker", err)
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
		if target := os.Getenv("ASC_STAPLER_SWAP_ON_FIND"); target != "" {
			if err := os.Rename(target, target+".original"); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		if target := os.Getenv("ASC_STAPLER_SWAP_AND_RESTORE_ON_FIND"); target != "" {
			if err := os.Rename(target, target+".original"); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := os.Rename(target, target+".lookup-replacement"); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := os.Rename(target+".original", target); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := os.Remove(target + ".lookup-replacement"); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		if code := staplerHelperExitCode("ASC_STAPLER_FIND_EXIT_CODE"); code >= 0 {
			fmt.Fprintln(os.Stderr, "stapler lookup failed")
			os.Exit(code)
		}
		fmt.Fprintln(os.Stdout, "/usr/bin/stapler")
		os.Exit(0)
	}
	if len(args) >= 4 && args[0] == "xcrun" && args[1] == "stapler" {
		operation := strings.ToUpper(args[2][:1]) + args[2][1:]
		if args[2] == "validate" {
			if observationPath := os.Getenv("ASC_STAPLER_VALIDATE_OBSERVED_PATH"); observationPath != "" {
				observed, err := os.ReadFile(args[3])
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
				if err := os.WriteFile(observationPath, observed, 0o600); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
			}
			if replacementTarget := os.Getenv("ASC_STAPLER_REPLACE_AFTER_VALIDATE"); replacementTarget != "" {
				if err := os.Rename(replacementTarget, replacementTarget+".original"); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
				if err := os.WriteFile(replacementTarget, []byte("replacement"), 0o600); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
			}
			if os.Getenv("ASC_STAPLER_VALIDATE_WAIT") == "1" {
				if readyPath := os.Getenv("ASC_STAPLER_VALIDATE_READY_PATH"); readyPath != "" {
					if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
						fmt.Fprintln(os.Stderr, err)
						os.Exit(2)
					}
				}
				for {
					time.Sleep(time.Second)
				}
			}
		}
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

func TestStapleWithVerifierMarksCancellationDuringInitialStapleAsPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_WAIT", "1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result *StaplerResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := StapleWithVerifier(ctx, target, nil, nil)
		done <- outcome{result: result, err: err}
	}()
	waitForStaplerCommand(t, logPath, "xcrun|stapler|staple|")
	cancel()

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("StapleWithVerifier() result = %#v, want nil after cancellation", got.result)
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("StapleWithVerifier() error = %v, want context cancellation", got.err)
		}
		var partialErr *StaplerPartialMutationError
		if !errors.As(got.err, &partialErr) || partialErr.Operation != StaplerOperationStaple {
			t.Fatalf("StapleWithVerifier() error = %T %v, want initial-staple partial marker", got.err, got.err)
		}
		if !partialErr.Interrupted || !strings.Contains(got.err.Error(), "staple was interrupted") {
			t.Fatalf("StapleWithVerifier() error = %v, want interrupted-staple classification", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StapleWithVerifier() did not return after cancellation")
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleWithVerifierMarksDeadlineDuringInitialStapleAsPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)
	t.Setenv("ASC_STAPLER_WAIT", "1")

	ctx := newStaplerDeadlineTestContext()
	t.Cleanup(ctx.close)
	type outcome struct {
		result *StaplerResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := StapleWithVerifier(ctx, target, nil, nil)
		done <- outcome{result: result, err: err}
	}()
	waitForStaplerCommand(t, logPath, "xcrun|stapler|staple|")
	ctx.close()

	select {
	case got := <-done:
		if got.result != nil {
			t.Fatalf("StapleWithVerifier() result = %#v, want nil after deadline", got.result)
		}
		if !errors.Is(got.err, context.DeadlineExceeded) {
			t.Fatalf("StapleWithVerifier() error = %v, want context deadline", got.err)
		}
		var partialErr *StaplerPartialMutationError
		if !errors.As(got.err, &partialErr) || partialErr.Operation != StaplerOperationStaple {
			t.Fatalf("StapleWithVerifier() error = %T %v, want initial-staple partial marker", got.err, got.err)
		}
		if !partialErr.Interrupted || !strings.Contains(got.err.Error(), "staple was interrupted") {
			t.Fatalf("StapleWithVerifier() error = %v, want interrupted-staple classification", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StapleWithVerifier() did not return after deadline")
	}
	assertStaplerCommands(t, logPath, []string{
		"xcrun|--find|stapler",
		"xcrun|stapler|staple|" + target,
	})
}

func TestStapleWithVerifierCancellationBeforeInitialChildStartIsNotPartial(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	helperCommandContext := commandContextFn
	commandContextFn = func(commandCtx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "stapler" {
			cancel()
		}
		return helperCommandContext(commandCtx, name, args...)
	}

	result, err := StapleWithVerifier(ctx, target, nil, nil)
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil before child start", result)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("StapleWithVerifier() error = %v, want context cancellation", err)
	}
	var partialErr *StaplerPartialMutationError
	if errors.As(err, &partialErr) {
		t.Fatalf("StapleWithVerifier() error = %T %v, must not mark a child that never started as partial", err, err)
	}
	assertStaplerCommands(t, logPath, []string{"xcrun|--find|stapler"})
}

func TestStapleWithVerifierCancellationBeforeInitialChildStartPreservesStageFailureWithoutPartialMutation(t *testing.T) {
	target := filepath.Join(t.TempDir(), "MyApp.dmg")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	logPath := filepath.Join(t.TempDir(), "commands.log")
	configureStaplerTestEnvironment(t, logPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	helperCommandContext := commandContextFn
	commandContextFn = func(commandCtx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "stapler" {
			cancel()
		}
		return helperCommandContext(commandCtx, name, args...)
	}
	stageCause := errors.New("target identity changed")
	result, err := StapleWithVerifier(ctx, target, nil, func(operation StaplerOperation, before bool) error {
		if operation == StaplerOperationStaple && !before {
			return stageCause
		}
		return nil
	})
	if result != nil {
		t.Fatalf("StapleWithVerifier() result = %#v, want nil before child start", result)
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, stageCause) {
		t.Fatalf("StapleWithVerifier() error = %v, want joined cancellation and stage failure", err)
	}
	var stageErr *StaplerStageVerificationError
	if !errors.As(err, &stageErr) || stageErr.Operation != StaplerOperationStaple || stageErr.Before {
		t.Fatalf("StapleWithVerifier() error = %T %v, want post-staple stage failure", err, err)
	}
	var partialErr *StaplerPartialMutationError
	if errors.As(err, &partialErr) {
		t.Fatalf("StapleWithVerifier() error = %T %v, child that never started must not be partial", err, err)
	}
	assertStaplerCommands(t, logPath, []string{"xcrun|--find|stapler"})
}

func waitForStaplerCommand(t *testing.T, logPath, prefix string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(data), prefix) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("stapler helper did not report command %q", prefix)
}

type staplerDeadlineTestContext struct {
	done chan struct{}
}

func newStaplerDeadlineTestContext() *staplerDeadlineTestContext {
	return &staplerDeadlineTestContext{done: make(chan struct{})}
}

func (ctx *staplerDeadlineTestContext) Deadline() (time.Time, bool) {
	return time.Now().Add(time.Hour), true
}

func (ctx *staplerDeadlineTestContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *staplerDeadlineTestContext) Err() error {
	select {
	case <-ctx.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (ctx *staplerDeadlineTestContext) Value(any) any {
	return nil
}

func (ctx *staplerDeadlineTestContext) close() {
	select {
	case <-ctx.done:
	default:
		close(ctx.done)
	}
}
