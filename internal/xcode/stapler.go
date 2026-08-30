package xcode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const staplerResolutionOutputLimit = 4 * 1024

// StaplerOperation identifies the local ticket operation that was requested.
type StaplerOperation string

const (
	StaplerOperationResolve  StaplerOperation = "resolve"
	StaplerOperationStaple   StaplerOperation = "staple"
	StaplerOperationValidate StaplerOperation = "validate"
)

// StaplerResult is the result of a successful local ticket operation.
type StaplerResult struct {
	Path      string
	Operation string
	Stapled   bool
	Validated bool
}

// StaplerStageVerifier checks the artifact immediately before and after each
// stapler operation. It is used by callers that pin the target identity during
// the multi-stage staple flow. A true before value identifies the pre-stage
// check; false identifies the post-stage check.
type StaplerStageVerifier func(operation StaplerOperation, before bool) error

// StaplerStageVerificationError identifies a verifier failure at one child
// operation boundary. The wrapped error remains available to callers that need
// to classify the underlying cause, while Error provides a stable diagnostic
// that does not include verifier details.
type StaplerStageVerificationError struct {
	Operation StaplerOperation
	Before    bool
	Err       error
}

func (e *StaplerStageVerificationError) Error() string {
	if e == nil {
		return "stapler stage verification failed"
	}
	position := "after"
	if e.Before {
		position = "before"
	}
	return fmt.Sprintf("stapler %s verification failed %s operation", e.Operation, position)
}

func (e *StaplerStageVerificationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// StaplerCommandError preserves the operation and child exit status for a
// failed stapler invocation. ExitCode is -1 when no ordinary process status is
// available, such as a start failure or signal termination.
type StaplerCommandError struct {
	Operation string
	ExitCode  int
	Err       error
}

func (e *StaplerCommandError) Error() string {
	if e == nil {
		return "stapler command failed"
	}
	if e.Err == nil {
		return fmt.Sprintf("stapler %s failed", e.Operation)
	}
	return fmt.Sprintf("stapler %s failed: %v", e.Operation, e.Err)
}

func (e *StaplerCommandError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// StaplerPartialMutationError identifies either an interrupted staple child or
// a follow-up validation failure after stapling. Its stable message warns that
// the artifact may have been modified while Unwrap retains the cancellation or
// child error for internal classification.
type StaplerPartialMutationError struct {
	Operation   StaplerOperation
	Interrupted bool
	Err         error
}

func (e *StaplerPartialMutationError) Error() string {
	if e == nil {
		return "stapler follow-up validation failed after staple; artifact may have been modified but was not verified"
	}
	if e.Interrupted {
		return "stapler staple was interrupted; artifact may have been modified but was not verified"
	}
	if e.Operation == StaplerOperationStaple {
		return "stapler post-staple verification failed; artifact may have been modified but was not verified"
	}
	return "stapler " + string(e.Operation) + " failed after staple; artifact may have been modified but was not verified"
}

func (e *StaplerPartialMutationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Staple retrieves and attaches a ticket, then validates the same artifact.
// The artifact path must have been validated by the command layer before this
// local runner is called.
func Staple(ctx context.Context, path string, logWriter io.Writer) (*StaplerResult, error) {
	return StapleWithVerifier(ctx, path, logWriter, nil)
}

// StapleWithVerifier retrieves and attaches a ticket, then validates the same
// artifact. When verifier is non-nil, it runs immediately before and after
// both child operations so callers can reject a replaced target between the
// staple and validation stages.
func StapleWithVerifier(ctx context.Context, path string, logWriter io.Writer, verifier StaplerStageVerifier) (*StaplerResult, error) {
	if err := ensureStaplerAvailable(ctx, logWriter); err != nil {
		return nil, err
	}
	if err := verifyStaplerStage(verifier, StaplerOperationStaple, true); err != nil {
		return nil, err
	}
	stapleErr := runStaplerOperation(ctx, StaplerOperationStaple, path, logWriter)
	if verifyErr := verifyStaplerStage(verifier, StaplerOperationStaple, false); verifyErr != nil {
		partialErr := error(verifyErr)
		if stapleErr != nil {
			partialErr = errors.Join(stapleErr, verifyErr)
		}
		return nil, &StaplerPartialMutationError{
			Operation: StaplerOperationStaple,
			Err:       partialErr,
		}
	}
	if stapleErr != nil {
		if isStaplerOperationAttemptedCancellation(stapleErr) {
			return nil, &StaplerPartialMutationError{
				Operation:   StaplerOperationStaple,
				Interrupted: true,
				Err:         stapleErr,
			}
		}
		return nil, stapleErr
	}
	if err := verifyStaplerStage(verifier, StaplerOperationValidate, true); err != nil {
		return nil, &StaplerPartialMutationError{
			Operation: StaplerOperationStaple,
			Err:       err,
		}
	}
	validateErr := runStaplerOperation(ctx, StaplerOperationValidate, path, logWriter)
	if verifyErr := verifyStaplerStage(verifier, StaplerOperationValidate, false); verifyErr != nil {
		partialErr := error(verifyErr)
		if validateErr != nil {
			partialErr = errors.Join(validateErr, verifyErr)
		}
		return nil, &StaplerPartialMutationError{
			Operation: StaplerOperationValidate,
			Err:       partialErr,
		}
	}
	if validateErr != nil {
		return nil, &StaplerPartialMutationError{
			Operation: StaplerOperationValidate,
			Err:       validateErr,
		}
	}
	return &StaplerResult{
		Path:      path,
		Operation: string(StaplerOperationStaple),
		Stapled:   true,
		Validated: true,
	}, nil
}

func verifyStaplerStage(verifier StaplerStageVerifier, operation StaplerOperation, before bool) error {
	if verifier == nil {
		return nil
	}
	if err := verifier(operation, before); err != nil {
		return &StaplerStageVerificationError{
			Operation: operation,
			Before:    before,
			Err:       err,
		}
	}
	return nil
}

// ValidateStaple validates an already stapled artifact without modifying it.
// The artifact path must have been validated by the command layer before this
// local runner is called.
func ValidateStaple(ctx context.Context, path string, logWriter io.Writer) (*StaplerResult, error) {
	return ValidateWithVerifier(ctx, path, logWriter, nil)
}

// ValidateWithVerifier validates an already stapled artifact without
// modifying it. When verifier is non-nil, it runs immediately before and after
// the validation child process, after stapler resolution has completed.
func ValidateWithVerifier(ctx context.Context, path string, logWriter io.Writer, verifier StaplerStageVerifier) (*StaplerResult, error) {
	if err := ensureStaplerAvailable(ctx, logWriter); err != nil {
		return nil, err
	}
	if err := verifyStaplerStage(verifier, StaplerOperationValidate, true); err != nil {
		return nil, err
	}
	validateErr := runStaplerOperation(ctx, StaplerOperationValidate, path, logWriter)
	if verifyErr := verifyStaplerStage(verifier, StaplerOperationValidate, false); verifyErr != nil {
		if validateErr != nil {
			return nil, errors.Join(validateErr, verifyErr)
		}
		return nil, verifyErr
	}
	if validateErr != nil {
		return nil, validateErr
	}
	return &StaplerResult{
		Path:      path,
		Operation: string(StaplerOperationValidate),
		Validated: true,
	}, nil
}

func ensureStaplerAvailable(ctx context.Context, logWriter io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if runtimeGOOS != "darwin" {
		return fmt.Errorf("stapler is supported on macOS only; current platform is %s", runtimeGOOS)
	}
	if _, err := lookPathFn("xcrun"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("xcrun not available; install Xcode and ensure the active developer directory is configured")
		}
		return fmt.Errorf("locate xcrun: %w", err)
	}

	cmd := commandContextFn(ctx, "xcrun", "--find", "stapler")
	stdout := newTailBuffer(staplerResolutionOutputLimit)
	stderr := newXcodeDiagnosticBuffer(staplerResolutionOutputLimit, logWriter)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := runXcodeCommand(cmd); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		failure := error(fmt.Errorf("xcrun --find stapler failed: %w", err))
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			failure = fmt.Errorf("xcrun --find stapler failed: %s: %w", detail, err)
		}
		return newStaplerCommandError(StaplerOperationResolve, failure)
	}
	if strings.TrimSpace(stdout.String()) == "" {
		return fmt.Errorf("xcrun did not resolve stapler")
	}
	return nil
}

// staplerOperationAttemptedCancellationError records that a stapler child was
// invoked before its context was canceled. A cancellation before the child is
// started remains an ordinary preflight error; once staple has been attempted,
// the caller must warn that the artifact may have been modified.
type staplerOperationAttemptedCancellationError struct {
	err error
}

func (e *staplerOperationAttemptedCancellationError) Error() string {
	return "stapler operation canceled after child invocation"
}

func (e *staplerOperationAttemptedCancellationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func isStaplerOperationAttemptedCancellation(err error) bool {
	var attempted *staplerOperationAttemptedCancellationError
	return errors.As(err, &attempted)
}

func runStaplerOperation(ctx context.Context, operation StaplerOperation, path string, logWriter io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	started, err := runStaplerChildCommand(ctx, operation, path, logWriter)
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		if !started {
			return ctxErr
		}
		return &staplerOperationAttemptedCancellationError{err: ctxErr}
	}
	return newStaplerCommandError(operation, err)
}

func runStaplerChildCommand(ctx context.Context, operation StaplerOperation, path string, logWriter io.Writer) (bool, error) {
	cmd := commandContextFn(ctx, "xcrun", "stapler", string(operation), path)
	outputWindow := newXcodeDiagnosticBuffer(xcodebuildErrorTailLimit, logWriter)
	cmd.Stdout = outputWindow
	cmd.Stderr = outputWindow
	cmd.WaitDelay = xcodeCommandPipeWaitDelay
	if err := cmd.Start(); err != nil {
		return false, formatCommandOutputError(ctx, err, outputWindow, string(operation), "xcrun stapler", true)
	}
	if err := normalizeXcodeCommandWaitError(cmd, cmd.Wait()); err != nil {
		return true, formatCommandOutputError(ctx, err, outputWindow, string(operation), "xcrun stapler", true)
	}
	return true, nil
}

func newStaplerCommandError(operation StaplerOperation, err error) *StaplerCommandError {
	exitCode := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	return &StaplerCommandError{
		Operation: string(operation),
		ExitCode:  exitCode,
		Err:       err,
	}
}
