package notarization

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

var (
	runStaplerStaple              = localxcode.StapleWithVerifier
	runStaplerValidate            = localxcode.ValidateWithVerifier
	validateStaplerDetailsFn      = validateStaplerTargetDetails
	openStaplerTargetDirFn        = openStaplerTargetDir
	checkStaplerTargetContainedFn = func(root rootfs.Root, relative string) error {
		return root.CheckContained(relative)
	}
	probeStaplerTargetKindFn     = probeStaplerTargetKind
	openStaplerTargetDirectoryFn = func(root rootfs.Root, relative string) (*os.File, error) {
		return root.OpenDir(relative)
	}
	openStaplerTargetFileFn = func(root rootfs.Root, relative string) (*os.File, error) {
		return root.OpenFile(relative)
	}
)

// SetValidateStaplerTargetForTesting replaces target validation and returns a
// restore function. It exists so command-level tests can exercise filesystem
// failures without depending on host permissions or filesystem behavior.
func SetValidateStaplerTargetForTesting(fn func(string) (string, error)) func() {
	previousDetails := validateStaplerDetailsFn
	if fn == nil {
		validateStaplerDetailsFn = validateStaplerTargetDetails
	} else {
		validateStaplerDetailsFn = func(pathValue string) (*validatedStaplerTarget, error) {
			validatedPath, err := fn(pathValue)
			if err != nil {
				return nil, err
			}
			return validateStaplerTargetDetails(validatedPath)
		}
	}
	return func() {
		validateStaplerDetailsFn = previousDetails
	}
}

type singleStringValue struct {
	flagName string
	value    string
	set      bool
}

func bindSingleStringFlag(fs *flag.FlagSet, name, usage string) *singleStringValue {
	value := &singleStringValue{flagName: name}
	fs.Var(value, name, usage)
	return value
}

func (v *singleStringValue) String() string {
	if v == nil {
		return ""
	}
	return v.value
}

func (v *singleStringValue) Set(value string) error {
	if v.set {
		return fmt.Errorf("--%s specified multiple times; pass one value", v.flagName)
	}
	v.value = value
	v.set = true
	return nil
}

// NotarizationCommand returns the notarization command group.
func NotarizationCommand() *ffcli.Command {
	return notarizationCommand()
}

// notarizationCommand returns the top-level notarization command.
func notarizationCommand() *ffcli.Command {
	return &ffcli.Command{
		Name:       "notarization",
		ShortUsage: "asc notarization <subcommand> [flags]",
		ShortHelp:  "Manage macOS notarization submissions.",
		LongHelp: `Manage macOS notarization submissions via the Apple Notary API.

Examples:
  asc notarization submit --file ./MyApp.zip
  asc notarization submit --file ./MyApp.zip --wait
  asc notarization staple --file ./MyApp.dmg --confirm
  asc notarization validate --file ./MyApp.dmg
  asc notarization status --id "SUBMISSION_ID"
  asc notarization log --id "SUBMISSION_ID"
  asc notarization list`,
		UsageFunc: shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			submitCommand(),
			stapleCommand(),
			validateStapleCommand(),
			statusCommand(),
			logCommand(),
			listCommand(),
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// stapleCommand returns the local ticket stapling subcommand.
func stapleCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization staple", flag.ExitOnError)

	filePath := bindSingleStringFlag(fs, "file", "[experimental] Path to a notarized app bundle, disk image, or signed flat package (required; zip files must be recreated after stapling)")
	confirm := fs.Bool("confirm", false, "[experimental] Confirm in-place ticket stapling (required)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "staple",
		ShortUsage: "asc notarization staple --file <path> --confirm [flags]",
		ShortHelp:  "[experimental] Attach and validate a macOS notarization ticket locally.",
		LongHelp: `[experimental] Attach Apple's notarization ticket to a local macOS artifact and
validate it immediately afterward. The target must be a notarized app bundle,
UDIF disk image, or signed flat installer package. ZIP archives cannot be
stapled directly; staple the contained item and recreate the archive. This
command runs on macOS only and Apple's stapler may require network access.

Examples:
  asc notarization staple --file ./MyApp.dmg --confirm
  asc notarization staple --file ./MyApp.pkg --confirm --output json
  asc notarization staple --file ./MyApp.app --confirm --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("notarization staple does not accept positional arguments")
			}
			if !*confirm {
				fmt.Fprintln(os.Stderr, "Error: --confirm is required for in-place ticket stapling")
				return shared.MissingRequiredUsageError("--confirm")
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}
			target, err := validateStaplerDetailsFn(filePath.String())
			if err != nil {
				if isStaplerTargetUsageError(err) {
					return shared.UsageErrorf("notarization staple: %v", err)
				}
				return reportStaplerTargetFilesystemFailure("staple")
			}
			if target == nil {
				return reportStaplerTargetFilesystemFailure("staple")
			}
			defer target.close()
			pathValue := target.path
			if err := target.verifyIdentity("before stapling"); err != nil {
				return reportStaplerTargetStageFailure("staple", "before stapling", err)
			}

			result, runErr := runStaplerStaple(ctx, pathValue, os.Stderr, func(operation localxcode.StaplerOperation, before bool) error {
				return target.verifyIdentity(staplerStageDescription(operation, before))
			})
			stageErr := target.verifyIdentity("after stapling")
			if runErr != nil && isStaplerTargetStageError(runErr) {
				return reportStaplerTargetStageFailure("staple", "after stapling", runErr)
			}
			if stageErr != nil {
				return reportStaplerTargetStageFailure("staple", "after stapling", stageErr)
			}
			if runErr != nil {
				return reportStaplerFailure("staple", runErr)
			}
			if result == nil {
				return reportStaplerFailure("staple", errors.New("local stapler returned no result"))
			}
			if !result.Stapled || !result.Validated {
				return reportStaplerFailure("staple", errors.New("local stapler did not report a verified ticket"))
			}
			return shared.PrintOutput(&asc.NotarizationStapleResult{
				FilePath:  pathValue,
				Operation: "staple",
				Stapled:   result.Stapled,
				Validated: result.Validated,
			}, *output.Output, *output.Pretty)
		},
	}
}

// validateStapleCommand returns the local ticket validation subcommand.
func validateStapleCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization validate", flag.ExitOnError)

	filePath := bindSingleStringFlag(fs, "file", "[experimental] Path to an artifact with an existing notarization ticket (required; zip files must be validated after recreating them)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "validate",
		ShortUsage: "asc notarization validate --file <path> [flags]",
		ShortHelp:  "[experimental] Validate a stapled macOS notarization ticket locally.",
		LongHelp: `[experimental] Validate an existing stapled ticket on a local macOS artifact.
The target must be a notarized app bundle, UDIF disk image, or signed flat
installer package. ZIP archives cannot be validated directly; validate the
contained item after recreating the archive. This command never mutates the
target, runs on macOS only, and Apple's stapler may require network access.

Examples:
  asc notarization validate --file ./MyApp.dmg
  asc notarization validate --file ./MyApp.pkg --output json
  asc notarization validate --file ./MyApp.app --output markdown`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("notarization validate does not accept positional arguments")
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}
			target, err := validateStaplerDetailsFn(filePath.String())
			if err != nil {
				if isStaplerTargetUsageError(err) {
					return shared.UsageErrorf("notarization validate: %v", err)
				}
				return reportStaplerTargetFilesystemFailure("validate")
			}
			if target == nil {
				return reportStaplerTargetFilesystemFailure("validate")
			}
			defer target.close()
			pathValue := target.path
			if err := target.verifyIdentity("before validation"); err != nil {
				return reportStaplerTargetStageFailure("validate", "before validation", err)
			}

			result, runErr := runStaplerValidate(ctx, pathValue, os.Stderr, func(operation localxcode.StaplerOperation, before bool) error {
				return target.verifyIdentity(staplerStageDescription(operation, before))
			})
			stageErr := target.verifyIdentity("after validation")
			if runErr != nil && isStaplerTargetStageError(runErr) {
				return reportStaplerTargetStageFailure("validate", "after validation", runErr)
			}
			if stageErr != nil {
				return reportStaplerTargetStageFailure("validate", "after validation", stageErr)
			}
			if runErr != nil {
				return reportStaplerFailure("validate", runErr)
			}
			if result == nil {
				return reportStaplerFailure("validate", errors.New("local stapler returned no result"))
			}
			if !result.Validated {
				return reportStaplerFailure("validate", errors.New("local stapler did not report a valid ticket"))
			}
			return shared.PrintOutput(&asc.NotarizationValidateResult{
				FilePath:  pathValue,
				Operation: "validate",
				Validated: result.Validated,
			}, *output.Output, *output.Pretty)
		},
	}
}

type staplerTargetUsageError struct {
	err error
}

func (e *staplerTargetUsageError) Error() string {
	if e == nil || e.err == nil {
		return "invalid notarization artifact target"
	}
	return e.err.Error()
}

func (e *staplerTargetUsageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func newStaplerTargetUsageError(err error) error {
	if err == nil {
		return nil
	}
	return &staplerTargetUsageError{err: err}
}

func isStaplerTargetUsageError(err error) bool {
	var usageErr *staplerTargetUsageError
	return errors.As(err, &usageErr)
}

func validateStaplerTarget(pathValue string) (string, error) {
	target, err := validateStaplerTargetDetails(pathValue)
	if err != nil {
		return "", err
	}
	target.close()
	return target.path, nil
}

type validatedStaplerTarget struct {
	path      string
	root      rootfs.Root
	relative  string
	directory bool
	identity  os.FileInfo
	// handle stays open for the whole operation. Retaining the descriptor
	// keeps the artifact's inode allocated, so a replacement cannot receive
	// the recycled file ID and then satisfy os.SameFile against the recorded
	// identity. The retained rootfs.Root pins only the filesystem root.
	handle *os.File
}

func (target *validatedStaplerTarget) close() {
	if target == nil {
		return
	}
	if target.handle != nil {
		_ = target.handle.Close()
	}
	_ = target.root.Close()
}

// pinnedIdentity reports the retained descriptor's current metadata. It fails
// when the artifact handle was not retained, which would leave the recorded
// identity vulnerable to inode reuse.
func (target *validatedStaplerTarget) pinnedIdentity() (os.FileInfo, error) {
	if target == nil || target.handle == nil {
		return nil, errors.New("artifact target descriptor is not retained")
	}
	return target.handle.Stat()
}

type staplerTargetIdentityError struct {
	stage string
}

func (e *staplerTargetIdentityError) Error() string {
	if e == nil || e.stage == "" {
		return "artifact target changed"
	}
	return "artifact target changed " + e.stage
}

// staplerTargetVerifyError marks a stage boundary that could not be evaluated
// because reopening or inspecting the artifact failed operationally. It is
// deliberately distinct from staplerTargetIdentityError: a revoked permission,
// a descriptor limit, or an I/O error must not be reported to the operator as
// a replaced artifact, because the corrective action differs.
type staplerTargetVerifyError struct {
	stage string
	err   error
}

func (e *staplerTargetVerifyError) Error() string {
	if e == nil || e.stage == "" {
		return "could not verify artifact target"
	}
	return "could not verify artifact target " + e.stage
}

func (e *staplerTargetVerifyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (target *validatedStaplerTarget) verifyIdentity(stage string) error {
	if target == nil || target.identity == nil {
		return &staplerTargetIdentityError{stage: stage}
	}
	pinned, err := target.pinnedIdentity()
	if err != nil {
		return &staplerTargetVerifyError{stage: stage, err: err}
	}
	if !os.SameFile(target.identity, pinned) {
		return &staplerTargetIdentityError{stage: stage}
	}
	opened, err := target.open()
	if err != nil {
		return target.classifyStageOpenFailure(stage, err)
	}
	defer opened.Close()
	current, err := opened.Stat()
	if err != nil {
		return &staplerTargetVerifyError{stage: stage, err: err}
	}
	if !os.SameFile(target.identity, current) || current.IsDir() != target.directory {
		return &staplerTargetIdentityError{stage: stage}
	}
	return nil
}

// classifyStageOpenFailure decides whether a failed stage reopen proves the
// target changed or only that the filesystem could not be inspected. It probes
// the final component with a rooted no-follow Lstat rather than reading the
// open error's text, so a vanished target, a kind flip, or a replacement by a
// symlink stays an identity failure while every other cause stays operational.
func (target *validatedStaplerTarget) classifyStageOpenFailure(stage string, openErr error) error {
	info, probeErr := probeStaplerTargetKindFn(target.root, target.relative)
	if probeErr != nil {
		if errors.Is(probeErr, os.ErrNotExist) {
			return &staplerTargetIdentityError{stage: stage}
		}
		return &staplerTargetVerifyError{stage: stage, err: openErr}
	}
	if info == nil || info.IsDir() != target.directory {
		return &staplerTargetIdentityError{stage: stage}
	}
	if errors.Is(openErr, rootfs.ErrSymlink) {
		return &staplerTargetIdentityError{stage: stage}
	}
	return &staplerTargetVerifyError{stage: stage, err: openErr}
}

func staplerStageDescription(operation localxcode.StaplerOperation, before bool) string {
	if before {
		return "before " + string(operation)
	}
	return "after " + string(operation)
}

func (target *validatedStaplerTarget) open() (*os.File, error) {
	if target == nil {
		return nil, errors.New("artifact target is missing")
	}
	if target.directory {
		return openStaplerTargetDirectoryFn(target.root, target.relative)
	}
	return openStaplerTargetFileFn(target.root, target.relative)
}

// errStaplerTargetRaced marks a target that changed between the kind probe and
// the open that followed it. The probe already proved the semantic
// preconditions, so a later disagreement is an operational race rather than
// invalid operator input.
var errStaplerTargetRaced = errors.New("artifact target changed during inspection")

// staplerTargetWrongKindError reports that the final component exists but is
// not a directory bundle. It carries the probed identity so the caller can
// both decide between the regular-file fallback and a semantic rejection and
// bind the later open to the same filesystem object without matching error
// text.
type staplerTargetWrongKindError struct {
	info os.FileInfo
}

func (*staplerTargetWrongKindError) Error() string {
	return "stapler target is not a directory"
}

type staplerTargetDirectoryOpenError struct {
	err error
}

func (*staplerTargetDirectoryOpenError) Error() string {
	return "opening stapler target directory failed"
}

func (e *staplerTargetDirectoryOpenError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// staplerTargetTraversalError marks failures while checking the path leading
// to the final artifact component. A traversal failure must remain
// operational, even when its underlying syscall happens to be ENOTDIR; only
// a successful final-component kind probe may authorize file fallback.
type staplerTargetTraversalError struct {
	err error
}

func (*staplerTargetTraversalError) Error() string {
	return "checking stapler target path failed"
}

func (e *staplerTargetTraversalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func probeStaplerTargetKind(root rootfs.Root, relative string) (os.FileInfo, error) {
	rooted, err := root.OpenRoot()
	if err != nil {
		return nil, err
	}
	info, err := rooted.Lstat(relative)
	closeErr := rooted.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return info, nil
}

// openStaplerTargetDir classifies the final component through a rooted
// no-follow Lstat before opening a directory. This keeps the regular-file
// fallback tied to an explicit local result rather than parsing an arbitrary
// operational error string returned by a directory open.
func openStaplerTargetDir(root rootfs.Root, relative string) (*os.File, error) {
	if err := checkStaplerTargetContainedFn(root, relative); err != nil {
		return nil, &staplerTargetTraversalError{err: err}
	}
	info, err := probeStaplerTargetKindFn(root, relative)
	if err != nil {
		return nil, &staplerTargetTraversalError{err: err}
	}
	if info == nil {
		return nil, errors.New("stapler target kind probe returned no result")
	}
	if !info.IsDir() {
		return nil, &staplerTargetWrongKindError{info: info}
	}
	opened, err := openStaplerTargetDirectoryFn(root, relative)
	if err != nil {
		return nil, &staplerTargetDirectoryOpenError{err: err}
	}
	openedInfo, err := opened.Stat()
	if err != nil {
		_ = opened.Close()
		return nil, &staplerTargetDirectoryOpenError{err: err}
	}
	if !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = opened.Close()
		return nil, &staplerTargetDirectoryOpenError{err: errStaplerTargetRaced}
	}
	return opened, nil
}

func validateStaplerTargetDetails(pathValue string) (*validatedStaplerTarget, error) {
	if strings.TrimSpace(pathValue) == "" {
		return nil, newStaplerTargetUsageError(errors.New("--file is required"))
	}
	if strings.ContainsRune(pathValue, 0) {
		return nil, newStaplerTargetUsageError(errors.New("--file must not contain a NUL byte"))
	}
	absolute, err := filepath.Abs(pathValue)
	if err != nil {
		return nil, fmt.Errorf("resolve --file: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if strings.EqualFold(filepath.Ext(absolute), ".zip") {
		return nil, newStaplerTargetUsageError(errors.New("zip archives cannot be stapled or validated directly; staple the contained item and recreate the archive"))
	}

	root, relative, err := newStaplerTargetRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("open artifact root: %w", err)
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			_ = root.Close()
		}
	}()

	opened, openErr := openStaplerTargetDirFn(root, relative)
	if openErr == nil {
		keepHandle := false
		defer func() {
			if !keepHandle {
				_ = opened.Close()
			}
		}()
		openedInfo, statErr := opened.Stat()
		if statErr != nil {
			return nil, fmt.Errorf("stat artifact directory: %w", statErr)
		}
		if !openedInfo.IsDir() {
			return nil, newStaplerTargetUsageError(errors.New("artifact target is not a directory bundle"))
		}
		keepRoot = true
		keepHandle = true
		return &validatedStaplerTarget{
			path:      absolute,
			root:      root,
			relative:  relative,
			directory: true,
			identity:  openedInfo,
			handle:    opened,
		}, nil
	}

	var wrongKindErr *staplerTargetWrongKindError
	if !errors.As(openErr, &wrongKindErr) {
		if semanticErr := staplerTargetSemanticError(openErr, absolute); semanticErr != nil {
			return nil, semanticErr
		}
		return nil, fmt.Errorf("open artifact directory: %w", openErr)
	}
	// The probe already established the final component's kind, so a special
	// file is rejected here instead of being inferred from the text of a
	// failed regular-file open.
	if wrongKindErr.info == nil || !wrongKindErr.info.Mode().IsRegular() {
		return nil, newStaplerTargetUsageError(fmt.Errorf("%q is not a regular file or directory bundle", absolute))
	}

	// Past this point the target was proven to exist, to not be a symlink, and
	// to be a regular file. Any failure here is a replacement race or another
	// operational fault, so it must keep runtime classification instead of
	// being reported as invalid input with the artifact path attached.
	opened, openErr = openStaplerTargetFileFn(root, relative)
	if openErr != nil {
		return nil, fmt.Errorf("open artifact: %w", openErr)
	}
	keepHandle := false
	defer func() {
		if !keepHandle {
			_ = opened.Close()
		}
	}()
	openedInfo, statErr := opened.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("stat artifact: %w", statErr)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(wrongKindErr.info, openedInfo) {
		return nil, fmt.Errorf("artifact changed kind during open: %w", errStaplerTargetRaced)
	}
	if openedInfo.Size() <= 0 {
		return nil, newStaplerTargetUsageError(errors.New("artifact file must not be empty"))
	}
	keepRoot = true
	keepHandle = true
	return &validatedStaplerTarget{
		path:     absolute,
		root:     root,
		relative: relative,
		identity: openedInfo,
		handle:   opened,
	}, nil
}

func newStaplerTargetRoot(absolute string) (rootfs.Root, string, error) {
	rootPath := filepath.VolumeName(absolute) + string(os.PathSeparator)
	root, err := rootfs.New(rootPath)
	if err != nil {
		return rootfs.Root{}, "", err
	}
	inspectionPath := staplerNoFollowPath(absolute)
	relative, err := filepath.Rel(rootPath, inspectionPath)
	if err != nil {
		_ = root.Close()
		return rootfs.Root{}, "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		_ = root.Close()
		return rootfs.Root{}, "", fmt.Errorf("%w: artifact path escapes filesystem root", rootfs.ErrEscapesRoot)
	}
	return root, relative, nil
}

func staplerNoFollowPath(absolute string) string {
	if runtime.GOOS != "darwin" {
		return absolute
	}
	for _, alias := range []string{"/etc", "/tmp", "/var"} {
		if absolute == alias || strings.HasPrefix(absolute, alias+string(os.PathSeparator)) {
			return filepath.Join("/private", strings.TrimPrefix(absolute, string(os.PathSeparator)))
		}
	}
	return absolute
}

// staplerTargetSemanticError maps a pre-probe traversal failure to an operator
// input error. Only error values are inspected; no branch reads an error's
// message text. A directory-open failure is deliberately excluded because it
// happens after the target's kind was already proven, which makes it
// operational.
func staplerTargetSemanticError(err error, absolute string) error {
	if err == nil {
		return nil
	}
	var directoryOpenErr *staplerTargetDirectoryOpenError
	if errors.As(err, &directoryOpenErr) {
		return nil
	}
	if errors.Is(err, rootfs.ErrSymlink) {
		return newStaplerTargetUsageError(fmt.Errorf("refusing to read symlink %q", absolute))
	}
	if errors.Is(err, os.ErrNotExist) {
		return newStaplerTargetUsageError(fmt.Errorf("%q does not exist", absolute))
	}
	return nil
}

func reportStaplerFailure(command string, err error) error {
	var commandErr *localxcode.StaplerCommandError
	if errors.As(err, &commandErr) {
		if commandErr.ExitCode > 0 {
			if command == "staple" && commandErr.Operation == string(localxcode.StaplerOperationValidate) {
				fmt.Fprintln(os.Stderr, "Error: notarization staple completed, but follow-up validation failed; the artifact may have been modified but was not verified")
			} else if commandErr.Operation == string(localxcode.StaplerOperationResolve) {
				fmt.Fprintf(os.Stderr, "Error: notarization %s could not resolve Apple's stapler tool (exit status %d)\n", command, commandErr.ExitCode)
			} else {
				fmt.Fprintf(os.Stderr, "Error: notarization %s failed during %s (exit status %d)\n", command, commandErr.Operation, commandErr.ExitCode)
			}
			return shared.NewReportedError(shared.NewProcessExitError(commandErr.ExitCode))
		}
		fmt.Fprintf(os.Stderr, "Error: notarization %s failed during %s before a usable exit status was available\n", command, commandErr.Operation)
		return shared.NewReportedError(err)
	}
	fmt.Fprintf(os.Stderr, "Error: notarization %s: %v\n", command, err)
	return shared.NewReportedError(err)
}

func reportStaplerTargetFilesystemFailure(command string) error {
	message := fmt.Sprintf("notarization %s: could not inspect artifact filesystem", command)
	fmt.Fprintln(os.Stderr, "Error: "+message)
	return shared.NewReportedError(errors.New(message))
}

func reportStaplerTargetIdentityFailure(command, stage string) error {
	message := fmt.Sprintf("notarization %s: artifact target changed %s", command, stage)
	fmt.Fprintln(os.Stderr, "Error: "+message)
	return shared.NewReportedError(errors.New(message))
}

// isStaplerTargetStageError reports whether err came from a stage boundary
// check, whether the target was proven replaced or merely could not be
// inspected.
func isStaplerTargetStageError(err error) bool {
	var identityErr *staplerTargetIdentityError
	var verifyErr *staplerTargetVerifyError
	return errors.As(err, &identityErr) || errors.As(err, &verifyErr)
}

// reportStaplerTargetStageFailure emits the diagnostic that matches the cause:
// a proven replacement names the stage it was detected at, while a boundary
// that could not be evaluated reports the sanitized filesystem failure.
func reportStaplerTargetStageFailure(command, fallbackStage string, err error) error {
	var verifyErr *staplerTargetVerifyError
	if errors.As(err, &verifyErr) {
		return reportStaplerTargetFilesystemFailure(command)
	}
	var identityErr *staplerTargetIdentityError
	if errors.As(err, &identityErr) && identityErr.stage != "" {
		return reportStaplerTargetIdentityFailure(command, identityErr.stage)
	}
	return reportStaplerTargetIdentityFailure(command, fallbackStage)
}

// submitCommand returns the submit subcommand.
func submitCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization submit", flag.ExitOnError)

	filePath := fs.String("file", "", "Path to the file to notarize (required, zip/dmg/pkg)")
	wait := fs.Bool("wait", false, "Wait for notarization to complete")
	pollInterval := fs.String("poll-interval", "15s", "Polling interval when using --wait")
	timeout := fs.String("timeout", "30m", "Timeout when using --wait")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "submit",
		ShortUsage: "asc notarization submit --file <path> [flags]",
		ShortHelp:  "Submit software for notarization.",
		LongHelp: `Submit a file for macOS notarization via the Apple Notary API.

The file must be a zip, dmg, or pkg archive. The command computes the file's
SHA-256 hash, creates a submission, uploads the file to Apple's S3 bucket,
and optionally waits for the notarization to complete.

Examples:
  asc notarization submit --file ./MyApp.zip
  asc notarization submit --file ./MyApp.zip --wait
  asc notarization submit --file ./MyApp.zip --wait --poll-interval 30s --timeout 1h
  asc notarization submit --file ./MyApp.zip --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			pathValue := strings.TrimSpace(*filePath)
			if pathValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --file is required")
				return shared.MissingRequiredUsageError("--file")
			}

			interval, err := time.ParseDuration(strings.TrimSpace(*pollInterval))
			if err != nil || interval <= 0 {
				return fmt.Errorf("notarization submit: --poll-interval must be a valid positive duration (e.g. 15s, 1m)")
			}

			timeoutDuration, err := time.ParseDuration(strings.TrimSpace(*timeout))
			if err != nil || timeoutDuration <= 0 {
				return fmt.Errorf("notarization submit: --timeout must be a valid positive duration (e.g. 30m, 1h)")
			}

			// Preserve the explicit symlink error while relying on the no-follow
			// open below for the actual security boundary.
			pathInfo, err := os.Lstat(pathValue)
			if err != nil {
				return fmt.Errorf("notarization submit: %w", err)
			}
			if pathInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("notarization submit: refusing to read symlink %q", pathValue)
			}
			if pathInfo.IsDir() {
				return fmt.Errorf("notarization submit: %q is a directory", pathValue)
			}
			if !pathInfo.Mode().IsRegular() {
				return fmt.Errorf("notarization submit: %q is not a regular file", pathValue)
			}

			fileHandle, err := secureopen.OpenExistingNoFollow(pathValue)
			if err != nil {
				return fmt.Errorf("notarization submit: failed to open file: %w", err)
			}
			defer fileHandle.Close()

			info, err := fileHandle.Stat()
			if err != nil {
				return fmt.Errorf("notarization submit: failed to stat opened file: %w", err)
			}
			if info.IsDir() {
				return fmt.Errorf("notarization submit: %q is a directory", pathValue)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("notarization submit: %q is not a regular file", pathValue)
			}
			if info.Size() <= 0 {
				return fmt.Errorf("notarization submit: file must not be empty")
			}

			ext := strings.ToLower(filepath.Ext(pathValue))
			if ext != ".zip" && ext != ".dmg" && ext != ".pkg" {
				return fmt.Errorf("notarization submit: unsupported file type %q (must be .zip, .dmg, or .pkg)", ext)
			}

			// Compute SHA-256
			if shared.ProgressEnabled() {
				fmt.Fprintf(os.Stderr, "Computing SHA-256 hash of %s...\n", pathValue)
			}
			sha256Hash, err := asc.ComputeFileSHA256(fileHandle)
			if err != nil {
				return fmt.Errorf("notarization submit: failed to compute SHA-256: %w", err)
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("notarization submit: %w", err)
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			// Submit to Notary API
			submissionName := info.Name()
			if shared.ProgressEnabled() {
				fmt.Fprintf(os.Stderr, "Submitting %s for notarization...\n", submissionName)
			}

			submitResp, err := client.SubmitNotarization(requestCtx, sha256Hash, submissionName)
			if err != nil {
				return fmt.Errorf("notarization submit: %w", err)
			}

			submissionID := submitResp.Data.ID
			if shared.ProgressEnabled() {
				fmt.Fprintf(os.Stderr, "Submission created: %s\n", submissionID)
			}

			// Upload file to S3
			if shared.ProgressEnabled() {
				fmt.Fprintf(os.Stderr, "Uploading %s to Apple...\n", submissionName)
			}

			uploadCtx, uploadCancel := shared.ContextWithUploadTimeout(ctx)
			defer uploadCancel()

			creds := asc.S3Credentials{
				AccessKeyID:     submitResp.Data.Attributes.AwsAccessKeyID,
				SecretAccessKey: submitResp.Data.Attributes.AwsSecretAccessKey,
				SessionToken:    submitResp.Data.Attributes.AwsSessionToken,
				Bucket:          submitResp.Data.Attributes.Bucket,
				Object:          submitResp.Data.Attributes.Object,
			}

			contentType := notaryContentType(pathValue)
			if err := asc.UploadToS3(uploadCtx, creds, fileHandle, sha256Hash, info.Size(), contentType); err != nil {
				return fmt.Errorf("notarization submit: upload failed: %w", err)
			}

			if shared.ProgressEnabled() {
				fmt.Fprintln(os.Stderr, "Upload complete.")
			}

			// If not waiting, print the submission response and exit
			if !*wait {
				if shared.ProgressEnabled() {
					fmt.Fprintf(os.Stderr, "Use 'asc notarization status --id %s' to check progress.\n", submissionID)
				}
				resp := &asc.NotarySubmissionStatusResponse{
					Data: asc.NotarySubmissionStatusData{
						ID:   submissionID,
						Type: "submissions",
						Attributes: asc.NotarySubmissionStatusAttributes{
							Status:      asc.NotaryStatusInProgress,
							Name:        submissionName,
							CreatedDate: "",
						},
					},
				}
				return shared.PrintOutput(resp, *output.Output, *output.Pretty)
			}

			// Wait for notarization to complete
			if shared.ProgressEnabled() {
				fmt.Fprintf(os.Stderr, "Waiting for notarization (polling every %s, timeout %s)...\n", interval, timeoutDuration)
			}

			waitCtx, waitCancel := context.WithTimeout(ctx, timeoutDuration)
			defer waitCancel()

			statusResp, err := waitForNotarization(waitCtx, client, submissionID, interval)
			if err != nil {
				return fmt.Errorf("notarization submit: %w", err)
			}

			if err := shared.PrintOutput(statusResp, *output.Output, *output.Pretty); err != nil {
				return err
			}

			switch statusResp.Data.Attributes.Status {
			case asc.NotaryStatusAccepted:
				if shared.ProgressEnabled() {
					fmt.Fprintln(os.Stderr, "Notarization complete! Status: Accepted")
				}
				return nil
			case asc.NotaryStatusInvalid, asc.NotaryStatusRejected:
				if shared.ProgressEnabled() {
					fmt.Fprintf(os.Stderr, "Notarization failed. Status: %s\n", statusResp.Data.Attributes.Status)
					fmt.Fprintf(os.Stderr, "Run 'asc notarization log --id %s' for details.\n", submissionID)
				}
				return shared.NewReportedError(fmt.Errorf("notarization %s: %s", submissionID, statusResp.Data.Attributes.Status))
			default:
				return nil
			}
		},
	}
}

// statusCommand returns the status subcommand.
func statusCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization status", flag.ExitOnError)

	submissionID := fs.String("id", "", "Submission ID (required)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "status",
		ShortUsage: "asc notarization status --id \"SUBMISSION_ID\"",
		ShortHelp:  "Get the status of a notarization submission.",
		LongHelp: `Get the status of a notarization submission.

Status values: Accepted, In Progress, Invalid, Rejected.

Examples:
  asc notarization status --id "SUBMISSION_ID"
  asc notarization status --id "SUBMISSION_ID" --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			idValue := strings.TrimSpace(*submissionID)
			if idValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --id is required")
				return shared.MissingRequiredUsageError("--id")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("notarization status: %w", err)
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			resp, err := client.GetNotarizationStatus(requestCtx, idValue)
			if err != nil {
				return fmt.Errorf("notarization status: failed to fetch: %w", err)
			}

			return shared.PrintOutput(resp, *output.Output, *output.Pretty)
		},
	}
}

// logCommand returns the log subcommand.
func logCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization log", flag.ExitOnError)

	submissionID := fs.String("id", "", "Submission ID (required)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "log",
		ShortUsage: "asc notarization log --id \"SUBMISSION_ID\"",
		ShortHelp:  "Get the developer log URL for a notarization submission.",
		LongHelp: `Get the developer log URL for a notarization submission.

The log contains detailed information about the notarization result,
including any issues found during the scan.

Examples:
  asc notarization log --id "SUBMISSION_ID"
  asc notarization log --id "SUBMISSION_ID" --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			idValue := strings.TrimSpace(*submissionID)
			if idValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --id is required")
				return shared.MissingRequiredUsageError("--id")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("notarization log: %w", err)
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			resp, err := client.GetNotarizationLogs(requestCtx, idValue)
			if err != nil {
				return fmt.Errorf("notarization log: failed to fetch: %w", err)
			}

			return shared.PrintOutput(resp, *output.Output, *output.Pretty)
		},
	}
}

// listCommand returns the list subcommand.
func listCommand() *ffcli.Command {
	fs := flag.NewFlagSet("notarization list", flag.ExitOnError)

	limit := fs.Int("limit", 0, "Maximum number of results to display (0 = all)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc notarization list [flags]",
		ShortHelp:  "List previous notarization submissions.",
		LongHelp: `List previous notarization submissions.

Examples:
  asc notarization list
  asc notarization list --limit 5
  asc notarization list --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if *limit < 0 {
				return fmt.Errorf("notarization list: --limit must not be negative")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("notarization list: %w", err)
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			resp, err := client.ListNotarizations(requestCtx)
			if err != nil {
				return fmt.Errorf("notarization list: failed to fetch: %w", err)
			}

			if *limit > 0 && len(resp.Data) > *limit {
				resp.Data = resp.Data[:*limit]
			}

			return shared.PrintOutput(resp, *output.Output, *output.Pretty)
		},
	}
}

// notarizationPollMaxBackoff caps the delay applied after repeated transient
// status-check failures.
const notarizationPollMaxBackoff = 2 * time.Minute

// waitForNotarization polls the notarization status until the submission reaches
// a terminal state, the wait deadline expires, or a status check fails for a
// reason that will not resolve on its own. Transient failures (transport errors,
// request timeouts, and retryable HTTP statuses) are reported on stderr and
// retried with backoff, because the archive is already uploaded and the
// submission keeps progressing server-side.
func waitForNotarization(ctx context.Context, client *asc.Client, submissionID string, pollInterval time.Duration) (*asc.NotarySubmissionStatusResponse, error) {
	consecutiveFailures := 0
	var lastTransientErr error

	for {
		requestCtx, cancel := shared.ContextWithTimeout(ctx)
		resp, err := client.GetNotarizationStatus(requestCtx, submissionID)
		cancel()

		delay := pollInterval
		switch {
		case err == nil:
			consecutiveFailures = 0
			lastTransientErr = nil

			switch resp.Data.Attributes.Status {
			case asc.NotaryStatusAccepted, asc.NotaryStatusInvalid, asc.NotaryStatusRejected:
				return resp, nil
			default:
				// Treat unknown statuses (including InProgress) as non-terminal and continue polling
				if shared.ProgressEnabled() {
					fmt.Fprintf(os.Stderr, "Status: %s (checking again in %s)\n", resp.Data.Attributes.Status, pollInterval)
				}
			}
		case ctx.Err() != nil:
			// The wait deadline expired (or the caller cancelled) while the
			// status request was still in flight.
			return nil, notarizationWaitEndedError(ctx, lastTransientErr)
		case isTransientNotarizationPollError(err):
			consecutiveFailures++
			lastTransientErr = err
			delay = notarizationPollBackoff(pollInterval, consecutiveFailures)
			fmt.Fprintf(os.Stderr, "Warning: notarization status check failed (%v); retrying in %s\n", err, delay)
		default:
			return nil, fmt.Errorf("failed to check status: %w", err)
		}

		if !waitBeforeNextNotarizationPoll(ctx, delay) {
			return nil, notarizationWaitEndedError(ctx, lastTransientErr)
		}
	}
}

// waitBeforeNextNotarizationPoll sleeps for delay and reports whether the wait
// context is still live.
func waitBeforeNextNotarizationPoll(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// notarizationWaitEndedError explains why the wait stopped once the wait context
// finished, preserving the most recent transient status-check failure.
func notarizationWaitEndedError(ctx context.Context, lastTransientErr error) error {
	reason := "timed out waiting for notarization"
	if errors.Is(ctx.Err(), context.Canceled) {
		reason = "canceled while waiting for notarization"
	}
	if lastTransientErr != nil {
		return fmt.Errorf("%s (last status check failed: %w): %w", reason, lastTransientErr, ctx.Err())
	}
	return fmt.Errorf("%s: %w", reason, ctx.Err())
}

// isTransientNotarizationPollError reports whether a status-check failure is
// worth retrying. The Notary API path has no client-side retry wrapper, so the
// wait loop classifies transport failures, per-request timeouts, and retryable
// HTTP statuses itself.
func isTransientNotarizationPollError(err error) bool {
	if err == nil {
		return false
	}
	if asc.IsRetryable(err) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// Only the per-request timeout reaches here; callers check the wait
		// context before classifying.
		return true
	}

	var statusErr interface{ HTTPStatusCode() int }
	if errors.As(err, &statusErr) {
		switch statusErr.HTTPStatusCode() {
		case http.StatusRequestTimeout,
			http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

// notarizationPollBackoff spaces out retries after consecutive transient
// failures without ever polling faster than the caller's interval.
func notarizationPollBackoff(pollInterval time.Duration, consecutiveFailures int) time.Duration {
	maxBackoff := notarizationPollMaxBackoff
	if pollInterval > maxBackoff {
		maxBackoff = pollInterval
	}

	delay := pollInterval
	for i := 1; i < consecutiveFailures; i++ {
		if delay >= maxBackoff {
			return maxBackoff
		}
		delay *= 2
	}
	if delay > maxBackoff {
		return maxBackoff
	}
	return delay
}

func notaryContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return "application/zip"
	case ".dmg":
		return "application/x-apple-diskimage"
	case ".pkg":
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}
