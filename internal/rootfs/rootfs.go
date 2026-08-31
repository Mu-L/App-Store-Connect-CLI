// Package rootfs provides rooted filesystem operations for paths that are not
// fully trusted, such as filenames, directory components, or manifest entries
// that come from a repository checkout or a remote API response.
//
// Every operation is anchored to a trusted root chosen by the operator (for
// example a --out-dir flag, a manifest directory, or the resolved .asc
// directory). Paths are validated lexically so absolute paths, volume or
// UNC-style changes, and parent traversal are rejected, and filesystem access
// refuses to follow symlinks for any component below the root. Writes stage
// through unpredictable, exclusive, no-follow temporary files so a
// pre-created symlink cannot redirect them.
//
// Roots created with AllowingInternalSymlinks relax only the parent-component
// rule, accepting a symlinked directory whose target stays inside the root; a
// symlinked final component is always refused.
package rootfs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

var (
	// ErrEscapesRoot reports a path that does not stay beneath the trusted root.
	ErrEscapesRoot = errors.New("path escapes trusted root")
	// ErrSymlink reports a path component that is a symlink below the trusted root.
	ErrSymlink = errors.New("refusing to follow symlink")
	// ErrFileIdentityChanged reports that a path no longer names the captured
	// descriptor-backed file identity.
	ErrFileIdentityChanged = errors.New("file identity changed")
	// ErrFileIdentityMismatch reports that an identity belongs to another root.
	ErrFileIdentityMismatch = errors.New("file identity belongs to another root")
	// ErrFileIdentityClosed reports that the Root which owns an identity has
	// already been closed.
	ErrFileIdentityClosed = errors.New("file identity is closed")
	// ErrFileIdentityMutationUnsupported reports that the host cannot couple a
	// pathname mutation to a retained file descriptor or handle. Strict
	// identity operations fail before moving or replacing any entry when this
	// capability is unavailable.
	ErrFileIdentityMutationUnsupported = errors.New("identity-coupled file mutation unsupported")
	// ErrQuarantineCleanupUncertain reports that a quarantined entry could not
	// be proven safe to remove. Callers must preserve the quarantine path from
	// the wrapped error for operator recovery.
	ErrQuarantineCleanupUncertain = errors.New("quarantine cleanup uncertain")
	// ErrStagingCleanupUncertain reports that a private transaction staging
	// entry could not be proven safe to remove. The staging name is retained in
	// the wrapped error for operator recovery.
	ErrStagingCleanupUncertain = errors.New("staging cleanup uncertain")
	// ErrFileIdentityDataTooLarge reports that retaining a complete identity
	// snapshot would exceed the bounded memory contract for identity methods.
	ErrFileIdentityDataTooLarge = errors.New("file identity data exceeds size limit")
)

const (
	temporaryFilePattern        = ".asc-tmp-*"
	backupFilePattern           = ".asc-tmp-backup-*"
	rollbackFilePattern         = ".asc-tmp-rollback-*"
	fileIdentityDataLimit int64 = 8 << 20
)

// Root is a trusted directory anchor for rooted filesystem operations.
type Root struct {
	path             string
	openPath         string
	selectedIdentity *rootIdentity
	pendingCreation  *rootCreation
	// internalSymlinks tolerates symlinked components below the root when they
	// resolve back inside the root.
	internalSymlinks bool
	// afterValidationForTest makes path-swap regressions deterministic. It is
	// intentionally unexported and unset outside package tests.
	afterValidationForTest func()
	// beforeOpenRootForTest makes trusted-root path-swap regressions
	// deterministic. It is intentionally unexported and unset outside tests.
	beforeOpenRootForTest func()
	// beforeCreateRootForTest makes missing-root ancestor replacement races
	// deterministic. It is intentionally unexported and unset outside tests.
	beforeCreateRootForTest func()
	// renameNoReplaceForTest makes unsupported-filesystem regressions
	// deterministic. It is intentionally unexported and unset outside tests.
	renameNoReplaceForTest func(root *os.Root, oldName, newName string) error
	// removeStagedFileForTest injects a cleanup failure after a legacy hard-link
	// fallback has already published the complete destination. Compatibility
	// callers receive the published metadata while the staged entry is preserved.
	removeStagedFileForTest func(root *os.Root, name string) error
	// syncDirectoryForTest injects a post-publication directory-sync result so
	// callers can verify that a sync failure still returns the installed
	// identity for conditional rollback.
	syncDirectoryForTest func(root *os.Root) error
	// afterPublicationOpenForTest runs after the published file has been
	// reopened no-follow but before its directory entry is checked again. It
	// makes the post-publication identity window deterministic in rootfs tests.
	afterPublicationOpenForTest func(root *os.Root, name string)
	// beforePublicationOpenForTest runs after the initial publication Lstat and
	// before the no-follow reopen. It makes a replacement during that interval
	// deterministic without weakening the production API.
	beforePublicationOpenForTest func(root *os.Root, name string)
	// openPublishedFileForTest injects a transient result from the rooted
	// published-file reopen without changing production callers.
	openPublishedFileForTest func(root *os.Root, name string) (*os.File, error)
	// statPublishedFileForTest injects a transient descriptor Stat result after
	// publication without changing production callers.
	statPublishedFileForTest func(file *os.File) (os.FileInfo, error)
	// postPublicationLstatForTest replaces the first published-entry Lstat in
	// tests so transient identity-observation failures can be exercised without
	// widening the production API.
	postPublicationLstatForTest func(root *os.Root, name string) (os.FileInfo, error)
	// conditionalMutation hooks make the compare-and-publish/remove tests
	// deterministic without widening the production API with callbacks.
	beforeConditionalQuarantineForTest        func(root *os.Root, name string)
	afterConditionalQuarantineForTest         func(root *os.Root, quarantineName, name string)
	beforeConditionalQuarantineRemovalForTest func(root *os.Root, quarantineName string)
	// openExpectedFileForTest injects failures while a conditional operation
	// verifies the original or quarantined file.
	openExpectedFileForTest func(root *os.Root, name string, expected os.FileInfo, expectedData []byte) (*os.File, os.FileInfo, error)
	// postConditionalQuarantineLstatForTest injects an error while checking
	// the original destination after it has been quarantined. It makes the
	// cleanup/recovery contract deterministic without widening the public API.
	postConditionalQuarantineLstatForTest  func(root *os.Root, name string) (os.FileInfo, error)
	beforeConditionalPublishForTest        func(root *os.Root, name string)
	afterConditionalPublicationForTest     func(root *os.Root, name string)
	afterConditionalPublicationOpenForTest func(root *os.Root, name string, file *os.File)
	// simulateWindowsCloseForTest closes the staging descriptor before
	// publication and skips Unix descriptor retention, exercising the
	// pre-identity failure contract without requiring a Windows runner.
	simulateWindowsCloseForTest bool
	// requireNativeNoReplace preserves CreateNewFileAtomic's strict contract
	// while CreateNewFrom may use the atomic hard-link fallback.
	requireNativeNoReplace bool
}

// FileIdentity is an opaque, descriptor-backed identity captured beneath a
// Root. Its descriptor is retained until the owning Root is closed, preventing
// inode or file-ID reuse while a transaction carries the identity through
// publication and rollback. Callers must not construct or copy one manually;
// use Root.CaptureFile or an identity-returning publication method.
//
// An identity is only valid with the Root that created it and while that Root
// remains open. The snapshot accessors are intentionally read-only; mutation
// methods validate the retained descriptor before acting on a pathname.
type FileIdentity struct {
	owner *rootIdentity
	file  *os.File
	info  os.FileInfo
	data  []byte
	path  string
}

// Info returns the captured file metadata snapshot. The snapshot is useful for
// reporting and comparison only; it does not replace the retained descriptor
// used by identity-checked mutations.
func (identity *FileIdentity) Info() os.FileInfo {
	if identity == nil {
		return nil
	}
	return identity.info
}

// Data returns a copy of the bytes captured with the file identity.
func (identity *FileIdentity) Data() []byte {
	if identity == nil {
		return nil
	}
	return bytes.Clone(identity.data)
}

// Mode returns the captured permission bits.
func (identity *FileIdentity) Mode() os.FileMode {
	if identity == nil || identity.info == nil {
		return 0
	}
	return identity.info.Mode().Perm()
}

type rootCreation struct {
	mu           sync.Mutex
	lexicalBase  string
	physicalBase string
	suffix       []string
	baseIdentity *rootIdentity
}

type rootIdentity struct {
	mu            sync.RWMutex
	pinned        *os.Root
	retainedFiles []*os.File
	cleanup       runtime.Cleanup
	hasCleanup    bool
	closing       bool
	inFlight      int
	condition     *sync.Cond
	closed        bool
}

func (identity *rootIdentity) begin() error {
	if identity == nil {
		return ErrFileIdentityClosed
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.closed || identity.closing {
		return ErrFileIdentityClosed
	}
	identity.inFlight++
	return nil
}

func (identity *rootIdentity) end() {
	if identity == nil {
		return
	}
	identity.mu.Lock()
	if identity.inFlight > 0 {
		identity.inFlight--
	}
	if identity.inFlight == 0 && identity.condition != nil {
		identity.condition.Broadcast()
	}
	identity.mu.Unlock()
}

func (identity *rootIdentity) isPinned() bool {
	if identity == nil {
		return false
	}
	identity.mu.RLock()
	defer identity.mu.RUnlock()
	return identity.pinned != nil
}

// pin retains one descriptor for the selected directory. Keeping that
// descriptor open prevents the original inode or file ID from being recycled
// while Root values still refer to it. The cleanup is attached to the shared
// identity rather than a Root copy so the descriptor is closed exactly once.
func (identity *rootIdentity) pin(candidate *os.Root) bool {
	if candidate == nil {
		return false
	}
	if identity == nil {
		_ = candidate.Close()
		return false
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.closed {
		_ = candidate.Close()
		return false
	}
	if identity.pinned == nil {
		identity.pinned = candidate
		identity.cleanup = runtime.AddCleanup(identity, closePinnedRoot, candidate)
		identity.hasCleanup = true
		return true
	}
	selectedInfo, selectedErr := identity.pinned.Stat(".")
	candidateInfo, candidateErr := candidate.Stat(".")
	_ = candidate.Close()
	return selectedErr == nil && candidateErr == nil && os.SameFile(selectedInfo, candidateInfo)
}

func (identity *rootIdentity) matches(candidate os.FileInfo) bool {
	if identity == nil || candidate == nil {
		return false
	}
	identity.mu.RLock()
	defer identity.mu.RUnlock()
	if identity.pinned == nil {
		return false
	}
	selected, err := identity.pinned.Stat(".")
	return err == nil && os.SameFile(selected, candidate)
}

// retainFile keeps a published file descriptor attached to the selected root
// until Root.Close. FileInfo alone does not keep an inode alive, so a caller
// that needs to conditionally roll back a publication can use the returned
// identity without reopening the path and racing identity reuse.
func (identity *rootIdentity) retainFile(file *os.File) bool {
	if identity == nil || file == nil {
		return false
	}
	identity.mu.Lock()
	defer identity.mu.Unlock()
	if identity.closed {
		_ = file.Close()
		return false
	}
	identity.retainedFiles = append(identity.retainedFiles, file)
	return true
}

func (identity *rootIdentity) retainIdentity(file *os.File, info os.FileInfo, data []byte, path string) (*FileIdentity, error) {
	if file == nil || info == nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, fmt.Errorf("%w: descriptor or metadata is unavailable", ErrFileIdentityChanged)
	}
	if int64(len(data)) > fileIdentityDataLimit {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %d bytes exceeds %d-byte limit", ErrFileIdentityDataTooLarge, len(data), fileIdentityDataLimit)
	}
	if !identity.retainFile(file) {
		return nil, ErrFileIdentityClosed
	}
	return &FileIdentity{
		owner: identity,
		file:  file,
		info:  info,
		data:  bytes.Clone(data),
		path:  filepath.Clean(path),
	}, nil
}

func (identity *FileIdentity) validateOwner(owner *rootIdentity) error {
	if identity == nil {
		return fmt.Errorf("%w: identity is unavailable", ErrFileIdentityChanged)
	}
	if identity.owner != owner {
		return ErrFileIdentityMismatch
	}
	if owner == nil {
		return ErrFileIdentityClosed
	}
	owner.mu.RLock()
	closed := owner.closed
	owner.mu.RUnlock()
	if closed {
		return ErrFileIdentityClosed
	}
	if identity.file == nil || identity.info == nil {
		return fmt.Errorf("%w: identity descriptor is unavailable", ErrFileIdentityChanged)
	}
	current, err := identity.file.Stat()
	if err != nil {
		return errors.Join(ErrFileIdentityChanged, fmt.Errorf("stat captured identity: %w", err))
	}
	if !os.SameFile(identity.info, current) {
		return ErrFileIdentityChanged
	}
	return nil
}

func (identity *FileIdentity) validate(owner *rootIdentity, path string) error {
	if err := identity.validateOwner(owner); err != nil {
		return err
	}
	if filepath.Clean(path) != identity.path {
		return fmt.Errorf("%w: identity path does not match %q", ErrFileIdentityChanged, path)
	}
	return nil
}

func closePinnedRoot(root *os.Root) {
	_ = root.Close()
}

func (identity *rootIdentity) close() error {
	if identity == nil {
		return nil
	}
	identity.mu.Lock()
	if identity.closed {
		identity.mu.Unlock()
		return nil
	}
	identity.closing = true
	if identity.condition == nil {
		identity.condition = sync.NewCond(&identity.mu)
	}
	for identity.inFlight > 0 {
		identity.condition.Wait()
	}
	identity.closed = true
	pinned := identity.pinned
	identity.pinned = nil
	retainedFiles := identity.retainedFiles
	identity.retainedFiles = nil
	cleanup := identity.cleanup
	hasCleanup := identity.hasCleanup
	identity.hasCleanup = false
	identity.mu.Unlock()
	if hasCleanup {
		cleanup.Stop()
	}
	var closeErrors []error
	for _, file := range retainedFiles {
		if err := file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	if pinned != nil {
		closeErrors = append(closeErrors, pinned.Close())
	}
	return errors.Join(closeErrors...)
}

// New returns a Root anchored at path. The root itself is operator-selected and
// may live outside the current repository; only paths below it are constrained.
func New(path string) (Root, error) {
	if path == "" {
		return Root{}, fmt.Errorf("%w: trusted root path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(path, 0) {
		return Root{}, fmt.Errorf("%w: trusted root path contains a NUL byte", ErrEscapesRoot)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Root{}, fmt.Errorf("resolve trusted root %q: %w", path, err)
	}
	absolute = filepath.Clean(absolute)
	lexicalBase, physicalBase, suffix, err := resolveRootSelection(absolute)
	if err != nil {
		return Root{}, fmt.Errorf("resolve trusted root %q: %w", path, err)
	}
	openPath := filepath.Join(append([]string{physicalBase}, suffix...)...)
	selectedExists := len(suffix) == 0
	root := Root{path: absolute, openPath: openPath, selectedIdentity: &rootIdentity{}}
	if !selectedExists {
		base, err := openAbsoluteRootNoFollow(physicalBase)
		if err != nil {
			return Root{}, fmt.Errorf("open trusted root ancestor %q: %w", lexicalBase, err)
		}
		baseInfo, statErr := base.Stat(".")
		if statErr != nil {
			_ = base.Close()
			return Root{}, fmt.Errorf("stat trusted root ancestor %q: %w", lexicalBase, statErr)
		}
		selectedAtPath, statErr := os.Stat(lexicalBase)
		if statErr != nil {
			_ = base.Close()
			return Root{}, fmt.Errorf("stat selected root ancestor %q: %w", lexicalBase, statErr)
		}
		if !os.SameFile(baseInfo, selectedAtPath) {
			_ = base.Close()
			return Root{}, symlinkError(lexicalBase)
		}
		baseIdentity := &rootIdentity{}
		if !baseIdentity.pin(base) {
			return Root{}, symlinkError(lexicalBase)
		}
		root.pendingCreation = &rootCreation{
			lexicalBase:  lexicalBase,
			physicalBase: physicalBase,
			suffix:       append([]string(nil), suffix...),
			baseIdentity: baseIdentity,
		}
		return root, nil
	}
	selected, err := openAbsoluteRootNoFollow(openPath)
	if err != nil {
		return Root{}, fmt.Errorf("open trusted root %q: %w", path, err)
	}
	identity, statErr := selected.Stat(".")
	if statErr != nil {
		_ = selected.Close()
		return Root{}, fmt.Errorf("stat trusted root %q: %w", path, statErr)
	}
	selectedAtPath, err := os.Stat(absolute)
	if err != nil {
		_ = selected.Close()
		return Root{}, fmt.Errorf("stat selected root %q: %w", path, err)
	}
	if !os.SameFile(identity, selectedAtPath) {
		_ = selected.Close()
		return Root{}, symlinkError(absolute)
	}
	if !root.selectedIdentity.pin(selected) {
		return Root{}, symlinkError(absolute)
	}
	return root, nil
}

func resolveRootSelection(absolute string) (string, string, []string, error) {
	candidate := absolute
	reversedSuffix := make([]string, 0)
	for {
		_, err := os.Lstat(candidate)
		if err == nil {
			physical, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", "", nil, fmt.Errorf("resolve existing ancestor %q: %w", candidate, err)
			}
			resolvedInfo, err := os.Stat(physical)
			if err != nil {
				return "", "", nil, fmt.Errorf("stat existing ancestor %q: %w", candidate, err)
			}
			if !resolvedInfo.IsDir() {
				return "", "", nil, fmt.Errorf("trusted root ancestor %q is not a directory", candidate)
			}
			suffix := make([]string, len(reversedSuffix))
			for index := range reversedSuffix {
				suffix[len(reversedSuffix)-1-index] = reversedSuffix[index]
			}
			return candidate, physical, suffix, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", "", nil, fmt.Errorf("inspect trusted root ancestor %q: %w", candidate, err)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", "", nil, fmt.Errorf("no existing ancestor for trusted root %q", absolute)
		}
		component := filepath.Base(candidate)
		if err := validateMissingRootComponent(component); err != nil {
			return "", "", nil, err
		}
		reversedSuffix = append(reversedSuffix, component)
		candidate = parent
	}
}

func validateMissingRootComponent(component string) error {
	if component == "" || component == "." || component == ".." ||
		filepath.Clean(component) != component || filepath.IsAbs(component) ||
		filepath.VolumeName(component) != "" || strings.ContainsRune(component, 0) {
		return fmt.Errorf("%w: unsafe missing trusted-root component %q", ErrEscapesRoot, component)
	}
	return nil
}

// OpenFile opens an existing regular file through a rooted traversal. Paths
// below the current working directory or OS temporary directory use that
// trusted anchor; other paths use their filesystem root. Unlike a
// final-component O_NOFOLLOW open, this rejects symlinks in parent components
// below the selected root.
func OpenFile(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path %q: %w", path, err)
	}
	volumeRoot := filepath.VolumeName(absolute) + string(filepath.Separator)
	rootPath := volumeRoot
	for _, candidate := range []string{workingDirectory(), os.TempDir()} {
		candidate, err = filepath.Abs(candidate)
		if err != nil {
			continue
		}
		candidate = filepath.Clean(candidate)
		if _, err := relativeWithinRoot(candidate, absolute); err == nil && len(candidate) > len(rootPath) {
			rootPath = candidate
		}
	}
	root, err := New(rootPath)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(root.Path(), absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %q below %q: %w", ErrEscapesRoot, path, root.Path(), err)
	}
	return root.OpenFile(relative)
}

func workingDirectory() string {
	path, err := os.Getwd()
	if err != nil {
		return ""
	}
	return path
}

// Path returns the absolute trusted root path.
func (r Root) Path() string {
	return r.path
}

// Close releases the selected directory descriptor shared by this Root and all
// of its copies. Close is idempotent; no copied Root may be used afterward.
func (r Root) Close() error {
	var pendingErr error
	if r.pendingCreation != nil {
		r.pendingCreation.mu.Lock()
		pendingErr = r.pendingCreation.baseIdentity.close()
		r.pendingCreation.mu.Unlock()
	}
	return errors.Join(r.selectedIdentity.close(), pendingErr)
}

// OpenRoot opens the trusted root without following symlinks introduced after
// New selected it. New records the physical target of a pre-existing trusted
// symlink layout, while later path substitutions cannot change the selected
// directory identity. Every physical component and the final root are reopened
// from parent directory handles.
func (r Root) OpenRoot() (*os.Root, error) {
	if r.beforeOpenRootForTest != nil {
		r.beforeOpenRootForTest()
	}
	if !r.selectedIdentity.isPinned() {
		return nil, symlinkError(r.path)
	}
	opened, err := openAbsoluteRootNoFollow(r.openPath)
	if err != nil {
		return nil, err
	}
	identity, err := opened.Stat(".")
	if err != nil || !r.selectedIdentity.matches(identity) {
		_ = opened.Close()
		if err != nil {
			return nil, err
		}
		return nil, symlinkError(r.path)
	}
	return opened, nil
}

// ContainsPath reports whether path resolves within the directory identity
// selected by New. It verifies that the retained root is still reachable at
// its selected physical path before comparing prospective paths, so replacing
// the root after selection fails closed.
func (r Root) ContainsPath(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(path, 0) {
		return false, fmt.Errorf("%w: path contains a NUL byte", ErrEscapesRoot)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("resolve path %q: %w", path, err)
	}
	opened, err := r.OpenRoot()
	if err != nil {
		return false, fmt.Errorf("verify selected root %q: %w", r.path, err)
	}
	if err := opened.Close(); err != nil {
		return false, err
	}
	physical, err := resolveProspectivePhysicalPath(filepath.Clean(absolute))
	if err != nil {
		return false, err
	}
	return pathWithinRootIdentity(r.selectedIdentity, physical)
}

// ResolveProspectivePath returns the physical spelling of a future file path
// by resolving its parent and appending the final name without opening or
// following that final entry. Callers can use it to compare publication paths
// that may reach the same destination through different symlinked parents,
// including when intermediate directories do not exist yet.
func ResolveProspectivePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("%w: path contains a NUL byte", ErrEscapesRoot)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return "", fmt.Errorf("%w: path is a filesystem root", ErrEscapesRoot)
	}
	physicalParent, err := resolveProspectivePhysicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(physicalParent, filepath.Base(absolute)), nil
}

// ContainsAnchoredPath reports whether an already-open directory is within this
// root. The lexical path must still resolve to the supplied directory identity;
// replacements between anchoring and comparison fail closed.
func (r Root) ContainsAnchoredPath(path string, anchored *os.Root) (bool, error) {
	if anchored == nil {
		return false, fmt.Errorf("%w: anchored path is nil", ErrEscapesRoot)
	}
	anchoredInfo, err := anchored.Stat(".")
	if err != nil {
		return false, fmt.Errorf("stat anchored path %q: %w", path, err)
	}
	if path == "" {
		return false, fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(path, 0) {
		return false, fmt.Errorf("%w: path contains a NUL byte", ErrEscapesRoot)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("resolve path %q: %w", path, err)
	}
	selected, err := r.OpenRoot()
	if err != nil {
		return false, fmt.Errorf("verify selected root %q: %w", r.path, err)
	}
	if err := selected.Close(); err != nil {
		return false, err
	}
	physical, err := resolveProspectivePhysicalPath(filepath.Clean(absolute))
	if err != nil {
		return false, err
	}
	current, err := openAbsoluteRootNoFollow(physical)
	if err != nil {
		return false, fmt.Errorf("open anchored path %q: %w", path, err)
	}
	currentInfo, statErr := current.Stat(".")
	closeErr := current.Close()
	if statErr != nil {
		return false, statErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	if !os.SameFile(anchoredInfo, currentInfo) {
		return false, symlinkError(path)
	}
	return pathWithinRootIdentity(r.selectedIdentity, physical)
}

func pathWithinRootIdentity(identity *rootIdentity, physical string) (bool, error) {
	current := filepath.Clean(physical)
	for {
		info, err := os.Stat(current)
		if err == nil {
			if identity.matches(info) {
				return true, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}

func resolveProspectivePhysicalPath(absolute string) (string, error) {
	candidate := absolute
	reversedSuffix := make([]string, 0)
	for {
		if _, err := os.Lstat(candidate); err == nil {
			physical, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", fmt.Errorf("resolve existing path %q: %w", candidate, err)
			}
			suffix := make([]string, len(reversedSuffix))
			for index := range reversedSuffix {
				suffix[len(reversedSuffix)-1-index] = reversedSuffix[index]
			}
			return filepath.Join(append([]string{physical}, suffix...)...), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect path %q: %w", candidate, err)
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", fmt.Errorf("no existing ancestor for path %q", absolute)
		}
		reversedSuffix = append(reversedSuffix, filepath.Base(candidate))
		candidate = parent
	}
}

func openAbsoluteRootNoFollow(absolute string) (*os.Root, error) {
	workingDir := workingDirectory()
	if workingDir != "" {
		physicalWorkingDir, err := filepath.EvalSymlinks(workingDir)
		if err == nil {
			workingDir = filepath.Clean(physicalWorkingDir)
		} else {
			workingDir = ""
		}
	}
	return openAbsoluteRootNoFollowFrom(
		absolute,
		workingDir,
		func() (*os.Root, error) { return os.OpenRoot(".") },
		os.OpenRoot,
	)
}

func openAbsoluteRootNoFollowFrom(
	absolute string,
	workingDir string,
	openWorkingDir func() (*os.Root, error),
	openVolumeRoot func(string) (*os.Root, error),
) (*os.Root, error) {
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	anchor := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(absolute, anchor)

	var current *os.Root
	if workingDir != "" {
		workingDir = filepath.Clean(workingDir)
		if workingRelative, err := relativeWithinRoot(workingDir, absolute); err == nil {
			current, err = openWorkingDir()
			if err != nil {
				return nil, err
			}
			openedInfo, openedErr := current.Stat(".")
			selectedInfo, selectedErr := os.Stat(workingDir)
			if openedErr != nil || selectedErr != nil || !os.SameFile(openedInfo, selectedInfo) {
				_ = current.Close()
				if openedErr != nil {
					return nil, openedErr
				}
				if selectedErr != nil {
					return nil, selectedErr
				}
				return nil, symlinkError(workingDir)
			}
			anchor = workingDir
			relative = workingRelative
		}
	}
	if current == nil {
		var err error
		current, err = openVolumeRoot(anchor)
		if err != nil {
			return nil, err
		}
	}
	if relative == "" || relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		if before.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, symlinkError(absolute)
		}
		if !before.IsDir() {
			_ = current.Close()
			return nil, fmt.Errorf("%q is not a directory", absolute)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			_ = next.Close()
			_ = current.Close()
			if err != nil {
				return nil, err
			}
			return nil, symlinkError(absolute)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

// AllowingInternalSymlinks returns a copy of the root that accepts a symlinked
// directory component below the root when that component resolves back inside
// the root, and still rejects one that escapes.
//
// Use it only where symlinked directories inside the root are an established,
// supported layout. A symlinked final component is still refused.
func (r Root) AllowingInternalSymlinks() Root {
	r.internalSymlinks = true
	return r
}

// containsResolvedComponent reports whether a symlinked component below the root
// resolves back inside the root.
func (r Root) containsResolvedComponent(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	root := r.path
	if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
		root = resolvedRoot
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// checkSymlinkComponent decides whether a symlinked component below the root is
// acceptable for this root's policy.
func (r Root) checkSymlinkComponent(path string) error {
	if r.internalSymlinks && r.containsResolvedComponent(path) {
		return nil
	}
	return symlinkError(path)
}

// ValidateRelative reports whether name is safe to join onto a trusted root.
// Both Unix and Windows separator conventions are considered so a repository
// can not smuggle a drive-relative, UNC-style, or backslash-traversing path
// past validation on a different host platform.
func ValidateRelative(name string) error {
	if name == "" {
		return fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: %q contains a NUL byte", ErrEscapesRoot, name)
	}
	if isAbsoluteLike(name) {
		return fmt.Errorf("%w: %q must be relative to the trusted root", ErrEscapesRoot, name)
	}
	for _, component := range strings.FieldsFunc(name, isPathSeparator) {
		if component == ".." {
			return fmt.Errorf("%w: %q traverses above the trusted root", ErrEscapesRoot, name)
		}
	}
	return nil
}

// ValidateRelativeAllowingTraversal rejects absolute, drive-relative and
// UNC-style paths but permits ".." segments, for callers that resolve a path
// against a base directory below the root and then confirm containment of the
// joined result with Resolve.
func ValidateRelativeAllowingTraversal(name string) error {
	if name == "" {
		return fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: %q contains a NUL byte", ErrEscapesRoot, name)
	}
	if isAbsoluteLike(name) {
		return fmt.Errorf("%w: %q must be relative to the trusted root", ErrEscapesRoot, name)
	}
	return nil
}

// Resolve validates name and returns its absolute path beneath the root. name
// may be relative to the root or an absolute path that is already inside it.
func (r Root) Resolve(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: path is empty", ErrEscapesRoot)
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: %q contains a NUL byte", ErrEscapesRoot, name)
	}

	if isAbsoluteLike(name) {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("%w: %q is not an absolute path below %q", ErrEscapesRoot, name, r.path)
		}
		cleaned := filepath.Clean(name)
		if err := r.checkWithin(cleaned, name); err != nil {
			return "", err
		}
		return cleaned, nil
	}

	if err := ValidateRelative(name); err != nil {
		return "", err
	}
	joined := filepath.Join(r.path, name)
	if err := r.checkWithin(joined, name); err != nil {
		return "", err
	}
	return joined, nil
}

// ResolveContainedFinalSymlink resolves a final symlink only when its physical
// target remains beneath this root. The returned name is relative to the root
// and contains no symlink components, so callers can perform the actual I/O
// through rooted no-follow operations without reopening the link.
func (r Root) ResolveContainedFinalSymlink(name string) (string, error) {
	absolute, err := r.Resolve(name)
	if err != nil {
		return "", err
	}
	if err := r.checkParentComponents(absolute); err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("%w: %q is not a symlink", ErrSymlink, absolute)
	}

	physicalRoot, err := filepath.EvalSymlinks(r.path)
	if err != nil {
		return "", err
	}
	physicalTarget, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return relativeWithinRoot(physicalRoot, physicalTarget)
}

// CheckContained verifies that name stays beneath the root and that neither its
// parent components nor its final component is a symlink below the root.
func (r Root) CheckContained(name string) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if err := r.checkParentComponents(resolved); err != nil {
		return err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return symlinkError(resolved)
	}
	return nil
}

// CheckParents verifies that name stays beneath the root and that every
// component below the root leading to it is acceptable under the root's symlink
// policy. The final component is not inspected.
func (r Root) CheckParents(name string) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	return r.checkParentComponents(resolved)
}

// OpenFile opens an existing regular file beneath the root without following
// symlinks in the final component or in any component below the root.
func (r Root) OpenFile(name string) (*os.File, error) {
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := r.checkParentComponents(resolved); err != nil {
		return nil, err
	}
	info, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, symlinkError(resolved)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", resolved)
	}
	if r.afterValidationForTest != nil {
		r.afterValidationForTest()
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(parent, base)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%q is not a regular file", resolved)
	}
	return file, nil
}

// CaptureFile opens and reads a regular file beneath the root while retaining
// the descriptor that supplied its identity. The default snapshot is bounded
// by the identity memory limit; use CaptureFileLimited to request a smaller
// bound. The returned token is bound to this Root and remains valid until
// Root.Close. Callers must use the token for subsequent identity-checked
// mutations instead of retaining an os.FileInfo snapshot returned by os.Stat.
func (r Root) CaptureFile(name string) (*FileIdentity, error) {
	return r.CaptureFileLimited(name, fileIdentityDataLimit)
}

// CaptureFileLimited is CaptureFile with an explicit maximum byte count for
// the retained data snapshot. It refuses, rather than truncates, a regular
// file larger than limit. The limit cannot exceed the identity memory bound so
// every retained token remains bounded until Root.Close.
func (r Root) CaptureFileLimited(name string, limit int64) (*FileIdentity, error) {
	if err := r.selectedIdentity.begin(); err != nil {
		return nil, err
	}
	defer r.selectedIdentity.end()
	if limit < 0 {
		return nil, fmt.Errorf("file identity capture limit must not be negative")
	}
	if limit > fileIdentityDataLimit {
		return nil, fmt.Errorf("file identity capture limit %d exceeds %d-byte limit: %w", limit, fileIdentityDataLimit, ErrFileIdentityDataTooLarge)
	}
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := r.checkParentComponents(resolved); err != nil {
		return nil, err
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(parent, base)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", resolved)
	}
	var data []byte
	if limit == math.MaxInt64 {
		data, err = io.ReadAll(file)
	} else {
		data, err = io.ReadAll(io.LimitReader(file, limit+1))
		if err == nil && int64(len(data)) > limit {
			return nil, fmt.Errorf("%q exceeds the %d-byte file identity capture limit: %w", resolved, limit, ErrFileIdentityDataTooLarge)
		}
	}
	if err != nil {
		return nil, err
	}
	identity, err := r.selectedIdentity.retainIdentity(file, info, data, resolved)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	return identity, nil
}

// CheckFileIdentity verifies that name still refers to the descriptor-backed
// identity captured by this Root. It performs no mutation and is safe to use
// immediately before issuing a receipt or other assertion that depends on a
// committed publication.
func (r Root) CheckFileIdentity(name string, expected *FileIdentity) error {
	if err := r.selectedIdentity.begin(); err != nil {
		return err
	}
	defer r.selectedIdentity.end()
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if err := expected.validate(r.selectedIdentity, resolved); err != nil {
		return err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return err
	}
	defer parent.Close()
	file, _, err := r.openExpectedIdentityRootedFile(parent, base, expected)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrFileIdentityChanged, err)
		}
		return err
	}
	return file.Close()
}

// OpenDir opens an existing directory beneath the root without following
// symlinks in the final component or in any component below the root.
func (r Root) OpenDir(name string) (*os.File, error) {
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := r.checkParentComponents(resolved); err != nil {
		return nil, err
	}
	info, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, symlinkError(resolved)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", resolved)
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(parent, base)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !openedInfo.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("%q is not a directory", resolved)
	}
	return file, nil
}

// ReadFile reads a regular file beneath the root without following symlinks.
func (r Root) ReadFile(name string) ([]byte, error) {
	file, err := r.OpenFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// ReadFileLimited reads at most limit bytes from a regular file beneath the
// root. It rejects, rather than truncates, files that exceed the limit.
func (r Root) ReadFileLimited(name string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("read limit must not be negative")
	}
	file, err := r.OpenFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if limit == math.MaxInt64 {
		return io.ReadAll(file)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q exceeds the %d-byte size limit", name, limit)
	}
	return data, nil
}

// ReadFileOptional reads a regular file beneath the root and reports whether it
// exists. A missing file is not an error; a symlinked path still is.
func (r Root) ReadFileOptional(name string) ([]byte, bool, error) {
	data, err := r.ReadFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

// MkdirAll creates name and any missing parents beneath the root, rejecting any
// existing component that is a symlink or not a directory.
func (r Root) MkdirAll(name string, perm os.FileMode) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if err := r.ensureRootDir(perm); err != nil {
		return err
	}
	rooted, relative, err := r.openRooted(resolved, true)
	if err != nil {
		return err
	}
	defer rooted.Close()
	if err := r.validateDirectoryComponents(resolved); err != nil {
		return err
	}
	if err := rooted.MkdirAll(relative, perm); err != nil {
		return err
	}
	return r.validateDirectoryComponents(resolved)
}

// WriteFile atomically creates or replaces a file beneath the root.
func (r Root) WriteFile(name string, data []byte, perm os.FileMode) error {
	_, err := r.WriteFrom(name, bytes.NewReader(data), perm)
	return err
}

// WriteFrom atomically creates or replaces a file beneath the root with the
// contents of reader and returns the number of bytes written.
func (r Root) WriteFrom(name string, reader io.Reader, perm os.FileMode) (int64, error) {
	return r.writeFrom(name, reader, perm, true)
}

func (r Root) writeFrom(name string, reader io.Reader, perm os.FileMode, exactModeForNew bool) (int64, error) {
	return r.writeFromPreservingMetadata(name, reader, perm, exactModeForNew, nil, nil)
}

func (r Root) writeFromPreservingMetadata(
	name string,
	reader io.Reader,
	perm os.FileMode,
	exactModeForNew bool,
	metadataSource *os.File,
	metadataInfo os.FileInfo,
) (int64, error) {
	resolved, err := r.prepareWrite(name)
	if err != nil {
		return 0, err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return 0, err
	}
	defer parent.Close()

	hadExisting, err := checkReplaceableFileInRoot(parent, base, resolved)
	if err != nil {
		return 0, err
	}
	if r.afterValidationForTest != nil {
		r.afterValidationForTest()
	}

	temporary, temporaryName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", temporaryFilePattern, perm)
	if err != nil {
		return 0, err
	}
	success := false
	defer func() {
		_ = temporary.Close()
		if !success {
			_ = parent.Remove(temporaryName)
		}
	}()

	// Preserve supported filesystem metadata from the already-open original.
	// Otherwise keep the exact mode of an ordinary replacement. For a new file,
	// retain the process umask unless the caller explicitly requested an exact
	// mode.
	if metadataSource != nil {
		if err := copyReplacementMetadata(temporary, metadataSource, metadataInfo); err != nil {
			return 0, err
		}
	} else if hadExisting || exactModeForNew {
		if err := temporary.Chmod(perm); err != nil {
			return 0, err
		}
	}
	written, err := io.Copy(temporary, reader)
	if err != nil {
		return 0, err
	}
	if err := temporary.Sync(); err != nil {
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		return 0, err
	}

	if err := replaceFileInRoot(parent, temporaryName, base, hadExisting); err != nil {
		return 0, err
	}
	success = true
	return written, nil
}

// WriteFilePreservingMode atomically creates or replaces a regular file beneath
// the root. Existing files retain supported ownership, permission, ACL, and
// extended-attribute metadata without mutating aliases outside the rooted path.
// Where the platform exposes link counts, multiply linked files are refused
// rather than silently changing hard-link semantics. New files use perm subject
// to the process umask.
func (r Root) WriteFilePreservingMode(name string, data []byte, perm os.FileMode) error {
	resolved, err := r.prepareWrite(name)
	if err != nil {
		return err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return err
	}
	defer parent.Close()

	hadExisting, err := checkReplaceableFileInRoot(parent, base, resolved)
	if err != nil {
		return err
	}
	if !hadExisting {
		_, err := r.writeFrom(name, bytes.NewReader(data), perm, false)
		return err
	}

	file, err := secureopen.OpenExistingWritableNoFollowInRoot(parent, base)
	if err != nil {
		return fmt.Errorf("open existing file %q for replacement: %w", resolved, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if multiple, err := hasMultipleHardLinks(file, openedInfo); err != nil {
		return fmt.Errorf("inspect existing file %q: %w", resolved, err)
	} else if multiple {
		return fmt.Errorf("refusing to rewrite multiply linked file %q", resolved)
	}
	_, err = r.writeFromPreservingMetadata(name, bytes.NewReader(data), perm, false, file, openedInfo)
	return err
}

// CheckWriteFilePreservingMode performs the non-mutating checks required before
// WriteFilePreservingMode replaces an existing file. Missing destinations are
// accepted; callers can use this to preflight a multi-file plan before its first
// write.
func (r Root) CheckWriteFilePreservingMode(name string) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if resolved == r.path {
		return fmt.Errorf("%w: %q is the trusted root itself", ErrEscapesRoot, name)
	}
	if err := r.checkParentComponents(resolved); err != nil {
		return err
	}

	info, err := os.Lstat(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return symlinkError(resolved)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", resolved)
	}

	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return err
	}
	defer parent.Close()
	file, err := secureopen.OpenExistingWritableNoFollowInRoot(parent, base)
	if err != nil {
		return fmt.Errorf("open existing file %q for replacement: %w", resolved, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if multiple, err := hasMultipleHardLinks(file, openedInfo); err != nil {
		return fmt.Errorf("inspect existing file %q: %w", resolved, err)
	} else if multiple {
		return fmt.Errorf("refusing to rewrite multiply linked file %q", resolved)
	}
	return nil
}

// CheckCreateNewFile performs the non-mutating checks required before
// CreateNewFile publishes a destination. Missing parents are accepted because
// the eventual rooted write creates them; existing files and symlinks are not.
func (r Root) CheckCreateNewFile(name string) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if resolved == r.path {
		return fmt.Errorf("%w: %q is the trusted root itself", ErrEscapesRoot, name)
	}
	if err := r.checkParentComponents(resolved); err != nil {
		return err
	}
	info, err := os.Lstat(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return symlinkError(resolved)
	}
	return fmt.Errorf("%q already exists: %w", resolved, os.ErrExist)
}

// RemoveFileIfSame is the compatibility adapter for callers that still have a
// metadata snapshot. New transaction code must use RemoveFileIfSameIdentity;
// this historical path keeps its snapshot and fallback semantics unchanged.
func (r Root) RemoveFileIfSame(name string, expected os.FileInfo, expectedData []byte) error {
	identity, err := r.compatibilityIdentity(name, expected, expectedData)
	if err != nil {
		return err
	}
	return r.removeFileIfSameLegacy(name, identity.info, identity.data)
}

func (r Root) removeFileIfSameLegacy(name string, expected os.FileInfo, expectedData []byte) (resultErr error) {
	parent, base, err := r.openConditionalFileParent(name)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
	}()

	quarantineName, quarantine, _, err := r.quarantineExpectedFile(parent, base, expected, expectedData)
	if err != nil {
		return err
	}
	if err := quarantine.Close(); err != nil {
		return errors.Join(err, r.restoreOrRemoveQuarantine(parent, quarantineName, base, expected, expectedData))
	}
	if _, err := r.lstatAfterConditionalQuarantine(parent, base); err == nil {
		return errors.Join(
			fmt.Errorf("destination was replaced while removing the expected file"),
			r.removeExpectedQuarantine(parent, quarantineName, expected, expectedData),
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, r.restoreOrRemoveQuarantine(parent, quarantineName, base, expected, expectedData))
	}
	if err := r.removeExpectedQuarantine(parent, quarantineName, expected, expectedData); err != nil {
		return err
	}
	if err := r.syncConditionalParentDirectory(parent); err != nil {
		return err
	}
	return nil
}

// RemoveFileIfSameIdentity removes name only when the descriptor-backed
// identity captured by the same Root still matches. The matching file is first
// moved to an unpredictable quarantine name in the same rooted directory. A
// replacement observed before quarantine is rejected, and a replacement that
// appears after quarantine is never removed through the original destination
// name. ErrFileIdentityChanged leaves the current destination untouched when
// the race is observable. ErrQuarantineCleanupUncertain means the quarantined
// entry could not be safely verified or removed; callers must keep the wrapped
// quarantine evidence for recovery.
func (r Root) RemoveFileIfSameIdentity(name string, expected *FileIdentity) (resultErr error) {
	if err := r.selectedIdentity.begin(); err != nil {
		return err
	}
	defer r.selectedIdentity.end()
	if runtime.GOOS == "windows" {
		return ErrFileIdentityMutationUnsupported
	}
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if err := expected.validate(r.selectedIdentity, resolved); err != nil {
		return err
	}
	parent, base, err := r.openConditionalFileParent(name)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
	}()

	quarantineName, quarantine, _, err := r.quarantineExpectedIdentityFile(parent, base, expected)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrFileIdentityChanged, err)
		}
		return err
	}
	if err := quarantine.Close(); err != nil {
		return errors.Join(err, r.restoreExpectedQuarantine(parent, quarantineName, base, expected, err))
	}
	if _, err := r.lstatAfterConditionalQuarantine(parent, base); err == nil {
		return errors.Join(
			fmt.Errorf("%w: destination was replaced while removing the expected file", ErrFileIdentityChanged),
			r.removeExpectedIdentityQuarantine(parent, quarantineName, expected),
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, r.restoreExpectedQuarantine(parent, quarantineName, base, expected, err))
	}
	if err := r.removeExpectedIdentityQuarantine(parent, quarantineName, expected); err != nil {
		return err
	}
	if err := r.syncConditionalParentDirectory(parent); err != nil {
		return err
	}
	return nil
}

// WriteFileIfSame atomically replaces name with data only when the original
// destination still matches expected and expectedData. Existing metadata is
// copied from the expected file when preserveMetadata is true. The original
// destination is quarantined before the replacement is published, and both
// quarantine and publication use no-replace rooted operations so a concurrent
// writer's complete file is preserved.
func (r Root) WriteFileIfSame(
	name string,
	data []byte,
	perm os.FileMode,
	expected os.FileInfo,
	expectedData []byte,
	preserveMetadata bool,
) error {
	identity, err := r.compatibilityIdentity(name, expected, expectedData)
	if err != nil {
		return err
	}
	_, err = r.writeFileIfSame(name, data, perm, identity, preserveMetadata, false, nil, false, false)
	return err
}

// WriteFileIfSameWithInfo is the metadata-snapshot compatibility form of
// WriteFileIfSame. It returns the published file's current metadata but does
// not retain a descriptor. Callers that need identity-coupled rollback must
// use ReplaceFileIfSame with a FileIdentity captured by this Root.
func (r Root) WriteFileIfSameWithInfo(
	name string,
	data []byte,
	perm os.FileMode,
	expected os.FileInfo,
	expectedData []byte,
	preserveMetadata bool,
) (os.FileInfo, error) {
	identity, err := r.compatibilityIdentity(name, expected, expectedData)
	if err != nil {
		return nil, err
	}
	publishedInfo, err := r.writeFileIfSame(name, data, perm, identity, preserveMetadata, false, nil, false, false)
	return publishedInfo, err
}

// ReplaceFileIfSame atomically stages data and conditionally replaces name
// using an identity captured by this Root. The returned identity is retained
// until Root.Close and remains available when publication succeeded but a
// later cleanup or durability step failed. It requires the platform's native
// no-replace rename; it never silently substitutes the hard-link fallback used
// by the legacy os.FileInfo adapter. If native publication is unavailable, the
// original is restored when possible or its quarantine is retained and the
// unsupported error is returned.
func (r Root) ReplaceFileIfSame(
	name string,
	expected *FileIdentity,
	data []byte,
	perm os.FileMode,
	preserveMetadata bool,
) (*FileIdentity, error) {
	if err := r.selectedIdentity.begin(); err != nil {
		return nil, err
	}
	defer r.selectedIdentity.end()
	if runtime.GOOS == "windows" {
		return nil, ErrFileIdentityMutationUnsupported
	}
	if int64(len(data)) > fileIdentityDataLimit {
		return nil, fmt.Errorf("%d bytes exceeds %d-byte identity limit: %w", len(data), fileIdentityDataLimit, ErrFileIdentityDataTooLarge)
	}
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	if err := expected.validate(r.selectedIdentity, resolved); err != nil {
		return nil, err
	}
	var installed *FileIdentity
	_, err = r.writeFileIfSame(name, data, perm, expected, preserveMetadata, true, &installed, true, true)
	return installed, err
}

// compatibilityIdentity adapts the historical metadata-and-bytes API to the
// shared write helper without retaining a descriptor or imposing the strict
// identity API's bounded snapshot contract. Strict transaction callers must
// obtain a descriptor-backed token from CaptureFile or a publication method.
func (r Root) compatibilityIdentity(name string, expected os.FileInfo, expectedData []byte) (*FileIdentity, error) {
	if expected == nil {
		return nil, fmt.Errorf("%w: expected snapshot is unavailable", ErrFileIdentityChanged)
	}
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	return &FileIdentity{
		info: expected,
		data: expectedData,
		path: filepath.Clean(resolved),
	}, nil
}

func (r Root) writeFileIfSame(
	name string,
	data []byte,
	perm os.FileMode,
	expected *FileIdentity,
	preserveMetadata bool,
	retainPublishedIdentity bool,
	identityOut **FileIdentity,
	requireNativeNoReplace bool,
	strictIdentity bool,
) (_ os.FileInfo, resultErr error) {
	if strictIdentity && int64(len(data)) > fileIdentityDataLimit {
		return nil, fmt.Errorf("%d bytes exceeds %d-byte identity limit: %w", len(data), fileIdentityDataLimit, ErrFileIdentityDataTooLarge)
	}
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, err
	}
	if strictIdentity {
		if err := expected.validate(r.selectedIdentity, resolved); err != nil {
			return nil, err
		}
	}
	var publishedInfo os.FileInfo
	parent, base, err := r.openConditionalFileParent(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
	}()

	quarantineExpected := func() (string, *os.File, os.FileInfo, error) {
		if strictIdentity {
			return r.quarantineExpectedIdentityFile(parent, base, expected)
		}
		return r.quarantineExpectedFile(parent, base, expected.info, expected.data)
	}
	removeQuarantine := func(quarantineName string) error {
		if strictIdentity {
			return r.removeExpectedIdentityQuarantine(parent, quarantineName, expected)
		}
		return r.removeExpectedQuarantine(parent, quarantineName, expected.info, expected.data)
	}
	restoreQuarantine := func(quarantineName string) error {
		if strictIdentity {
			return r.restoreExpectedQuarantine(parent, quarantineName, base, expected, nil)
		}
		return r.restoreOrRemoveQuarantine(parent, quarantineName, base, expected.info, expected.data)
	}

	quarantineName, quarantine, quarantineInfo, err := quarantineExpected()
	if err != nil {
		if strictIdentity && errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrFileIdentityChanged, err)
		}
		return nil, err
	}
	quarantineClosed := false
	defer func() {
		if !quarantineClosed {
			resultErr = errors.Join(resultErr, quarantine.Close())
		}
	}()

	// The destination must remain absent after the expected file was moved.
	// If a replacement appeared, leave it untouched and discard only the
	// transaction's quarantined copy.
	if _, err := r.lstatAfterConditionalQuarantine(parent, base); err == nil {
		return nil, errors.Join(
			fmt.Errorf("%w: destination changed while preparing replacement", ErrFileIdentityChanged),
			removeQuarantine(quarantineName),
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}

	temporary, temporaryName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", temporaryFilePattern, perm)
	if err != nil {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	var temporaryInfo os.FileInfo
	temporaryDone := false
	temporaryClosed := false
	temporaryRetained := false
	defer func() {
		if strictIdentity && !temporaryDone {
			stagingInfo := temporaryInfo
			var stagingErr error
			if stagingInfo == nil && !temporaryClosed && !temporaryRetained {
				stagingInfo, stagingErr = temporary.Stat()
			}
			if stagingInfo == nil {
				resultErr = errors.Join(resultErr, stagingCleanupUncertain(temporaryName, "observe staging identity before removal", stagingErr))
			} else {
				resultErr = errors.Join(resultErr, r.removeStagingIfSame(parent, temporaryName, stagingInfo))
			}
		}
		if !temporaryClosed && !temporaryRetained {
			resultErr = errors.Join(resultErr, temporary.Close())
		}
		if !temporaryDone {
			if !strictIdentity {
				if err := parent.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
					resultErr = errors.Join(resultErr, fmt.Errorf("remove staging file: %w", err))
				}
			}
		}
	}()

	if preserveMetadata {
		if err := copyReplacementMetadata(temporary, quarantine, quarantineInfo); err != nil {
			return nil, errors.Join(err, restoreQuarantine(quarantineName))
		}
	} else if err := temporary.Chmod(perm); err != nil {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	if err := quarantine.Close(); err != nil {
		quarantineClosed = true
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	quarantineClosed = true
	written, err := io.Copy(temporary, bytes.NewReader(data))
	if err != nil {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	if written != int64(len(data)) {
		return nil, errors.Join(io.ErrShortWrite, restoreQuarantine(quarantineName))
	}
	if err := temporary.Sync(); err != nil {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	temporaryInfo, err = temporary.Stat()
	if err != nil {
		return nil, errors.Join(err, restoreQuarantine(quarantineName))
	}
	if !temporaryInfo.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("staging file is not regular"), restoreQuarantine(quarantineName))
	}
	// Keep the staged descriptor through publication and the immediate identity
	// recheck where the platform permits it. Windows requires closing before
	// rename, but the reopened destination descriptor still pins the installed
	// inode before the directory entry is checked again.
	if runtime.GOOS == "windows" || r.simulateWindowsCloseForTest {
		if err := temporary.Close(); err != nil {
			temporaryClosed = true
			return nil, errors.Join(err, restoreQuarantine(quarantineName))
		}
		temporaryClosed = true
	}
	if r.beforeConditionalPublishForTest != nil {
		r.beforeConditionalPublishForTest(parent, base)
	}
	var published bool
	var publicationCleanupErr error
	renameNoReplace := secureopen.RenameNoReplaceInRoot
	if r.renameNoReplaceForTest != nil {
		renameNoReplace = r.renameNoReplaceForTest
	}
	if requireNativeNoReplace {
		publicationCleanupErr = renameNoReplace(parent, temporaryName, base)
		published = publicationCleanupErr == nil
	} else {
		published, publicationCleanupErr = r.renameOrLinkNoReplace(parent, temporaryName, base)
	}
	if !published {
		return nil, errors.Join(publicationCleanupErr, restoreQuarantine(quarantineName))
	}
	temporaryDone = true
	quarantineLeftAfterPublication := func(err error) error {
		if publicationCleanupErr != nil {
			err = errors.Join(err, publicationCleanupErr)
		}
		return errors.Join(
			err,
			fmt.Errorf("quarantined file %q was left in place after publication uncertainty", quarantineName),
		)
	}
	retainedData := data
	if !strictIdentity {
		retainedData = nil
	}
	// On Unix the staged descriptor can remain open through publication. Keep
	// that descriptor attached to the selected root for the identity form so a
	// post-publication reopen failure still has a live reference to the inode
	// that this operation installed. Windows closes the staging handle before
	// rename, so the no-follow destination reopen below is its first available
	// identity reference.
	if retainPublishedIdentity && !strictIdentity && runtime.GOOS != "windows" && !r.simulateWindowsCloseForTest {
		installed, retainErr := r.selectedIdentity.retainIdentity(temporary, temporaryInfo, retainedData, resolved)
		if retainErr != nil {
			temporaryClosed = true
			return nil, quarantineLeftAfterPublication(fmt.Errorf("retain staged file identity: %w", retainErr))
		}
		temporaryRetained = true
		if identityOut != nil {
			*identityOut = installed
		}
	}
	postPublicationIdentityFailure := func(err error) (os.FileInfo, error) {
		if temporaryRetained {
			return temporaryInfo, quarantineLeftAfterPublication(err)
		}
		return nil, quarantineLeftAfterPublication(err)
	}
	if r.afterConditionalPublicationForTest != nil {
		r.afterConditionalPublicationForTest(parent, base)
	}
	// Capture the identity through a no-follow descriptor before cleaning up the
	// quarantine. The descriptor is retained for the identity form so a caller
	// can couple a later rollback to this exact installed inode.
	publishedFile, err := secureopen.OpenExistingNoFollowInRoot(parent, base)
	if err != nil {
		return postPublicationIdentityFailure(fmt.Errorf("open published file for identity verification: %w", err))
	}
	if r.afterConditionalPublicationOpenForTest != nil {
		r.afterConditionalPublicationOpenForTest(parent, base, publishedFile)
	}
	publishedStat, err := publishedFile.Stat()
	if err != nil {
		_ = publishedFile.Close()
		return postPublicationIdentityFailure(fmt.Errorf("stat published file for identity verification: %w", err))
	}
	if !publishedStat.Mode().IsRegular() {
		_ = publishedFile.Close()
		return postPublicationIdentityFailure(fmt.Errorf("published file is not regular"))
	}
	if !os.SameFile(temporaryInfo, publishedStat) {
		_ = publishedFile.Close()
		return postPublicationIdentityFailure(fmt.Errorf("published file identity changed during publication"))
	}
	closePublishedFile := true
	defer func() {
		if closePublishedFile {
			resultErr = errors.Join(resultErr, publishedFile.Close())
		}
	}()
	if retainPublishedIdentity && !strictIdentity {
		if !temporaryRetained {
			installed, retainErr := r.selectedIdentity.retainIdentity(publishedFile, publishedStat, retainedData, resolved)
			if retainErr != nil {
				_ = publishedFile.Close()
				closePublishedFile = false
				return nil, quarantineLeftAfterPublication(fmt.Errorf("retain published file identity: %w", retainErr))
			}
			closePublishedFile = false
			if identityOut != nil {
				*identityOut = installed
			}
		}
	}
	publishedInfo = publishedStat
	latestInfo, err := parent.Lstat(base)
	if err != nil {
		return publishedInfo, quarantineLeftAfterPublication(fmt.Errorf("recheck published file: %w", err))
	}
	if latestInfo.Mode()&os.ModeSymlink != 0 || !latestInfo.Mode().IsRegular() || !os.SameFile(publishedStat, latestInfo) {
		return publishedInfo, quarantineLeftAfterPublication(fmt.Errorf("%w: published file identity changed after publication", ErrFileIdentityChanged))
	}
	// A strict identity is created only after both the descriptor reopen and the
	// final destination observation prove that the installed directory entry is
	// the staged inode. Staging evidence is never returned as a publication
	// token when either observation fails.
	if retainPublishedIdentity && strictIdentity {
		installed, retainErr := r.selectedIdentity.retainIdentity(publishedFile, publishedInfo, data, resolved)
		if retainErr != nil {
			closePublishedFile = false
			return publishedInfo, quarantineLeftAfterPublication(fmt.Errorf("retain published file identity: %w", retainErr))
		}
		closePublishedFile = false
		if identityOut != nil {
			*identityOut = installed
		}
	}
	if !retainPublishedIdentity {
		if err := publishedFile.Close(); err != nil {
			closePublishedFile = false
			return nil, quarantineLeftAfterPublication(fmt.Errorf("close published file after identity verification: %w", err))
		}
		closePublishedFile = false
	}
	// The published destination is complete, so only the transaction's
	// quarantined inode is removed. A concurrent replacement at base is never
	// targeted by this cleanup.
	if err := removeQuarantine(quarantineName); err != nil {
		return publishedInfo, errors.Join(err, publicationCleanupErr)
	}
	if err := r.syncConditionalParentDirectory(parent); err != nil {
		return publishedInfo, errors.Join(err, publicationCleanupErr)
	}
	return publishedInfo, publicationCleanupErr
}

func (r Root) openConditionalFileParent(name string) (*os.Root, string, error) {
	resolved, err := r.Resolve(name)
	if err != nil {
		return nil, "", err
	}
	if resolved == r.path {
		return nil, "", fmt.Errorf("%w: %q is the trusted root itself", ErrEscapesRoot, name)
	}
	if err := r.checkParentComponents(resolved); err != nil {
		return nil, "", err
	}
	return r.openParentRooted(resolved)
}

func (r Root) openExpectedIdentityRootedFile(parent *os.Root, name string, expected *FileIdentity) (*os.File, os.FileInfo, error) {
	if err := expected.validateOwner(r.selectedIdentity); err != nil {
		return nil, nil, err
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(parent, name)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("expected file is not regular")
	}
	if !os.SameFile(expected.info, info) {
		return nil, nil, ErrFileIdentityChanged
	}
	if info.Mode().Perm() != expected.info.Mode().Perm() {
		return nil, nil, fmt.Errorf("%w: file permissions changed", ErrFileIdentityChanged)
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(len(expected.data))+1))
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(contents, expected.data) {
		return nil, nil, fmt.Errorf("%w: file contents changed", ErrFileIdentityChanged)
	}
	closeOnError = false
	return file, info, nil
}

func (r Root) quarantineExpectedIdentityFile(parent *os.Root, base string, expected *FileIdentity) (quarantineName string, quarantined *os.File, quarantineInfo os.FileInfo, resultErr error) {
	file, _, err := r.openExpectedIdentityRootedFile(parent, base, expected)
	if err != nil {
		return "", nil, nil, err
	}
	// Keep the original descriptor live through the rename. If the pathname
	// was replaced after the initial verification, RenameNoReplace must not
	// accidentally quarantine the replacement and then lose it when the
	// expected identity check fails.
	fileClosed := false
	defer func() {
		if !fileClosed {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if r.beforeConditionalQuarantineForTest != nil {
		r.beforeConditionalQuarantineForTest(parent, base)
	}
	if runtime.GOOS == "windows" {
		if err := file.Close(); err != nil {
			fileClosed = true
			return "", nil, nil, err
		}
		fileClosed = true
	}
	quarantineName, err = r.renameToFreshQuarantine(parent, base)
	if err != nil {
		return "", nil, nil, err
	}
	if !fileClosed {
		if err := file.Close(); err != nil {
			fileClosed = true
			return "", nil, nil, errors.Join(err, r.restoreExpectedQuarantine(parent, quarantineName, base, expected, err))
		}
		fileClosed = true
	}
	if r.afterConditionalQuarantineForTest != nil {
		r.afterConditionalQuarantineForTest(parent, quarantineName, base)
	}
	quarantined, quarantineInfo, err = r.openExpectedIdentityRootedFile(parent, quarantineName, expected)
	if err != nil {
		return "", nil, nil, errors.Join(err, r.restoreQuarantineIfBaseAbsent(parent, quarantineName, base, err))
	}
	return quarantineName, quarantined, quarantineInfo, nil
}

// renameToFreshQuarantine chooses an unpredictable, initially absent name and
// moves source to it with the platform's no-replace primitive. Unlike the
// older compatibility path, it never creates and then path-removes a
// placeholder. A collision is retried atomically; any other failure leaves the
// source entry untouched and is returned to the caller.
func (r Root) renameToFreshQuarantine(parent *os.Root, source string) (string, error) {
	renameNoReplace := secureopen.RenameNoReplaceInRoot
	if r.renameNoReplaceForTest != nil {
		renameNoReplace = r.renameNoReplaceForTest
	}
	for range 10_000 {
		name, err := randomRootedName(rollbackFilePattern)
		if err != nil {
			return "", err
		}
		err = renameNoReplace(parent, source, name)
		if err == nil {
			return name, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("failed to choose an unused quarantine name")
}

func randomRootedName(pattern string) (string, error) {
	prefix := pattern
	suffix := ""
	if index := strings.LastIndex(pattern, "*"); index >= 0 {
		prefix = pattern[:index]
		suffix = pattern[index+1:]
	}
	var randomBytes [12]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}
	return filepath.Join(".", prefix+hex.EncodeToString(randomBytes[:])+suffix), nil
}

// restoreQuarantineIfBaseAbsent repairs the only recoverable pre-publication
// race: a different file was moved from the caller-visible name into the
// quarantine before its identity could be verified. If the original name is
// still absent, rooted no-replace rename puts that entry back without deleting
// a concurrent recreation. If the name was recreated, or either observation is
// uncertain, the quarantine remains in place as evidence.
func (r Root) restoreQuarantineIfBaseAbsent(parent *os.Root, quarantineName, base string, cause error) error {
	_, err := parent.Lstat(base)
	if err == nil {
		return r.leaveQuarantineAfterUncertainty(quarantineName, cause)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(r.leaveQuarantineAfterUncertainty(quarantineName, cause), fmt.Errorf("inspect destination before quarantine recovery: %w", err))
	}
	if err := secureopen.RenameNoReplaceInRoot(parent, quarantineName, base); err != nil {
		if errors.Is(err, os.ErrExist) {
			return r.leaveQuarantineAfterUncertainty(quarantineName, cause)
		}
		return errors.Join(r.leaveQuarantineAfterUncertainty(quarantineName, cause), fmt.Errorf("restore quarantined entry: %w", err))
	}
	if err := r.syncConditionalParentDirectory(parent); err != nil {
		return errors.Join(cause, fmt.Errorf("sync restored quarantined entry: %w", err))
	}
	return nil
}

// restoreExpectedQuarantine validates the retained identity before recovering
// a strict operation that failed before publication. A mismatching quarantine
// is treated as a moved concurrent entry and is restored with no-replace
// semantics when the original name is still absent; it is never removed.
func (r Root) restoreExpectedQuarantine(parent *os.Root, quarantineName, base string, expected *FileIdentity, cause error) error {
	if err := expected.validateOwner(r.selectedIdentity); err != nil {
		return r.leaveQuarantineAfterUncertainty(quarantineName, errors.Join(cause, err))
	}
	file, _, err := r.openExpectedIdentityRootedFile(parent, quarantineName, expected)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			err = closeErr
		}
	}
	if err != nil {
		cause = errors.Join(cause, err)
	}
	return r.restoreQuarantineIfBaseAbsent(parent, quarantineName, base, cause)
}

func (r Root) quarantineExpectedFile(parent *os.Root, base string, expected os.FileInfo, expectedData []byte) (quarantineName string, quarantined *os.File, quarantineInfo os.FileInfo, resultErr error) {
	file, _, err := r.openExpectedRootedFile(parent, base, expected, expectedData)
	if err != nil {
		return "", nil, nil, err
	}
	// Keep the original descriptor live through the rename. If the pathname
	// was replaced after the initial verification, RenameNoReplace must not
	// accidentally quarantine the replacement and then lose it when the
	// expected identity check fails.
	fileClosed := false
	defer func() {
		if !fileClosed {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if r.beforeConditionalQuarantineForTest != nil {
		r.beforeConditionalQuarantineForTest(parent, base)
	}
	// Windows may deny a pathname rename while the opened handle is live even
	// when the caller requested delete sharing. The publication primitive keeps
	// its staged handle through validation where the platform permits it; for
	// this rollback quarantine, close before rename on Windows and validate the
	// moved entry immediately afterward.
	if runtime.GOOS == "windows" {
		if err := file.Close(); err != nil {
			fileClosed = true
			return "", nil, nil, err
		}
		fileClosed = true
	}
	quarantineFile, quarantineName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", rollbackFilePattern, 0o600)
	if err != nil {
		return "", nil, nil, err
	}
	if err := quarantineFile.Close(); err != nil {
		return "", nil, nil, errors.Join(err, parent.Remove(quarantineName))
	}
	if err := parent.Remove(quarantineName); err != nil {
		return "", nil, nil, err
	}
	if err := secureopen.RenameNoReplaceInRoot(parent, base, quarantineName); err != nil {
		return "", nil, nil, err
	}
	if !fileClosed {
		if err := file.Close(); err != nil {
			fileClosed = true
			return "", nil, nil, errors.Join(err, r.restoreQuarantineEntry(parent, quarantineName, base))
		}
		fileClosed = true
	}
	if r.afterConditionalQuarantineForTest != nil {
		r.afterConditionalQuarantineForTest(parent, quarantineName, base)
	}
	quarantined, quarantineInfo, err = r.openExpectedRootedFile(parent, quarantineName, expected, expectedData)
	if err != nil {
		return "", nil, nil, errors.Join(err, r.restoreQuarantineEntry(parent, quarantineName, base))
	}
	return quarantineName, quarantined, quarantineInfo, nil
}

func openExpectedRootedFile(parent *os.Root, name string, expected os.FileInfo, expectedData []byte) (*os.File, os.FileInfo, error) {
	if expected == nil {
		return nil, nil, fmt.Errorf("expected file identity is unavailable")
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(parent, name)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("expected file is not regular")
	}
	if !os.SameFile(expected, info) {
		return nil, nil, ErrFileIdentityChanged
	}
	if info.Mode().Perm() != expected.Mode().Perm() {
		return nil, nil, fmt.Errorf("%w: file permissions changed", ErrFileIdentityChanged)
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(len(expectedData))+1))
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(contents, expectedData) {
		return nil, nil, fmt.Errorf("%w: file contents changed", ErrFileIdentityChanged)
	}
	closeOnError = false
	return file, info, nil
}

func (r Root) openExpectedRootedFile(parent *os.Root, name string, expected os.FileInfo, expectedData []byte) (*os.File, os.FileInfo, error) {
	if r.openExpectedFileForTest != nil {
		return r.openExpectedFileForTest(parent, name, expected, expectedData)
	}
	return openExpectedRootedFile(parent, name, expected, expectedData)
}

func (r Root) removeExpectedQuarantine(parent *os.Root, quarantineName string, expected os.FileInfo, expectedData []byte) error {
	file, _, err := r.openExpectedRootedFile(parent, quarantineName, expected, expectedData)
	if err != nil {
		return quarantineCleanupUncertain(quarantineName, "verify quarantined file before removal", err)
	}
	if err := file.Close(); err != nil {
		return quarantineCleanupUncertain(quarantineName, "close quarantined file before removal", err)
	}
	if r.beforeConditionalQuarantineRemovalForTest != nil {
		r.beforeConditionalQuarantineRemovalForTest(parent, quarantineName)
	}
	latest, err := parent.Lstat(quarantineName)
	if err != nil {
		return quarantineCleanupUncertain(quarantineName, "recheck quarantined file before removal", err)
	}
	if !os.SameFile(expected, latest) || latest.Mode().Perm() != expected.Mode().Perm() {
		return quarantineCleanupUncertain(quarantineName, "quarantined file identity changed before removal", nil)
	}
	// There is no portable compare-and-unlink primitive for the final Lstat
	// and path-based Remove. The unpredictable quarantine name and the
	// identity/content recheck make replacement observable and preserve a
	// mismatch, but a hostile replacement in this final interval remains a
	// residual concurrency limitation of the supported platforms.
	if err := parent.Remove(quarantineName); err != nil {
		return quarantineCleanupUncertain(quarantineName, "remove quarantined file", err)
	}
	return nil
}

// removeExpectedIdentityQuarantine is the token-only quarantine cleanup used
// by strict identity operations. The retained descriptor and captured bytes
// are the only expected-state inputs; callers cannot substitute an arbitrary
// FileInfo snapshot after a transaction has started.
//
// POSIX does not expose a portable compare-and-unlink operation. We therefore
// perform a final rooted identity observation and remove only when it still
// names the retained quarantine inode. If the observation is missing,
// mismatched, or otherwise uncertain, no further pathname mutation is made and
// the quarantine is left as recoverable evidence.
func (r Root) removeExpectedIdentityQuarantine(parent *os.Root, quarantineName string, expected *FileIdentity) error {
	if err := expected.validateOwner(r.selectedIdentity); err != nil {
		return quarantineCleanupUncertain(quarantineName, "validate quarantined file identity before removal", err)
	}
	file, info, err := r.openExpectedIdentityRootedFile(parent, quarantineName, expected)
	if err != nil {
		return quarantineCleanupUncertain(quarantineName, "verify quarantined file before removal", err)
	}
	if err := file.Close(); err != nil {
		return quarantineCleanupUncertain(quarantineName, "close quarantined file before removal", err)
	}
	if r.beforeConditionalQuarantineRemovalForTest != nil {
		r.beforeConditionalQuarantineRemovalForTest(parent, quarantineName)
	}
	latest, err := parent.Lstat(quarantineName)
	if err != nil {
		return quarantineCleanupUncertain(quarantineName, "recheck quarantined file before removal", err)
	}
	if !os.SameFile(info, latest) || latest.Mode().Perm() != info.Mode().Perm() {
		return quarantineCleanupUncertain(quarantineName, "quarantined file identity changed before removal", nil)
	}
	if err := parent.Remove(quarantineName); err != nil {
		return quarantineCleanupUncertain(quarantineName, "remove quarantined file", err)
	}
	return nil
}

// removeStagingIfSame removes an unpublished private entry only when the
// identity observed through its still-live staging descriptor remains at the
// same random name. It never removes a replacement that appeared at that
// name; instead it returns explicit uncertainty and leaves the entry for
// recovery.
func (r Root) removeStagingIfSame(parent *os.Root, stagingName string, expected os.FileInfo) error {
	if expected == nil {
		return stagingCleanupUncertain(stagingName, "staging identity is unavailable", nil)
	}
	latest, err := parent.Lstat(stagingName)
	if err != nil {
		return stagingCleanupUncertain(stagingName, "recheck staging file before removal", err)
	}
	if !os.SameFile(expected, latest) || latest.Mode().Perm() != expected.Mode().Perm() {
		return stagingCleanupUncertain(stagingName, "staging file identity changed before removal", nil)
	}
	if err := parent.Remove(stagingName); err != nil {
		return stagingCleanupUncertain(stagingName, "remove staging file", err)
	}
	return nil
}

func stagingCleanupUncertain(stagingName, operation string, err error) error {
	message := fmt.Sprintf("staging file %q cleanup uncertain during %s", stagingName, operation)
	if err != nil {
		return errors.Join(ErrStagingCleanupUncertain, fmt.Errorf("%s: %w", message, err))
	}
	return errors.Join(ErrStagingCleanupUncertain, errors.New(message))
}

// leaveQuarantineAfterUncertainty records that the named quarantine was not
// mutated after a failed identity observation. The name is deliberately
// retained in the error so an operator can recover or inspect the entry.
func (r Root) leaveQuarantineAfterUncertainty(quarantineName string, cause error) error {
	message := fmt.Errorf("quarantined file %q was left in place after identity uncertainty", quarantineName)
	if cause == nil {
		return errors.Join(ErrQuarantineCleanupUncertain, message)
	}
	return errors.Join(ErrQuarantineCleanupUncertain, message, cause)
}

func quarantineCleanupUncertain(quarantineName, operation string, err error) error {
	uncertain := fmt.Sprintf("quarantined file %q cleanup uncertain during %s", quarantineName, operation)
	if err != nil {
		return errors.Join(ErrQuarantineCleanupUncertain, fmt.Errorf("%s: %w", uncertain, err))
	}
	return errors.Join(ErrQuarantineCleanupUncertain, errors.New(uncertain))
}

func (r Root) lstatAfterConditionalQuarantine(parent *os.Root, name string) (os.FileInfo, error) {
	if r.postConditionalQuarantineLstatForTest != nil {
		return r.postConditionalQuarantineLstatForTest(parent, name)
	}
	return parent.Lstat(name)
}

func (r Root) syncConditionalParentDirectory(parent *os.Root) error {
	if r.syncDirectoryForTest != nil {
		return r.syncDirectoryForTest(parent)
	}
	directory, err := parent.Open(".")
	if err != nil {
		return fmt.Errorf("open parent directory for durability sync: %w", err)
	}
	if err := directory.Sync(); err != nil && !unsupportedDirectorySyncError(err) {
		_ = directory.Close()
		return fmt.Errorf("sync parent directory after conditional write: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close parent directory after conditional write: %w", err)
	}
	return nil
}

func (r Root) restoreOrRemoveQuarantine(parent *os.Root, quarantineName, base string, expected os.FileInfo, expectedData []byte) error {
	file, _, err := r.openExpectedRootedFile(parent, quarantineName, expected, expectedData)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := secureopen.RenameNoReplaceInRoot(parent, quarantineName, base); err == nil {
		return r.syncConditionalParentDirectory(parent)
	} else if errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		return errors.Join(err, fmt.Errorf("quarantined file %q was left in place", quarantineName))
	} else if errors.Is(err, os.ErrExist) {
		// A replacement already occupies the original name. Keep the
		// quarantined entry as a recoverable copy rather than deleting either
		// the replacement or the original transaction state.
		return errors.Join(
			fmt.Errorf("preserve concurrent replacement: %w", err),
			fmt.Errorf("quarantined file %q was left in place", quarantineName),
		)
	} else {
		return err
	}
}

// restoreQuarantineEntry puts a quarantined directory entry back at its
// original name without validating its contents. It is used only when the
// entry turned out not to be the expected inode, so preserving that entry is
// safer than attempting to remove or otherwise interpret it. A successful
// restore is followed by a parent-directory sync so the recovery is durable.
func (r Root) restoreQuarantineEntry(parent *os.Root, quarantineName, base string) error {
	if err := secureopen.RenameNoReplaceInRoot(parent, quarantineName, base); err == nil {
		return r.syncConditionalParentDirectory(parent)
	} else if errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		return errors.Join(err, fmt.Errorf("quarantined replacement %q was left in place", quarantineName))
	} else if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("preserve concurrent replacement while restoring quarantine: %w", err)
	} else {
		return err
	}
}

func (r Root) renameOrLinkNoReplace(parent *os.Root, temporaryName, name string) (bool, error) {
	renameNoReplace := secureopen.RenameNoReplaceInRoot
	if r.renameNoReplaceForTest != nil {
		renameNoReplace = r.renameNoReplaceForTest
	}
	if err := renameNoReplace(parent, temporaryName, name); err == nil {
		return true, nil
	} else if !errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		return false, err
	}
	if err := parent.Link(temporaryName, name); err != nil {
		return false, err
	}
	remove := parent.Remove
	if r.removeStagedFileForTest != nil {
		remove = func(path string) error {
			return r.removeStagedFileForTest(parent, path)
		}
	}
	if err := remove(temporaryName); err != nil {
		return true, fmt.Errorf("publish succeeded but remove staged file: %w", err)
	}
	return true, nil
}

// CheckFileParent validates a future file path and all existing parent
// components without requiring the final destination name to be absent.
func (r Root) CheckFileParent(name string) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if resolved == r.path {
		return fmt.Errorf("%w: %q is the trusted root itself", ErrEscapesRoot, name)
	}
	return r.checkParentComponents(resolved)
}

// CheckDirectoryWritable verifies that a temporary regular file can be created
// and removed within an existing directory beneath the root.
func (r Root) CheckDirectoryWritable(name string, perm os.FileMode) error {
	resolved, err := r.Resolve(name)
	if err != nil {
		return err
	}
	if err := r.validateExistingDir(resolved); err != nil {
		return err
	}
	rooted, relative, err := r.openRooted(resolved, false)
	if err != nil {
		return err
	}
	directory, err := rooted.OpenRoot(relative)
	_ = rooted.Close()
	if err != nil {
		return err
	}
	defer directory.Close()

	probe, probeName, err := secureopen.CreateTempNoFollowInRoot(directory, ".", ".asc-write-probe-*", perm)
	if err != nil {
		return err
	}
	defer func() {
		_ = probe.Close()
		_ = directory.Remove(probeName)
	}()
	if err := probe.Chmod(perm); err != nil {
		return err
	}
	if err := probe.Close(); err != nil {
		return err
	}
	if err := directory.Remove(probeName); err != nil {
		return err
	}
	return nil
}

// CreateNewFile writes data to a new file beneath the root and fails when the
// destination already exists. It prefers atomic no-replace publication, then
// falls back to rooted, no-follow O_EXCL creation when the filesystem does not
// support atomic no-replace rename.
func (r Root) CreateNewFile(name string, data []byte, perm os.FileMode) error {
	_, err := r.CreateNewFrom(name, bytes.NewReader(data), perm)
	if !errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		return err
	}
	return r.createNewFileExclusive(name, data, perm)
}

// CreateNewFileAtomic atomically publishes complete data as a new file beneath
// the root. It returns ErrRenameNoReplaceUnsupported instead of falling back
// when the filesystem cannot provide atomic no-replace rename semantics.
func (r Root) CreateNewFileAtomic(name string, data []byte, perm os.FileMode) error {
	r.requireNativeNoReplace = true
	_, _, err := r.createNewFromWithInfo(name, bytes.NewReader(data), perm, false, nil, nil, false)
	return err
}

// CreateNewFileAtomicWithInfo is the compatibility metadata-snapshot adapter.
// It returns the published file's current metadata without retaining a
// descriptor. Callers that need identity-coupled rollback should use
// CreateNewFileAtomicWithIdentity instead of trusting the returned snapshot.
func (r Root) CreateNewFileAtomicWithInfo(name string, data []byte, perm os.FileMode) (os.FileInfo, error) {
	r.requireNativeNoReplace = true
	_, publishedInfo, err := r.createNewFromWithInfo(name, bytes.NewReader(data), perm, false, nil, nil, false)
	return publishedInfo, err
}

// CreateNewFileAtomicWithIdentity is the token-returning form of
// CreateNewFileAtomic. The returned descriptor-backed identity is retained
// until Root.Close and is returned only after rooted observations prove that
// the staged inode is the installed destination, so a caller can conditionally
// roll back the exact file created by this operation.
func (r Root) CreateNewFileAtomicWithIdentity(name string, data []byte, perm os.FileMode) (*FileIdentity, error) {
	if err := r.selectedIdentity.begin(); err != nil {
		return nil, err
	}
	defer r.selectedIdentity.end()
	if int64(len(data)) > fileIdentityDataLimit {
		return nil, fmt.Errorf("%d bytes exceeds %d-byte identity limit: %w", len(data), fileIdentityDataLimit, ErrFileIdentityDataTooLarge)
	}
	r.requireNativeNoReplace = true
	var identity *FileIdentity
	_, publishedInfo, err := r.createNewFromWithInfo(name, bytes.NewReader(data), perm, true, data, &identity, true)
	if identity != nil && publishedInfo != nil && !os.SameFile(identity.Info(), publishedInfo) {
		return identity, errors.Join(err, ErrFileIdentityChanged)
	}
	return identity, err
}

func (r Root) createNewFileExclusive(name string, data []byte, perm os.FileMode) error {
	resolved, err := r.prepareWrite(name)
	if err != nil {
		return err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return err
	}
	defer parent.Close()

	if r.afterValidationForTest != nil {
		r.afterValidationForTest()
	}
	file, err := secureopen.OpenNewFileNoFollowInRoot(parent, base, perm)
	if err != nil {
		return err
	}
	createdInfo, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return statErr
	}
	complete := false
	defer func() {
		_ = file.Close()
		if complete {
			return
		}
		currentInfo, currentErr := parent.Lstat(base)
		if currentErr == nil && os.SameFile(createdInfo, currentInfo) {
			_ = parent.Remove(base)
		}
	}()
	if err := file.Chmod(perm); err != nil {
		return err
	}
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

// CreateNewFrom atomically publishes reader's complete contents as a new file
// beneath the root. It stages an unpredictable no-follow file in the same
// directory, syncs it, then uses an atomic no-replace rename. On platforms that
// permit it, the staging handle remains open through publication identity
// verification so an immediate replacement cannot reuse the staged inode. A
// read, write, sync, close, or publish failure leaves an existing destination
// intact.
func (r Root) CreateNewFrom(name string, reader io.Reader, perm os.FileMode) (int64, error) {
	written, _, err := r.createNewFromWithInfo(name, reader, perm, false, nil, nil, false)
	return written, err
}

func (r Root) createNewFromWithInfo(name string, reader io.Reader, perm os.FileMode, retainPublishedIdentity bool, identityData []byte, identityOut **FileIdentity, strictIdentity bool) (written int64, _ os.FileInfo, resultErr error) {
	resolved, err := r.prepareWrite(name)
	if err != nil {
		return 0, nil, err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
	}()

	info, err := parent.Lstat(base)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return 0, nil, symlinkError(resolved)
		}
		return 0, nil, fmt.Errorf("%q already exists: %w", resolved, os.ErrExist)
	case !errors.Is(err, os.ErrNotExist):
		return 0, nil, err
	}
	if r.afterValidationForTest != nil {
		r.afterValidationForTest()
	}

	file, temporaryName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", temporaryFilePattern, perm)
	if err != nil {
		return 0, nil, err
	}
	published := false
	stagingClosed := false
	stagingRetained := false
	var stagedInfo os.FileInfo
	retainedData := identityData
	if !strictIdentity {
		retainedData = nil
	}
	openPublishedFile := secureopen.OpenExistingNoFollowInRoot
	if r.openPublishedFileForTest != nil {
		openPublishedFile = r.openPublishedFileForTest
	}
	statPublishedFile := func(file *os.File) (os.FileInfo, error) {
		if r.statPublishedFileForTest != nil {
			return r.statPublishedFileForTest(file)
		}
		return file.Stat()
	}
	closeStaging := func() error {
		if stagingClosed || stagingRetained {
			return nil
		}
		stagingClosed = true
		return file.Close()
	}
	retainStagingIdentity := func() bool {
		if strictIdentity || !retainPublishedIdentity || stagingClosed || stagingRetained || runtime.GOOS == "windows" || r.simulateWindowsCloseForTest {
			return false
		}
		identity, retainErr := r.selectedIdentity.retainIdentity(file, stagedInfo, retainedData, resolved)
		if retainErr != nil {
			return false
		}
		stagingRetained = true
		if identityOut != nil {
			*identityOut = identity
		}
		return true
	}
	retainPublishedDestinationIdentity := func() (os.FileInfo, bool) {
		if strictIdentity || !retainPublishedIdentity || r.selectedIdentity == nil {
			return nil, false
		}
		publishedFile, openErr := openPublishedFile(parent, base)
		if openErr != nil {
			return nil, false
		}
		publishedInfo, statErr := statPublishedFile(publishedFile)
		if statErr != nil || !publishedInfo.Mode().IsRegular() || !os.SameFile(stagedInfo, publishedInfo) {
			_ = publishedFile.Close()
			return nil, false
		}
		identity, retainErr := r.selectedIdentity.retainIdentity(publishedFile, publishedInfo, retainedData, resolved)
		if retainErr != nil {
			_ = publishedFile.Close()
			return nil, false
		}
		if identityOut != nil {
			*identityOut = identity
		}
		return publishedInfo, true
	}
	defer func() {
		if strictIdentity && !published {
			var stagingErr error
			if stagedInfo == nil && !stagingClosed && !stagingRetained {
				stagedInfo, stagingErr = file.Stat()
			}
			if stagedInfo == nil {
				resultErr = errors.Join(resultErr, stagingCleanupUncertain(temporaryName, "observe staging identity before removal", stagingErr))
			} else {
				resultErr = errors.Join(resultErr, r.removeStagingIfSame(parent, temporaryName, stagedInfo))
			}
		}
		if err := closeStaging(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close staging file: %w", err))
		}
		if !published && !strictIdentity {
			if err := parent.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove staging file: %w", err))
			}
		}
	}()
	if err := file.Chmod(perm); err != nil {
		return 0, nil, err
	}
	written, err = io.Copy(file, reader)
	if err != nil {
		return written, nil, err
	}
	if err := file.Sync(); err != nil {
		return written, nil, err
	}
	stagedInfo, err = file.Stat()
	if err != nil {
		return written, nil, err
	}
	if !stagedInfo.Mode().IsRegular() {
		return written, nil, fmt.Errorf("staged file %q is not regular", resolved)
	}
	// Keep the staging descriptor open through publication and the identity
	// check on Unix. If a racing writer unlinks the published name immediately,
	// the open descriptor keeps the original inode alive so the filesystem
	// cannot reuse its identity for the replacement before Lstat observes it.
	// Windows requires the handle to be closed before its rename operation.
	if runtime.GOOS == "windows" || r.simulateWindowsCloseForTest {
		if err := closeStaging(); err != nil {
			return written, nil, err
		}
	}
	renameNoReplace := secureopen.RenameNoReplaceInRoot
	if r.renameNoReplaceForTest != nil {
		renameNoReplace = r.renameNoReplaceForTest
	}
	if err := renameNoReplace(parent, temporaryName, base); err != nil {
		if !errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
			return written, nil, err
		}
		if r.requireNativeNoReplace {
			return written, nil, err
		}
		// A hard link atomically publishes the complete staged inode without an
		// existing destination. The staging descriptor remains open on Unix so
		// the identity check below cannot mistake an immediately recycled inode
		// for the file created by this call.
		if linkErr := parent.Link(temporaryName, base); linkErr != nil {
			return written, nil, linkErr
		}
		if removeErr := parent.Remove(temporaryName); removeErr != nil {
			return written, nil, fmt.Errorf("publish succeeded but remove staged file: %w", removeErr)
		}
	}
	published = true
	createdInfo, err := parent.Lstat(base)
	if r.postPublicationLstatForTest != nil {
		createdInfo, err = r.postPublicationLstatForTest(parent, base)
	}
	if err != nil {
		if publishedInfo, retained := retainPublishedDestinationIdentity(); retained {
			return written, publishedInfo, fmt.Errorf("stat published file %q: %w", resolved, err)
		}
		if retainStagingIdentity() {
			return written, stagedInfo, fmt.Errorf("stat published file %q: %w", resolved, err)
		}
		return written, nil, fmt.Errorf("stat published file %q: %w", resolved, err)
	}
	if createdInfo.Mode()&os.ModeSymlink != 0 {
		return written, nil, symlinkError(resolved)
	}
	if !createdInfo.Mode().IsRegular() {
		return written, nil, fmt.Errorf("published file %q is not regular", resolved)
	}
	if !os.SameFile(stagedInfo, createdInfo) {
		return written, nil, fmt.Errorf("%w: published file %q identity changed during publication", ErrFileIdentityChanged, resolved)
	}
	// Reopen the destination through the rooted no-follow primitive and use
	// that handle's identity as the returned receipt. On Unix the staging
	// descriptor remains open through this check; on Windows the destination
	// handle is the first stable reference after the rename. Keeping this
	// descriptor live also prevents an immediate unlink/recreate from reusing
	// the installed file identity before the directory entry is checked again.
	if r.beforePublicationOpenForTest != nil {
		r.beforePublicationOpenForTest(parent, base)
	}
	publishedFile, err := openPublishedFile(parent, base)
	if err != nil {
		if retainedInfo, retained := retainPublishedDestinationIdentity(); retained {
			return written, retainedInfo, fmt.Errorf("open published file %q for identity verification: %w", resolved, err)
		}
		if retainStagingIdentity() {
			return written, stagedInfo, fmt.Errorf("open published file %q for identity verification: %w", resolved, err)
		}
		return written, nil, fmt.Errorf("open published file %q for identity verification: %w", resolved, err)
	}
	closePublishedFile := true
	defer func() {
		if closePublishedFile {
			_ = publishedFile.Close()
		}
	}()
	publishedInfo, err := statPublishedFile(publishedFile)
	if err != nil {
		_ = publishedFile.Close()
		closePublishedFile = false
		if retainedInfo, retained := retainPublishedDestinationIdentity(); retained {
			return written, retainedInfo, fmt.Errorf("stat opened published file %q: %w", resolved, err)
		}
		if retainStagingIdentity() {
			return written, stagedInfo, fmt.Errorf("stat opened published file %q: %w", resolved, err)
		}
		return written, nil, fmt.Errorf("stat opened published file %q: %w", resolved, err)
	}
	if !publishedInfo.Mode().IsRegular() {
		return written, nil, fmt.Errorf("opened published file %q is not regular", resolved)
	}
	if !os.SameFile(stagedInfo, publishedInfo) {
		return written, nil, fmt.Errorf("%w: published file %q identity changed before reopen", ErrFileIdentityChanged, resolved)
	}
	if retainPublishedIdentity && !strictIdentity {
		identity, retainErr := r.selectedIdentity.retainIdentity(publishedFile, publishedInfo, retainedData, resolved)
		if retainErr != nil {
			return written, nil, fmt.Errorf("retain published file identity")
		}
		closePublishedFile = false
		if identityOut != nil {
			*identityOut = identity
		}
	}
	if r.afterPublicationOpenForTest != nil {
		r.afterPublicationOpenForTest(parent, base)
	}
	latestInfo, err := parent.Lstat(base)
	if err != nil {
		return written, publishedInfo, fmt.Errorf("recheck published file %q: %w", resolved, err)
	}
	if latestInfo.Mode()&os.ModeSymlink != 0 || !latestInfo.Mode().IsRegular() {
		return written, publishedInfo, fmt.Errorf("recheck published file %q is not regular", resolved)
	}
	if !os.SameFile(publishedInfo, latestInfo) {
		return written, publishedInfo, fmt.Errorf("%w: published file %q identity changed after reopen", ErrFileIdentityChanged, resolved)
	}
	if retainPublishedIdentity && strictIdentity {
		identity, retainErr := r.selectedIdentity.retainIdentity(publishedFile, publishedInfo, identityData, resolved)
		if retainErr != nil {
			closePublishedFile = false
			return written, publishedInfo, errors.Join(ErrFileIdentityChanged, fmt.Errorf("retain published file identity: %w", retainErr))
		}
		closePublishedFile = false
		if identityOut != nil {
			*identityOut = identity
		}
	}
	directory, err := parent.Open(".")
	if err != nil {
		return written, publishedInfo, fmt.Errorf("open parent directory for durability sync: %w", err)
	}
	if err := directory.Sync(); err != nil && !unsupportedDirectorySyncError(err) {
		_ = directory.Close()
		return written, publishedInfo, fmt.Errorf("sync parent directory after publish: %w", err)
	}
	if err := directory.Close(); err != nil {
		return written, publishedInfo, fmt.Errorf("close parent directory after durability sync: %w", err)
	}
	if err := closeStaging(); err != nil {
		return written, publishedInfo, fmt.Errorf("close staged file after publication: %w", err)
	}
	return written, publishedInfo, nil
}

// AppendFile appends data to a file beneath the root, creating it when missing,
// without following a final or parent symlink.
func (r Root) AppendFile(name string, data []byte, perm os.FileMode) error {
	resolved, err := r.prepareWrite(name)
	if err != nil {
		return err
	}
	parent, base, err := r.openParentRooted(resolved)
	if err != nil {
		return err
	}
	defer parent.Close()

	hadExisting := false
	if info, err := parent.Lstat(base); err == nil {
		hadExisting = true
		if info.Mode()&os.ModeSymlink != 0 {
			return symlinkError(resolved)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%q is not a regular file", resolved)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if r.afterValidationForTest != nil {
		r.afterValidationForTest()
	}

	var file *os.File
	if hadExisting {
		file, err = secureopen.OpenExistingAppendNoFollowInRoot(parent, base)
	} else {
		file, err = secureopen.OpenNewFileNoFollowInRoot(parent, base, perm)
	}
	if err != nil {
		return err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("%q is not a regular file", resolved)
	}
	if hadExisting {
		if multiple, err := hasMultipleHardLinks(file, openedInfo); err != nil {
			_ = file.Close()
			return fmt.Errorf("inspect existing file %q: %w", resolved, err)
		} else if multiple {
			_ = file.Close()
			return fmt.Errorf("refusing to append to multiply linked file %q", resolved)
		}
		// Security logs and similar callers use perm to tighten an existing
		// file. New files retain the process umask from their exclusive create.
		if err := file.Chmod(perm); err != nil {
			_ = file.Close()
			return err
		}
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (r Root) prepareWrite(name string) (string, error) {
	resolved, err := r.Resolve(name)
	if err != nil {
		return "", err
	}
	if resolved == r.path {
		return "", fmt.Errorf("%w: %q is the trusted root itself", ErrEscapesRoot, name)
	}
	parent, err := r.relativeToRoot(filepath.Dir(resolved))
	if err != nil {
		return "", err
	}
	if err := r.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	return resolved, nil
}

func (r Root) ensureRootDir(perm os.FileMode) error {
	info, err := os.Stat(r.path)
	switch {
	case err == nil:
		if !info.IsDir() {
			return fmt.Errorf("trusted root %q is not a directory", r.path)
		}
		if r.selectedIdentity.isPinned() {
			return nil
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if r.selectedIdentity.isPinned() {
		return symlinkError(r.path)
	}
	if r.pendingCreation == nil {
		return symlinkError(r.path)
	}
	r.pendingCreation.mu.Lock()
	defer r.pendingCreation.mu.Unlock()
	if r.selectedIdentity.isPinned() {
		return nil
	}
	if r.beforeCreateRootForTest != nil {
		r.beforeCreateRootForTest()
	}
	baseAtPath, err := os.Stat(r.pendingCreation.lexicalBase)
	if err != nil {
		return err
	}
	if !r.pendingCreation.baseIdentity.matches(baseAtPath) {
		return symlinkError(r.pendingCreation.lexicalBase)
	}
	base, err := openAbsoluteRootNoFollow(r.pendingCreation.physicalBase)
	if err != nil {
		return err
	}
	baseInfo, err := base.Stat(".")
	if err != nil || !r.pendingCreation.baseIdentity.matches(baseInfo) {
		_ = base.Close()
		if err != nil {
			return err
		}
		return symlinkError(r.pendingCreation.physicalBase)
	}
	created, err := createMissingRoot(base, r.pendingCreation.suffix, perm, r.pendingCreation.physicalBase)
	if err != nil {
		return err
	}
	selectedAtPath, err := os.Stat(r.path)
	if err != nil {
		created.rollback()
		return err
	}
	openedInfo, err := created.final.Stat(".")
	if err != nil || !os.SameFile(openedInfo, selectedAtPath) {
		created.rollback()
		if err != nil {
			return err
		}
		return symlinkError(r.path)
	}
	if err := r.pendingCreation.baseIdentity.close(); err != nil {
		created.rollback()
		return err
	}
	opened := created.release()
	if !r.selectedIdentity.pin(opened) {
		return symlinkError(r.path)
	}
	return nil
}

type missingRootCreation struct {
	roots      []*os.Root
	suffix     []string
	created    []bool
	final      *os.Root
	terminated bool
}

func (creation *missingRootCreation) rollback() {
	if creation == nil || creation.terminated {
		return
	}
	creation.terminated = true
	for index := len(creation.suffix) - 1; index >= 0; index-- {
		if creation.created[index] {
			_ = creation.roots[index].Remove(creation.suffix[index])
		}
	}
	for _, root := range creation.roots {
		_ = root.Close()
	}
}

func (creation *missingRootCreation) release() *os.Root {
	if creation == nil || creation.terminated {
		return nil
	}
	creation.terminated = true
	for index := 0; index < len(creation.roots)-1; index++ {
		_ = creation.roots[index].Close()
	}
	return creation.final
}

func createMissingRoot(base *os.Root, suffix []string, perm os.FileMode, basePath string) (_ *missingRootCreation, resultErr error) {
	creation := &missingRootCreation{
		roots:   []*os.Root{base},
		suffix:  append([]string(nil), suffix...),
		created: make([]bool, len(suffix)),
	}
	defer func() {
		if resultErr != nil {
			creation.rollback()
		}
	}()
	current := base
	for index, component := range suffix {
		componentPath := filepath.Join(append([]string{basePath}, suffix[:index+1]...)...)
		if err := validateMissingRootComponent(component); err != nil {
			return nil, err
		}
		if _, err := current.Lstat(component); err == nil {
			return nil, symlinkError(componentPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := current.Mkdir(component, perm); err != nil {
			return nil, err
		}
		creation.created[index] = true
		before, err := current.Lstat(component)
		if err != nil {
			return nil, err
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return nil, symlinkError(componentPath)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		after, err := next.Stat(".")
		if err != nil || !os.SameFile(before, after) {
			_ = next.Close()
			if err != nil {
				return nil, err
			}
			return nil, symlinkError(componentPath)
		}
		creation.roots = append(creation.roots, next)
		current = next
	}
	creation.final = current
	return creation, nil
}

func (r Root) openRooted(absolute string, resolveFinal bool) (*os.Root, string, error) {
	rooted, err := r.OpenRoot()
	if err != nil {
		return nil, "", err
	}
	relative, err := r.rootedRelative(absolute, resolveFinal)
	if err != nil {
		_ = rooted.Close()
		return nil, "", err
	}
	return rooted, relative, nil
}

func (r Root) openParentRooted(absolute string) (*os.Root, string, error) {
	rooted, relative, err := r.openRooted(absolute, false)
	if err != nil {
		return nil, "", err
	}
	parent, err := rooted.OpenRoot(filepath.Dir(relative))
	_ = rooted.Close()
	if err != nil {
		return nil, "", err
	}
	return parent, filepath.Base(relative), nil
}

// rootedRelative converts an already-contained absolute path into a name for
// os.Root. Existing internal directory symlinks are resolved to their physical
// path so AllowingInternalSymlinks remains compatible with absolute in-root
// links, while the final file component remains unresolved for no-follow open.
func (r Root) rootedRelative(absolute string, resolveFinal bool) (string, error) {
	components, err := r.componentsBelowRoot(absolute)
	if err != nil {
		return "", err
	}
	physicalRoot, err := filepath.EvalSymlinks(r.path)
	if err != nil {
		return "", err
	}
	current := physicalRoot
	resolveCount := len(components)
	if !resolveFinal && resolveCount > 0 {
		resolveCount--
	}

	for index := 0; index < resolveCount; index++ {
		candidate := filepath.Join(current, components[index])
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			for _, remaining := range components[index:] {
				current = filepath.Join(current, remaining)
			}
			return relativeWithinRoot(physicalRoot, current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if !r.internalSymlinks {
				return "", symlinkError(candidate)
			}
			resolved, err := filepath.EvalSymlinks(candidate)
			if err != nil {
				return "", err
			}
			if _, err := relativeWithinRoot(physicalRoot, resolved); err != nil {
				return "", symlinkError(candidate)
			}
			resolvedInfo, err := os.Stat(candidate)
			if err != nil {
				return "", err
			}
			if !resolvedInfo.IsDir() {
				return "", fmt.Errorf("%q is not a directory", candidate)
			}
			current = resolved
			continue
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%q is not a directory", candidate)
		}
		current = candidate
	}
	for _, remaining := range components[resolveCount:] {
		current = filepath.Join(current, remaining)
	}
	return relativeWithinRoot(physicalRoot, current)
}

func relativeWithinRoot(root string, path string) (string, error) {
	if !strings.EqualFold(filepath.VolumeName(path), filepath.VolumeName(root)) {
		return "", fmt.Errorf("%w: %q changes volume from %q", ErrEscapesRoot, path, root)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not below %q", ErrEscapesRoot, path, root)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q is not below %q", ErrEscapesRoot, path, root)
	}
	return relative, nil
}

func (r Root) componentsBelowRoot(absolute string) ([]string, error) {
	relative, err := r.relativeToRoot(absolute)
	if err != nil {
		return nil, err
	}
	if relative == "." {
		return nil, nil
	}
	parts := strings.Split(relative, string(filepath.Separator))
	components := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		components = append(components, part)
	}
	return components, nil
}

func (r Root) relativeToRoot(absolute string) (string, error) {
	relative, err := filepath.Rel(r.path, absolute)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not below %q", ErrEscapesRoot, absolute, r.path)
	}
	return relative, nil
}

func (r Root) checkWithin(absolute string, original string) error {
	if !strings.EqualFold(filepath.VolumeName(absolute), filepath.VolumeName(r.path)) {
		return fmt.Errorf("%w: %q changes volume from %q", ErrEscapesRoot, original, r.path)
	}
	relative, err := filepath.Rel(r.path, absolute)
	if err != nil {
		return fmt.Errorf("%w: %q is not below %q", ErrEscapesRoot, original, r.path)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q is not below %q", ErrEscapesRoot, original, r.path)
	}
	return nil
}

func (r Root) checkParentComponents(absolute string) error {
	components, err := r.componentsBelowRoot(absolute)
	if err != nil {
		return err
	}
	if len(components) == 0 {
		return nil
	}
	current := r.path
	for _, component := range components[:len(components)-1] {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if err := r.checkSymlinkComponent(current); err != nil {
				return err
			}
			if resolved, err := os.Stat(current); err != nil {
				return err
			} else if !resolved.IsDir() {
				return fmt.Errorf("%q is not a directory", current)
			}
			continue
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", current)
		}
	}
	return nil
}

func (r Root) validateDirectoryComponents(absolute string) error {
	components, err := r.componentsBelowRoot(absolute)
	if err != nil {
		return err
	}
	current := r.path
	for _, component := range components {
		current = filepath.Join(current, component)
		if err := r.validateExistingDir(current); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
	}
	return nil
}

func (r Root) validateExistingDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := r.checkSymlinkComponent(path); err != nil {
			return err
		}
		resolved, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !resolved.IsDir() {
			return fmt.Errorf("%q is not a directory", path)
		}
		return nil
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	return nil
}

func checkReplaceableFileInRoot(rooted *os.Root, name string, displayPath string) (bool, error) {
	info, err := rooted.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, symlinkError(displayPath)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%q is not a regular file", displayPath)
	}
	return true, nil
}

// replaceFileInRoot moves the staged temporary file onto path. Unix renames replace
// the destination atomically; Windows renames fail when the destination exists,
// so the original is moved aside first and restored if the final move fails.
func replaceFileInRoot(parent *os.Root, temporaryName string, name string, hadExisting bool) error {
	if err := parent.Rename(temporaryName, name); err == nil {
		return nil
	} else if !hadExisting || runtime.GOOS != "windows" {
		return err
	}

	backup, backupName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", backupFilePattern, 0o600)
	if err != nil {
		return err
	}
	if err := backup.Close(); err != nil {
		return errors.Join(err, parent.Remove(backupName))
	}
	if err := parent.Remove(backupName); err != nil {
		return err
	}
	if err := parent.Rename(name, backupName); err != nil {
		return err
	}
	if err := parent.Rename(temporaryName, name); err != nil {
		restoreErr := parent.Rename(backupName, name)
		if restoreErr != nil {
			return errors.Join(
				err,
				fmt.Errorf("restore original from backup %q: %w", backupName, restoreErr),
			)
		}
		return err
	}
	if err := parent.Remove(backupName); err != nil {
		return fmt.Errorf("replacement succeeded but remove backup %q: %w", backupName, err)
	}
	return nil
}

func symlinkError(path string) error {
	return fmt.Errorf("%w: %q", ErrSymlink, path)
}

func isAbsoluteLike(path string) bool {
	if path == "" {
		return false
	}
	if isPathSeparator(rune(path[0])) {
		return true
	}
	if filepath.IsAbs(path) {
		return true
	}
	return len(path) >= 2 && path[1] == ':' && isASCIILetter(path[0])
}

func isPathSeparator(r rune) bool {
	return r == '/' || r == '\\'
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
