package screenshots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

const matrixGlobalLockDirectory = ".asc-matrix-locks"

// acquireMatrixGlobalLock uses a stable, privacy-safe lock file outside the
// output tree. Keeping the name independent of the operator path avoids
// leaking paths into filesystem entries while still coordinating independent
// processes that selected the same destination or simulator.
func acquireMatrixGlobalLock(ctx context.Context, key string) (func() error, error) {
	if ctx == nil {
		return nil, errors.New("matrix lock context is required")
	}
	root, err := openMatrixGlobalLockRoot()
	if err != nil {
		return nil, errors.New("matrix global lock is unavailable")
	}
	digest := sha256.Sum256([]byte(key))
	name := ".asc-matrix-lock-" + hex.EncodeToString(digest[:])
	release, err := acquireMatrixNamedLock(ctx, root, name)
	if err != nil {
		_ = root.Close()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, errors.New("matrix global lock is unavailable")
	}
	return func() error {
		return errors.Join(release(), root.Close())
	}, nil
}

// matrixGlobalLockBaseDirForTest is intentionally a narrow test seam. The
// production namespace is rooted in the user's home directory, while tests
// use a disposable equivalent without changing the host's home state.
var matrixGlobalLockBaseDirForTest string

func openMatrixGlobalLockRoot() (rootfs.Root, error) {
	baseDir := matrixGlobalLockBaseDirForTest
	if baseDir == "" {
		var err error
		baseDir, err = os.UserHomeDir()
		if err != nil {
			return rootfs.Root{}, err
		}
	}
	if strings.TrimSpace(baseDir) == "" {
		return rootfs.Root{}, errors.New("user home directory is empty")
	}
	lockRootPath := filepath.Join(baseDir, ".asc", matrixGlobalLockDirectory)
	lockRoot, err := rootfs.New(lockRootPath)
	if err != nil {
		return rootfs.Root{}, err
	}
	if err := lockRoot.MkdirAll(".", 0o700); err != nil {
		_ = lockRoot.Close()
		return rootfs.Root{}, err
	}
	anchor, err := lockRoot.OpenDir(".")
	if err != nil {
		_ = lockRoot.Close()
		return rootfs.Root{}, err
	}
	if err := anchor.Chmod(0o700); err != nil {
		_ = anchor.Close()
		_ = lockRoot.Close()
		return rootfs.Root{}, err
	}
	if err := anchor.Close(); err != nil {
		_ = lockRoot.Close()
		return rootfs.Root{}, err
	}
	return lockRoot, nil
}

func acquireMatrixSimulatorLock(ctx context.Context, udid string) (func() error, error) {
	return acquireMatrixGlobalLock(ctx, "simulator:"+normalizeMatrixUDID(udid))
}

// acquireMatrixOutputLocks orders all destination locks before acquisition so
// two concurrent runs with the same paths in a different order cannot deadlock.
func acquireMatrixOutputLocks(ctx context.Context, paths []string) (func() error, error) {
	identities := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		identity := matrixOutputLockIdentity(path)
		if identity != "" {
			identities[identity] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(identities))
	for identity := range identities {
		ordered = append(ordered, identity)
	}
	sort.Strings(ordered)

	releases := make([]func() error, 0, len(ordered))
	for _, identity := range ordered {
		release, err := acquireMatrixGlobalLock(ctx, "output:"+identity)
		if err != nil {
			var releaseErr error
			for i := len(releases) - 1; i >= 0; i-- {
				releaseErr = errors.Join(releaseErr, releases[i]())
			}
			return nil, errors.Join(err, releaseErr)
		}
		releases = append(releases, release)
	}
	return func() error {
		var releaseErr error
		for i := len(releases) - 1; i >= 0; i-- {
			releaseErr = errors.Join(releaseErr, releases[i]())
		}
		return releaseErr
	}, nil
}

func matrixOutputLockIdentity(path string) string {
	if physical, ok := resolveMatrixPhysicalPath(path); ok {
		return normalizeMatrixLockPath(physical)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return normalizeMatrixLockPath(path)
	}
	return normalizeMatrixLockPath(absPath)
}

func normalizeMatrixLockPath(path string) string {
	path = filepath.Clean(path)
	return normalizeMatrixLockPathWithCase(path, matrixFilesystemCaseInsensitive(path))
}

func normalizeMatrixLockPathWithCase(path string, caseInsensitive bool) string {
	if caseInsensitive {
		return strings.ToLower(path)
	}
	return path
}

// matrixFilesystemCaseInsensitive probes an existing path component without
// creating anything. Case-folding lock identities is safe only when the
// selected filesystem itself aliases a case variant; preserving spelling on a
// case-sensitive filesystem keeps distinct destinations independently locked.
func matrixFilesystemCaseInsensitive(path string) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			name := filepath.Base(current)
			variant := matrixCaseVariant(name)
			if variant != "" {
				variantInfo, variantErr := os.Lstat(filepath.Join(filepath.Dir(current), variant))
				return variantErr == nil && os.SameFile(info, variantInfo)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}

func matrixCaseVariant(name string) string {
	variant := []byte(name)
	for i, char := range variant {
		switch {
		case char >= 'a' && char <= 'z':
			variant[i] = char - ('a' - 'A')
			return string(variant)
		case char >= 'A' && char <= 'Z':
			variant[i] = char + ('a' - 'A')
			return string(variant)
		}
	}
	return ""
}

func matrixLockError(kind string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("matrix %s lock failed: %w", kind, err)
}
