package web

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cached web sessions are shared mutable state across concurrent `asc`
// processes: one can persist a refreshed session while another is deciding
// whether the entry it loaded is still the one to delete. A store-global and
// per-entry advisory lock file serializes those transactions so a compare and
// the delete it authorizes cannot straddle a persist.
//
// The locks are taken at their anchors in a fixed order so concurrent holders
// cannot deadlock against each other. The session cache directory covers
// file-backed entries, which live there anyway. A stable per-user OS directory
// covers the keychain store, which is global to the user: two processes that
// select the keychain backend under different ASC_WEB_SESSION_CACHE_DIR or HOME
// values share no cache directory, yet still read and write the same aggregate
// keychain item. Holding whichever anchors can be created makes those
// processes exclude each other as long as either anchor is shared.
//
// The lock is advisory and best effort by design. Acquisition is bounded, a
// lock left behind by a killed process remains harmless because advisory locks
// are released when descriptors close, and any failure to lock falls through
// to the unlocked operation: refusing to persist or discard a session because
// a lock file cannot be created would turn a cache
// optimization into an auth outage, and refusing to discard one would leave a
// proven-stale jar to burn another 2FA code.
var (
	errSessionLockHeld        = errors.New("session lock is held")
	errSessionLockUnavailable = errors.New("cached web session could not be locked")
	sessionLockPollInterval   = 2 * time.Millisecond
	sessionLockWaitTimeout    = 2 * time.Second
	sessionSharedLockRoot     = platformSessionLockRoot
)

// withSessionGlobalLock runs fn while holding the best-effort store lock.
func withSessionGlobalLock(fn func() error) error {
	release := acquireSessionGlobalLock()
	defer release()
	return fn()
}

// withSessionEntryLock runs fn while holding the advisory store and entry
// locks for one cached session entry.
func withSessionEntryLock(key string, fn func() error) error {
	release := acquireSessionMutationLocks(key)
	defer release()
	return fn()
}

// withRequiredSessionEntryLock refuses to mutate an import when no complete
// lock set can be acquired. This is needed for the keychain backend: unlike a
// file create, its aggregate API has no create-only operation, so a failed
// lock would make a no-overwrite check racy.
func withRequiredSessionEntryLock(key string, fn func() error) error {
	release, ok := acquireRequiredSessionEntryLock(key)
	if !ok {
		return fmt.Errorf("%w: %s", errSessionLockUnavailable, key)
	}
	defer release()
	return fn()
}

// acquireRequiredSessionEntryLock acquires every lock anchor used by the
// best-effort lock. Requiring all anchors keeps the keychain guard safe even
// when the cache directory and the stable per-user keychain anchor differ.
func acquireRequiredSessionEntryLock(key string) (func(), bool) {
	noop := func() {}
	if strings.TrimSpace(key) == "" {
		return noop, true
	}
	paths := append([]string{}, sessionGlobalLockPaths()...)
	paths = appendUniqueLockPaths(paths, sessionEntryLockPaths(key)...)
	releases, ok := acquireRequiredLockPaths(paths)
	if !ok {
		return noop, false
	}
	return releaseLockPaths(releases), true
}

// acquireRequiredLockPaths acquires every lock in paths or none of them. It
// is used at the no-overwrite persistence boundary, where proceeding without
// a complete lock set would make the keychain aggregate read/modify/write
// sequence racy.
func acquireRequiredLockPaths(paths []string) ([]func(), bool) {
	if len(paths) == 0 {
		return nil, false
	}
	releases := make([]func(), 0, len(paths))
	for _, path := range paths {
		release, ok := acquireSessionLockPath(path)
		if !ok {
			releaseLockPaths(releases)
			return nil, false
		}
		releases = append(releases, release)
	}
	return releases, true
}

func releaseLockPaths(releases []func()) func() {
	return func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
}

// acquireSessionMutationLocks takes the store lock before the entry locks.
// The stable store anchor is what serializes keychain aggregate updates for
// different accounts and processes configured with different cache dirs.
func acquireSessionMutationLocks(key string) func() {
	paths := append([]string{}, sessionGlobalLockPaths()...)
	paths = appendUniqueLockPaths(paths, sessionEntryLockPaths(key)...)
	releases := make([]func(), 0, len(paths))
	for _, path := range paths {
		if release, ok := acquireSessionLockPath(path); ok {
			releases = append(releases, release)
		}
	}
	return releaseLockPaths(releases)
}

// acquireSessionGlobalLock takes every store anchor that can be locked and
// returns a release func for them. Anchors that cannot be taken are skipped:
// ordinary persistence and deletion retain their existing fail-open behavior.
func acquireSessionGlobalLock() func() {
	releases := make([]func(), 0, 2)
	for _, path := range sessionGlobalLockPaths() {
		if release, ok := acquireSessionLockPath(path); ok {
			releases = append(releases, release)
		}
	}
	return releaseLockPaths(releases)
}

// acquireSessionEntryLock takes the entry lock at every anchor that can be
// locked and returns a release func for them. Anchors that cannot be taken are
// skipped rather than reported: see the fail-open rationale above.
func acquireSessionEntryLock(key string) func() {
	if strings.TrimSpace(key) == "" {
		return func() {}
	}
	paths := sessionEntryLockPaths(key)
	releases := make([]func(), 0, len(paths))
	for _, path := range paths {
		if release, ok := acquireSessionLockPath(path); ok {
			releases = append(releases, release)
		}
	}
	return releaseLockPaths(releases)
}

// sessionGlobalLockPaths returns the store lock anchors in the same order
// every caller acquires them.
func sessionGlobalLockPaths() []string {
	paths := make([]string, 0, 2)
	if dir, err := webSessionCacheDir(); err == nil && strings.TrimSpace(dir) != "" {
		paths = append(paths, filepath.Join(dir, "store.lock"))
	}
	if path := sessionSharedGlobalLockPath(); path != "" {
		paths = appendUniqueLockPaths(paths, path)
	}
	return paths
}

func sessionSharedGlobalLockPath() string {
	dir := strings.TrimSpace(sessionSharedLockRoot())
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sessionSharedLockDirName(), "store.lock")
}

func appendUniqueLockPaths(paths []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(paths)+len(additions))
	for _, path := range paths {
		seen[path] = struct{}{}
	}
	for _, path := range additions {
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

// sessionEntryLockPaths returns the lock anchors for one entry, in the fixed
// order every caller acquires them.
func sessionEntryLockPaths(key string) []string {
	name := "session-" + key + ".lock"
	paths := make([]string, 0, 2)
	if dir, err := webSessionCacheDir(); err == nil && strings.TrimSpace(dir) != "" {
		paths = append(paths, filepath.Join(dir, name))
	}
	if path := sessionSharedEntryLockPath(key); path != "" {
		paths = appendUniqueLockPaths(paths, path)
	}
	return paths
}

func sessionSharedEntryLockPath(key string) string {
	dir := strings.TrimSpace(sessionSharedLockRoot())
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, sessionSharedLockDirName(), "session-"+key+".lock")
}

func acquireSessionLockPath(path string) (func(), bool) {
	if isSharedSessionLockPath(path) {
		return acquireSharedSessionLockFile(path)
	}
	return acquireLockFile(path)
}

func isSharedSessionLockPath(path string) bool {
	root := strings.TrimSpace(sessionSharedLockRoot())
	if root == "" || path == "" {
		return false
	}
	return filepath.Dir(path) == filepath.Join(root, sessionSharedLockDirName())
}

// sessionSharedLockDirName keeps the persistent shared anchor per OS user. Its
// parent is stable across process-local cache, HOME, and temporary-directory
// settings so processes that reach the same keychain derive the same path.
func sessionSharedLockDirName() string { return platformSessionLockDirName() }

func acquireLockFile(path string) (func(), bool) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false
	}
	return acquirePreparedLockFile(path, func(path string) (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	})
}

func acquirePreparedLockFile(path string, openFile func(string) (*os.File, error)) (func(), bool) {
	deadline := time.Now().Add(sessionLockWaitTimeout)
	for {
		file, err := openFile(path)
		if err == nil {
			if err := lockSessionFile(file); err == nil {
				return func() {
					_ = unlockSessionFile(file)
					_ = file.Close()
				}, true
			} else if !isSessionLockHeld(err) {
				_ = file.Close()
				return nil, false
			}
			_ = file.Close()
			if !time.Now().Before(deadline) {
				return nil, false
			}
			time.Sleep(sessionLockPollInterval)
			continue
		}
		if !os.IsNotExist(err) && !os.IsPermission(err) {
			// A read-only or otherwise unusable directory cannot be locked.
			return nil, false
		}
		if !time.Now().Before(deadline) {
			return nil, false
		}
		time.Sleep(sessionLockPollInterval)
	}
}

func isSessionLockHeld(err error) bool { return errors.Is(err, errSessionLockHeld) }
