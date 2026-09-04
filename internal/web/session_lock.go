package web

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Cached web sessions are shared mutable state across concurrent `asc`
// processes. A per-entry advisory lock serializes the read/modify/write
// transactions used by the file and keychain backends. The file backend also
// has an O_EXCL create boundary below; the lock is what gives the keychain's
// read-then-write aggregate the same no-overwrite behavior.
//
// Locking is bounded and stale lock files are reclaimed. Ordinary refresh and
// login writes are best effort so a cache lock cannot turn an optional cache
// into an authentication outage. Import persistence uses the required variant
// because allowing it to continue unlocked could replace a session created
// while the bundle was being validated.
const (
	sessionLockPollInterval = 2 * time.Millisecond
	sessionLockWaitTimeout  = 2 * time.Second
	sessionLockStaleAfter   = 30 * time.Second
)

var errSessionLockUnavailable = errors.New("cached web session could not be locked")

// withSessionEntryLock runs fn while holding the advisory lock for one cached
// session entry. If the cache directory cannot hold a lock, it falls through
// to preserve the existing best-effort cache behavior for login/refresh.
func withSessionEntryLock(key string, fn func() error) error {
	release, _ := acquireSessionEntryLock(key)
	defer release()
	return fn()
}

// withRequiredSessionEntryLock refuses to mutate an import when the lock
// cannot be acquired. This is needed for the keychain backend: unlike a file
// create, its aggregate API has no create-only operation, so a failed lock
// would make a no-overwrite check racy.
func withRequiredSessionEntryLock(key string, fn func() error) error {
	release, ok := acquireSessionEntryLock(key)
	if !ok {
		return fmt.Errorf("%w: %s", errSessionLockUnavailable, key)
	}
	defer release()
	return fn()
}

func acquireSessionEntryLock(key string) (func(), bool) {
	noop := func() {}
	if strings.TrimSpace(key) == "" {
		return noop, true
	}
	path, err := sessionEntryLockPath(key)
	if err != nil {
		return noop, false
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return noop, false
	}

	deadline := time.Now().Add(sessionLockWaitTimeout)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = file.WriteString(strconv.Itoa(os.Getpid()))
			_ = file.Close()
			return func() { _ = os.Remove(path) }, true
		}
		if !os.IsExist(err) {
			return noop, false
		}
		if breakStaleSessionEntryLock(path) {
			continue
		}
		if !time.Now().Before(deadline) {
			return noop, false
		}
		time.Sleep(sessionLockPollInterval)
	}
}

func sessionEntryLockPath(key string) (string, error) {
	dir, err := webSessionCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "session-"+key+".lock"), nil
}

// breakStaleSessionEntryLock removes a lock left by a process that died
// before releasing it, reporting whether the next acquisition attempt should
// be made immediately.
func breakStaleSessionEntryLock(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if time.Since(info.ModTime()) < sessionLockStaleAfter {
		return false
	}
	return os.Remove(path) == nil
}
