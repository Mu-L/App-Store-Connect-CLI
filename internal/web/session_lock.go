package web

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Cached web sessions are shared mutable state across concurrent `asc`
// processes: one can persist a refreshed session while another is deciding
// whether the entry it loaded is still the one to delete. A per-entry advisory
// lock file next to the session file serializes those transactions so a
// compare and the delete it authorizes cannot straddle a persist.
//
// The lock is advisory and best effort by design. Acquisition is bounded, a
// lock left behind by a killed process is broken after it goes stale, and any
// failure to lock falls through to the unlocked operation: refusing to persist
// or discard a session because a lock file cannot be created would turn a
// cache optimization into an auth outage.
//
// A file lock also covers the keychain backend, because every `asc` process
// resolves the same session cache directory. It cannot serialize against
// another program editing the same keychain items, which no other program is
// expected to do.
const (
	sessionLockPollInterval = 2 * time.Millisecond
	sessionLockWaitTimeout  = 2 * time.Second
	sessionLockStaleAfter   = 30 * time.Second
)

// withSessionEntryLock runs fn while holding the advisory lock for one cached
// session entry.
func withSessionEntryLock(key string, fn func() error) error {
	release := acquireSessionEntryLock(key)
	defer release()
	return fn()
}

// acquireSessionEntryLock returns a release func. The lock is skipped, rather
// than reported, when it cannot be taken.
func acquireSessionEntryLock(key string) func() {
	noop := func() {}
	if strings.TrimSpace(key) == "" {
		return noop
	}
	path, err := sessionEntryLockPath(key)
	if err != nil {
		return noop
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return noop
	}

	deadline := time.Now().Add(sessionLockWaitTimeout)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = file.WriteString(strconv.Itoa(os.Getpid()))
			_ = file.Close()
			return func() { _ = os.Remove(path) }
		}
		if !os.IsExist(err) {
			// A read-only or otherwise unusable cache directory cannot be
			// locked. Proceed unlocked instead of failing the caller.
			return noop
		}
		if breakStaleSessionEntryLock(path) {
			continue
		}
		if !time.Now().Before(deadline) {
			return noop
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

// breakStaleSessionEntryLock removes a lock left behind by a process that died
// before releasing it, reporting whether the next acquisition attempt is worth
// making immediately.
func breakStaleSessionEntryLock(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// The holder released it between the failed create and this stat.
		return os.IsNotExist(err)
	}
	if time.Since(info.ModTime()) < sessionLockStaleAfter {
		return false
	}
	return os.Remove(path) == nil
}
