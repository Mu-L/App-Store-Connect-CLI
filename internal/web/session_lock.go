package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Cached web sessions are shared mutable state across concurrent `asc`
// processes: one can persist a refreshed session while another is deciding
// whether the entry it loaded is still the one to delete. A per-entry advisory
// lock file serializes those transactions so a compare and the delete it
// authorizes cannot straddle a persist.
//
// The lock is taken at two anchors, in a fixed order so concurrent holders
// cannot deadlock against each other. The session cache directory covers
// file-backed entries, which live there anyway. A per-user temporary directory
// covers the keychain store, which is global to the user: two processes that
// select the keychain backend under different ASC_WEB_SESSION_CACHE_DIR or HOME
// values share no cache directory, yet still read and write the same keychain
// item. Holding whichever anchors can be created makes those processes exclude
// each other as long as either anchor is shared.
//
// The lock is advisory and best effort by design. Acquisition is bounded, a
// lock left behind by a killed process is broken once stale, and any failure to
// lock falls through to the unlocked operation: refusing to persist or discard
// a session because a lock file cannot be created would turn a cache
// optimization into an auth outage, and refusing to discard one would leave a
// proven-stale jar to burn another 2FA code.
var (
	sessionLockPollInterval = 2 * time.Millisecond
	sessionLockWaitTimeout  = 2 * time.Second
	// Long enough that a legitimate holder waiting on a native keychain prompt
	// is not evicted mid-transaction. A lock orphaned by a killed process costs
	// every later caller only the bounded wait before it proceeds unlocked, so
	// waiting longer to break one is the cheaper mistake.
	sessionLockStaleAfter = 2 * time.Minute

	sessionLockTempDir = os.TempDir
)

// withSessionEntryLock runs fn while holding the advisory lock for one cached
// session entry.
func withSessionEntryLock(key string, fn func() error) error {
	release := acquireSessionEntryLock(key)
	defer release()
	return fn()
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
		if release, ok := acquireLockFile(path); ok {
			releases = append(releases, release)
		}
	}
	return func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
}

// sessionEntryLockPaths returns the lock anchors for one entry, in the fixed
// order every caller acquires them.
func sessionEntryLockPaths(key string) []string {
	name := "session-" + key + ".lock"
	paths := make([]string, 0, 2)
	if dir, err := webSessionCacheDir(); err == nil && strings.TrimSpace(dir) != "" {
		paths = append(paths, filepath.Join(dir, name))
	}
	if dir := strings.TrimSpace(sessionLockTempDir()); dir != "" {
		paths = append(paths, filepath.Join(dir, sessionSharedLockDirName(), name))
	}
	return paths
}

// sessionSharedLockDirName keeps the shared anchor per user: a lock file in a
// world-writable temporary directory can only be removed by its owner, so
// mixing users there would make every stale lock permanent for everyone else.
func sessionSharedLockDirName() string {
	return "asc-web-session-locks-" + strconv.Itoa(os.Getuid())
}

func acquireLockFile(path string) (func(), bool) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false
	}
	token := sessionLockToken()
	deadline := time.Now().Add(sessionLockWaitTimeout)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = file.WriteString(token)
			_ = file.Close()
			return func() { releaseLockFile(path, token) }, true
		}
		if !os.IsExist(err) {
			// A read-only or otherwise unusable directory cannot be locked.
			return nil, false
		}
		if breakStaleLockFile(path) {
			continue
		}
		if !time.Now().Before(deadline) {
			return nil, false
		}
		time.Sleep(sessionLockPollInterval)
	}
}

// releaseLockFile removes the lock only while this acquisition still owns it.
// A transaction that outlives the stale window has its lock broken and taken
// over, and must not then delete the successor's lock on its way out.
func releaseLockFile(path, token string) {
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != token {
		return
	}
	_ = os.Remove(path)
}

// sessionLockToken identifies one acquisition. The nonce matters as much as the
// pid: a recycled pid must not let a later process release a lock it never took.
func sessionLockToken() string {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(nonce[:]))
}

// breakStaleLockFile removes a lock left behind by a process that died before
// releasing it, reporting whether the next acquisition attempt is worth making
// immediately.
func breakStaleLockFile(path string) bool {
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
