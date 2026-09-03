package web

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The lock is what makes a compare-and-delete and a persist mutually
// exclusive, so overlapping holders must be impossible.
func TestWithSessionEntryLockExcludesConcurrentHolders(t *testing.T) {
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	key := webSessionCacheKey("user@example.com")
	var mu sync.Mutex
	holders, maxHolders := 0, 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withSessionEntryLock(key, func() error {
				mu.Lock()
				holders++
				if holders > maxHolders {
					maxHolders = holders
				}
				mu.Unlock()
				time.Sleep(time.Millisecond)
				mu.Lock()
				holders--
				mu.Unlock()
				return nil
			})
		}()
	}
	wg.Wait()

	if maxHolders != 1 {
		t.Fatalf("expected the entry lock to admit one holder at a time, got %d", maxHolders)
	}
	for _, path := range sessionEntryLockPaths(key) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected the lock file at %q to be released, stat error: %v", path, err)
		}
	}
}

// Two processes on the keychain backend can be configured with different cache
// directories and still share one global keychain store, so at least one anchor
// must not depend on the cache directory.
func TestSessionEntryLockSharesAnAnchorAcrossCacheDirs(t *testing.T) {
	shared := t.TempDir()
	withStubbedSessionLockTempDir(t, shared)

	key := webSessionCacheKey("user@example.com")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "cache-a"))
	first := sessionEntryLockPaths(key)
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "cache-b"))
	second := sessionEntryLockPaths(key)

	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected two anchors per configuration, got %v and %v", first, second)
	}
	if first[0] == second[0] {
		t.Fatalf("expected the cache directory anchor to differ, got %q twice", first[0])
	}
	if first[1] != second[1] {
		t.Fatalf("expected a cache-directory-independent anchor, got %q and %q", first[1], second[1])
	}
	if !strings.HasPrefix(first[1], shared) {
		t.Fatalf("expected the shared anchor under %q, got %q", shared, first[1])
	}
}

// The shared anchor has to actually exclude: a holder configured with one cache
// directory must block a second one configured with another.
func TestSessionEntryLockExcludesHoldersWithDifferentCacheDirs(t *testing.T) {
	withStubbedSessionLockTempDir(t, t.TempDir())
	withShortSessionLockWait(t, 100*time.Millisecond)

	key := webSessionCacheKey("user@example.com")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "cache-a"))
	release := acquireSessionEntryLock(key)

	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "cache-b"))
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		acquireSessionEntryLock(key)()
		done <- time.Since(start)
	}()

	select {
	case waited := <-done:
		if waited < sessionLockWaitTimeout {
			t.Fatalf("expected the shared anchor to hold off the second acquisition, it returned after %s", waited)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second acquisition never returned")
	}
	sharedLock := sessionEntryLockPaths(key)[1]
	if _, err := os.Stat(sharedLock); err != nil {
		t.Fatalf("expected the holder to keep the shared lock the blocked caller gave up on: %v", err)
	}
	release()
	if _, err := os.Stat(sharedLock); !os.IsNotExist(err) {
		t.Fatalf("expected the holder to release the shared lock, stat error: %v", err)
	}
}

// A transaction that outlives the stale window has its lock broken and taken
// over. It must not delete the successor's lock on its way out.
func TestSessionEntryLockReleaseKeepsALockTakenOverByAnotherHolder(t *testing.T) {
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))
	withStubbedSessionLockTempDir(t, t.TempDir())

	key := webSessionCacheKey("user@example.com")
	release := acquireSessionEntryLock(key)
	for _, path := range sessionEntryLockPaths(key) {
		if err := os.WriteFile(path, []byte("another-holder"), 0o600); err != nil {
			t.Fatalf("WriteFile error: %v", err)
		}
	}
	release()

	for _, path := range sessionEntryLockPaths(key) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("expected the successor lock at %q to survive: %v", path, err)
		}
		if string(raw) != "another-holder" {
			t.Fatalf("expected the successor token at %q, got %q", path, raw)
		}
	}
}

func withStubbedSessionLockTempDir(t *testing.T, dir string) {
	t.Helper()
	prev := sessionLockTempDir
	sessionLockTempDir = func() string { return dir }
	t.Cleanup(func() { sessionLockTempDir = prev })
}

func withShortSessionLockWait(t *testing.T, wait time.Duration) {
	t.Helper()
	prev := sessionLockWaitTimeout
	sessionLockWaitTimeout = wait
	t.Cleanup(func() { sessionLockWaitTimeout = prev })
}

// A process killed mid-transaction leaves its lock file behind. The next one
// must break it instead of refusing to touch the cache forever.
func TestWithSessionEntryLockBreaksAStaleLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web-cache")
	t.Setenv(webSessionCacheDirEnv, dir)

	key := webSessionCacheKey("user@example.com")
	lockPath := sessionEntryLockPaths(key)[0]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll error: %v", err)
	}
	if err := os.WriteFile(lockPath, []byte("999999"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	stale := time.Now().Add(-2 * sessionLockStaleAfter)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatalf("Chtimes error: %v", err)
	}

	ran := false
	start := time.Now()
	if err := withSessionEntryLock(key, func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("withSessionEntryLock error: %v", err)
	}
	if !ran {
		t.Fatal("expected the locked operation to run")
	}
	if elapsed := time.Since(start); elapsed >= sessionLockWaitTimeout {
		t.Fatalf("expected a stale lock to be broken without waiting out the timeout, took %s", elapsed)
	}
}

// A cache directory that cannot hold a lock file must not block the operation:
// an unlocked persist or delete is the pre-existing behavior, an aborted login
// is not.
func TestWithSessionEntryLockFallsThroughWhenTheDirectoryIsUnusable(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	t.Setenv(webSessionCacheDirEnv, filepath.Join(blocker, "web-cache"))

	ran := false
	if err := withSessionEntryLock(webSessionCacheKey("user@example.com"), func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("withSessionEntryLock error: %v", err)
	}
	if !ran {
		t.Fatal("expected the operation to run unlocked when no lock file can be created")
	}
}
