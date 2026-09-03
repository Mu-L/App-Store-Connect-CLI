package web

import (
	"os"
	"path/filepath"
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
	lockPath, err := sessionEntryLockPath(key)
	if err != nil {
		t.Fatalf("sessionEntryLockPath error: %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected the lock file to be released, stat error: %v", err)
	}
}

// A process killed mid-transaction leaves its lock file behind. The next one
// must break it instead of refusing to touch the cache forever.
func TestWithSessionEntryLockBreaksAStaleLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "web-cache")
	t.Setenv(webSessionCacheDirEnv, dir)

	key := webSessionCacheKey("user@example.com")
	lockPath, err := sessionEntryLockPath(key)
	if err != nil {
		t.Fatalf("sessionEntryLockPath error: %v", err)
	}
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
