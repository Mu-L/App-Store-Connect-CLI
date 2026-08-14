//go:build !windows

package distribute

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHashDistributionFileClosesRootDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.ipa")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGCPercent)
	before := countOpenDistributionDescriptors(t)
	for range 32 {
		if _, err := hashDistributionFile(path); err != nil {
			t.Fatal(err)
		}
	}
	after := countOpenDistributionDescriptors(t)
	if leaked := after - before; leaked > 0 {
		t.Fatalf("hashDistributionFile leaked %d file descriptors", leaked)
	}
}

func countOpenDistributionDescriptors(t *testing.T) int {
	t.Helper()
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	maximum := int(limit.Cur)
	if maximum > 4096 {
		maximum = 4096
	}
	count := 0
	for descriptor := range maximum {
		if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err == nil {
			count++
		} else if !errors.Is(err, unix.EBADF) {
			t.Fatalf("inspect descriptor %d: %v", descriptor, err)
		}
	}
	return count
}
