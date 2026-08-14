//go:build windows

package rootfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnsupportedDirectorySyncErrorWindows(t *testing.T) {
	if !unsupportedDirectorySyncError(syscall.ERROR_ACCESS_DENIED) {
		t.Fatal("ERROR_ACCESS_DENIED should be treated as unsupported for a directory handle")
	}
	if unsupportedDirectorySyncError(syscall.Errno(29)) {
		t.Fatal("real write failures must not be suppressed")
	}
}

func TestCreateNewFileAtomicPublishesOnWindows(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	if err := root.CreateNewFileAtomic("plan.json", []byte("planned"), 0o600); err != nil {
		t.Fatalf("CreateNewFileAtomic() error = %v", err)
	}
	if got := mustRead(t, filepath.Join(dir, "plan.json")); got != "planned" {
		t.Fatalf("published content = %q, want planned", got)
	}
	if err := root.CreateNewFileAtomic("plan.json", []byte("replacement"), 0o600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("retry error = %v, want os.ErrExist", err)
	}
}
