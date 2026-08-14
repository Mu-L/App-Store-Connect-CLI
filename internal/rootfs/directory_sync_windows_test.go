//go:build windows

package rootfs

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestUnsupportedDirectorySyncErrorOnWindows(t *testing.T) {
	if !unsupportedDirectorySyncError(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("ERROR_ACCESS_DENIED should be treated as an unsupported directory sync")
	}
	if unsupportedDirectorySyncError(windows.ERROR_WRITE_FAULT) {
		t.Fatal("ERROR_WRITE_FAULT should remain a directory sync failure")
	}
}
