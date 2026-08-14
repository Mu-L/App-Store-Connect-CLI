//go:build windows

package rootfs

import (
	"errors"
	"syscall"
)

func unsupportedDirectorySyncError(err error) bool {
	// os.File.Sync uses FlushFileBuffers on Windows. Directory handles are
	// opened read-only, while FlushFileBuffers requires write access and returns
	// ERROR_ACCESS_DENIED even though the atomic publish already succeeded.
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
