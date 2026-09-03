//go:build windows

package web

import "os"

func platformSessionLockRoot() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return dir
	}
	return os.TempDir()
}

func platformSessionLockDirName() string { return "asc-web-session-locks" }
