//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package web

import (
	"os"
	"path/filepath"
	"strconv"
)

func platformSessionLockRoot() string { return "/tmp" }
func platformSessionLockDirName() string {
	return filepath.Join("asc-web-session-locks-" + strconv.Itoa(os.Getuid()))
}
