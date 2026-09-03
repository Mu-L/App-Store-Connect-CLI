//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package web

import (
	"os"
	"strconv"
)

func platformSessionLockRoot() string { return "/tmp" }
func platformSessionLockDirName() string {
	return "asc-web-session-locks-" + strconv.Itoa(os.Getuid())
}
