//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package xcode

import "os"

func currentExactIPAOwner() (uint64, bool) {
	return uint64(os.Geteuid()), true
}
