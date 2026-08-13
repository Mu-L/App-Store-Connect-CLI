//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd && !dragonfly

package xcode

func currentExactIPAOwner() (uint64, bool) {
	return 0, false
}
