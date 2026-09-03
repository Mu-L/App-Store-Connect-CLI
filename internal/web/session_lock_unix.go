//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package web

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockSessionFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return errSessionLockHeld
	}
	return err
}

func unlockSessionFile(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
