//go:build !windows

package distribution

import (
	"os"
	"syscall"
	"testing"
)

func TestCodeVerificationTreatsNameTooLongAsTerminal(t *testing.T) {
	err := &os.PathError{
		Op:   "write",
		Path: "Payload/App.app/overlong-component",
		Err:  syscall.ENAMETOOLONG,
	}
	if isRetryableCodeVerificationError(err) {
		t.Fatal("ENAMETOOLONG must remain a terminal input failure")
	}
}
