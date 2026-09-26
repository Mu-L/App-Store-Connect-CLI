//go:build !darwin && !linux

package rootfs

import (
	"os"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

func openChmodFile(parent *os.Root, base string) (*os.File, error) {
	return secureopen.OpenExistingNoFollowInRoot(parent, base)
}

func chmodFileDescriptor(file *os.File, mode os.FileMode) error {
	return file.Chmod(mode)
}
