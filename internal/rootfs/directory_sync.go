package rootfs

import "os"

func syncDirectory(directory *os.File) error {
	err := directory.Sync()
	if err != nil && !unsupportedDirectorySyncError(err) {
		return err
	}
	return nil
}
