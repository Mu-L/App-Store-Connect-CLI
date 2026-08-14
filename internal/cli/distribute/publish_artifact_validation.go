package distribute

import (
	"fmt"
	"os"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

func inspectExistingProtectedPublishArtifact(root *os.Root, name, label string) (bool, error) {
	file, err := secureopen.OpenExistingNoFollowInRoot(root, name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if err := validateProtectedPublishArtifact(file, info, label); err != nil {
		return false, err
	}
	return true, nil
}

func validateProtectedPublishArtifact(file *os.File, info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be owner-private (mode 0600 or stricter)", label)
	}
	if err := validateProtectedPublishArtifactPlatform(file, info); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}
