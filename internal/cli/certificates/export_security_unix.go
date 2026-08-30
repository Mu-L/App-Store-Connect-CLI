//go:build !windows

package certificates

import (
	"fmt"
	"os"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

func validateCertificateExportProtectedFile(_ *os.File, info os.FileInfo, label string) error {
	if info.Mode().Perm()&0o077 != 0 {
		return permissionErrorForCertificateExport(label)
	}
	return nil
}

// prepareCertificateExportOutput verifies the staged output's effective
// permissions before any PKCS#12 bytes are written. Filesystems such as FAT,
// exFAT, and some CIFS or FUSE mounts ignore or translate the requested 0600
// mode; failing closed here keeps the identity from being published with
// group- or world-readable permissions while the command reports success.
func prepareCertificateExportOutput(file *os.File) error {
	if file == nil {
		return fmt.Errorf("output permissions cannot be verified")
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("verify output permissions: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"output permissions %#o are not restricted to the owner; the --p12-out filesystem must support mode 0600",
			info.Mode().Perm(),
		)
	}
	return nil
}

func createCertificateExportStagingFile(root *os.Root, name string, perm os.FileMode) (*os.File, error) {
	return secureopen.OpenNewFileNoFollowInRoot(root, name, perm)
}

func permissionErrorForCertificateExport(label string) error {
	return fmt.Errorf("%s permissions must be 0600 or more restrictive", label)
}
