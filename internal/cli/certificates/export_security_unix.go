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

func prepareCertificateExportOutput(_ *os.File) error {
	return nil
}

func createCertificateExportStagingFile(root *os.Root, name string, perm os.FileMode) (*os.File, error) {
	return secureopen.OpenNewFileNoFollowInRoot(root, name, perm)
}

func permissionErrorForCertificateExport(label string) error {
	return fmt.Errorf("%s permissions must be 0600 or more restrictive", label)
}
