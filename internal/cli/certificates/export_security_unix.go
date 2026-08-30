//go:build !windows

package certificates

import (
	"fmt"
	"os"
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

func permissionErrorForCertificateExport(label string) error {
	return fmt.Errorf("%s permissions must be 0600 or more restrictive", label)
}
