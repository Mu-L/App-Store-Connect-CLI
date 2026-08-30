//go:build windows

package certificates

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCertificateExportOwnerAccessMaskUsesFileRights(t *testing.T) {
	mask := certificateExportOwnerAccessMask()
	required := uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.WRITE_DAC | windows.DELETE)
	if mask&required != required {
		t.Fatalf("certificateExportOwnerAccessMask() = %#x, want read/write/delete rights %#x", mask, required)
	}
	if mask&windows.GENERIC_ALL != 0 {
		t.Fatalf("certificateExportOwnerAccessMask() = %#x, want file-specific rights", mask)
	}
}

func TestCreateCertificateExportStagingFileProtectsDACLAtCreation(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	defer root.Close()

	const name = ".asc-cert-export-security-test"
	file, err := createCertificateExportStagingFile(root, name, 0o600)
	if err != nil {
		t.Fatalf("createCertificateExportStagingFile() error = %v", err)
	}
	defer file.Close()
	defer root.Remove(name)

	currentUser, err := certificateExportCurrentUserSID()
	if err != nil {
		t.Fatalf("certificateExportCurrentUserSID() error = %v", err)
	}
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetSecurityInfo(%q) error = %v", filepath.Join(directory, name), err)
	}
	if err := certificateExportVerifyProtectedDACL(descriptor, currentUser, false); err != nil {
		t.Fatalf("certificateExportVerifyProtectedDACL() error = %v, want owner-only DACL at creation", err)
	}
	if err := prepareCertificateExportOutput(file); err != nil {
		t.Fatalf("prepareCertificateExportOutput() error = %v after creation-time protection", err)
	}
}
