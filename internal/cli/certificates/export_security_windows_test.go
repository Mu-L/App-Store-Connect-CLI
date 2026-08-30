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

func TestValidateCertificateExportProtectedFileAcceptsNormallyCreatedInput(t *testing.T) {
	// `asc certificates csr generate` and ordinary tooling create files whose
	// DACL is inherited from the parent directory. On a standard profile that
	// effective DACL is restricted to the current user plus SYSTEM and
	// Administrators, and the export command must accept it as an input.
	path := filepath.Join(t.TempDir(), "input.key")
	if err := os.WriteFile(path, []byte("key material"), 0o600); err != nil {
		t.Fatalf("write input file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open input file: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat input file: %v", err)
	}

	if err := validateCertificateExportProtectedFile(file, info, "private key"); err != nil {
		t.Fatalf("validateCertificateExportProtectedFile() error = %v, want inherited restricted DACL accepted", err)
	}
}

func TestCertificateExportOutputModeStillRejectsInheritedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.p12")
	if err := os.WriteFile(path, []byte("identity"), 0o600); err != nil {
		t.Fatalf("write output file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open output file: %v", err)
	}
	defer file.Close()

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
		t.Fatalf("GetSecurityInfo() error = %v", err)
	}
	if err := certificateExportVerifyProtectedDACL(descriptor, currentUser, false); err == nil {
		t.Fatal("certificateExportVerifyProtectedDACL() accepted an inherited DACL in output mode")
	}
}
