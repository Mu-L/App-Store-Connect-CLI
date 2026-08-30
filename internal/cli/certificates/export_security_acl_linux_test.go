//go:build linux

package certificates

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// linuxTestACLBlob builds a POSIX ACL xattr (version 2) that grants uid 12345
// read access alongside the owner entries: USER_OBJ rw, USER(12345) r,
// GROUP_OBJ none, MASK r, OTHER none. Mode bits stay 0600 while the named
// entry grants another account access.
func linuxTestACLBlob() []byte {
	const (
		aclUserObj  = 0x01
		aclUser     = 0x02
		aclGroupObj = 0x04
		aclMask     = 0x10
		aclOther    = 0x20
		undefinedID = 0xFFFFFFFF
	)
	blob := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(blob[0:4], 2)
	entries := []struct {
		tag  uint16
		perm uint16
		id   uint32
	}{
		{aclUserObj, 6, undefinedID},
		{aclUser, 4, 12345},
		{aclGroupObj, 0, undefinedID},
		{aclMask, 4, undefinedID},
		{aclOther, 0, undefinedID},
	}
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(blob[offset:], entry.tag)
		binary.LittleEndian.PutUint16(blob[offset+2:], entry.perm)
		binary.LittleEndian.PutUint32(blob[offset+4:], entry.id)
	}
	return blob
}

func applyLinuxTestACL(t *testing.T, file *os.File) {
	t.Helper()
	err := unix.Fsetxattr(int(file.Fd()), linuxPOSIXACLAccessAttribute, linuxTestACLBlob(), 0)
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
		t.Skipf("POSIX ACLs are unavailable on this filesystem: %v", err)
	}
	if err != nil {
		t.Fatalf("apply test ACL: %v", err)
	}
}

func TestValidateCertificateExportProtectedFileRejectsPOSIXACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.key")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create protected file: %v", err)
	}
	defer file.Close()
	applyLinuxTestACL(t, file)

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat protected file: %v", err)
	}
	err = validateCertificateExportProtectedFile(file, info, "private key")
	if err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("validateCertificateExportProtectedFile() error = %v, want extended-ACL rejection", err)
	}
}

func TestPrepareCertificateExportOutputStripsPOSIXACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "staging.p12")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create staging file: %v", err)
	}
	defer file.Close()
	applyLinuxTestACL(t, file)

	if err := prepareCertificateExportOutput(file); err != nil {
		t.Fatalf("prepareCertificateExportOutput() error = %v, want POSIX ACL stripped", err)
	}
	hasACL, err := certificateExportFileHasACL(file)
	if err != nil {
		t.Fatalf("certificateExportFileHasACL() error = %v", err)
	}
	if hasACL {
		t.Fatal("staging file retains its POSIX ACL after preparation")
	}
}
