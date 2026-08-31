package rootfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

func TestCaptureFileIdentityRejectsSameContentReplacement(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	const original = "same bytes"
	if err := os.WriteFile(filepath.Join(dir, "settings.xcconfig"), []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}

	identity, err := root.CaptureFile("settings.xcconfig")
	if err != nil {
		t.Fatalf("CaptureFile() error = %v", err)
	}
	if string(identity.Data()) != original {
		t.Fatalf("captured data = %q, want %q", identity.Data(), original)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement.xcconfig"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "replacement.xcconfig"), filepath.Join(dir, "settings.xcconfig")); err != nil {
		t.Fatal(err)
	}

	if _, err := root.ReplaceFileIfSame("settings.xcconfig", identity, []byte("updated"), 0o640, true); !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want ErrFileIdentityChanged", err)
	}
	if got := mustRead(t, filepath.Join(dir, "settings.xcconfig")); got != original {
		t.Fatalf("replacement content = %q, want %q", got, original)
	}
}

func TestFileIdentityIsInvalidAfterRootClose(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "settings.xcconfig"), []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("settings.xcconfig")
	if err != nil {
		t.Fatalf("CaptureFile() error = %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("Root.Close() error = %v", err)
	}
	if _, err := root.ReplaceFileIfSame("settings.xcconfig", identity, []byte("new"), 0o640, true); !errors.Is(err, ErrFileIdentityClosed) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want ErrFileIdentityClosed", err)
	}
}

func TestCheckFileIdentityRejectsSameContentReplacement(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	const content = "same bytes"
	path := filepath.Join(dir, "settings.xcconfig")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("settings.xcconfig")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "replacement"), path); err != nil {
		t.Fatal(err)
	}
	if err := root.CheckFileIdentity("settings.xcconfig", identity); !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("CheckFileIdentity() error = %v, want ErrFileIdentityChanged", err)
	}
}

func TestCreateNewFileAtomicWithIdentityReturnsPublicationToken(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })

	identity, err := root.CreateNewFileAtomicWithIdentity("receipt.json", []byte("receipt"), 0o600)
	if err != nil {
		t.Fatalf("CreateNewFileAtomicWithIdentity() error = %v", err)
	}
	if identity == nil {
		t.Fatal("CreateNewFileAtomicWithIdentity() returned nil identity")
	}
	diskInfo, err := os.Stat(filepath.Join(dir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(identity.Info(), diskInfo) {
		t.Fatal("publication token does not identify the installed inode")
	}
}

func TestRemoveFileIfSameIdentityPreservesSameContentReplacement(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	const content = "receipt"
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("receipt.json")
	if err != nil {
		t.Fatalf("CaptureFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "replacement.json"), path); err != nil {
		t.Fatal(err)
	}

	if err := root.RemoveFileIfSameIdentity("receipt.json", identity); !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("RemoveFileIfSameIdentity() error = %v, want ErrFileIdentityChanged", err)
	}
	if got := mustRead(t, path); got != content {
		t.Fatalf("replacement content = %q, want %q", got, content)
	}
}

func TestFileIdentityCannotCrossRoots(t *testing.T) {
	firstDir := t.TempDir()
	secondDir := t.TempDir()
	first := mustRoot(t, firstDir)
	second := mustRoot(t, secondDir)
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	if err := os.WriteFile(filepath.Join(firstDir, "value"), []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := first.CaptureFile("value")
	if err != nil {
		t.Fatalf("CaptureFile() error = %v", err)
	}
	if _, err := second.ReplaceFileIfSame("value", identity, []byte("new"), 0o600, false); !errors.Is(err, ErrFileIdentityMismatch) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want ErrFileIdentityMismatch", err)
	}
}

func TestCaptureFileIdentityRejectsOversizeSnapshot(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	if err := os.WriteFile(filepath.Join(dir, "large"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := root.CaptureFileLimited("large", 4); !errors.Is(err, ErrFileIdentityDataTooLarge) {
		t.Fatalf("CaptureFileLimited() error = %v, want ErrFileIdentityDataTooLarge", err)
	}
	identity, err := root.CaptureFile("large")
	if err != nil {
		t.Fatal(err)
	}
	oversize := make([]byte, int(fileIdentityDataLimit)+1)
	if _, err := root.ReplaceFileIfSame("large", identity, oversize, 0o600, false); !errors.Is(err, ErrFileIdentityDataTooLarge) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want ErrFileIdentityDataTooLarge", err)
	}
	if got := mustRead(t, filepath.Join(dir, "large")); got != "12345" {
		t.Fatalf("destination after oversize replacement = %q, want unchanged snapshot", got)
	}
}

func TestReplaceFileIfSameDoesNotFallBackWhenNativeNoReplaceIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	const original = "original"
	if err := os.WriteFile(filepath.Join(dir, "value"), []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("value")
	if err != nil {
		t.Fatal(err)
	}
	root.renameNoReplaceForTest = func(*os.Root, string, string) error {
		return secureopen.ErrRenameNoReplaceUnsupported
	}

	if _, err := root.ReplaceFileIfSame("value", identity, []byte("updated"), 0o640, true); !errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want ErrRenameNoReplaceUnsupported", err)
	}
	if got := mustRead(t, filepath.Join(dir, "value")); got != original {
		t.Fatalf("destination after unsupported publication = %q, want %q", got, original)
	}
}

func TestRootCloseWaitsForIdentityOperation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict identity removal requires a handle-backed Windows primitive")
	}
	dir := t.TempDir()
	root := mustRoot(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "receipt.json"), []byte("receipt"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	root.beforeConditionalQuarantineForTest = func(*os.Root, string) {
		close(entered)
		<-release
	}
	operationDone := make(chan error, 1)
	go func() {
		operationDone <- root.RemoveFileIfSameIdentity("receipt.json", identity)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("identity operation did not reach the in-flight barrier")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- root.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Root.Close() returned before identity operation completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-operationDone; err != nil {
		t.Fatalf("RemoveFileIfSameIdentity() error = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Root.Close() error = %v", err)
	}
}

func TestCreateNewFileAtomicWithIdentityDoesNotReturnUnprovenToken(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	injected := errors.New("injected publication observation failure")
	root.postPublicationLstatForTest = func(*os.Root, string) (os.FileInfo, error) {
		return nil, injected
	}

	identity, err := root.CreateNewFileAtomicWithIdentity("receipt.json", []byte("receipt"), 0o600)
	if identity != nil {
		t.Fatal("CreateNewFileAtomicWithIdentity() returned a token before publication identity was proven")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("CreateNewFileAtomicWithIdentity() error = %v, want injected observation failure", err)
	}
	if got := mustRead(t, filepath.Join(dir, "receipt.json")); got != "receipt" {
		t.Fatalf("published contents = %q, want receipt", got)
	}
}

func TestCreateNewFileAtomicWithIdentityRejectsReplacementDuringIdentityCheck(t *testing.T) {
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	const content = "receipt"
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	root.afterPublicationOpenForTest = func(parent *os.Root, name string) {
		if err := parent.Rename(name, "published-original"); err != nil {
			t.Fatalf("move original publication: %v", err)
		}
		if err := parent.Rename("replacement", name); err != nil {
			t.Fatalf("install same-content replacement: %v", err)
		}
	}

	identity, err := root.CreateNewFileAtomicWithIdentity("receipt.json", []byte(content), 0o600)
	if identity != nil {
		t.Fatal("CreateNewFileAtomicWithIdentity() returned a token after the destination was replaced")
	}
	if !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("CreateNewFileAtomicWithIdentity() error = %v, want ErrFileIdentityChanged", err)
	}
	if got := mustRead(t, filepath.Join(dir, "receipt.json")); got != content {
		t.Fatalf("replacement contents = %q, want %q", got, content)
	}
	if got := mustRead(t, filepath.Join(dir, "published-original")); got != content {
		t.Fatalf("original publication contents = %q, want %q", got, content)
	}
}

func TestRemoveFileIfSameIdentityRestoresReplacementMovedBeforeQuarantineObservation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict identity removal requires a handle-backed Windows primitive")
	}
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	root.beforeConditionalQuarantineForTest = func(parent *os.Root, name string) {
		if err := parent.Rename(name, "original-moved"); err != nil {
			t.Fatalf("move original before quarantine: %v", err)
		}
		if err := parent.Rename("replacement", name); err != nil {
			t.Fatalf("install replacement before quarantine: %v", err)
		}
	}

	err = root.RemoveFileIfSameIdentity("receipt.json", identity)
	if !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("RemoveFileIfSameIdentity() error = %v, want identity change", err)
	}
	if got := mustRead(t, path); got != "replacement" {
		t.Fatalf("replacement contents = %q, want replacement", got)
	}
}

func TestReplaceFileIfSameIdentityRestoresReplacementMovedBeforeQuarantineObservation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict identity replacement requires a handle-backed Windows primitive")
	}
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	path := filepath.Join(dir, "settings.xcconfig")
	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("settings.xcconfig")
	if err != nil {
		t.Fatal(err)
	}
	root.beforeConditionalQuarantineForTest = func(parent *os.Root, name string) {
		if err := parent.Rename(name, "original-moved"); err != nil {
			t.Fatalf("move original before quarantine: %v", err)
		}
		if err := parent.Rename("replacement", name); err != nil {
			t.Fatalf("install replacement before quarantine: %v", err)
		}
	}

	installed, err := root.ReplaceFileIfSame("settings.xcconfig", identity, []byte("updated"), 0o640, true)
	if installed != nil {
		t.Fatal("ReplaceFileIfSame() returned an identity after pre-publication mismatch")
	}
	if !errors.Is(err, ErrFileIdentityChanged) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want identity change", err)
	}
	if got := mustRead(t, path); got != "replacement" {
		t.Fatalf("replacement contents = %q, want replacement", got)
	}
}

func TestRemoveFileIfSameIdentityLeavesChangedQuarantine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict identity removal requires a handle-backed Windows primitive")
	}
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var changedQuarantine string
	root.beforeConditionalQuarantineRemovalForTest = func(parent *os.Root, quarantineName string) {
		changedQuarantine = quarantineName
		if err := parent.Rename(quarantineName, "original-quarantine"); err != nil {
			t.Fatalf("move original quarantine: %v", err)
		}
		if err := parent.Rename("replacement", quarantineName); err != nil {
			t.Fatalf("install replacement quarantine: %v", err)
		}
	}

	err = root.RemoveFileIfSameIdentity("receipt.json", identity)
	if !errors.Is(err, ErrQuarantineCleanupUncertain) {
		t.Fatalf("RemoveFileIfSameIdentity() error = %v, want quarantine uncertainty", err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination after quarantine race = %v, want absent", statErr)
	}
	if got := mustRead(t, filepath.Join(dir, "original-quarantine")); got != "original" {
		t.Fatalf("original quarantine contents = %q, want original", got)
	}
	if changedQuarantine == "" {
		t.Fatal("quarantine race hook did not capture the random name")
	}
	if got := mustRead(t, filepath.Join(dir, changedQuarantine)); got != "replacement" {
		t.Fatalf("replacement quarantine contents = %q, want replacement", got)
	}
}

func TestReplaceFileIfSameIdentityLeavesChangedQuarantineWithInstalledToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict identity replacement requires a handle-backed Windows primitive")
	}
	dir := t.TempDir()
	root := mustRoot(t, dir)
	t.Cleanup(func() { _ = root.Close() })
	path := filepath.Join(dir, "settings.xcconfig")
	if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "replacement"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := root.CaptureFile("settings.xcconfig")
	if err != nil {
		t.Fatal(err)
	}
	var changedQuarantine string
	root.beforeConditionalQuarantineRemovalForTest = func(parent *os.Root, quarantineName string) {
		changedQuarantine = quarantineName
		if err := parent.Rename(quarantineName, "original-quarantine"); err != nil {
			t.Fatalf("move original quarantine: %v", err)
		}
		if err := parent.Rename("replacement", quarantineName); err != nil {
			t.Fatalf("install replacement quarantine: %v", err)
		}
	}

	installed, err := root.ReplaceFileIfSame("settings.xcconfig", identity, []byte("updated"), 0o640, true)
	if installed == nil {
		t.Fatal("ReplaceFileIfSame() returned nil token after proving publication")
	}
	if !errors.Is(err, ErrQuarantineCleanupUncertain) {
		t.Fatalf("ReplaceFileIfSame() error = %v, want quarantine uncertainty", err)
	}
	if got := mustRead(t, path); got != "updated" {
		t.Fatalf("published contents = %q, want updated", got)
	}
	if got := mustRead(t, filepath.Join(dir, "original-quarantine")); got != "original" {
		t.Fatalf("original quarantine contents = %q, want original", got)
	}
	if changedQuarantine == "" {
		t.Fatal("quarantine race hook did not capture the random name")
	}
	if got := mustRead(t, filepath.Join(dir, changedQuarantine)); got != "replacement" {
		t.Fatalf("replacement quarantine contents = %q, want replacement", got)
	}
}
