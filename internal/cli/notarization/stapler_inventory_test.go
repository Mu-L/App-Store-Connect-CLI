package notarization

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStaplerDirectoryInventoryBindsNestedBytesAndMode(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	nestedPath := filepath.Join(targetPath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	baseline, err := target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err != nil {
		t.Fatalf("capture baseline: %v", err)
	}
	if baseline.entryCount != 3 {
		t.Fatalf("baseline entry count = %d, want one root, directory, and file", baseline.entryCount)
	}
	// Keep the size and mode unchanged: the content digest must still bind the
	// nested file, rather than relying on a directory or outer-target identity.
	if err := os.WriteFile(nestedPath, []byte("changed!"), 0o600); err != nil {
		t.Fatalf("replace nested file: %v", err)
	}
	err = target.verifyDirectoryInventory(context.Background(), baseline, "before validation")
	if err == nil {
		t.Fatal("verifyDirectoryInventory() = nil, want nested-byte mismatch")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("verifyDirectoryInventory() error = %T %v, want identity error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) || strings.Contains(err.Error(), "Info.plist") {
		t.Fatalf("verification error = %q, must not expose nested path", err.Error())
	}

	if err := os.WriteFile(nestedPath, []byte("original"), 0o640); err != nil {
		t.Fatalf("restore nested file with changed mode: %v", err)
	}
	if err := os.Chmod(nestedPath, 0o640); err != nil {
		t.Fatalf("change nested mode: %v", err)
	}
	err = target.verifyDirectoryInventory(context.Background(), baseline, "before validation")
	if err == nil {
		t.Fatal("verifyDirectoryInventory() = nil, want nested-mode mismatch")
	}
	if !errors.As(err, &identityErr) {
		t.Fatalf("verifyDirectoryInventory() error = %T %v, want identity error", err, err)
	}
}

func TestStaplerDirectoryInventoryRejectsSymlinkAndSpecialEntries(t *testing.T) {
	tests := []struct {
		name string
		make func(t *testing.T, directory string)
	}{
		{
			name: "escaping symlink",
			make: func(t *testing.T, directory string) {
				if err := os.Symlink(filepath.Dir(directory), filepath.Join(directory, "Contents-link")); err != nil {
					if runtime.GOOS == "windows" {
						t.Skipf("symlink creation unavailable: %v", err)
					}
					t.Fatalf("create symlink: %v", err)
				}
			},
		},
		{
			name: "special file",
			make: func(t *testing.T, directory string) {
				makeStaplerSpecialEntry(t, directory)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetPath := filepath.Join(t.TempDir(), "MyApp.app")
			if err := os.Mkdir(targetPath, 0o755); err != nil {
				t.Fatalf("create bundle: %v", err)
			}
			test.make(t, targetPath)
			target, err := validateStaplerTargetDetails(targetPath)
			if err != nil {
				t.Fatalf("validate target: %v", err)
			}
			t.Cleanup(target.close)

			_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
			if err == nil {
				t.Fatal("captureDirectoryInventoryAtStage() = nil, want fail-closed entry rejection")
			}
			var verifyErr *staplerTargetVerifyError
			if !errors.As(err, &verifyErr) {
				t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want verify error", err, err)
			}
			if strings.Contains(err.Error(), targetPath) || strings.Contains(err.Error(), "Contents-link") || strings.Contains(err.Error(), "named-pipe") {
				t.Fatalf("inventory error = %q, must not expose entry path", err.Error())
			}
		})
	}
}

func TestStaplerDirectoryInventoryAllowsContainedSymlinkWithoutFollowing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixtures require platform support")
	}
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	versioned := filepath.Join(targetPath, "Versions", "1")
	if err := os.MkdirAll(versioned, 0o755); err != nil {
		t.Fatalf("create versioned bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versioned, "Info.plist"), []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write versioned bundle file: %v", err)
	}
	linkPath := filepath.Join(targetPath, "Versions", "Current")
	if err := os.Symlink("1", linkPath); err != nil {
		t.Fatalf("create contained symlink: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	inventory, err := target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err != nil {
		t.Fatalf("capture contained-symlink inventory: %v", err)
	}
	if inventory.entryCount != 5 {
		t.Fatalf("inventory entry count = %d, want root, Versions, 1, Info.plist, and Current", inventory.entryCount)
	}

	if err := os.Remove(linkPath); err != nil {
		t.Fatalf("remove contained symlink: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside target: %v", err)
	}
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}
	if _, err := target.captureDirectoryInventoryAtStage(context.Background(), "before validation"); err == nil {
		t.Fatal("capture escaping-symlink inventory = nil, want fail-closed rejection")
	}
}

func TestStaplerDirectoryInventoryHonorsCanceledContext(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = target.captureDirectoryInventoryAtStage(ctx, "before validation")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %v, want context cancellation", err)
	}
	var verifyErr *staplerTargetVerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want verify error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) {
		t.Fatalf("inventory error = %q, must not expose target path", err.Error())
	}
}

func TestStaplerDirectoryInventoryStopsWhenContextCancelsDuringScan(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	nestedPath := filepath.Join(targetPath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	ctx := &cancelDuringStaplerInventoryContext{cancelAfterChecks: 4}
	_, err = target.captureDirectoryInventoryAtStage(ctx, "before validation")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %v, want cancellation during scan", err)
	}
	var verifyErr *staplerTargetVerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want verify error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) || strings.Contains(err.Error(), "Info.plist") {
		t.Fatalf("inventory error = %q, must not expose path", err.Error())
	}
}

type cancelDuringStaplerInventoryContext struct {
	checks            int
	cancelAfterChecks int
}

func (ctx *cancelDuringStaplerInventoryContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (*cancelDuringStaplerInventoryContext) Done() <-chan struct{} {
	return nil
}

func (ctx *cancelDuringStaplerInventoryContext) Err() error {
	ctx.checks++
	if ctx.checks > ctx.cancelAfterChecks {
		return context.Canceled
	}
	return nil
}

func (*cancelDuringStaplerInventoryContext) Value(any) any {
	return nil
}

func TestStaplerDirectoryInventoryEnforcesEntryBounds(t *testing.T) {
	scanner := staplerInventoryScanner{entryCount: staplerInventoryMaxEntries}
	if err := scanner.noteEntry("entry"); err == nil {
		t.Fatal("noteEntry() = nil at entry cap, want rejection")
	}
	scanner = staplerInventoryScanner{}
	if err := scanner.noteEntry(strings.Repeat("x", staplerInventoryMaxPath+1)); err == nil {
		t.Fatal("noteEntry() = nil over path cap, want rejection")
	}
}

func TestStaplerDirectoryInventoryReadsLargeDirectoriesInBoundedBatches(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := readdirStaplerInventoryNamesFn
	var calls, requested int
	readdirStaplerInventoryNamesFn = func(_ *os.File, count int) ([]string, error) {
		calls++
		requested = count
		// Simulate a directory larger than the hard cap without creating
		// hundreds of thousands of filesystem entries. The scanner must reject
		// the batch before retaining or inspecting its names.
		return make([]string, staplerInventoryMaxEntries), io.EOF
	}
	t.Cleanup(func() { readdirStaplerInventoryNamesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err == nil {
		t.Fatal("captureDirectoryInventoryAtStage() = nil, want entry-cap rejection")
	}
	if calls != 1 {
		t.Fatalf("directory read calls = %d, want one bounded-cap read", calls)
	}
	if requested != staplerInventoryReadBatchSize {
		t.Fatalf("directory read request = %d, want bounded batch size %d", requested, staplerInventoryReadBatchSize)
	}
	if strings.Contains(err.Error(), targetPath) {
		t.Fatalf("inventory error = %q, must not expose target path", err.Error())
	}
}

func TestStaplerDirectoryInventoryIgnoresDirectoryMtimeOnlyChanges(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	nestedPath := filepath.Join(targetPath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := readdirStaplerInventoryNamesFn
	changed := false
	readdirStaplerInventoryNamesFn = func(file *os.File, count int) ([]string, error) {
		batch, readErr := file.Readdirnames(count)
		if !changed {
			changed = true
			mtime := time.Now().Add(2 * time.Second)
			if err := os.Chtimes(targetPath, mtime, mtime); err != nil {
				t.Fatalf("change directory mtime: %v", err)
			}
		}
		return batch, readErr
	}
	t.Cleanup(func() { readdirStaplerInventoryNamesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err != nil {
		t.Fatalf("captureDirectoryInventoryAtStage() = %v, want content-only inventory to ignore mtime-only metadata change", err)
	}
}

func TestStaplerDirectoryInventoryIgnoresUnrelatedSiblingMetadataChurn(t *testing.T) {
	root := t.TempDir()
	targetPath := filepath.Join(root, "MyApp.app")
	if err := os.MkdirAll(filepath.Join(targetPath, "Contents"), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetPath, "Contents", "Info.plist"), []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	before, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}

	// A sibling create can perturb a directory's reported size even when the
	// recursively inventoried entries are otherwise stable. Keep the siblings
	// in this isolated fixture; this test exercises the identity check only,
	// while the recursive inventory remains responsible for binding contents.
	const siblingCount = 4096
	var after os.FileInfo
	for index := 0; index < siblingCount; index++ {
		path := filepath.Join(targetPath, "sibling-"+strconv.Itoa(index))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("create sibling %d: %v", index, err)
		}
		after, err = os.Stat(targetPath)
		if err != nil {
			t.Fatalf("stat bundle after sibling %d: %v", index, err)
		}
		if before.Size() != after.Size() {
			break
		}
	}
	if before.Size() == after.Size() {
		// Some filesystems do not expose directory-size churn. Force the other
		// directory-only metadata field to change so the test remains portable.
		mtime := before.ModTime().Add(2 * time.Second)
		if err := os.Chtimes(targetPath, mtime, mtime); err != nil {
			t.Fatalf("change directory metadata: %v", err)
		}
		after, err = os.Stat(targetPath)
		if err != nil {
			t.Fatalf("restat bundle: %v", err)
		}
	}
	if before.Size() == after.Size() {
		if before.ModTime().Equal(after.ModTime()) {
			t.Fatal("sibling metadata churn did not change directory metadata")
		}
	}
	if !staplerInventoryInfoStable(before, after) {
		t.Fatal("directory metadata churn must not invalidate a stable directory identity")
	}
}

func TestStaplerInventoryRetainsRegularFileMetadataBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Info.plist")
	if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if err := os.WriteFile(path, []byte("fixture!"), 0o644); err != nil {
		t.Fatalf("change file size: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("restat file: %v", err)
	}
	if staplerInventoryInfoStable(before, after) {
		t.Fatal("regular-file size changes must invalidate the bound metadata")
	}
}

func TestStaplerDirectoryInventoryRejectsEntryAddedAfterEnumeration(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	nestedPath := filepath.Join(targetPath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(nestedPath), 0o755); err != nil {
		t.Fatalf("create bundle contents: %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write nested file: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := readdirStaplerInventoryNamesFn
	injected := false
	readdirStaplerInventoryNamesFn = func(file *os.File, count int) ([]string, error) {
		batch, readErr := file.Readdirnames(count)
		if !injected && errors.Is(readErr, io.EOF) {
			injected = true
			if err := os.WriteFile(filepath.Join(targetPath, "added-after-enumeration"), []byte("late"), 0o600); err != nil {
				t.Fatalf("add late bundle entry: %v", err)
			}
		}
		return batch, readErr
	}
	t.Cleanup(func() { readdirStaplerInventoryNamesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err == nil {
		t.Fatal("captureDirectoryInventoryAtStage() = nil, want entry-addition race rejection")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want identity error", err, err)
	}
}

func TestStaplerDirectoryInventoryRejectsSameNameReplacementAfterEnumeration(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	entryPath := filepath.Join(targetPath, "Info.plist")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if err := os.WriteFile(entryPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write bundle entry: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := afterStaplerInventoryNamesFn
	afterStaplerInventoryNamesFn = func() {
		originalPath := entryPath + ".original"
		if err := os.Rename(entryPath, originalPath); err != nil {
			t.Fatalf("move original entry: %v", err)
		}
		if err := os.WriteFile(entryPath, []byte("replaced"), 0o600); err != nil {
			t.Fatalf("replace bundle entry: %v", err)
		}
		if err := os.Remove(originalPath); err != nil {
			t.Fatalf("remove original entry: %v", err)
		}
	}
	t.Cleanup(func() { afterStaplerInventoryNamesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err == nil {
		t.Fatal("captureDirectoryInventoryAtStage() = nil, want same-name replacement rejection")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want identity error", err, err)
	}
}

func TestStaplerDirectoryInventoryRejectsDirectChildAddedAfterFinalEnumeration(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	entryPath := filepath.Join(targetPath, "Info.plist")
	latePath := filepath.Join(targetPath, "Late.plist")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if err := os.WriteFile(entryPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write bundle entry: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := afterStaplerInventoryNamesFn
	afterStaplerInventoryNamesFn = func() {
		if err := os.WriteFile(latePath, []byte("late"), 0o600); err != nil {
			t.Fatalf("add late bundle entry: %v", err)
		}
	}
	t.Cleanup(func() { afterStaplerInventoryNamesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err == nil {
		t.Fatal("captureDirectoryInventoryAtStage() = nil, want late direct-child rejection")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want identity error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) || strings.Contains(err.Error(), "Late.plist") {
		t.Fatalf("inventory error = %q, must not expose entry path", err.Error())
	}
}

func TestStaplerDirectoryInventoryRejectsSameNameReplacementAfterRetainedChecks(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "MyApp.app")
	entryPath := filepath.Join(targetPath, "Info.plist")
	originalPath := entryPath + ".original"
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if err := os.WriteFile(entryPath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write bundle entry: %v", err)
	}
	target, err := validateStaplerTargetDetails(targetPath)
	if err != nil {
		t.Fatalf("validate target: %v", err)
	}
	t.Cleanup(target.close)

	previous := afterStaplerInventoryEntriesFn
	afterStaplerInventoryEntriesFn = func() {
		if err := os.Rename(entryPath, originalPath); err != nil {
			t.Fatalf("move original entry: %v", err)
		}
		if err := os.WriteFile(entryPath, []byte("replaced"), 0o600); err != nil {
			t.Fatalf("replace bundle entry: %v", err)
		}
		if err := os.Remove(originalPath); err != nil {
			t.Fatalf("remove original entry: %v", err)
		}
	}
	t.Cleanup(func() { afterStaplerInventoryEntriesFn = previous })

	_, err = target.captureDirectoryInventoryAtStage(context.Background(), "before validation")
	if err == nil {
		t.Fatal("captureDirectoryInventoryAtStage() = nil, want late same-name replacement rejection")
	}
	var identityErr *staplerTargetIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("captureDirectoryInventoryAtStage() error = %T %v, want identity error", err, err)
	}
	if strings.Contains(err.Error(), targetPath) || strings.Contains(err.Error(), "Info.plist") {
		t.Fatalf("inventory error = %q, must not expose entry path", err.Error())
	}
}
