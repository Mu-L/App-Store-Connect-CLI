package distribution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestPrepareIPAWritesDeterministicPrivateBundle(t *testing.T) {
	ipaPath := validIPA(t, []string{"secret-device-b", "secret-device-a"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	result := preparePath(t, ipaPath, PrepareOptions{
		Root: root, Title: "Preview", Channel: "pull-request-42", SourceRevision: "abcdef", SourceURL: "https://example.com/revision/abcdef",
	})
	if result.Reused {
		t.Fatal("new bundle reported as reused")
	}
	wantSuffix := filepath.Join(".asc", "distribution", "com.example.demo", "1.0-1-"+result.Descriptor.Artifact.SHA256[:12])
	if !strings.HasSuffix(result.BundlePath, wantSuffix) {
		t.Fatalf("bundle path = %q, want suffix %q", result.BundlePath, wantSuffix)
	}
	data, err := os.ReadFile(filepath.Join(result.BundlePath, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret-device")) || bytes.Contains(data, []byte(ipaPath)) {
		t.Fatalf("descriptor leaked private or absolute input data: %s", data)
	}
	var descriptor Descriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		t.Fatal(err)
	}
	if descriptor.App.Title != "Preview" || descriptor.Source == nil || descriptor.Source.Channel != "pull-request-42" {
		t.Fatalf("unexpected descriptor: %#v", descriptor)
	}
	if descriptor.Artifact.RelativePath != "payload/app.ipa" {
		t.Fatalf("artifact path = %q", descriptor.Artifact.RelativePath)
	}
	if bytes.Contains(data, []byte("preparation")) {
		t.Fatalf("descriptor persisted transient eligibility: %s", data)
	}
	copied, err := os.ReadFile(filepath.Join(result.BundlePath, "payload", "app.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(ipaPath)
	if !bytes.Equal(copied, original) {
		t.Fatal("copied IPA differs")
	}
}

func TestPrepareIPAPathUsesRootedNoFollowInputAndReturnsProfileEvidence(t *testing.T) {
	installVerifiedPreparationForTest(t)
	inputDir := t.TempDir()
	profile := signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"private-device"}, Expires: time.Now().Add(24 * time.Hour)})
	source := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(inputDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "nested", "Demo.ipa"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	inputRoot, err := rootfs.New(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	result, err := PrepareIPAPath(context.Background(), inputRoot, filepath.Join("nested", "Demo.ipa"), PrepareOptions{Root: output})
	if err != nil {
		t.Fatalf("PrepareIPAPath() error = %v", err)
	}
	want := sha256.Sum256(profile)
	if result.Descriptor.Signing.EmbeddedProfileSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("embedded profile SHA-256 = %q, want %q", result.Descriptor.Signing.EmbeddedProfileSHA256, hex.EncodeToString(want[:]))
	}
	if len(result.Descriptor.Signing.Devices) != 0 {
		t.Fatalf("prepared descriptor disclosed devices: %#v", result.Descriptor.Signing.Devices)
	}
	if err := ValidateDescriptorForPublish(result.Descriptor); err != nil {
		t.Fatalf("ValidateDescriptorForPublish() error = %v", err)
	}
	expected := ExpectedIPA{SHA256: result.Descriptor.Artifact.SHA256, SizeBytes: result.Descriptor.Artifact.SizeBytes}
	exact, err := PrepareIPAPathExact(context.Background(), inputRoot, filepath.Join("nested", "Demo.ipa"), expected, PrepareOptions{Root: output})
	if err != nil {
		t.Fatalf("PrepareIPAPathExact() error = %v", err)
	}
	if !exact.Reused || exact.BundlePath != result.BundlePath {
		t.Fatalf("exact preparation did not reuse matching snapshot: %#v", exact)
	}
}

func TestPrepareIPAPathExactRejectsPathReplacementBeforeOutput(t *testing.T) {
	afterIPASnapshotForTest = func() { t.Fatal("identity mismatch proceeded past private snapshot") }
	t.Cleanup(func() { afterIPASnapshotForTest = nil })
	inputDir := t.TempDir()
	original := validIPA(t, []string{"original-device"}, time.Now().Add(time.Hour), false)
	replacement := validIPA(t, []string{"replacement-device"}, time.Now().Add(time.Hour), false)
	target := filepath.Join(inputDir, "Demo.ipa")
	copyFileForTest(t, original, target)
	expected := expectedIPAForTest(t, target)

	staged := filepath.Join(inputDir, "replacement.ipa")
	copyFileForTest(t, replacement, staged)
	if err := os.Rename(staged, target); err != nil {
		t.Fatal(err)
	}
	inputRoot, err := rootfs.New(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	_, err = PrepareIPAPathExact(context.Background(), inputRoot, "Demo.ipa", expected, PrepareOptions{Root: output})
	if !errors.Is(err, ErrIPAIdentityMismatch) {
		t.Fatalf("PrepareIPAPathExact() error = %v, want ErrIPAIdentityMismatch", err)
	}
	assertEmptyDirectory(t, output)
}

func TestPrepareIPAPathExactRejectsWrongExpectedIdentityBeforeOutput(t *testing.T) {
	afterIPASnapshotForTest = func() { t.Fatal("identity mismatch proceeded past private snapshot") }
	t.Cleanup(func() { afterIPASnapshotForTest = nil })
	inputDir := t.TempDir()
	source := validIPA(t, []string{"private-device"}, time.Now().Add(time.Hour), false)
	target := filepath.Join(inputDir, "Demo.ipa")
	copyFileForTest(t, source, target)
	want := expectedIPAForTest(t, target)
	inputRoot, err := rootfs.New(inputDir)
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*ExpectedIPA){
		"digest": func(expected *ExpectedIPA) { expected.SHA256 = strings.Repeat("0", 64) },
		"size":   func(expected *ExpectedIPA) { expected.SizeBytes++ },
		"both": func(expected *ExpectedIPA) {
			expected.SHA256 = strings.Repeat("f", 64)
			expected.SizeBytes++
		},
	} {
		t.Run(name, func(t *testing.T) {
			expected := want
			mutate(&expected)
			output := t.TempDir()
			_, err := PrepareIPAPathExact(context.Background(), inputRoot, "Demo.ipa", expected, PrepareOptions{Root: output})
			if !errors.Is(err, ErrIPAIdentityMismatch) {
				t.Fatalf("PrepareIPAPathExact() error = %v, want ErrIPAIdentityMismatch", err)
			}
			assertEmptyDirectory(t, output)
		})
	}
}

func TestPrepareIPAPathRejectsUnsafeInputBeforeOutput(t *testing.T) {
	inputDir := t.TempDir()
	outsideIPA := validIPA(t, []string{"one"}, time.Now().Add(time.Hour), false)
	if err := os.Symlink(outsideIPA, filepath.Join(inputDir, "linked.ipa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outsideIPA), filepath.Join(inputDir, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	inputRoot, err := rootfs.New(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../escape.ipa", "linked.ipa", filepath.Join("linked-dir", filepath.Base(outsideIPA))} {
		t.Run(path, func(t *testing.T) {
			output := t.TempDir()
			_, err := PrepareIPAPath(context.Background(), inputRoot, path, PrepareOptions{Root: output})
			if err == nil {
				t.Fatal("expected unsafe rooted input rejection")
			}
			entries, readErr := os.ReadDir(output)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("unsafe input wrote output: %#v", entries)
			}
		})
	}
}

func TestPrepareIPAPathHonorsCanceledContextBeforeFilesystemWork(t *testing.T) {
	inputDir := t.TempDir()
	inputRoot, err := rootfs.New(inputDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output := t.TempDir()
	_, err = PrepareIPAPath(ctx, inputRoot, "missing.ipa", PrepareOptions{Root: output})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareIPAPath() error = %v, want context.Canceled", err)
	}
	entries, readErr := os.ReadDir(output)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled preparation wrote output: %#v", entries)
	}
}

func TestValidateDescriptorForPublishRequiresExactEvidence(t *testing.T) {
	descriptor := Descriptor{
		SchemaVersion: "1", Platform: "IOS", DistributionMethod: "release-testing",
		App:      App{BundleID: "com.example.demo", Title: "Demo", Version: "1.0", BuildNumber: "1"},
		Artifact: Artifact{RelativePath: "payload/app.ipa", SizeBytes: 1, SHA256: strings.Repeat("a", 64)},
		Signing: Signing{
			ProfileClass: ProfileClassAdHoc, ProfileUUID: "uuid", TeamID: "TEAM", ExpiresAt: "2035-01-01T00:00:00Z", DeviceCount: 1,
			DeviceSetSHA256: strings.Repeat("b", 64), EmbeddedProfileSHA256: strings.Repeat("c", 64),
			ProfileCertificateSHA256Fingerprints: []string{strings.Repeat("d", 64)},
			ProfileIntegrityVerification:         CodeSignatureVerification{Status: CodeSignatureVerified},
			ProfileTrustVerification:             CodeSignatureVerification{Status: CodeSignatureVerified},
			CodeSignatureVerification: CodeSignatureVerification{
				Status: CodeSignatureVerified, Scope: CodeSignatureScopeCompleteMainApp,
				SignerCertificateSHA256Fingerprints: []string{strings.Repeat("d", 64)},
			},
		},
	}
	if err := ValidateDescriptorForPublish(descriptor); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Descriptor){
		"profile digest": func(value *Descriptor) { value.Signing.EmbeddedProfileSHA256 = "" },
		"profile trust":  func(value *Descriptor) { value.Signing.ProfileTrustVerification.Status = CodeSignatureNotVerified },
		"code scope":     func(value *Descriptor) { value.Signing.CodeSignatureVerification.Scope = "narrow" },
		"unbound signer": func(value *Descriptor) {
			value.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = []string{strings.Repeat("e", 64)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := descriptor
			candidate.Signing.ProfileCertificateSHA256Fingerprints = append([]string(nil), descriptor.Signing.ProfileCertificateSHA256Fingerprints...)
			candidate.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = append([]string(nil), descriptor.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints...)
			mutate(&candidate)
			if err := ValidateDescriptorForPublish(candidate); err == nil {
				t.Fatal("expected descriptor evidence rejection")
			}
		})
	}
}

func TestPrepareIPAReusesExactBundleWithoutChangingFiles(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	first := preparePath(t, ipaPath, PrepareOptions{Root: root})
	descriptorPath := filepath.Join(first.BundlePath, "bundle.json")
	before, err := os.Stat(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	second := preparePath(t, ipaPath, PrepareOptions{Root: root})
	if !second.Reused || second.BundlePath != first.BundlePath {
		t.Fatalf("unexpected reuse: %#v", second)
	}
	after, err := os.Stat(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("reuse rewrote descriptor")
	}
}

func TestPrepareIPASyncsStagedHierarchyBeforeDestinationParent(t *testing.T) {
	originalSync := syncPreparedDirectory
	t.Cleanup(func() { syncPreparedDirectory = originalSync })
	var order []string
	syncPreparedDirectory = func(root *os.Root, label string) error {
		order = append(order, label)
		return originalSync(root, label)
	}

	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	result := preparePath(t, ipaPath, PrepareOptions{Root: t.TempDir(), OutputDir: "output/bundle"})
	if result.Reused {
		t.Fatal("new publication reported reused")
	}
	want := []string{"staged payload", "staged bundle", "destination parent"}
	if !slices.Equal(order, want) {
		t.Fatalf("directory sync order = %v, want %v", order, want)
	}
}

func TestPrepareIPAFailsClosedWhenStagedDirectorySyncFails(t *testing.T) {
	for _, failedLabel := range []string{"staged payload", "staged bundle"} {
		t.Run(failedLabel, func(t *testing.T) {
			originalSync := syncPreparedDirectory
			t.Cleanup(func() { syncPreparedDirectory = originalSync })
			syncPreparedDirectory = func(root *os.Root, label string) error {
				if label == failedLabel {
					return errors.New("injected directory sync failure")
				}
				return originalSync(root, label)
			}
			installVerifiedPreparationForTest(t)
			ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
			file, err := os.Open(ipaPath)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, _ := file.Stat()
			root := t.TempDir()
			_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
			if err == nil || !strings.Contains(err.Error(), "injected directory sync failure") {
				t.Fatalf("PrepareIPA() error = %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(root, "output", "bundle")); !os.IsNotExist(statErr) {
				t.Fatalf("failed staged sync published final bundle: %v", statErr)
			}
			entries, readErr := os.ReadDir(filepath.Join(root, "output"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed staged sync left artifacts: %#v", entries)
			}
		})
	}
}

func TestPrepareIPARecoversAmbiguousFinalRenameWithExactReuse(t *testing.T) {
	originalRename := renamePreparedBundleNoReplace
	originalSync := syncPreparedDirectory
	t.Cleanup(func() {
		renamePreparedBundleNoReplace = originalRename
		syncPreparedDirectory = originalSync
	})
	renameCalls := 0
	renamePreparedBundleNoReplace = func(root *os.Root, oldName, newName string) error {
		renameCalls++
		if err := originalRename(root, oldName, newName); err != nil {
			return err
		}
		return errors.New("injected lost rename response")
	}
	failedParentSync := false
	syncPreparedDirectory = func(root *os.Root, label string) error {
		if err := originalSync(root, label); err != nil {
			return err
		}
		if label == "destination parent" && !failedParentSync {
			failedParentSync = true
			return errors.New("injected ambiguous destination sync failure")
		}
		return nil
	}

	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	installVerifiedPreparationForTest(t)
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := file.Stat()
	_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	_ = file.Close()
	if err == nil || !strings.Contains(err.Error(), "ambiguous destination sync failure") {
		t.Fatalf("ambiguous rename error = %v", err)
	}
	descriptorPath := filepath.Join(root, "output", "bundle", "bundle.json")
	before, err := os.Stat(descriptorPath)
	if err != nil {
		t.Fatalf("exact final bundle missing after ambiguous rename: %v", err)
	}

	file, err = os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if err != nil {
		t.Fatalf("ambiguous rename resume error = %v", err)
	}
	if !result.Reused || renameCalls != 1 {
		t.Fatalf("ambiguous rename resume result=%+v calls=%d", result, renameCalls)
	}
	after, err := os.Stat(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("ambiguous rename resume rewrote exact bundle")
	}
}

func TestPrepareIPAResumesAfterDestinationParentSyncFailure(t *testing.T) {
	originalSync := syncPreparedDirectory
	t.Cleanup(func() { syncPreparedDirectory = originalSync })
	failed := false
	syncPreparedDirectory = func(root *os.Root, label string) error {
		if err := originalSync(root, label); err != nil {
			return err
		}
		if label == "destination parent" && !failed {
			failed = true
			return errors.New("injected destination parent sync failure")
		}
		return nil
	}

	installVerifiedPreparationForTest(t)
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := file.Stat()
	_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	_ = file.Close()
	if err == nil || !strings.Contains(err.Error(), "injected destination parent sync failure") {
		t.Fatalf("first PrepareIPA() error = %v", err)
	}
	descriptorPath := filepath.Join(root, "output", "bundle", "bundle.json")
	before, statErr := os.Stat(descriptorPath)
	if statErr != nil {
		t.Fatalf("final bundle absent after post-rename sync failure: %v", statErr)
	}

	file, err = os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if err != nil {
		t.Fatalf("resume PrepareIPA() error = %v", err)
	}
	if !result.Reused {
		t.Fatalf("resume result = %+v, want exact reuse", result)
	}
	after, statErr := os.Stat(descriptorPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("resume rewrote exact bundle")
	}
}

func TestPrepareIPAExactReuseFailsClosedOnDirectorySyncFailure(t *testing.T) {
	for _, failedLabel := range []string{"existing payload", "existing bundle", "destination parent"} {
		t.Run(failedLabel, func(t *testing.T) {
			ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
			root := t.TempDir()
			first := preparePath(t, ipaPath, PrepareOptions{Root: root, OutputDir: "output/bundle"})
			descriptorPath := filepath.Join(first.BundlePath, "bundle.json")
			before, err := os.Stat(descriptorPath)
			if err != nil {
				t.Fatal(err)
			}

			originalSync := syncPreparedDirectory
			t.Cleanup(func() { syncPreparedDirectory = originalSync })
			syncPreparedDirectory = func(root *os.Root, label string) error {
				if label == failedLabel {
					return errors.New("injected exact-reuse sync failure")
				}
				return originalSync(root, label)
			}
			installVerifiedPreparationForTest(t)
			file, err := os.Open(ipaPath)
			if err != nil {
				t.Fatal(err)
			}
			info, _ := file.Stat()
			_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
			_ = file.Close()
			if err == nil || !strings.Contains(err.Error(), "injected exact-reuse sync failure") {
				t.Fatalf("exact-reuse error = %v", err)
			}
			after, err := os.Stat(descriptorPath)
			if err != nil {
				t.Fatal(err)
			}
			if !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("failed exact-reuse sync rewrote bundle")
			}
		})
	}
}

func TestPrepareIPAExactReusePropagatesTransientInspectionErrors(t *testing.T) {
	for _, failedStep := range []string{
		"open existing bundle",
		"read existing bundle directory",
		"open existing payload",
		"read existing payload directory",
		"read existing descriptor",
		"hash existing IPA",
	} {
		t.Run(failedStep, func(t *testing.T) {
			ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
			root := t.TempDir()
			preparePath(t, ipaPath, PrepareOptions{Root: root, OutputDir: "output/bundle"})

			inspectExactBundleForTest = func(step string) error {
				if step == failedStep {
					return syscall.EIO
				}
				return nil
			}
			t.Cleanup(func() { inspectExactBundleForTest = nil })
			installVerifiedPreparationForTest(t)
			file, err := os.Open(ipaPath)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
			if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrBundleConflict) {
				t.Fatalf("inspection error = %v, want retryable EIO and not ErrBundleConflict", err)
			}
		})
	}
}

func TestPrepareIPAAmbiguousRenameConflictDoesNotReportReuse(t *testing.T) {
	originalRename := renamePreparedBundleNoReplace
	t.Cleanup(func() { renamePreparedBundleNoReplace = originalRename })
	renamePreparedBundleNoReplace = func(root *os.Root, oldName, newName string) error {
		if err := root.Mkdir(newName, 0o755); err != nil {
			return err
		}
		return errors.New("injected ambiguous conflicting rename")
	}

	installVerifiedPreparationForTest(t)
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	root := t.TempDir()
	_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("ambiguous conflict error = %v, want ErrBundleConflict", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(root, "output"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 2 {
		t.Fatalf("ambiguous conflict entries = %#v, want conflicting final plus preserved ambiguous stage", entries)
	}
	foundBundle, foundStage := false, false
	for _, entry := range entries {
		foundBundle = foundBundle || entry.Name() == "bundle"
		if strings.HasPrefix(entry.Name(), ".asc-distribute-stage-") {
			foundStage = true
			if _, statErr := os.Stat(filepath.Join(root, "output", entry.Name(), "bundle.json")); statErr != nil {
				t.Fatalf("preserved ambiguous stage is incomplete: %v", statErr)
			}
		}
	}
	if !foundBundle || !foundStage {
		t.Fatalf("ambiguous conflict entries = %#v", entries)
	}
}

func TestPrepareIPAExactReuseRejectsFinalDirectoryReplacementDuringSync(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	first := preparePath(t, ipaPath, PrepareOptions{Root: root, OutputDir: "output/bundle"})

	originalSync := syncPreparedDirectory
	t.Cleanup(func() { syncPreparedDirectory = originalSync })
	replaced := false
	syncPreparedDirectory = func(parent *os.Root, label string) error {
		if err := originalSync(parent, label); err != nil {
			return err
		}
		if label == "destination parent" && !replaced {
			replaced = true
			if err := parent.Rename("bundle", "displaced-exact-bundle"); err != nil {
				return err
			}
			if err := parent.Mkdir("bundle", 0o755); err != nil {
				return err
			}
			replacement, err := parent.OpenRoot("bundle")
			if err != nil {
				return err
			}
			defer replacement.Close()
			return writeNewRootedFile(replacement, "replacement-sentinel", []byte("do-not-overwrite"), 0o600)
		}
		return nil
	}

	installVerifiedPreparationForTest(t)
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	result, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if err == nil || result.Reused || !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("replacement race result=%+v error=%v", result, err)
	}
	sentinel, readErr := os.ReadFile(filepath.Join(root, "output", "bundle", "replacement-sentinel"))
	if readErr != nil || string(sentinel) != "do-not-overwrite" {
		t.Fatalf("replacement was modified: data=%q err=%v", sentinel, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "output", "displaced-exact-bundle", "bundle.json")); statErr != nil {
		t.Fatalf("validated original was deleted: %v", statErr)
	}
	if _, statErr := os.Stat(first.BundlePath); statErr != nil {
		t.Fatalf("replacement final directory disappeared: %v", statErr)
	}
}

func TestPrepareIPAExactReuseRejectsPayloadReplacementDuringSync(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	preparePath(t, ipaPath, PrepareOptions{Root: root, OutputDir: "output/bundle"})

	originalSync := syncPreparedDirectory
	t.Cleanup(func() { syncPreparedDirectory = originalSync })
	replaced := false
	syncPreparedDirectory = func(parent *os.Root, label string) error {
		if err := originalSync(parent, label); err != nil {
			return err
		}
		if label == "destination parent" && !replaced {
			replaced = true
			bundle, err := parent.OpenRoot("bundle")
			if err != nil {
				return err
			}
			defer bundle.Close()
			if err := bundle.Rename("payload", "displaced-exact-payload"); err != nil {
				return err
			}
			if err := bundle.Mkdir("payload", 0o755); err != nil {
				return err
			}
			replacement, err := bundle.OpenRoot("payload")
			if err != nil {
				return err
			}
			defer replacement.Close()
			return writeNewRootedFile(replacement, "replacement-sentinel", []byte("do-not-overwrite"), 0o600)
		}
		return nil
	}

	installVerifiedPreparationForTest(t)
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	result, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if err == nil || result.Reused || !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("payload replacement result=%+v error=%v", result, err)
	}
	sentinel, readErr := os.ReadFile(filepath.Join(root, "output", "bundle", "payload", "replacement-sentinel"))
	if readErr != nil || string(sentinel) != "do-not-overwrite" {
		t.Fatalf("replacement payload was modified: data=%q err=%v", sentinel, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "output", "bundle", "displaced-exact-payload", "app.ipa")); statErr != nil {
		t.Fatalf("validated payload was deleted: %v", statErr)
	}
}

func TestPrepareIPADoesNotCleanupPublishedBundleMovedBackToStageName(t *testing.T) {
	originalRename := renamePreparedBundleNoReplace
	originalSync := syncPreparedDirectory
	t.Cleanup(func() {
		renamePreparedBundleNoReplace = originalRename
		syncPreparedDirectory = originalSync
	})
	var stagedName, finalName string
	renamePreparedBundleNoReplace = func(parent *os.Root, oldName, newName string) error {
		stagedName, finalName = oldName, newName
		return originalRename(parent, oldName, newName)
	}
	moved := false
	syncPreparedDirectory = func(parent *os.Root, label string) error {
		if err := originalSync(parent, label); err != nil {
			return err
		}
		if label == "destination parent" && !moved {
			moved = true
			return parent.Rename(finalName, stagedName)
		}
		return nil
	}

	installVerifiedPreparationForTest(t)
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	root := t.TempDir()
	_, err = PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"})
	if err == nil || !strings.Contains(err.Error(), "changed during destination durability sync") {
		t.Fatalf("moved publication error = %v", err)
	}
	if stagedName == "" {
		t.Fatal("rename hook did not capture staging name")
	}
	if _, statErr := os.Stat(filepath.Join(root, "output", stagedName, "bundle.json")); statErr != nil {
		t.Fatalf("published bundle moved to staging name was deleted: %v", statErr)
	}
}

func TestPrepareIPAReuseRejectsEmbeddedProfileDigestMismatch(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	first := preparePath(t, ipaPath, PrepareOptions{Root: root})
	descriptorPath := filepath.Join(first.BundlePath, "bundle.json")
	data, err := os.ReadFile(descriptorPath)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor Descriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		t.Fatal(err)
	}
	descriptor.Signing.EmbeddedProfileSHA256 = strings.Repeat("0", 64)
	tampered, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, '\n')
	if err := os.WriteFile(descriptorPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("PrepareIPA() error = %v, want ErrBundleConflict", err)
	}
}

func TestDescriptorEmbeddedProfileHashIsWireCompatibleWithPublisherSchema(t *testing.T) {
	descriptor := Descriptor{Signing: Signing{EmbeddedProfileSHA256: strings.Repeat("a", 64)}}
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"embeddedProfileSha256"`)) {
		t.Fatalf("descriptor omitted profile digest: %s", data)
	}
	var publisherDescriptor PreparedDescriptor
	if err := json.Unmarshal(data, &publisherDescriptor); err != nil {
		t.Fatalf("publisher descriptor rejected forward-compatible evidence: %v", err)
	}
}

func TestPrepareIPARefusesConflictingExistingBundle(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	root := t.TempDir()
	first := preparePath(t, ipaPath, PrepareOptions{Root: root})
	descriptorPath := filepath.Join(first.BundlePath, "bundle.json")
	if err := os.WriteFile(descriptorPath, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(ipaPath)
	defer file.Close()
	info, _ := file.Stat()
	_, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root})
	if !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("error = %v, want ErrBundleConflict", err)
	}
	got, _ := os.ReadFile(descriptorPath)
	if string(got) != "sentinel" {
		t.Fatalf("conflict overwritten: %q", got)
	}
}

func TestPrepareIPAPublishesFromStableSnapshot(t *testing.T) {
	installVerifiedPreparationForTest(t)
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(24*time.Hour), false)
	original, err := os.ReadFile(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(ipaPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	afterIPASnapshotForTest = func() {
		if _, writeErr := file.WriteAt(bytes.Repeat([]byte{0}, len(original)), 0); writeErr != nil {
			t.Errorf("mutate source after snapshot: %v", writeErr)
		}
	}
	t.Cleanup(func() { afterIPASnapshotForTest = nil })

	result, err := PrepareIPA(file, int64(len(original)), PrepareOptions{Root: t.TempDir()})
	if err != nil {
		t.Fatalf("PrepareIPA() error = %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(result.BundlePath, "payload", "app.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, original) {
		t.Fatal("prepared payload did not use the stable pre-mutation snapshot")
	}
}

func TestPrepareIPARejectsOutputParentSwappedToSymlink(t *testing.T) {
	installVerifiedPreparationForTest(t)
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(time.Hour), false)
	root := t.TempDir()
	outside := t.TempDir()
	parent := filepath.Join(root, "output")
	afterOutputParentsCreatedForTest = func() {
		if err := os.Rename(parent, parent+"-original"); err != nil {
			t.Errorf("rename output parent: %v", err)
			return
		}
		if err := os.Symlink(outside, parent); err != nil {
			t.Errorf("replace output parent with symlink: %v", err)
		}
	}
	t.Cleanup(func() { afterOutputParentsCreatedForTest = nil })

	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root, OutputDir: "output/bundle"}); err == nil {
		t.Fatal("expected swapped output parent rejection")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("wrote through swapped output symlink: %#v", entries)
	}
}

func TestPrepareIPARejectsIneligibleAndCredentialURLBeforeWriting(t *testing.T) {
	tests := []struct {
		name string
		path string
		opts PrepareOptions
	}{
		{name: "development", path: validIPA(t, []string{"one"}, time.Now().Add(time.Hour), true), opts: PrepareOptions{}},
		{name: "expired", path: validIPA(t, []string{"one"}, time.Now().Add(-time.Hour), false), opts: PrepareOptions{}},
		{name: "credential URL", path: validIPA(t, []string{"one"}, time.Now().Add(time.Hour), false), opts: PrepareOptions{SourceURL: "https://token@example.com/revision"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.opts.Root = root
			file, _ := os.Open(test.path)
			defer file.Close()
			info, _ := file.Stat()
			if _, err := PrepareIPA(file, info.Size(), test.opts); err == nil {
				t.Fatal("expected error")
			}
			entries, _ := os.ReadDir(root)
			if len(entries) != 0 {
				t.Fatalf("wrote before validation: %#v", entries)
			}
		})
	}
}

func TestPrepareIPARejectsUnverifiedProfileTrustAndCodeBeforeWriting(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(time.Hour), false)
	root := t.TempDir()
	file, err := os.Open(ipaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root}); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("PrepareIPA() error = %v, want ErrNotEligible", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unverified IPA wrote output: %#v", entries)
	}
}

func TestPrepareIPARejectsSymlinkedDefaultOutputParent(t *testing.T) {
	ipaPath := validIPA(t, []string{"one"}, time.Now().Add(time.Hour), false)
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".asc")); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(ipaPath)
	defer file.Close()
	info, _ := file.Stat()
	if _, err := PrepareIPA(file, info.Size(), PrepareOptions{Root: root}); err == nil {
		t.Fatal("expected symlinked .asc rejection")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("wrote through symlink: %#v", entries)
	}
}

func TestValidatePrepareOptionsRejectsControlMetadata(t *testing.T) {
	if err := ValidatePrepareOptions(PrepareOptions{Channel: "safe\nsecret"}); err == nil {
		t.Fatal("expected control character rejection")
	}
	if err := ValidatePrepareOptions(PrepareOptions{Channel: "safe\u202Esecret"}); err == nil {
		t.Fatal("expected bidi format control rejection")
	}
}

func TestSafePathComponentIsCollisionSafeAndContained(t *testing.T) {
	values := []string{"..", "a/b", "a-b", "a\\b", "x\x00y", "é"}
	seen := map[string]bool{}
	for _, value := range values {
		got, err := safePathComponent(value)
		if err != nil {
			t.Fatalf("safePathComponent(%q): %v", value, err)
		}
		if got == "." || got == ".." || strings.ContainsAny(got, `/\\`) {
			t.Fatalf("unsafe result %q", got)
		}
		if seen[got] {
			t.Fatalf("collision for %q: %q", value, got)
		}
		seen[got] = true
	}
}

func preparePath(t *testing.T, path string, options PrepareOptions) PrepareResult {
	t.Helper()
	installVerifiedPreparationForTest(t)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	result, err := PrepareIPA(file, info.Size(), options)
	if err != nil {
		t.Fatalf("PrepareIPA() error = %v", err)
	}
	return result
}

func installVerifiedPreparationForTest(t *testing.T) {
	t.Helper()
	verifyCompleteSigningForTest = func(inspection *Inspection) {
		inspection.Signing.ProfileIntegrityVerification.Status = CodeSignatureVerified
		inspection.Signing.ProfileTrustVerification.Status = CodeSignatureVerified
		inspection.Signing.CodeSignatureVerification.Status = CodeSignatureVerified
		inspection.Signing.CodeSignatureVerification.Scope = CodeSignatureScopeCompleteMainApp
		inspection.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints = append(
			[]string(nil), inspection.Signing.ProfileCertificateSHA256Fingerprints...,
		)
	}
	t.Cleanup(func() { verifyCompleteSigningForTest = nil })
}

func expectedIPAForTest(t *testing.T, path string) ExpectedIPA {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return ExpectedIPA{SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}
}

func copyFileForTest(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertEmptyDirectory(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected output side effects: %#v", entries)
	}
}
