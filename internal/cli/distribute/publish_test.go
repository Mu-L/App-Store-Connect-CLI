package distribute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/distribution"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestPublishCommandRequiresFlagsBeforeSideEffects(t *testing.T) {
	originalLoad := loadPreparedBundle
	t.Cleanup(func() { loadPreparedBundle = originalLoad })
	called := false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		called = true
		return nil, nil
	}

	command := PublishCommand()
	if err := command.ParseAndRun(context.Background(), []string{"--endpoint", "https://objects.example.com"}); err == nil {
		t.Fatal("expected required flag error")
	}
	if called {
		t.Fatal("bundle was loaded before flag validation")
	}
}

func TestPublicationVerifierUsesUploadTimeoutForIPA(t *testing.T) {
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("ASC_UPLOAD_TIMEOUT", "5m")
	t.Setenv("ASC_UPLOAD_TIMEOUT_SECONDS", "")

	recorder := &deadlineRecordingVerifier{}
	verifier := publicationVerifier{delegate: recorder, documentTimeout: 30 * time.Second}

	if err := verifier.Verify(context.Background(), distribution.VerifyRequest{Kind: distribution.VerifyIPA}); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), distribution.VerifyRequest{Kind: distribution.VerifyDocument}); err != nil {
		t.Fatal(err)
	}

	if recorder.ipaBudget < 4*time.Minute {
		t.Fatalf("IPA verification budget = %s, want upload-sized timeout", recorder.ipaBudget)
	}
	if recorder.documentBudget <= 0 || recorder.documentBudget > 30*time.Second {
		t.Fatalf("document verification budget = %s, want at most 30s", recorder.documentBudget)
	}
}

func TestPublishCommandValidatesOutputBeforeLocalOrRemoteSideEffects(t *testing.T) {
	originalLoad, originalStore := loadPreparedBundle, newObjectStore
	t.Cleanup(func() { loadPreparedBundle, newObjectStore = originalLoad, originalStore })
	loadCalled, storeCalled := false, false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		loadCalled = true
		return nil, nil
	}
	newObjectStore = func(context.Context, distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalled = true
		return noOpStore{}, time.Time{}, nil
	}
	stateDir := filepath.Join(t.TempDir(), "not-created")
	err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", t.TempDir(), "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
		"--receipt", filepath.Join(stateDir, "receipt.json"), "--link-path", filepath.Join(stateDir, "link.json"), "--output", "bogus",
	})
	if err == nil {
		t.Fatal("expected invalid output error")
	}
	if loadCalled || storeCalled {
		t.Fatalf("side effects before output validation: load=%t store=%t", loadCalled, storeCalled)
	}
	if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("state directory was created before output validation: %v", statErr)
	}
}

func TestPublishCommandRejectsUnsafeBucketBeforeSideEffects(t *testing.T) {
	originalLoad := loadPreparedBundle
	t.Cleanup(func() { loadPreparedBundle = originalLoad })
	loadCalled := false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		loadCalled = true
		return nil, errors.New("unexpected bundle load")
	}
	stateDir := t.TempDir()
	err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", t.TempDir(), "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket\x1b]0;pwned\x07", "--prefix", "app",
		"--receipt", filepath.Join(stateDir, "receipt.json"), "--link-path", filepath.Join(stateDir, "link.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "--bucket") {
		t.Fatalf("error = %v, want unsafe bucket usage error", err)
	}
	if loadCalled {
		t.Fatal("bundle was loaded before unsafe bucket rejection")
	}
}

func TestPublishCommandRejectsOverflowingLifetimeBeforeSideEffects(t *testing.T) {
	originalLoad, originalStore := loadPreparedBundle, newObjectStore
	t.Cleanup(func() { loadPreparedBundle, newObjectStore = originalLoad, originalStore })
	loadCalled, storeCalled := false, false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		loadCalled = true
		return nil, errors.New("unexpected bundle load")
	}
	newObjectStore = func(context.Context, distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalled = true
		return noOpStore{}, time.Time{}, nil
	}
	base := t.TempDir()
	bundleDir := filepath.Join(base, "missing-bundle")
	stateDir := filepath.Join(base, "missing-state")
	err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", bundleDir, "--endpoint", "https://objects.example.com", "--region", "auto",
		"--bucket", "bucket", "--prefix", "app", "--receipt", filepath.Join(stateDir, "receipt.json"),
		"--link-path", filepath.Join(stateDir, "link.json"), "--url-ttl", "2562047h", "--download-grace", "100h",
	})
	if err == nil || !strings.Contains(err.Error(), "--url-ttl must not exceed 7d") {
		t.Fatalf("ParseAndRun() error = %v, want overflow rejection", err)
	}
	if loadCalled || storeCalled {
		t.Fatalf("side effects before lifetime validation: load=%t store=%t", loadCalled, storeCalled)
	}
	for _, path := range []string{bundleDir, stateDir} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("validation created %s: %v", path, statErr)
		}
	}
}

func TestPublishCommandAcceptsExactlySevenDayPrivateLifetime(t *testing.T) {
	originalLoad, originalStore := loadPreparedBundle, newObjectStore
	t.Cleanup(func() { loadPreparedBundle, newObjectStore = originalLoad, originalStore })
	want := errors.New("accepted lifetime reached bundle load")
	loadCalled, storeCalled := false, false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		loadCalled = true
		return nil, want
	}
	newObjectStore = func(context.Context, distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalled = true
		return noOpStore{}, time.Time{}, nil
	}
	bundleDir := t.TempDir()
	stateDir := t.TempDir()
	err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", bundleDir, "--endpoint", "https://objects.example.com", "--region", "auto",
		"--bucket", "bucket", "--prefix", "app", "--receipt", filepath.Join(stateDir, "receipt.json"),
		"--link-path", filepath.Join(stateDir, "link.json"), "--url-ttl", "167h", "--download-grace", "1h",
	})
	if !errors.Is(err, want) {
		t.Fatalf("ParseAndRun() error = %v, want accepted-lifetime sentinel", err)
	}
	if !loadCalled || storeCalled {
		t.Fatalf("exact boundary flow: load=%t store=%t", loadCalled, storeCalled)
	}
}

func TestPublishCommandWritesSensitiveLink0600AndRedactedReceipt(t *testing.T) {
	originalLoad, originalStore, originalPublish, originalReverify := loadPreparedBundle, newObjectStore, runPublish, reverifyPublication
	t.Cleanup(func() {
		loadPreparedBundle, newObjectStore, runPublish = originalLoad, originalStore, originalPublish
		reverifyPublication = originalReverify
	})
	dir := t.TempDir()
	ipaPath := filepath.Join(dir, "app.ipa")
	if err := os.WriteFile(ipaPath, []byte("ipa"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		file, err := os.Open(ipaPath)
		return &distribution.PreparedBundle{IPA: file, IPASHA256: "sha", IPASize: 3, Descriptor: distribution.PreparedDescriptor{App: distribution.PreparedApp{BundleID: "com.example", Version: "1", BuildNumber: "2"}}}, err
	}
	storeCalls := 0
	newObjectStore = func(ctx context.Context, config distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalls++
		if _, ok := ctx.Deadline(); !ok {
			return nil, time.Time{}, errors.New("object-store setup context has no deadline")
		}
		if config.RequestTimeout <= 0 {
			return nil, time.Time{}, errors.New("object-store request timeout is not bounded")
		}
		return noOpStore{}, time.Time{}, nil
	}
	runPublish = func(ctx context.Context, _ io.ReadSeeker, _ distribution.PreparedDescriptor, options distribution.PublishOptions) (distribution.PublishReceipt, distribution.SensitiveLinks, error) {
		if _, ok := ctx.Deadline(); ok {
			return distribution.PublishReceipt{}, distribution.SensitiveLinks{}, errors.New("publication flow inherited an expiring phase context")
		}
		if _, err := options.Store.Ensure(ctx, distribution.PutObject{}); err != nil {
			return distribution.PublishReceipt{}, distribution.SensitiveLinks{}, err
		}
		if _, err := options.Store.PresignGet(ctx, "key", time.Minute); err != nil {
			return distribution.PublishReceipt{}, distribution.SensitiveLinks{}, err
		}
		return distribution.PublishReceipt{SchemaVersion: "1", Access: distribution.AccessPrivate, Bucket: "bucket", Prefix: "app", Artifact: distribution.StoredObject{SHA256: "sha", SizeBytes: 3}, App: distribution.PreparedApp{BundleID: "com.example", Version: "1", BuildNumber: "2"}, InstallURL: "https://example.com/?X-Amz-Signature=REDACTED", Verified: true},
			distribution.SensitiveLinks{SchemaVersion: "1", InstallURL: "https://example.com/?X-Amz-Signature=secret"}, nil
	}
	reverifyPublication = func(ctx context.Context, _ distribution.Verifier, _ distribution.PublishReceipt, _ distribution.SensitiveLinks, _ time.Time) error {
		if _, ok := ctx.Deadline(); ok {
			return errors.New("recovery flow inherited an expiring phase context")
		}
		return nil
	}
	stateDir := t.TempDir()
	receiptPath := filepath.Join(stateDir, "receipt.json")
	linkPath := filepath.Join(stateDir, "link.json")
	command := PublishCommand()
	err := command.ParseAndRun(context.Background(), []string{
		"--bundle-dir", dir, "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
		"--receipt", receiptPath, "--link-path", linkPath, "--output", "json",
	})
	if err != nil {
		t.Fatalf("ParseAndRun() error = %v", err)
	}
	link, err := os.ReadFile(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(link), "Signature=secret") {
		t.Fatalf("link = %s", link)
	}
	info, err := os.Stat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("link mode = %o, want 600", got)
	}
	receipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(receipt), "Signature=secret") || !strings.Contains(string(receipt), "REDACTED") {
		t.Fatalf("receipt leaked exact URL: %s", receipt)
	}
	if err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", dir, "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
		"--receipt", receiptPath, "--link-path", linkPath, "--output", "json",
	}); err != nil {
		t.Fatalf("idempotent recovery error = %v", err)
	}
	if storeCalls != 1 {
		t.Fatalf("object store calls = %d, want 1 after recovery", storeCalls)
	}
	for _, changed := range [][]string{
		{"--download-endpoint", "https://different.example.com"},
		{"--url-ttl", "23h"},
		{"--download-grace", "2h"},
	} {
		arguments := []string{
			"--bundle-dir", dir, "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
			"--receipt", receiptPath, "--link-path", linkPath, "--output", "json",
		}
		arguments = append(arguments, changed...)
		if err := PublishCommand().ParseAndRun(context.Background(), arguments); err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("changed recovery option %v error = %v, want conflict", changed, err)
		}
	}
	var tampered publishState
	if err := json.Unmarshal(link, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Receipt.Signing.TeamID = "tampered-team"
	tamperedData, err := encodeJSON(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linkPath, tamperedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", dir, "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
		"--receipt", receiptPath, "--link-path", linkPath, "--output", "json",
	}); err == nil || !strings.Contains(err.Error(), "prepared bundle") {
		t.Fatalf("tampered signing recovery error = %v", err)
	}
}

func TestPublishCommandPreflightsArtifactCollisionBeforeObjectStore(t *testing.T) {
	originalLoad, originalStore := loadPreparedBundle, newObjectStore
	t.Cleanup(func() { loadPreparedBundle, newObjectStore = originalLoad, originalStore })
	dir := t.TempDir()
	stateDir := t.TempDir()
	receiptPath := filepath.Join(stateDir, "receipt.json")
	if err := os.WriteFile(receiptPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadCalled, storeCalled := false, false
	loadPreparedBundle = func(context.Context, rootfs.Root) (*distribution.PreparedBundle, error) {
		loadCalled = true
		return nil, nil
	}
	newObjectStore = func(context.Context, distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalled = true
		return noOpStore{}, time.Time{}, nil
	}
	err := PublishCommand().ParseAndRun(context.Background(), []string{
		"--bundle-dir", dir, "--endpoint", "https://objects.example.com", "--region", "auto", "--bucket", "bucket", "--prefix", "app",
		"--receipt", receiptPath, "--link-path", filepath.Join(stateDir, "link.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "without its sensitive link") {
		t.Fatalf("error = %v, want collision", err)
	}
	if loadCalled || storeCalled {
		t.Fatalf("side effects before artifact preflight: load=%t store=%t", loadCalled, storeCalled)
	}
}

func TestPublishArtifactsMustRemainOutsidePreparedBundle(t *testing.T) {
	bundle := t.TempDir()
	bundleRoot, err := rootfs.New(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer bundleRoot.Close()
	err = rejectBundleContainedArtifacts(bundleRoot, filepath.Join(bundle, "receipt.json"), filepath.Join(t.TempDir(), "link.json"))
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error = %v", err)
	}
}

func TestPublishArtifactsCannotEnterPreparedBundleThroughSymlinkAlias(t *testing.T) {
	realBundle := t.TempDir()
	alias := filepath.Join(t.TempDir(), "bundle-alias")
	if err := os.Symlink(realBundle, alias); err != nil {
		t.Fatal(err)
	}
	bundleRoot, err := rootfs.New(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer bundleRoot.Close()
	err = rejectBundleContainedArtifacts(bundleRoot, filepath.Join(realBundle, "state", "receipt.json"), filepath.Join(realBundle, "state", "link.json"))
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("error = %v, want physical containment rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(realBundle, "state")); !os.IsNotExist(statErr) {
		t.Fatalf("containment check created state directory: %v", statErr)
	}
}

func TestStagedFileRemainsAnchoredWhenParentPathIsSwapped(t *testing.T) {
	base := t.TempDir()
	original := filepath.Join(base, "original")
	moved := filepath.Join(base, "moved")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{original, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	parent, err := os.OpenRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	staged, err := stageFile(parent, "result.json")
	if err != nil {
		t.Fatal(err)
	}
	defer staged.cleanup()
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, original); err != nil {
		t.Fatal(err)
	}
	if err := staged.publish([]byte("anchored")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "result.json")); !os.IsNotExist(err) {
		t.Fatalf("outside result exists or stat error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(moved, "result.json"))
	if err != nil || string(data) != "anchored" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}

func TestArtifactPairUsesRootHandleRetainedFromPreflight(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	moved := filepath.Join(base, "moved")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{stateDir, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := preflightArtifactPaths(filepath.Join(stateDir, "receipt.json"), filepath.Join(stateDir, "link.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer paths.close()
	if err := os.Rename(stateDir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stateDir); err != nil {
		t.Fatal(err)
	}
	staged, err := paths.stagePair()
	if err != nil {
		t.Fatal(err)
	}
	defer staged.cleanup()
	receipt := distribution.PublishReceipt{SchemaVersion: "1"}
	if err := staged.publish(publishState{SchemaVersion: "1", Receipt: receipt}, receipt); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"receipt.json", "link.json"} {
		if _, err := os.Stat(filepath.Join(outside, name)); !os.IsNotExist(err) {
			t.Fatalf("outside %s exists or stat error = %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(moved, name)); err != nil {
			t.Fatalf("anchored %s: %v", name, err)
		}
	}
}

func TestArtifactPairRejectsDistinctParentSymlinkSwap(t *testing.T) {
	base := t.TempDir()
	receiptDir := filepath.Join(base, "receipts")
	linkDir := filepath.Join(base, "links")
	unintendedDir := filepath.Join(base, "unintended")
	for _, dir := range []string{receiptDir, linkDir, unintendedDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := preflightArtifactPaths(filepath.Join(receiptDir, "receipt.json"), filepath.Join(linkDir, "link.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer paths.close()
	if err := os.Remove(receiptDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unintendedDir, receiptDir); err != nil {
		t.Fatal(err)
	}

	if _, err := paths.stagePair(); err == nil {
		t.Fatal("stagePair() accepted a swapped parent symlink")
	}
	if _, err := os.Stat(filepath.Join(unintendedDir, "receipt.json")); !os.IsNotExist(err) {
		t.Fatalf("unintended receipt exists or stat error = %v", err)
	}
}

func TestPreflightRejectsArtifactPathsThatContainEachOther(t *testing.T) {
	base := t.TempDir()
	for _, test := range []struct {
		name    string
		receipt string
		link    string
	}{
		{name: "receipt contains link", receipt: filepath.Join(base, "result"), link: filepath.Join(base, "result", "link.json")},
		{name: "link contains receipt", receipt: filepath.Join(base, "result", "receipt.json"), link: filepath.Join(base, "result")},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths, err := preflightArtifactPaths(test.receipt, test.link)
			paths.close()
			if err == nil || !strings.Contains(err.Error(), "contain") {
				t.Fatalf("preflightArtifactPaths() error = %v, want containment rejection", err)
			}
		})
	}
}

func TestPreflightSecurelyCreatesMissingCommonParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "nested", "publishes")
	paths, err := preflightArtifactPaths(filepath.Join(parent, "receipt.json"), filepath.Join(parent, "link.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer paths.close()
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("parent mode = %o, want 700", info.Mode().Perm())
	}
	staged, err := paths.stagePair()
	if err != nil {
		t.Fatal(err)
	}
	defer staged.cleanup()
	if err := staged.publish(publishState{SchemaVersion: "1"}, distribution.PublishReceipt{SchemaVersion: "1"}); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightRejectsWorldReadableSensitiveLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(link, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := preflightArtifactPaths(filepath.Join(dir, "receipt.json"), link); err == nil || !strings.Contains(err.Error(), "owner-private") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadBoundedPublishStateEnforcesExactLimit(t *testing.T) {
	exact := bytes.Repeat([]byte("x"), maxPublishStateBytes)
	data, err := readBoundedPublishState(bytes.NewReader(exact))
	if err != nil {
		t.Fatalf("readBoundedPublishState() exact-limit error = %v", err)
	}
	if !bytes.Equal(data, exact) {
		t.Fatalf("readBoundedPublishState() returned %d bytes, want %d", len(data), len(exact))
	}

	secret := "X-Amz-Security-Token=do-not-echo"
	oversized := append(append([]byte(nil), exact...), secret...)
	if _, err := readBoundedPublishState(bytes.NewReader(oversized)); err == nil || !strings.Contains(err.Error(), "exceeds 2 MiB") {
		t.Fatalf("readBoundedPublishState() error = %v, want size rejection", err)
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("size error leaked sensitive content: %q", err)
	}
}

func TestReadBoundedPublishStatePreservesReadError(t *testing.T) {
	want := errors.New("read failed")
	if _, err := readBoundedPublishState(errorReader{err: want}); !errors.Is(err, want) {
		t.Fatalf("readBoundedPublishState() error = %v, want %v", err, want)
	}
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

type noOpStore struct{}

func (noOpStore) Ensure(context.Context, distribution.PutObject) (distribution.StoredObject, error) {
	return distribution.StoredObject{}, nil
}

func (noOpStore) PresignGet(context.Context, string, time.Duration) (string, error) {
	return "", nil
}

type deadlineRecordingVerifier struct {
	ipaBudget      time.Duration
	documentBudget time.Duration
}

func (verifier *deadlineRecordingVerifier) Verify(ctx context.Context, request distribution.VerifyRequest) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("verification context has no deadline")
	}
	budget := time.Until(deadline)
	switch request.Kind {
	case distribution.VerifyIPA:
		verifier.ipaBudget = budget
	default:
		verifier.documentBudget = budget
	}
	return nil
}
