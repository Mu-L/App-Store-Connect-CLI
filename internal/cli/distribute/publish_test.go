package distribute

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/distribution"
)

func TestPublishCommandRequiresFlagsBeforeSideEffects(t *testing.T) {
	originalLoad := loadPreparedBundle
	t.Cleanup(func() { loadPreparedBundle = originalLoad })
	called := false
	loadPreparedBundle = func(string) (*distribution.PreparedBundle, error) {
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

func TestPublishCommandValidatesOutputBeforeLocalOrRemoteSideEffects(t *testing.T) {
	originalLoad, originalStore := loadPreparedBundle, newObjectStore
	t.Cleanup(func() { loadPreparedBundle, newObjectStore = originalLoad, originalStore })
	loadCalled, storeCalled := false, false
	loadPreparedBundle = func(string) (*distribution.PreparedBundle, error) {
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
	loadPreparedBundle = func(string) (*distribution.PreparedBundle, error) {
		file, err := os.Open(ipaPath)
		return &distribution.PreparedBundle{IPA: file, IPASHA256: "sha", IPASize: 3, Descriptor: distribution.PreparedDescriptor{App: distribution.PreparedApp{BundleID: "com.example", Version: "1", BuildNumber: "2"}}}, err
	}
	storeCalls := 0
	newObjectStore = func(context.Context, distribution.S3StoreConfig) (distribution.ObjectStore, time.Time, error) {
		storeCalls++
		return noOpStore{}, time.Time{}, nil
	}
	runPublish = func(context.Context, io.ReadSeeker, distribution.PreparedDescriptor, distribution.PublishOptions) (distribution.PublishReceipt, distribution.SensitiveLinks, error) {
		return distribution.PublishReceipt{SchemaVersion: "1", Access: distribution.AccessPrivate, Bucket: "bucket", Prefix: "app", Artifact: distribution.StoredObject{SHA256: "sha", SizeBytes: 3}, App: distribution.PreparedApp{BundleID: "com.example", Version: "1", BuildNumber: "2"}, InstallURL: "https://example.com/?X-Amz-Signature=REDACTED", Verified: true},
			distribution.SensitiveLinks{SchemaVersion: "1", InstallURL: "https://example.com/?X-Amz-Signature=secret"}, nil
	}
	reverifyPublication = func(context.Context, distribution.Verifier, distribution.PublishReceipt, distribution.SensitiveLinks, time.Time) error {
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
	loadPreparedBundle = func(string) (*distribution.PreparedBundle, error) {
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
	err := rejectBundleContainedArtifacts(bundle, filepath.Join(bundle, "receipt.json"), filepath.Join(t.TempDir(), "link.json"))
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
	err := rejectBundleContainedArtifacts(alias, filepath.Join(realBundle, "state", "receipt.json"), filepath.Join(realBundle, "state", "link.json"))
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

type noOpStore struct{}

func (noOpStore) Ensure(context.Context, distribution.PutObject) (distribution.StoredObject, error) {
	return distribution.StoredObject{}, nil
}

func (noOpStore) PresignGet(context.Context, string, time.Duration) (string, error) {
	return "", nil
}
