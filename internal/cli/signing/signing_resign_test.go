package signing

import (
	"archive/zip"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestSigningCommandExposesResign(t *testing.T) {
	command := SigningCommand()
	for _, subcommand := range command.Subcommands {
		if subcommand.Name == "resign" {
			return
		}
	}
	t.Fatal("signing command does not expose resign")
}

func TestDecodeSigningResignManifestStrict(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "valid",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"profiles/app.mobileprovision"}]}`,
		},
		{
			name: "unknown field",
			data: `{"schemaVersion":1,"profiles":[],"extra":true}`,
			want: "decode profiles manifest",
		},
		{
			name: "duplicate field",
			data: `{"schemaVersion":1,"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"app.mobileprovision"}]}`,
			want: "duplicate",
		},
		{
			name: "wildcard bundle",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.*","profilePath":"app.mobileprovision"}]}`,
			want: "non-wildcard",
		},
		{
			name: "traversal profile",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"../app.mobileprovision"}]}`,
			want: "escapes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, err := decodeSigningResignManifest([]byte(test.data))
			if test.want == "" {
				if err != nil {
					t.Fatalf("decodeSigningResignManifest() error = %v", err)
				}
				if len(manifest.Profiles) != 1 || manifest.Profiles[0].BundleID != "com.example.app" {
					t.Fatalf("decoded manifest = %#v", manifest)
				}
				return
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("decodeSigningResignManifest() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestBuildSigningResignEntitlementsReplacesIdentity(t *testing.T) {
	existing := map[string]any{
		"application-identifier":                "OLDTEAM.com.example.app",
		"com.apple.application-identifier":      "OLDTEAM.com.example.app",
		"com.apple.developer.team-identifier":   "OLDTEAM",
		"get-task-allow":                        true,
		"com.apple.security.application-groups": []string{"group.com.example"},
	}
	profile := map[string]any{
		"application-identifier":                "NEWTEAM.com.example.app",
		"com.apple.application-identifier":      "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier":   "NEWTEAM",
		"get-task-allow":                        false,
		"com.apple.security.application-groups": []any{"group.com.example", "group.other"},
	}
	got, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		t.Fatalf("buildSigningResignEntitlements() error = %v", err)
	}
	if got["application-identifier"] != "NEWTEAM.com.example.app" || got["com.apple.developer.team-identifier"] != "NEWTEAM" {
		t.Fatalf("identity entitlements = %#v", got)
	}
	if got["get-task-allow"] != false || len(got) != len(existing) {
		t.Fatalf("rewritten entitlements = %#v", got)
	}
	if !signingResignEntitlementValuePermits(profile["com.apple.security.application-groups"], got["com.apple.security.application-groups"]) {
		t.Fatalf("capability entitlement was not preserved: %#v", got)
	}
}

func TestBuildSigningResignEntitlementsRejectsUnpermittedCapability(t *testing.T) {
	_, err := buildSigningResignEntitlements(
		map[string]any{"com.apple.security.application-groups": []string{"group.not-permitted"}},
		map[string]any{
			"application-identifier":                "TEAM.com.example.app",
			"com.apple.developer.team-identifier":   "TEAM",
			"get-task-allow":                        false,
			"com.apple.security.application-groups": []any{"group.allowed"},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("buildSigningResignEntitlements() error = %v, want unpermitted capability", err)
	}
}

func TestValidateSigningResignArchiveRejectsPathCollisions(t *testing.T) {
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/a/file", data: []byte("x")},
		{name: "Payload/App.app/a", data: []byte("not-a-directory")},
	})
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSigningResignArchive(context.Background(), reader); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("validateSigningResignArchive() error = %v, want collision", err)
	}
}

func TestSnapshotSigningResignIPAComputesDigestAndDoesNotRewriteSource(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.ipa")
	contents := []byte("deterministic ipa bytes")
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stagePath := filepath.Join(directory, "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	snapshot, digest, err := snapshotSigningResignIPA(context.Background(), source, int64(len(contents)), stage)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if digest != signingResignSHA256(contents) {
		t.Fatalf("snapshot digest = %q, want %q", digest, signingResignSHA256(contents))
	}
	snapshotData, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshotData, contents) {
		t.Fatalf("snapshot data = %q, want %q", snapshotData, contents)
	}
	sourceData, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceData, contents) {
		t.Fatalf("source changed to %q", sourceData)
	}
}

func TestSigningResignToolInvocationsUseExplicitKeychainAndNoDeepMutation(t *testing.T) {
	original := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = original })
	var calls [][]string
	runSigningResignToolFn = func(_ context.Context, executable string, args ...string) (signingResignToolOutput, error) {
		calls = append(calls, append([]string{executable}, args...))
		return signingResignToolOutput{}, nil
	}
	if err := signSigningResignObject(context.Background(), "/tmp/object", "ABC123", "/tmp/keychain", "/tmp/entitlements.plist"); err != nil {
		t.Fatal(err)
	}
	if err := verifySigningResignObject(context.Background(), "/tmp/object", "TEAM", false); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("tool calls = %#v", calls)
	}
	if strings.Contains(strings.Join(calls[0], " "), "--deep") || !strings.Contains(strings.Join(calls[0], " "), "--keychain /tmp/keychain") {
		t.Fatalf("sign invocation = %#v", calls[0])
	}
	if strings.Contains(strings.Join(calls[1], " "), "--deep") {
		t.Fatalf("leaf verify invocation unexpectedly deep = %#v", calls[1])
	}
}

func TestSortSigningResignCodePlansIsLeafFirst(t *testing.T) {
	plans := []signingResignCodePlan{
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Outer.framework", "Outer")},
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Outer.framework", "Versions", "A", "Inner")},
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Other.framework", "Other")},
	}
	sortSigningResignCodePlans(plans)
	innerIndex, outerIndex := -1, -1
	for index, plan := range plans {
		if strings.HasSuffix(plan.Path, filepath.Join("Versions", "A", "Inner")) {
			innerIndex = index
		}
		if strings.HasSuffix(plan.Path, filepath.Join("Outer.framework", "Outer")) {
			outerIndex = index
		}
	}
	if innerIndex < 0 || outerIndex < 0 || innerIndex >= outerIndex {
		t.Fatalf("outer framework executable was scheduled before its nested code: %#v", plans)
	}
}

type signingResignZipEntry struct {
	name      string
	data      []byte
	directory bool
}

func buildSigningResignZip(t *testing.T, entries []signingResignZipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, item := range entries {
		if item.directory {
			header := &zip.FileHeader{Name: item.name, Method: zip.Store}
			header.SetMode(os.ModeDir | 0o755)
			if _, err := writer.CreateHeader(header); err != nil {
				t.Fatal(err)
			}
			continue
		}
		file, err := writer.Create(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestRepackSigningResignTreeIsDeterministicAndBounded(t *testing.T) {
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(treePath, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(treePath, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	packedPath, size, digest, err := repackSigningResignTree(context.Background(), stageRoot, treeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 || digest != signingResignSHA256(mustReadFile(t, packedPath)) {
		t.Fatalf("packed artifact size=%d digest=%q", size, digest)
	}
	if _, err := os.Stat(packedPath); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSigningResignContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(contextError(ctx), context.Canceled) {
		t.Fatalf("contextError() = %v, want cancellation", contextError(ctx))
	}
}

func TestRunSigningResignEnvironmentNeverInstallsProfiles(t *testing.T) {
	original := signingResignPlatformDepsFn
	t.Cleanup(func() { signingResignPlatformDepsFn = original })
	temporary := t.TempDir()
	var events []string
	signingResignPlatformDepsFn = func() signingRunDeps {
		return signingRunDeps{
			GOOS:        "darwin",
			RandomBytes: func(size int) ([]byte, error) { return bytes.Repeat([]byte{0x42}, size), nil },
			TempDir: func() (string, error) {
				return filepath.Join(temporary, "session"), os.Mkdir(filepath.Join(temporary, "session"), 0o700)
			},
			RemoveTempDir: func(path string) error { events = append(events, "remove-temp"); return os.RemoveAll(path) },
			AcquireLock: func(context.Context) (func() error, error) {
				events = append(events, "lock")
				return func() error { events = append(events, "unlock"); return nil }, nil
			},
			Recover:       func(context.Context) error { events = append(events, "recover"); return nil },
			WriteJournal:  func(signingRunJournal, bool) error { events = append(events, "journal-write"); return nil },
			RemoveJournal: func() error { events = append(events, "journal-remove"); return nil },
			KeychainSearchList: func(context.Context) ([]string, error) {
				events = append(events, "list")
				return []string{"login.keychain-db"}, nil
			},
			CreateKeychain: func(context.Context, string, []byte) error { events = append(events, "create-keychain"); return nil },
			ImportIdentity: func(context.Context, string, []byte, []byte, []byte, string) error {
				events = append(events, "import")
				return nil
			},
			SetKeychainSearchList:     func(context.Context, []string) error { events = append(events, "activate"); return nil },
			RemoveKeychainSearchEntry: func(context.Context, string) error { events = append(events, "remove-search"); return nil },
			DeleteKeychain:            func(context.Context, string) error { events = append(events, "delete-keychain"); return nil },
		}
	}
	identity := testSigningResignIdentity(t)
	if err := runSigningResignEnvironment(context.Background(), identity, func(_ context.Context, keychainPath string) error {
		if keychainPath == "" {
			t.Fatal("callback received an empty keychain path")
		}
		events = append(events, "operation")
		return nil
	}); err != nil {
		t.Fatalf("runSigningResignEnvironment() error = %v", err)
	}
	joined := strings.Join(events, ",")
	if strings.Contains(joined, "install") || strings.Contains(joined, "profile") {
		t.Fatalf("environment unexpectedly touched a profile: %s", joined)
	}
	if !strings.Contains(joined, "create-keychain,remove-search,import") || !strings.Contains(joined, "activate,operation,remove-search,delete-keychain") {
		t.Fatalf("environment events = %s", joined)
	}
}

func testSigningResignIdentity(t *testing.T) *signingRunIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(cryptorand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test", OrganizationalUnit: []string{"TEAM"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &signingRunIdentity{Certificate: certificate, PrivateKey: key, CertificateSHA1: strings.Repeat("A", 40), CertificateSHA256: strings.Repeat("B", 64)}
}
