//go:build darwin

package signing

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestParseKeychainSearchList(t *testing.T) {
	got, err := parseKeychainSearchList([]byte("    \"/Users/me/Library/Keychains/login.keychain-db\"\n    \"/private/tmp/path with spaces.keychain-db\"\n"))
	if err != nil {
		t.Fatalf("parseKeychainSearchList() error: %v", err)
	}
	want := []string{"/Users/me/Library/Keychains/login.keychain-db", "/private/tmp/path with spaces.keychain-db"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
}

func TestRunSigningRunChildPreservesExitCode(t *testing.T) {
	err := runSigningRunChild(context.Background(), []string{"/bin/sh", "-c", "exit 42"})
	if code, ok := shared.ProcessExitCode(err); !ok || code != 42 {
		t.Fatalf("error = %v, want exit code 42", err)
	}
}

func TestRunSigningRunChildInterruptsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := runSigningRunChild(ctx, []string{"/bin/sh", "-c", "sleep 30"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled before launch", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("pre-canceled child did not return promptly")
	}
}

func TestParseSigningRunCertificateFingerprints(t *testing.T) {
	const fingerprint = "F05FBB6DC3E25BCCE5BB96697F633D1FC9CBBFD0"
	got := parseSigningRunCertificateFingerprints([]byte("SHA-256 hash: 0123456789\nSHA-1 hash: " + fingerprint + "\n"))
	if !reflect.DeepEqual(got, []string{fingerprint}) {
		t.Fatalf("fingerprints = %#v", got)
	}
}

func TestValidateSigningRunJournal(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "asc-signing-run.fixture")
	valid := signingRunJournal{
		SchemaVersion: 1,
		TempDir:       tempDir,
		KeychainPath:  filepath.Join(tempDir, "signing.keychain-db"),
	}
	if err := validateSigningRunJournal(valid); err != nil {
		t.Fatalf("valid journal rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*signingRunJournal)
	}{
		{name: "schema", mutate: func(journal *signingRunJournal) { journal.SchemaVersion = 2 }},
		{name: "broad temp", mutate: func(journal *signingRunJournal) { journal.TempDir = os.TempDir() }},
		{name: "outside temp", mutate: func(journal *signingRunJournal) { journal.TempDir = "/Users/me/asc-signing-run.bad" }},
		{name: "keychain mismatch", mutate: func(journal *signingRunJournal) { journal.KeychainPath = "/tmp/other" }},
		{name: "unplanned profile", mutate: func(journal *signingRunJournal) { journal.ProfilePath = "/tmp/profile" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := valid
			test.mutate(&journal)
			if err := validateSigningRunJournal(journal); err == nil {
				t.Fatalf("expected invalid journal: %+v", journal)
			}
		})
	}
}

func TestRemoveSigningRunTempDirRejectsBroadOrForeignPaths(t *testing.T) {
	for _, path := range []string{os.TempDir(), filepath.Join(os.TempDir(), "other"), "/", "/Users/me/asc-signing-run.fake"} {
		if err := removeSigningRunTempDir(path); err == nil {
			t.Fatalf("removeSigningRunTempDir(%q) unexpectedly succeeded", path)
		}
	}
}

func TestRecoverSigningRunJournalRemovesCodesignProbeCrashResidue(t *testing.T) {
	stateDir := t.TempDir()
	tempDir, err := os.MkdirTemp("", "asc-signing-run.")
	if err != nil {
		t.Fatalf("create signing temp dir: %v", err)
	}
	if err := os.Chmod(tempDir, 0o700); err != nil {
		t.Fatalf("chmod signing temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	if err := os.WriteFile(filepath.Join(tempDir, "codesign-probe"), []byte("probe"), 0o700); err != nil {
		t.Fatalf("write crash residue: %v", err)
	}

	previousStateDir := signingRunStateDirFn
	previousRemoveSearch := signingRunRecoveryRemoveSearchEntryFn
	previousDeleteKeychain := signingRunRecoveryDeleteKeychainFn
	signingRunStateDirFn = func() (string, error) { return stateDir, nil }
	signingRunRecoveryRemoveSearchEntryFn = func(context.Context, string) error { return nil }
	signingRunRecoveryDeleteKeychainFn = func(context.Context, string) error { return nil }
	t.Cleanup(func() {
		signingRunStateDirFn = previousStateDir
		signingRunRecoveryRemoveSearchEntryFn = previousRemoveSearch
		signingRunRecoveryDeleteKeychainFn = previousDeleteKeychain
	})

	journal := signingRunJournal{
		SchemaVersion: 1,
		TempDir:       tempDir,
		KeychainPath:  filepath.Join(tempDir, "signing.keychain-db"),
	}
	if err := writeSigningRunJournal(journal, false); err != nil {
		t.Fatalf("write recovery journal: %v", err)
	}
	if err := recoverSigningRunJournal(context.Background()); err != nil {
		t.Fatalf("recover signing run: %v", err)
	}
	if _, err := os.Stat(tempDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp dir stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "journal.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal stat error = %v, want not exist", err)
	}
}

func TestLimitedSigningBufferBoundsOutput(t *testing.T) {
	buffer := &limitedSigningBuffer{limit: 4}
	if written, err := buffer.Write([]byte("123456789")); err != nil || written != 9 {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if got := string(buffer.Bytes()); got != "1234" {
		t.Fatalf("buffer = %q", got)
	}
}

func TestWithSigningRunPartitionPasswordInputClearsDerivedBuffer(t *testing.T) {
	var captured []byte
	wantErr := errors.New("stop")
	err := withSigningRunPartitionPasswordInput([]byte{0x01, 0xab, 0xff}, func(stdin []byte) error {
		captured = stdin
		if string(stdin) != "01abff\n" {
			t.Fatalf("partition-list input = %q", stdin)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want injected error", err)
	}
	if !bytes.Equal(captured, make([]byte, len(captured))) {
		t.Fatalf("derived password input was not cleared: %v", captured)
	}
}

func TestReadBoundedSigningRunFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.p12")
	if err := os.WriteFile(path, []byte("identity"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if _, err := readBoundedSigningRunFile(path, 32, true); err != nil {
		t.Fatalf("private input rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := readBoundedSigningRunFile(path, 32, true); err == nil {
		t.Fatal("expected group/world-readable private input rejection")
	}
	if _, err := readBoundedSigningRunFile(path, 32, false); err != nil {
		t.Fatalf("read-only profile input rejected: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod writable: %v", err)
	}
	if _, err := readBoundedSigningRunFile(path, 32, false); err == nil {
		t.Fatal("expected group/world-writable profile input rejection")
	}
}

func TestInstallSigningRunProfileReusesAndProtectsExistingFiles(t *testing.T) {
	installDir := t.TempDir()
	previous := signingRunProfileInstallDirFn
	signingRunProfileInstallDirFn = func(context.Context) (string, error) { return installDir, nil }
	t.Cleanup(func() { signingRunProfileInstallDirFn = previous })
	const uuid = "A7EFEF21-3432-404F-A488-083800B570FF"
	data := []byte("signed-profile")
	digestBytes := sha256.Sum256(data)
	digest := strings.ToUpper(hex.EncodeToString(digestBytes[:]))
	journaled := signingRunProfileInstall{}
	installed, err := installSigningRunProfile(uuid, data, digest, func(planned signingRunProfileInstall) error {
		journaled = planned
		return nil
	})
	if err != nil {
		t.Fatalf("installSigningRunProfile: %v", err)
	}
	if !installed.Created || journaled.StagedPath == "" || journaled.Device == 0 || journaled.Inode == 0 {
		t.Fatalf("missing staged ownership proof: installed=%+v journaled=%+v", installed, journaled)
	}
	reused, err := installSigningRunProfile(uuid, data, digest, func(signingRunProfileInstall) error {
		t.Fatal("reused profile must not create a new journal entry")
		return nil
	})
	if err != nil || reused.Created {
		t.Fatalf("reuse = %+v, %v", reused, err)
	}
	if _, err := installSigningRunProfile(uuid, []byte("different"), strings.Repeat("A", 64), func(signingRunProfileInstall) error { return nil }); err == nil {
		t.Fatal("expected different existing profile conflict")
	}
	if err := removeSigningRunProfile(installed); err != nil {
		t.Fatalf("removeSigningRunProfile: %v", err)
	}
}

func TestInstallSigningRunProfileRejectsOversizedExistingFile(t *testing.T) {
	installDir := t.TempDir()
	previous := signingRunProfileInstallDirFn
	signingRunProfileInstallDirFn = func(context.Context) (string, error) { return installDir, nil }
	t.Cleanup(func() { signingRunProfileInstallDirFn = previous })
	const uuid = "A7EFEF21-3432-404F-A488-083800B570FF"
	path := filepath.Join(installDir, strings.ToLower(uuid)+".mobileprovision")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create oversized profile: %v", err)
	}
	if err := file.Truncate(signingRunInputLimit + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate oversized profile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close oversized profile: %v", err)
	}
	_, err = installSigningRunProfile(uuid, []byte("profile"), strings.Repeat("A", sha256.Size*2), func(signingRunProfileInstall) error {
		t.Fatal("oversized existing profile must not create a journal entry")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds the size limit") {
		t.Fatalf("error = %v, want size-limit rejection", err)
	}
}

func TestRemoveSigningRunProfileRefusesReplacement(t *testing.T) {
	installDir := t.TempDir()
	previous := signingRunProfileInstallDirFn
	signingRunProfileInstallDirFn = func(context.Context) (string, error) { return installDir, nil }
	t.Cleanup(func() { signingRunProfileInstallDirFn = previous })
	const uuid = "A7EFEF21-3432-404F-A488-083800B570FF"
	data := []byte("signed-profile")
	digestBytes := sha256.Sum256(data)
	digest := strings.ToUpper(hex.EncodeToString(digestBytes[:]))
	installed, err := installSigningRunProfile(uuid, data, digest, func(signingRunProfileInstall) error { return nil })
	if err != nil {
		t.Fatalf("installSigningRunProfile: %v", err)
	}
	if err := os.Remove(installed.Path); err != nil {
		t.Fatalf("remove original: %v", err)
	}
	if err := os.WriteFile(installed.Path, data, 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := removeSigningRunProfile(installed); err == nil || !strings.Contains(err.Error(), "file identity changed") {
		t.Fatalf("error = %v, want file identity refusal", err)
	}
}

func TestSigningRunDisposableKeychainSmoke(t *testing.T) {
	if os.Getenv("ASC_SIGNING_RUN_LIVE_TEST") != "1" {
		t.Skip("set ASC_SIGNING_RUN_LIVE_TEST=1 to exercise a disposable macOS keychain")
	}
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	tempDir, err := createSigningRunTempDir()
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	keychainPath := filepath.Join(tempDir, "signing.keychain-db")
	password, err := signingRunRandomBytes(32)
	if err != nil {
		t.Fatalf("random password: %v", err)
	}
	original, err := keychainSearchList(context.Background())
	if err != nil {
		t.Fatalf("read original search list: %v", err)
	}
	t.Cleanup(func() {
		_ = removeKeychainSearchEntry(context.Background(), keychainPath)
		_ = deleteSigningRunKeychain(context.Background(), keychainPath)
		_ = removeSigningRunTempDir(tempDir)
	})
	if err := createSigningRunKeychain(context.Background(), keychainPath, password); err != nil {
		t.Fatalf("create keychain: %v", err)
	}
	if err := removeKeychainSearchEntry(context.Background(), keychainPath); err != nil {
		t.Fatalf("isolate keychain: %v", err)
	}
	digest := sha1.Sum(inspection.Certificate.Raw)
	if err := importSigningRunIdentity(
		context.Background(), keychainPath, password, fixture.identity, []byte(fixture.password), strings.ToUpper(hex.EncodeToString(digest[:])),
	); err != nil {
		t.Fatalf("import identity: %v", err)
	}
	if err := deleteSigningRunKeychain(context.Background(), keychainPath); err != nil {
		t.Fatalf("delete keychain: %v", err)
	}
	if err := removeSigningRunTempDir(tempDir); err != nil {
		t.Fatalf("remove temp dir: %v", err)
	}
	after, err := keychainSearchList(context.Background())
	if err != nil {
		t.Fatalf("read final search list: %v", err)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatalf("keychain search list changed: before=%v after=%v", original, after)
	}
}
