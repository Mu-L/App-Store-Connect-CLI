package signing

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	signingpkg "github.com/rudrankriyam/App-Store-Connect-CLI/internal/signing"
)

func TestSigningSyncPullSelectorFlagsFailBeforeSecretsOrRepository(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "bundle requires profile type",
			args: []string{"--repo", "git@example.com:team/signing.git", "--bundle-id", "com.example.app"},
			want: "--profile-type is required with --bundle-id or --targets-file",
		},
		{
			name: "targets require profile type",
			args: []string{"--repo", "git@example.com:team/signing.git", "--targets-file", "targets.json"},
			want: "--profile-type is required with --bundle-id or --targets-file",
		},
		{
			name: "profile type requires selector",
			args: []string{"--repo", "git@example.com:team/signing.git", "--profile-type", "IOS_APP_STORE"},
			want: "--profile-type requires --bundle-id or --targets-file",
		},
		{
			name: "selectors conflict",
			args: []string{"--repo", "git@example.com:team/signing.git", "--bundle-id", "com.example.app", "--targets-file", "targets.json", "--profile-type", "IOS_APP_STORE"},
			want: "--bundle-id and --targets-file are mutually exclusive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(signingSyncPasswordEnvVar, "must-not-be-used")
			cmd := syncPullCommand()
			cmd.FlagSet.SetOutput(io.Discard)
			if err := cmd.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			err := cmd.Run(context.Background())
			if err == nil || err.Error() != test.want || !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("error = %v, want usage error %q", err, test.want)
			}
		})
	}
}

func TestSigningSyncPullReadsTargetsManifestBeforePassword(t *testing.T) {
	t.Setenv(signingSyncPasswordEnvVar, "must-not-be-used")
	cmd := syncPullCommand()
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.Parse([]string{
		"--repo", "git@example.com:team/signing.git",
		"--targets-file", "missing-targets.json",
		"--profile-type", "IOS_APP_STORE",
	}); err != nil {
		t.Fatal(err)
	}
	err := cmd.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "targets manifest") || !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want manifest usage error", err)
	}
}

func TestSelectSigningPullFilesChoosesCertificateOnlyTarget(t *testing.T) {
	key := mustECKey(t)
	certificate := mustSigningCertificate(t, key, 801)
	selectedProfile := mustSignedProfile(t, certificate, key, "TEAM123", "TEAM123.com.example.selected", time.Now().Add(time.Hour))
	otherProfile := mustSignedProfile(t, certificate, key, "TEAM123", "TEAM123.com.example.other", time.Now().Add(time.Hour))

	selectedPath := "profiles/adhoc/selected.mobileprovision"
	secondSelectedPath := "profiles/adhoc/selected-second.mobileprovision"
	otherPath := "profiles/adhoc/other.mobileprovision"
	certificatePath := "certs/distribution/shared.cer"
	files := []decryptedSigningFile{
		{RelativePath: certificatePath, Plaintext: certificate.Raw},
		{RelativePath: otherPath, Plaintext: otherProfile},
		{RelativePath: selectedPath, Plaintext: selectedProfile},
		{RelativePath: secondSelectedPath, Plaintext: selectedProfile},
	}

	selected, targets, err := selectSigningPullFiles(files, []string{"com.example.selected"}, "IOS_APP_ADHOC")
	if err != nil {
		t.Fatal(err)
	}
	if got := signingPullRelativePaths(selected); !slices.Equal(got, []string{certificatePath, secondSelectedPath, selectedPath}) {
		t.Fatalf("selected paths = %v", got)
	}
	if len(targets) != 1 || targets[0].BundleID != "com.example.selected" || targets[0].ProfilePath != secondSelectedPath {
		t.Fatalf("targets = %#v", targets)
	}
	if !slices.Equal(targets[0].ProfilePaths, []string{secondSelectedPath, selectedPath}) {
		t.Fatalf("target profile paths = %v", targets[0].ProfilePaths)
	}
	if !slices.Equal(targets[0].Files, []string{certificatePath, secondSelectedPath, selectedPath}) {
		t.Fatalf("target files = %v", targets[0].Files)
	}
}

func TestSelectSigningPullFilesRejectsCorruptUnselectedProfile(t *testing.T) {
	key := mustECKey(t)
	certificate := mustSigningCertificate(t, key, 804)
	profile := mustSignedProfile(t, certificate, key, "TEAM123", "TEAM123.com.example.selected", time.Now().Add(time.Hour))
	files := []decryptedSigningFile{
		{RelativePath: "certs/distribution/shared.cer", Plaintext: certificate.Raw},
		{RelativePath: "profiles/adhoc/selected.mobileprovision", Plaintext: profile},
		{RelativePath: "profiles/adhoc/unselected.mobileprovision", Plaintext: []byte("not CMS")},
	}

	_, _, err := selectSigningPullFiles(files, []string{"com.example.selected"}, "IOS_APP_ADHOC")
	if err == nil || !strings.Contains(err.Error(), "unselected.mobileprovision") {
		t.Fatalf("error = %v, want corrupt unselected profile refusal", err)
	}
}

func TestSelectSigningPullFilesRequiresStoredProfileCertificate(t *testing.T) {
	profileKey := mustECKey(t)
	profileCertificate := mustSigningCertificate(t, profileKey, 805)
	storedKey := mustECKey(t)
	storedCertificate := mustSigningCertificate(t, storedKey, 806)
	profile := mustSignedProfile(t, profileCertificate, profileKey, "TEAM123", "TEAM123.com.example.selected", time.Now().Add(time.Hour))
	files := []decryptedSigningFile{
		{RelativePath: "certs/distribution/other.cer", Plaintext: storedCertificate.Raw},
		{RelativePath: "profiles/adhoc/selected.mobileprovision", Plaintext: profile},
	}

	_, _, err := selectSigningPullFiles(files, []string{"com.example.selected"}, "IOS_APP_ADHOC")
	if err == nil || !strings.Contains(err.Error(), "no matching stored public certificate") {
		t.Fatalf("error = %v, want missing stored certificate refusal", err)
	}
}

func TestSelectSigningPullFilesKeepsOnlyRequestedIdentityContext(t *testing.T) {
	password := "repository-password"
	key := mustECKey(t)
	certificate := mustSigningCertificate(t, key, 802)
	identity := &signingIdentity{
		PrivateKey:        key,
		Certificate:       certificate,
		CertificateSHA256: certificateSHA256(certificate),
	}
	store := &signingpkg.GitStore{LocalDir: t.TempDir()}
	certificatePath := "certs/distribution/shared.cer"
	if err := store.WriteEncryptedFile(certificatePath, certificate.Raw, password); err != nil {
		t.Fatal(err)
	}

	allPaths := []string{certificatePath}
	contexts := make(map[string]*signingIdentityArtifacts)
	profiles := make(map[string]string)
	for _, bundleID := range []string{"com.example.selected", "com.example.other"} {
		artifacts, err := prepareSigningIdentityArtifacts(identity, password, bundleID, "IOS_APP_ADHOC")
		if err != nil {
			t.Fatal(err)
		}
		profilePath, profileContent := bindTestSigningIdentityArtifacts(t, artifacts, certificate, key, bundleID, "IOS_APP_ADHOC", strings.TrimPrefix(bundleID, "com.example."))
		if err := store.WriteEncryptedFile(profilePath, profileContent, password); err != nil {
			t.Fatal(err)
		}
		if err := writeOrReuseSigningIdentityArtifacts(store, artifacts, password); err != nil {
			t.Fatal(err)
		}
		contexts[bundleID] = artifacts
		profiles[bundleID] = profilePath
		allPaths = append(allPaths, profilePath, artifacts.IdentityPath, artifacts.BindingPath)
	}
	allPaths = uniqueSortedSigningSyncStrings(allPaths)
	decrypted, err := prepareDecryptedSigningFiles(store, allPaths, password, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	selected, targets, err := selectSigningPullFiles(decrypted, []string{"com.example.selected"}, "IOS_APP_ADHOC")
	if err != nil {
		t.Fatal(err)
	}
	paths := signingPullRelativePaths(selected)
	want := uniqueSortedSigningSyncStrings([]string{
		certificatePath,
		profiles["com.example.selected"],
		contexts["com.example.selected"].IdentityPath,
		contexts["com.example.selected"].BindingPath,
	})
	if !slices.Equal(paths, want) {
		t.Fatalf("selected paths = %v, want %v", paths, want)
	}
	if slices.Contains(paths, profiles["com.example.other"]) || slices.Contains(paths, contexts["com.example.other"].BindingPath) {
		t.Fatalf("selected paths contain other target: %v", paths)
	}
	if len(targets) != 1 || !slices.Equal(targets[0].Files, want) {
		t.Fatalf("targets = %#v, want files %v", targets, want)
	}
}

func TestSelectSigningPullFilesRequiresEveryRequestedTarget(t *testing.T) {
	key := mustECKey(t)
	certificate := mustSigningCertificate(t, key, 803)
	profile := mustSignedProfile(t, certificate, key, "TEAM123", "TEAM123.com.example.present", time.Now().Add(time.Hour))
	files := []decryptedSigningFile{
		{RelativePath: "certs/distribution/shared.cer", Plaintext: certificate.Raw},
		{RelativePath: "profiles/adhoc/present.mobileprovision", Plaintext: profile},
	}

	_, _, err := selectSigningPullFiles(files, []string{"com.example.missing", "com.example.present"}, "IOS_APP_ADHOC")
	if err == nil || !strings.Contains(err.Error(), "com.example.missing") {
		t.Fatalf("error = %v, want missing target", err)
	}
}

func TestPreflightSigningPullFilesIgnoresUnselectedDestinationCollision(t *testing.T) {
	rootDir := t.TempDir()
	unselectedPath := filepath.Join("profiles", "adhoc", "other.mobileprovision")
	destination := filepath.Join(rootDir, unselectedPath)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	selected := []decryptedSigningFile{{RelativePath: filepath.Join("profiles", "adhoc", "selected.mobileprovision")}}
	if err := preflightSigningPullFiles(rootDir, selected); err != nil {
		t.Fatalf("selected preflight was blocked by unrelated destination: %v", err)
	}
}

func signingPullRelativePaths(files []decryptedSigningFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.ToSlash(file.RelativePath))
	}
	return uniqueSortedSigningSyncStrings(paths)
}
