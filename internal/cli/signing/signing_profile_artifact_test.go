package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	signingpkg "github.com/rudrankriyam/App-Store-Connect-CLI/internal/signing"
)

func TestSigningProfileArtifactUpgradesLegacyAndPreservesExactScope(t *testing.T) {
	store := &signingpkg.GitStore{LocalDir: t.TempDir()}
	const password = "repository-password"
	path := filepath.Join("profiles", "appstore", "profile.mobileprovision")
	plaintext := []byte("signed-profile-content")
	if err := store.WriteEncryptedFile(path, plaintext, password); err != nil {
		t.Fatal(err)
	}
	profile := &asc.ProfileResponse{Data: asc.Resource[asc.ProfileAttributes]{ID: "profile-1"}}
	metadata, err := signingProfileArtifactMetadata(profile, "com.example.mac", "MAC_CATALYST_APP_STORE")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOrReuseSigningProfileArtifact(store, path, plaintext, password, metadata); err != nil {
		t.Fatal(err)
	}
	got, gotMetadata, err := store.ReadEncryptedFileWithMetadata(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) || gotMetadata.Version != 1 || gotMetadata.Kind != signingProfileArtifactKind ||
		gotMetadata.BundleID != "com.example.mac" || gotMetadata.ProfileType != "MAC_CATALYST_APP_STORE" || gotMetadata.ProfileResourceID != "profile-1" {
		t.Fatalf("artifact metadata = %+v plaintext=%q", gotMetadata, got)
	}
	encryptedPath := filepath.Join(store.LocalDir, path+".enc")
	before, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOrReuseSigningProfileArtifact(store, path, plaintext, password, metadata); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("semantic no-op rewrote authenticated profile ciphertext")
	}

	wrongScope := metadata
	wrongScope.ProfileType = "MAC_APP_STORE"
	if _, err := preflightSigningProfileArtifact(store, path, plaintext, password, wrongScope); err == nil || !strings.Contains(err.Error(), "different authenticated scope") {
		t.Fatalf("wrong-scope error = %v", err)
	}
}

func TestClassifySigningProfileArtifactRejectsIncompleteMetadata(t *testing.T) {
	_, _, err := classifySigningFile("profiles/appstore/profile.mobileprovision", []byte("profile"), signingpkg.EncryptedFileMetadata{
		Version:     1,
		Kind:        signingProfileArtifactKind,
		BundleID:    "com.example.app",
		ProfileType: "IOS_APP_STORE",
	}, "password")
	if err == nil || !strings.Contains(err.Error(), "missing its authenticated scope") {
		t.Fatalf("error = %v, want incomplete metadata refusal", err)
	}
}
