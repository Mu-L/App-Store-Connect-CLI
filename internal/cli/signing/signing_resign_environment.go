package signing

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/bitrise-io/go-pkcs12"
)

var signingResignPlatformDepsFn = platformSigningRunDeps

// runSigningResignEnvironment performs the narrow keychain portion of an IPA
// re-signing run. It intentionally does not install provisioning profiles in
// any user-controlled Xcode directory: profiles are embedded in the staged
// bundle by the caller instead.
func runSigningResignEnvironment(ctx context.Context, identity *signingRunIdentity, operation func(context.Context, string) error) (resultErr error) {
	if identity == nil || identity.Certificate == nil || identity.PrivateKey == nil {
		return fmt.Errorf("signing identity is missing")
	}
	if operation == nil {
		return fmt.Errorf("signing resign operation is required")
	}
	deps := signingResignPlatformDepsFn()
	if deps.GOOS != "darwin" {
		return fmt.Errorf("signing resign is supported only on macOS")
	}
	if deps.Stderr == nil {
		deps.Stderr = io.Discard
	}
	if deps.RandomBytes == nil || deps.TempDir == nil || deps.RemoveTempDir == nil ||
		deps.AcquireLock == nil || deps.Recover == nil || deps.WriteJournal == nil ||
		deps.RemoveJournal == nil || deps.KeychainSearchList == nil ||
		deps.CreateKeychain == nil || deps.ImportIdentity == nil ||
		deps.SetKeychainSearchList == nil || deps.RemoveKeychainSearchEntry == nil ||
		deps.DeleteKeychain == nil {
		return fmt.Errorf("signing environment is incomplete")
	}
	if err := contextError(ctx); err != nil {
		return err
	}

	unlock, err := deps.AcquireLock(ctx)
	if err != nil {
		return fmt.Errorf("acquire signing environment lock failed")
	}
	if unlock == nil {
		return fmt.Errorf("signing environment lock returned no release function")
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release signing environment lock failed"))
		}
	}()
	if err := deps.Recover(ctx); err != nil {
		return fmt.Errorf("recover prior signing environment failed")
	}

	tempDir, err := deps.TempDir()
	if err != nil {
		return fmt.Errorf("create private signing directory: %w", err)
	}
	keychainPath := filepath.Join(tempDir, "signing.keychain-db")
	cleanupTempOnly := func() {
		_ = deps.RemoveTempDir(tempDir)
	}
	if _, err := deps.KeychainSearchList(ctx); err != nil {
		cleanupTempOnly()
		return fmt.Errorf("read user keychain search list failed")
	}
	keychainPassword, err := deps.RandomBytes(32)
	if err != nil {
		cleanupTempOnly()
		return fmt.Errorf("generate keychain password: %w", err)
	}
	defer clear(keychainPassword)
	importPassword, err := deps.RandomBytes(32)
	if err != nil {
		cleanupTempOnly()
		return fmt.Errorf("generate identity import password: %w", err)
	}
	importPasswordText := []byte(fmt.Sprintf("%x", importPassword))
	clear(importPassword)
	defer clear(importPasswordText)
	normalizedIdentity, err := pkcs12.Encode(rand.Reader, identity.PrivateKey, identity.Certificate, nil, string(importPasswordText))
	if err != nil {
		cleanupTempOnly()
		return fmt.Errorf("normalize identity for temporary import: %w", err)
	}
	defer clear(normalizedIdentity)

	journal := signingRunJournal{SchemaVersion: 1, TempDir: tempDir, KeychainPath: keychainPath}
	if err := deps.WriteJournal(journal, false); err != nil {
		cleanupTempOnly()
		return fmt.Errorf("write signing environment recovery journal failed")
	}
	keychainAttempted := false
	cleanupDone := false
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if !keychainAttempted {
			if err := deps.RemoveTempDir(tempDir); err != nil {
				return fmt.Errorf("remove private signing directory failed")
			}
			return deps.RemoveJournal()
		}
		var cleanupErr error
		cleanupErr = errors.Join(cleanupErr, deps.RemoveKeychainSearchEntry(cleanupCtx, keychainPath))
		cleanupErr = errors.Join(cleanupErr, deps.DeleteKeychain(cleanupCtx, keychainPath))
		if cleanupErr != nil {
			return fmt.Errorf("signing environment cleanup did not complete; recovery journal retained")
		}
		if err := deps.RemoveTempDir(tempDir); err != nil {
			return fmt.Errorf("remove private signing directory failed")
		}
		if err := deps.RemoveJournal(); err != nil {
			return fmt.Errorf("remove signing environment recovery journal failed")
		}
		return nil
	}
	defer func() {
		if cleanupDone {
			return
		}
		if cleanupErr := cleanup(); cleanupErr != nil {
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	finish := func(primary error) error {
		cleanupDone = true
		return errors.Join(primary, cleanup())
	}

	keychainAttempted = true
	if err := deps.CreateKeychain(ctx, keychainPath, keychainPassword); err != nil {
		return finish(fmt.Errorf("create temporary keychain failed"))
	}
	if err := deps.RemoveKeychainSearchEntry(ctx, keychainPath); err != nil {
		return finish(fmt.Errorf("isolate temporary keychain failed"))
	}
	if err := deps.ImportIdentity(ctx, keychainPath, keychainPassword, normalizedIdentity, importPasswordText, identity.CertificateSHA1); err != nil {
		return finish(fmt.Errorf("import identity into temporary keychain failed"))
	}
	currentSearchList, err := deps.KeychainSearchList(ctx)
	if err != nil {
		return finish(fmt.Errorf("refresh user keychain search list failed"))
	}
	expectedSearchList := []string{keychainPath}
	for _, existing := range currentSearchList {
		if existing != keychainPath {
			expectedSearchList = append(expectedSearchList, existing)
		}
	}
	if err := deps.SetKeychainSearchList(ctx, expectedSearchList); err != nil {
		return finish(fmt.Errorf("activate temporary keychain failed"))
	}
	if err := operation(ctx, keychainPath); err != nil {
		return finish(err)
	}
	return finish(nil)
}
