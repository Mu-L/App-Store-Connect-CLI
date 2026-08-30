//go:build darwin

package signing

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func platformSigningKeychainInstallDeps() signingKeychainInstallDeps {
	runDeps := platformSigningRunDeps()
	return signingKeychainInstallDeps{
		GOOS:                      "darwin",
		SecurityAvailable:         signingRunSecurityAvailable(),
		CreateKeychain:            createPersistentSigningKeychain,
		ImportIdentity:            importPersistentSigningIdentity,
		KeychainSearchList:        runDeps.KeychainSearchList,
		SetKeychainSearchList:     runDeps.SetKeychainSearchList,
		RemoveKeychainSearchEntry: runDeps.RemoveKeychainSearchEntry,
		DeleteKeychain:            runDeps.DeleteKeychain,
	}
}

func createPersistentSigningKeychain(ctx context.Context, keychainPath string, password []byte) error {
	if len(password) == 0 {
		return fmt.Errorf("keychain password is empty")
	}
	if err := createKeychainWithSecurityFramework(keychainPath, password); err != nil {
		return err
	}
	_, stderr, err := runSigningUtility(ctx, nil, "set-keychain-settings", "-l", keychainPath)
	if err != nil {
		configureErr := utilityFailure("configure persistent keychain", stderr, err)
		if cleanupErr := deleteSigningRunKeychain(ctx, keychainPath); cleanupErr != nil {
			return errors.Join(configureErr, fmt.Errorf("remove unconfigured keychain: %w", cleanupErr))
		}
		return configureErr
	}
	return nil
}

func importPersistentSigningIdentity(ctx context.Context, keychainPath string, keychainPassword, identityData, importPassword []byte, expectedSHA1 string) error {
	if err := importPKCS12WithSecurityFramework(keychainPath, identityData, importPassword); err != nil {
		return err
	}
	if err := withPersistentSigningKeychainPasswordInput(keychainPassword, func(stdin []byte) error {
		_, stderr, err := runSigningUtility(ctx, stdin, "set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-t", "private", keychainPath)
		if err != nil {
			return utilityFailure("restrict key partition list", stderr, err)
		}
		return nil
	}); err != nil {
		return err
	}
	stdout, stderr, err := runSigningUtility(ctx, nil, "find-certificate", "-a", "-Z", keychainPath)
	if err != nil {
		return utilityFailure("verify imported certificate", stderr, err)
	}
	certificates := parseSigningRunCertificateFingerprints(stdout)
	if len(certificates) != 1 || !strings.EqualFold(certificates[0], expectedSHA1) {
		return fmt.Errorf("verify imported certificate: expected only certificate %s, found %v", expectedSHA1, certificates)
	}
	_, stderr, err = runSigningUtility(ctx, nil, "find-key", "-s", "-t", "private", keychainPath)
	if err != nil {
		return utilityFailure("verify imported private key", stderr, err)
	}
	return verifySigningRunIdentityUsable(ctx, filepath.Dir(keychainPath), keychainPath, expectedSHA1)
}

func withPersistentSigningKeychainPasswordInput(password []byte, operation func([]byte) error) error {
	stdin := make([]byte, len(password)+1)
	copy(stdin, password)
	stdin[len(stdin)-1] = '\n'
	defer clear(stdin)
	return operation(stdin)
}
