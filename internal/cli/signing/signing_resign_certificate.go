package signing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var extractSigningResignCertificateFn = extractSigningResignCertificate

func verifySigningResignCertificate(ctx context.Context, codePath, expectedSHA256 string) error {
	return extractSigningResignCertificateFn(ctx, codePath, expectedSHA256)
}

func extractSigningResignCertificate(ctx context.Context, codePath, expectedSHA256 string) (resultErr error) {
	if len(expectedSHA256) != sha256.Size*2 {
		return fmt.Errorf("expected signer certificate digest is invalid")
	}
	if _, err := hex.DecodeString(expectedSHA256); err != nil {
		return fmt.Errorf("expected signer certificate digest is invalid")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "asc-signing-resign-cert.")
	if err != nil {
		return fmt.Errorf("create certificate inspection directory: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(directory); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove certificate inspection directory failed"))
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure certificate inspection directory: %w", err)
	}
	prefix := filepath.Join(directory, "certificate-")
	if _, err := runSigningResignToolFn(ctx, "/usr/bin/codesign", "-d", "--extract-certificates="+prefix, codePath); err != nil {
		return fmt.Errorf("extract signer certificate: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read extracted signer certificates: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	found := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), filepath.Base(prefix)) {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), filepath.Base(prefix))); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return fmt.Errorf("read extracted signer certificate: %w", err)
		}
		certificate, err := x509.ParseCertificate(data)
		if err != nil {
			return fmt.Errorf("parse extracted signer certificate: %w", err)
		}
		digest := sha256.Sum256(certificate.Raw)
		if strings.EqualFold(hex.EncodeToString(digest[:]), expectedSHA256) {
			found = true
		}
		clear(data)
	}
	if !found {
		return fmt.Errorf("signed code object certificate does not match the supplied identity")
	}
	return nil
}
