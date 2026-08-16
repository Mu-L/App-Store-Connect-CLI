package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivateKeyErrorsCarryStructuredKinds(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.p8")
		err := ValidateKeyFile(path)
		assertPrivateKeyErrorKind(t, err, PrivateKeyNotFound)
		if !strings.Contains(err.Error(), "failed to open key file") {
			t.Fatalf("error message changed: %v", err)
		}
	})

	t.Run("invalid pem", func(t *testing.T) {
		_, err := LoadPrivateKeyFromPEM([]byte("not pem"))
		assertPrivateKeyErrorKind(t, err, PrivateKeyInvalidFormat)
		if got, want := err.Error(), "invalid PEM data"; got != want {
			t.Fatalf("error = %q, want %q", got, want)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal RSA key: %v", err)
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		_, err = LoadPrivateKeyFromPEM(data)
		assertPrivateKeyErrorKind(t, err, PrivateKeyUnsupportedAlgorithm)
		if got, want := err.Error(), "private key is not ECDSA"; got != want {
			t.Fatalf("error = %q, want %q", got, want)
		}
	})

	t.Run("insecure permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not expose POSIX key permissions")
		}
		path := filepath.Join(t.TempDir(), "key.p8")
		if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
			t.Fatalf("write key: %v", err)
		}
		err := ValidateKeyFile(path)
		assertPrivateKeyErrorKind(t, err, PrivateKeyPermissionDenied)
		if !strings.Contains(err.Error(), "private key file is too permissive") {
			t.Fatalf("error message changed: %v", err)
		}
	})
}

func assertPrivateKeyErrorKind(t *testing.T, err error, want PrivateKeyErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	got, ok := PrivateKeyErrorKindOf(err)
	if !ok || got != want {
		t.Fatalf("PrivateKeyErrorKindOf(%v) = %q, %t; want %q, true", err, got, ok, want)
	}
	var keyErr *PrivateKeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("errors.As(%v, *PrivateKeyError) = false", err)
	}
}
