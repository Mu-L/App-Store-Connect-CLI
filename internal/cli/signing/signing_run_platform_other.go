//go:build !darwin

package signing

import (
	"context"
	"crypto/x509"
	"os"
)

func platformSigningRunDeps() signingRunDeps {
	return signingRunDeps{GOOS: "unsupported", Stderr: os.Stderr}
}

func systemSigningRunRoots() (*x509.CertPool, error) { return x509.SystemCertPool() }

func validateSigningRunInputPermissions(string, os.FileInfo, bool) error { return nil }

func platformSigningRunContext(ctx context.Context) (context.Context, func()) {
	return ctx, func() {}
}
