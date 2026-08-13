//go:build darwin && !cgo

package signing

import (
	"context"
	"strings"
	"testing"
)

func TestSigningRunSecurityFrameworkRequiresCGO(t *testing.T) {
	if signingRunSecurityAvailable() {
		t.Fatal("signing security unexpectedly available without cgo")
	}
	if err := RecoverEphemeral(context.Background()); err == nil || !strings.Contains(err.Error(), "cgo-enabled macOS build") {
		t.Fatalf("RecoverEphemeral() error = %v, want cgo requirement", err)
	}
	for _, err := range []error{
		createKeychainWithSecurityFramework("unused", nil),
		importPKCS12WithSecurityFramework("unused", nil, nil),
	} {
		if err == nil || !strings.Contains(err.Error(), "requires a cgo-enabled macOS build") {
			t.Fatalf("error = %v, want cgo requirement", err)
		}
	}
}
