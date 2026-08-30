//go:build darwin

package signing

import (
	"strings"
	"testing"
)

func TestValidatePersistentSigningCertificateFingerprintsAllowsCertificateChain(t *testing.T) {
	leaf := strings.Repeat("A", 40)
	chain := []string{strings.Repeat("B", 40), leaf, strings.Repeat("C", 40)}
	if err := validatePersistentSigningCertificateFingerprints(chain, strings.ToLower(leaf)); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePersistentSigningCertificateFingerprintsRequiresLeafExactlyOnce(t *testing.T) {
	leaf := strings.Repeat("A", 40)
	for _, certificates := range [][]string{
		{strings.Repeat("B", 40)},
		{leaf, leaf},
	} {
		if err := validatePersistentSigningCertificateFingerprints(certificates, leaf); err == nil {
			t.Fatalf("certificates = %v, want exact-leaf-count failure", certificates)
		}
	}
}
