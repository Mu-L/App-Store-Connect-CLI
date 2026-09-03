package shared

import "strings"

// certificateTypeValues mirrors the CertificateType enum in
// docs/openapi/latest.json. App Store Connect rejects any other value, so the
// CLI validates against this list before performing side effects such as
// generating a private key or issuing a create request.
var certificateTypeValues = []string{
	"APPLE_PAY",
	"APPLE_PAY_MERCHANT_IDENTITY",
	"APPLE_PAY_PSP_IDENTITY",
	"APPLE_PAY_RSA",
	"DEVELOPER_ID_APPLICATION",
	"DEVELOPER_ID_APPLICATION_G2",
	"DEVELOPER_ID_KEXT",
	"DEVELOPER_ID_KEXT_G2",
	"DEVELOPMENT",
	"DISTRIBUTION",
	"IDENTITY_ACCESS",
	"IOS_DEVELOPMENT",
	"IOS_DISTRIBUTION",
	"MAC_APP_DEVELOPMENT",
	"MAC_APP_DISTRIBUTION",
	"MAC_INSTALLER_DISTRIBUTION",
	"PASS_TYPE_ID",
	"PASS_TYPE_ID_WITH_NFC",
}

var certificateTypeSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(certificateTypeValues))
	for _, value := range certificateTypeValues {
		set[value] = struct{}{}
	}
	return set
}()

// CertificateTypeList returns the supported App Store Connect certificate types.
func CertificateTypeList() []string {
	values := make([]string, len(certificateTypeValues))
	copy(values, certificateTypeValues)
	return values
}

// CanonicalCertificateType normalizes value and returns the matching App Store
// Connect certificate type. Callers must use the returned value rather than the
// raw flag input: App Store Connect matches the enum exactly, so a normalized
// spelling such as "ios-distribution" has to reach the API as "IOS_DISTRIBUTION".
func CanonicalCertificateType(value string) (string, bool) {
	normalized := NormalizeEnumToken(value)
	if _, ok := certificateTypeSet[normalized]; !ok {
		return "", false
	}
	return normalized, true
}

// ValidateCertificateType returns the canonical certificate type for value, or a
// usage-class error when value is not a supported certificate type.
func ValidateCertificateType(flagName, value string) (string, error) {
	if canonical, ok := CanonicalCertificateType(value); ok {
		return canonical, nil
	}
	return "", UsageErrorf(
		"%s must be one of: %s (got %q)",
		flagName,
		strings.Join(certificateTypeValues, ", "),
		strings.TrimSpace(value),
	)
}
