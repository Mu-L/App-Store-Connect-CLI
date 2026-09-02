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

// IsCertificateType reports whether value is a supported certificate type. The
// value is normalized before lookup so callers may pass raw flag input.
func IsCertificateType(value string) bool {
	_, ok := certificateTypeSet[NormalizeEnumToken(value)]
	return ok
}

// ValidateCertificateType returns a usage-class error when value is not a
// supported certificate type.
func ValidateCertificateType(flagName, value string) error {
	if IsCertificateType(value) {
		return nil
	}
	return UsageErrorf(
		"%s must be one of: %s (got %q)",
		flagName,
		strings.Join(certificateTypeValues, ", "),
		strings.TrimSpace(value),
	)
}
