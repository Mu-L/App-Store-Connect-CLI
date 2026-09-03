package shared

import "testing"

func TestCanonicalCertificateTypeNormalizesSeparatorsAndCase(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "canonical", value: "IOS_DISTRIBUTION", want: "IOS_DISTRIBUTION"},
		{name: "lowercase", value: "ios_distribution", want: "IOS_DISTRIBUTION"},
		{name: "hyphenated", value: "ios-distribution", want: "IOS_DISTRIBUTION"},
		{name: "spaced", value: " mac installer distribution ", want: "MAC_INSTALLER_DISTRIBUTION"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := CanonicalCertificateType(tt.value)
			if !ok {
				t.Fatalf("CanonicalCertificateType(%q) reported an unsupported type", tt.value)
			}
			if got != tt.want {
				t.Fatalf("CanonicalCertificateType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestCanonicalCertificateTypeRejectsUnknownValues(t *testing.T) {
	for _, value := range []string{"", "DEVELOPER_ID_INSTALLER", "TVOS_DISTRIBUTION", "ios distribution 2"} {
		if got, ok := CanonicalCertificateType(value); ok {
			t.Fatalf("CanonicalCertificateType(%q) = %q, want rejection", value, got)
		}
	}
}

func TestValidateCertificateTypeReturnsCanonicalValue(t *testing.T) {
	got, err := ValidateCertificateType("--certificate-type", "developer-id-application-g2")
	if err != nil {
		t.Fatalf("ValidateCertificateType() error: %v", err)
	}
	if got != "DEVELOPER_ID_APPLICATION_G2" {
		t.Fatalf("ValidateCertificateType() = %q, want %q", got, "DEVELOPER_ID_APPLICATION_G2")
	}

	if _, err := ValidateCertificateType("--certificate-type", "DEVELOPER_ID_INSTALLER"); err == nil {
		t.Fatal("expected an error for an unsupported certificate type")
	}
}
