package distribution

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
)

func TestInspectIPAAdHocOmitsDevicesByDefault(t *testing.T) {
	profile := signedProfile(t, profileFixture{
		BundleID: "com.example.demo",
		Devices:  []string{"device-b", "device-a"},
		Expires:  time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist": plistBytes(t, map[string]any{
			"CFBundleIdentifier":         "com.example.demo",
			"CFBundleDisplayName":        "Demo",
			"CFBundleShortVersionString": "1.2.3",
			"CFBundleVersion":            "45",
			"MinimumOSVersion":           "17.0",
		}),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})

	got := inspectPath(t, path, false)
	if got.SchemaVersion != "1" || got.Platform != "IOS" || got.DistributionMethod != "release-testing" {
		t.Fatalf("unexpected contract header: %#v", got)
	}
	if got.App.BundleID != "com.example.demo" || got.App.Title != "Demo" || got.App.BuildNumber != "45" {
		t.Fatalf("unexpected app: %#v", got.App)
	}
	if got.Signing.ProfileClass != ProfileClassAdHoc || got.Signing.DeviceCount != 2 || len(got.Signing.Devices) != 0 {
		t.Fatalf("unexpected signing result: %#v", got.Signing)
	}
	if got.Signing.DeviceSetSHA256 == "" || len(got.Signing.ProfileCertificateSHA256Fingerprints) != 1 {
		t.Fatalf("missing deterministic fingerprints: %#v", got.Signing)
	}
	if !got.Preparation.MetadataEligible || len(got.Preparation.Issues) != 0 {
		t.Fatalf("unexpected eligibility: %#v", got.Preparation)
	}
	if got.Signing.CodeSignatureVerification.Status != CodeSignatureInvalid {
		t.Fatalf("unexpected code signature verification: %#v", got.Signing.CodeSignatureVerification)
	}
	if got.Signing.ProfileIntegrityVerification.Status != CodeSignatureVerified || got.Signing.ProfileTrustVerification.Status != CodeSignatureInvalid {
		t.Fatalf("unexpected profile verification: %#v", got.Signing)
	}
	if got.Artifact.SHA256 == "" || got.Artifact.SizeBytes == 0 {
		t.Fatalf("unexpected artifact: %#v", got.Artifact)
	}
}

func TestInspectIPABindsExactEmbeddedProfileDigest(t *testing.T) {
	profile := signedProfile(t, profileFixture{
		BundleID: "com.example.demo",
		Devices:  []string{"private-device"},
		Expires:  time.Now().Add(24 * time.Hour),
	})
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})

	got := inspectPath(t, path, false)
	want := sha256.Sum256(profile)
	if got.Signing.EmbeddedProfileSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("embedded profile SHA-256 = %q, want %q", got.Signing.EmbeddedProfileSHA256, hex.EncodeToString(want[:]))
	}
	if len(got.Signing.Devices) != 0 {
		t.Fatalf("inspection disclosed devices by default: %#v", got.Signing.Devices)
	}
}

func TestInspectIPAIncludesSortedDevicesOnlyWhenRequested(t *testing.T) {
	path := validIPA(t, []string{"device-b", "device-a"}, time.Now().Add(24*time.Hour), false)
	got := inspectPath(t, path, true)
	if len(got.Signing.Devices) != 2 || got.Signing.Devices[0] != "device-a" || got.Signing.Devices[1] != "device-b" {
		t.Fatalf("devices = %#v", got.Signing.Devices)
	}
}

func TestInspectIPADeviceSetDigestUsesSemanticUDIDs(t *testing.T) {
	formatted := validIPA(t, []string{"0000-1111:aaaa", "2222-bbbb", "00001111AAAA"}, time.Now().Add(24*time.Hour), false)
	canonical := validIPA(t, []string{"00001111AAAA", "2222BBBB"}, time.Now().Add(24*time.Hour), false)
	different := validIPA(t, []string{"00001111AAAA", "3333CCCC"}, time.Now().Add(24*time.Hour), false)

	formattedSigning := inspectPath(t, formatted, false).Signing
	canonicalSigning := inspectPath(t, canonical, false).Signing
	differentSigning := inspectPath(t, different, false).Signing
	if formattedSigning.DeviceCount != 2 || formattedSigning.DeviceSetSHA256 != canonicalSigning.DeviceSetSHA256 {
		t.Fatalf("formatted=%#v canonical=%#v", formattedSigning, canonicalSigning)
	}
	if formattedSigning.DeviceSetSHA256 == differentSigning.DeviceSetSHA256 {
		t.Fatalf("different sets share digest %q", formattedSigning.DeviceSetSHA256)
	}
}

func TestInspectIPAClassifiesProfiles(t *testing.T) {
	tests := []struct {
		name       string
		devices    []string
		debuggable bool
		enterprise bool
		want       ProfileClass
	}{
		{name: "ad hoc", devices: []string{"one"}, want: ProfileClassAdHoc},
		{name: "development", devices: []string{"one"}, debuggable: true, want: ProfileClassDevelopment},
		{name: "enterprise", enterprise: true, want: ProfileClassEnterprise},
		{name: "app store", want: ProfileClassAppStore},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeIPA(t, map[string][]byte{
				"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"),
				"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{
					BundleID: "com.example.demo", Devices: test.devices, Debuggable: test.debuggable,
					Enterprise: test.enterprise, Expires: time.Now().Add(24 * time.Hour),
				}),
			})
			if got := inspectPath(t, path, false).Signing.ProfileClass; got != test.want {
				t.Fatalf("class = %q, want %q", got, test.want)
			}
		})
	}
}

func TestInspectIPARejectsUnsafeAndAmbiguousArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string][]byte
	}{
		{name: "traversal", entries: map[string][]byte{"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"), "Payload/../evil": {1}}},
		{name: "backslash", entries: map[string][]byte{"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"), `Payload\evil`: {1}}},
		{name: "bidirectional control", entries: map[string][]byte{"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"), "Payload/evil\u202Eipa": {1}}},
		{name: "oversized member name", entries: map[string][]byte{"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"), "Payload/" + strings.Repeat("a", maxArchiveMemberNameLen): {1}}},
		{name: "ambiguous main app", entries: map[string][]byte{"Payload/A.app/Info.plist": infoPlist(t, "com.example.a"), "Payload/B.app/Info.plist": infoPlist(t, "com.example.b")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeIPA(t, test.entries)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, _ := file.Stat()
			if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil {
				t.Fatal("expected inspection error")
			}
		})
	}
}

func TestInspectIPATamperedProfileFailsCMSVerification(t *testing.T) {
	profile := signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	profile[len(profile)/2] ^= 1
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})
	file, _ := os.Open(path)
	defer file.Close()
	info, _ := file.Stat()
	if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil {
		t.Fatal("expected tampered profile to fail")
	}
}

func TestVerifyAppleProfileTrustRequiresPinnedAppleIssuance(t *testing.T) {
	profile, root := appleShapedCMS(t, false)
	sum := sha256.Sum256(root.Raw)
	allowed := map[string]struct{}{hex.EncodeToString(sum[:]): {}}
	got := verifyAppleProfileTrust(profile, time.Now(), allowed)
	if got.Status != CodeSignatureVerified {
		t.Fatalf("Apple-shaped pinned chain status = %#v", got)
	}

	arbitrary := signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	message, err := pkcs7.Parse(arbitrary)
	if err != nil || len(message.Certificates) == 0 {
		t.Fatalf("parse arbitrary CMS: %v", err)
	}
	arbitrarySum := sha256.Sum256(message.Certificates[0].Raw)
	got = verifyAppleProfileTrust(message, time.Now(), map[string]struct{}{hex.EncodeToString(arbitrarySum[:]): {}})
	if got.Status != CodeSignatureInvalid {
		t.Fatalf("arbitrary trusted signer status = %#v", got)
	}

	multiple, root := appleShapedCMS(t, true)
	sum = sha256.Sum256(root.Raw)
	got = verifyAppleProfileTrust(multiple, time.Now(), map[string]struct{}{hex.EncodeToString(sum[:]): {}})
	if got.Status != CodeSignatureInvalid {
		t.Fatalf("multiple signer status = %#v", got)
	}
}

func TestInspectIPAReportsEmbeddedTargetAsNotReady(t *testing.T) {
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist":                      infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision":        signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)}),
		"Payload/Demo.app/PlugIns/Widget.appex/Info.plist": infoPlist(t, "com.example.demo.widget"),
	})
	got := inspectPath(t, path, false)
	if got.Preparation.MetadataEligible || len(got.EmbeddedTargets) != 1 {
		t.Fatalf("complex IPA was reported ready: %#v", got)
	}
}

func TestInspectIPARejectsFileOverSupportedSizeBeforeZIPWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxIPABytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectIPA(file, MaxIPABytes+1, InspectOptions{}); err == nil {
		t.Fatal("expected IPA size limit rejection")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectIPARejectsUnsafeAppMetadataBeforeDescriptorUse(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "bidirectional title", field: "CFBundleDisplayName", value: "Demo\u202Eipa"},
		{name: "format control bundle identifier", field: "CFBundleIdentifier", value: "com.example.\u200Bdemo"},
		{name: "oversized version", field: "CFBundleShortVersionString", value: strings.Repeat("1", 65)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := map[string]any{
				"CFBundleIdentifier":         "com.example.demo",
				"CFBundleDisplayName":        "Demo",
				"CFBundleShortVersionString": "1.0",
				"CFBundleVersion":            "1",
			}
			metadata[test.field] = test.value
			path := writeIPA(t, map[string][]byte{
				"Payload/Demo.app/Info.plist": plistBytes(t, metadata),
			})
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil {
				t.Fatal("expected unsafe app metadata rejection")
			}
		})
	}
}

func inspectPath(t *testing.T, path string, devices bool) Inspection {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectIPA(file, info.Size(), InspectOptions{IncludeDevices: devices, Now: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("InspectIPA() error = %v", err)
	}
	return got
}

func validIPA(t *testing.T, devices []string, expires time.Time, debuggable bool) string {
	t.Helper()
	return writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: devices, Expires: expires, Debuggable: debuggable}),
	})
}

func infoPlist(t *testing.T, bundleID string) []byte {
	t.Helper()
	return plistBytes(t, map[string]any{"CFBundleIdentifier": bundleID, "CFBundleName": "Demo", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1"})
}

func plistBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := plist.Marshal(value, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type profileFixture struct {
	BundleID   string
	Devices    []string
	Expires    time.Time
	Debuggable bool
	Enterprise bool
}

func signedProfile(t *testing.T, fixture profileFixture) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Profile Signer"}, NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	entitlements := map[string]any{"application-identifier": "TEAM123." + fixture.BundleID, "com.apple.developer.team-identifier": "TEAM123", "get-task-allow": fixture.Debuggable}
	payload := map[string]any{
		"UUID": "profile-uuid", "Name": "Test Profile", "TeamIdentifier": []string{"TEAM123"}, "ApplicationIdentifierPrefix": []string{"TEAM123"},
		"Platform":           []string{"iOS"},
		"ProvisionedDevices": fixture.Devices, "ProvisionsAllDevices": fixture.Enterprise,
		"ExpirationDate": fixture.Expires, "Entitlements": entitlements, "DeveloperCertificates": [][]byte{der},
	}
	signed, err := pkcs7.NewSignedData(plistBytes(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	result, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func appleShapedCMS(t *testing.T, multipleSigners bool) (*pkcs7.PKCS7, *x509.Certificate) {
	t.Helper()
	now := time.Now().Add(-time.Hour)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	issue := func(serial int64, subject, issuer pkix.Name, public any, issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, ca bool) *x509.Certificate {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: subject, Issuer: issuer,
			NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, public, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	rootKey := newKey()
	rootName := pkix.Name{CommonName: "Apple Root CA", Organization: []string{"Apple Inc."}}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: rootName, Issuer: rootName, NotBefore: now, NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey := newKey()
	intermediateName := pkix.Name{CommonName: "Apple iPhone Certification Authority", Organization: []string{"Apple Inc."}}
	intermediate := issue(101, intermediateName, rootName, &intermediateKey.PublicKey, root, rootKey, true)
	signerKey := newKey()
	signerName := pkix.Name{CommonName: "Apple iPhone OS Provisioning Profile Signing", Organization: []string{"Apple Inc."}}
	signer := issue(102, signerName, intermediateName, &signerKey.PublicKey, intermediate, intermediateKey, false)
	signed, err := pkcs7.NewSignedData([]byte("fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(signer, signerKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if multipleSigners {
		if err := signed.AddSigner(signer, signerKey, pkcs7.SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	signed.AddCertificate(intermediate)
	signed.AddCertificate(root)
	data, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	message, err := pkcs7.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return message, root
}

func writeIPA(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "App.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
