package distribution

import (
	"archive/zip"
	"bytes"
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
	"runtime"
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
	wantCodeSignatureStatus := CodeSignatureInvalid
	if runtime.GOOS != "darwin" {
		wantCodeSignatureStatus = CodeSignatureNotVerified
	}
	if got.Signing.CodeSignatureVerification.Status != wantCodeSignatureStatus {
		t.Fatalf("unexpected code signature verification: %#v", got.Signing.CodeSignatureVerification)
	}
	if runtime.GOOS != "darwin" && got.Signing.CodeSignatureVerification.Reason != "complete main-app code-signature verification is available only on macOS" {
		t.Fatalf("unexpected portable code signature reason: %#v", got.Signing.CodeSignatureVerification)
	}
	if got.Signing.ProfileIntegrityVerification.Status != CodeSignatureVerified || got.Signing.ProfileTrustVerification.Status != CodeSignatureInvalid {
		t.Fatalf("unexpected profile verification: %#v", got.Signing)
	}
	if got.Artifact.SHA256 == "" || got.Artifact.SizeBytes == 0 {
		t.Fatalf("unexpected artifact: %#v", got.Artifact)
	}
}

func TestInspectIPAIncludesSortedDevicesOnlyWhenRequested(t *testing.T) {
	path := validIPA(t, []string{"device-b", "device-a"}, time.Now().Add(24*time.Hour), false)
	got := inspectPath(t, path, true)
	if len(got.Signing.Devices) != 2 || got.Signing.Devices[0] != "device-a" || got.Signing.Devices[1] != "device-b" {
		t.Fatalf("devices = %#v", got.Signing.Devices)
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

func TestInspectIPAValidatesApplicationIdentifierPrefixDeclaration(t *testing.T) {
	t.Run("legacy prefix differs from team", func(t *testing.T) {
		path := writeIPA(t, map[string][]byte{
			"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"),
			"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{
				BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				ApplicationIdentifierPrefixes: []string{"LEGACY123"},
			}),
		})
		got := inspectPath(t, path, false)
		if got.Signing.TeamID != "TEAM123" || !got.Preparation.MetadataEligible {
			t.Fatalf("legacy profile inspection = %#v", got)
		}
	})

	for _, test := range []struct {
		name     string
		prefixes []string
	}{
		{name: "missing", prefixes: []string{}},
		{name: "ambiguous", prefixes: []string{"LEGACY123", "OTHER123"}},
		{name: "malformed", prefixes: []string{`LEGACY"123`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeIPA(t, map[string][]byte{
				"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"),
				"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{
					BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
					ApplicationIdentifierPrefixes: test.prefixes,
				}),
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
			if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil || !strings.Contains(err.Error(), "application identifier prefix") {
				t.Fatalf("InspectIPA() error = %v, want prefix declaration rejection", err)
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
		{name: "regular file shadows top-level directory", entries: map[string][]byte{"Payload": {1}, "Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo")}},
		{name: "regular file shadows app directory", entries: map[string][]byte{"Payload/Demo.app": {1}, "Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo")}},
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

func TestInspectIPARejectsUnreadableNonMainMembers(t *testing.T) {
	baseEntries := map[string][]byte{
		"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{
			BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		}),
	}

	t.Run("checksum failure", func(t *testing.T) {
		entries := cloneByteMap(baseEntries)
		entries["Symbols/resource.bin"] = bytes.Repeat([]byte("signed-resource"), 64)
		path := writeIPA(t, entries)
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		reader, err := zip.NewReader(file, info.Size())
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range reader.File {
			if member.Name != "Symbols/resource.bin" {
				continue
			}
			offset, err := member.DataOffset()
			if err != nil {
				t.Fatal(err)
			}
			var value [1]byte
			if _, err := file.ReadAt(value[:], offset); err != nil {
				t.Fatal(err)
			}
			value[0] ^= 0xff
			if _, err := file.WriteAt(value[:], offset); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		assertInspectErrorContains(t, path, "Symbols/resource.bin")
	})

	t.Run("truncated stream", func(t *testing.T) {
		path := writeIPAWithDeclaredRawEntries(t, baseEntries, []declaredRawZipEntry{
			{Name: "Symbols/truncated.bin", UncompressedSize: 1},
		})
		assertInspectErrorContains(t, path, "Symbols/truncated.bin")
	})
}

func TestInspectIPARejectsArchiveWideDeclaredExpansionFromCompressedNonMainMembers(t *testing.T) {
	const archiveExpansionLimit = uint64(16 << 30)
	baseEntries := map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)}),
	}
	tests := []struct {
		name     string
		declared []declaredRawZipEntry
	}{
		{
			name: "single highly compressed SwiftSupport member",
			declared: []declaredRawZipEntry{
				{Name: "SwiftSupport/libSwiftCore.dylib", UncompressedSize: archiveExpansionLimit},
			},
		},
		{
			name: "sum of non-main members",
			declared: []declaredRawZipEntry{
				{Name: "Symbols/part-1.bin", UncompressedSize: archiveExpansionLimit/2 + 1},
				{Name: "Symbols/part-2.bin", UncompressedSize: archiveExpansionLimit/2 + 1},
			},
		},
		{
			name: "declared size arithmetic cannot overflow",
			declared: []declaredRawZipEntry{
				{Name: "SwiftSupport/overflow.bin", UncompressedSize: ^uint64(0)},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeIPAWithDeclaredRawEntries(t, baseEntries, test.declared)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil || !strings.Contains(err.Error(), "declared expansion") {
				t.Fatalf("InspectIPA() error = %v, want archive-wide declared expansion rejection", err)
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
	if _, err := InspectIPA(file, MaxIPABytes+1, InspectOptions{}); err == nil {
		t.Fatal("expected IPA size limit rejection")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBundleMatchesUniversalProvisioningWildcard(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		app     string
		want    bool
	}{
		{name: "universal wildcard", profile: "*", app: "com.example.demo", want: true},
		{name: "universal wildcard rejects empty app", profile: "*", app: "", want: false},
		{name: "prefix wildcard", profile: "com.example.*", app: "com.example.demo", want: true},
		{name: "prefix wildcard requires suffix", profile: "com.example.*", app: "com.example.", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := bundleMatches(test.profile, test.app); got != test.want {
				t.Fatalf("bundleMatches(%q, %q) = %t, want %t", test.profile, test.app, got, test.want)
			}
		})
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
		{name: "bundle identifier path separator", field: "CFBundleIdentifier", value: "com.example/bad"},
		{name: "empty bundle identifier component", field: "CFBundleIdentifier", value: "com..example"},
		{name: "non-ASCII bundle identifier", field: "CFBundleIdentifier", value: "com.example.démo"},
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

func TestInspectIPARequiresMainAppIOSPlatformEvidence(t *testing.T) {
	base := map[string]any{
		"CFBundleIdentifier":         "com.example.demo",
		"CFBundleName":               "Demo",
		"CFBundleShortVersionString": "1.0",
		"CFBundleVersion":            "1",
	}
	for _, test := range []struct {
		name     string
		metadata map[string]any
	}{
		{name: "visionOS", metadata: map[string]any{"DTPlatformName": "xros", "CFBundleSupportedPlatforms": []string{"XROS"}}},
		{name: "tvOS", metadata: map[string]any{"DTPlatformName": "appletvos", "CFBundleSupportedPlatforms": []string{"AppleTVOS"}}},
		{name: "macOS", metadata: map[string]any{"DTPlatformName": "macosx", "CFBundleSupportedPlatforms": []string{"MacOSX"}}},
		{name: "simulator", metadata: map[string]any{"DTPlatformName": "iphonesimulator", "CFBundleSupportedPlatforms": []string{"iPhoneSimulator"}}},
		{name: "contradictory fields", metadata: map[string]any{"DTPlatformName": "iphoneos", "CFBundleSupportedPlatforms": []string{"XROS"}}},
		{name: "multiple platforms", metadata: map[string]any{"DTPlatformName": "iphoneos", "CFBundleSupportedPlatforms": []string{"iPhoneOS", "AppleTVOS"}}},
		{name: "missing metadata", metadata: map[string]any{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := clonePlistMap(base)
			for key, value := range test.metadata {
				metadata[key] = value
			}
			path := writeIPA(t, map[string][]byte{
				"Payload/Demo.app/Info.plist": plistBytesFormat(t, metadata, plist.XMLFormat),
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
			if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil || !strings.Contains(err.Error(), "iOS platform") {
				t.Fatalf("InspectIPA() error = %v, want iOS platform rejection", err)
			}
		})
	}
}

func TestInspectIPAAcceptsMainAppIOSPlatformEvidenceInXMLAndBinaryPlists(t *testing.T) {
	metadata := map[string]any{
		"CFBundleIdentifier":         "com.example.demo",
		"CFBundleName":               "Demo",
		"CFBundleShortVersionString": "1.0",
		"CFBundleVersion":            "1",
		"DTPlatformName":             "iphoneos",
		"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
	}
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		path := writeIPA(t, map[string][]byte{
			"Payload/Demo.app/Info.plist": plistBytesFormat(t, metadata, format),
		})
		got := inspectPath(t, path, false)
		if got.Platform != "IOS" {
			t.Fatalf("platform = %q, want IOS", got.Platform)
		}
	}
}

func TestInspectIPAUsesOnlyMainAppPlatformEvidence(t *testing.T) {
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist": infoPlist(t, "com.example.demo"),
		"Payload/Demo.app/PlugIns/Vision.appex/Info.plist": plistBytes(t, map[string]any{
			"CFBundleIdentifier":         "com.example.demo.vision",
			"DTPlatformName":             "xros",
			"CFBundleSupportedPlatforms": []string{"XROS"},
		}),
	})
	got := inspectPath(t, path, false)
	if got.Platform != "IOS" {
		t.Fatalf("platform = %q, want main-app IOS evidence", got.Platform)
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
	return plistBytes(t, map[string]any{
		"CFBundleIdentifier":         bundleID,
		"CFBundleName":               "Demo",
		"CFBundleShortVersionString": "1.0",
		"CFBundleVersion":            "1",
	})
}

func plistBytes(t *testing.T, value any) []byte {
	t.Helper()
	if payload, ok := value.(map[string]any); ok {
		payload = clonePlistMap(payload)
		if _, hasBundleID := payload["CFBundleIdentifier"]; hasBundleID {
			if _, hasPlatformName := payload["DTPlatformName"]; !hasPlatformName {
				if _, hasSupportedPlatforms := payload["CFBundleSupportedPlatforms"]; !hasSupportedPlatforms {
					payload["DTPlatformName"] = "iphoneos"
					payload["CFBundleSupportedPlatforms"] = []string{"iPhoneOS"}
				}
			}
		}
		value = payload
	}
	return plistBytesFormat(t, value, plist.XMLFormat)
}

func plistBytesFormat(t *testing.T, value any, format int) []byte {
	t.Helper()
	data, err := plist.Marshal(value, format)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func clonePlistMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func cloneByteMap(value map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func assertInspectErrorContains(t *testing.T, path, want string) {
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
	if _, err := InspectIPA(file, info.Size(), InspectOptions{}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("InspectIPA() error = %v, want member %q rejection", err, want)
	}
}

type profileFixture struct {
	BundleID                      string
	Devices                       []string
	Expires                       time.Time
	Debuggable                    bool
	Enterprise                    bool
	ApplicationIdentifierPrefixes []string
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
	prefixes := fixture.ApplicationIdentifierPrefixes
	if prefixes == nil {
		prefixes = []string{"TEAM123"}
	}
	applicationIdentifierPrefix := "TEAM123"
	if len(prefixes) > 0 {
		applicationIdentifierPrefix = prefixes[0]
	}
	entitlements := map[string]any{"application-identifier": applicationIdentifierPrefix + "." + fixture.BundleID, "com.apple.developer.team-identifier": "TEAM123", "get-task-allow": fixture.Debuggable}
	payload := map[string]any{
		"UUID": "profile-uuid", "Name": "Test Profile", "TeamIdentifier": []string{"TEAM123"}, "ApplicationIdentifierPrefix": prefixes,
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

type declaredRawZipEntry struct {
	Name             string
	UncompressedSize uint64
}

func writeIPAWithDeclaredRawEntries(t *testing.T, entries map[string][]byte, declaredEntries []declaredRawZipEntry) string {
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
	for _, declared := range declaredEntries {
		header := &zip.FileHeader{
			Name:               declared.Name,
			Method:             zip.Deflate,
			CompressedSize64:   2,
			UncompressedSize64: declared.UncompressedSize,
		}
		entry, err := writer.CreateRaw(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte{0x03, 0x00}); err != nil {
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

func TestHashSetDeterministic(t *testing.T) {
	a := hashSet([]string{"b", "a", "a"})
	b := hashSet([]string{"a", "b"})
	if !bytes.Equal([]byte(a), []byte(b)) {
		t.Fatalf("hashes differ: %q %q", a, b)
	}
}
