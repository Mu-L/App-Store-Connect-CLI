package distribution

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"
)

func TestInspectIPAVerifiesEveryMainExecutableArchitectureAgainstProfile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	profile := signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	message, err := pkcs7.Parse(profile)
	if err != nil || len(message.Certificates) == 0 {
		t.Fatalf("parse fixture profile: %v", err)
	}
	leaf := message.Certificates[0].Raw
	var extracted int
	var verified, listed bool
	runCodeSignTool = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "/usr/bin/lipo":
			if len(args) != 2 || args[0] != "-archs" {
				t.Fatalf("unexpected lipo args: %#v", args)
			}
			listed = true
			return []byte("arm64 x86_64\n"), nil
		case "/usr/bin/codesign":
			if len(args) > 1 && args[0] == "--verify" && args[1] == "--deep" {
				want := []string{"--verify", "--deep", "--strict", "--all-architectures", "--verbose=4"}
				if len(args) != len(want)+1 || strings.Join(args[:len(want)], "\x00") != strings.Join(want, "\x00") {
					t.Fatalf("unexpected codesign verify args: %#v", args)
				}
				verified = true
			}
			if len(args) > 0 && args[0] == "-d" && len(args) > 3 && args[1] == "--entitlements" && args[2] == ":-" {
				return plist.Marshal(map[string]any{
					"application-identifier":              "TEAM123.com.example.demo",
					"com.apple.developer.team-identifier": "TEAM123",
				}, plist.XMLFormat)
			}
			for _, argument := range args {
				if strings.HasPrefix(argument, "--extract-certificates=") {
					prefix := strings.TrimPrefix(argument, "--extract-certificates=")
					if err := os.WriteFile(prefix+"0", leaf, 0o600); err != nil {
						return nil, err
					}
					extracted++
				}
			}
			return nil, nil
		default:
			t.Fatalf("unexpected tool %q", name)
			return nil, nil
		}
	}
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist": plistBytes(t, map[string]any{
			"CFBundleIdentifier": "com.example.demo", "CFBundleName": "Demo",
			"CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "CFBundleExecutable": "Demo",
		}),
		"Payload/Demo.app/Demo":                     fakeMachO("main"),
		"Payload/Demo.app/Frameworks/Shared.dylib":  fakeMachO("nested"),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})
	got := inspectPath(t, path, false)
	if got.Signing.CodeSignatureVerification.Status != CodeSignatureVerified || extracted != 4 || !verified || !listed {
		t.Fatalf("verification=%#v extracted=%d", got.Signing.CodeSignatureVerification, extracted)
	}
	if len(got.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints) != 1 {
		t.Fatalf("fingerprints=%#v", got.Signing.CodeSignatureVerification.SignerCertificateSHA256Fingerprints)
	}
}

func TestInspectIPARejectsNestedCodeSignedByDifferentLeafEvenWhenDeepVerifyPasses(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	profile := signedProfile(t, profileFixture{BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	message, err := pkcs7.Parse(profile)
	if err != nil || len(message.Certificates) == 0 {
		t.Fatalf("parse fixture profile: %v", err)
	}
	mainLeaf := message.Certificates[0].Raw
	otherProfile := signedProfile(t, profileFixture{BundleID: "com.example.other", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	otherMessage, err := pkcs7.Parse(otherProfile)
	if err != nil || len(otherMessage.Certificates) == 0 {
		t.Fatalf("parse other profile: %v", err)
	}
	otherLeaf := otherMessage.Certificates[0].Raw
	runCodeSignTool = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/lipo" {
			return []byte("arm64\n"), nil
		}
		if len(args) > 3 && args[1] == "--entitlements" && args[2] == ":-" {
			return plist.Marshal(map[string]any{
				"application-identifier":              "TEAM123.com.example.demo",
				"com.apple.developer.team-identifier": "TEAM123",
			}, plist.XMLFormat)
		}
		for _, argument := range args {
			if strings.HasPrefix(argument, "--extract-certificates=") {
				leaf := mainLeaf
				if strings.Contains(args[len(args)-1], "Shared.dylib") {
					leaf = otherLeaf
				}
				return nil, os.WriteFile(strings.TrimPrefix(argument, "--extract-certificates=")+"0", leaf, 0o600)
			}
		}
		return nil, nil
	}
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })
	path := writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist": plistBytes(t, map[string]any{
			"CFBundleIdentifier": "com.example.demo", "CFBundleName": "Demo",
			"CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "CFBundleExecutable": "Demo",
		}),
		"Payload/Demo.app/Demo":                     fakeMachO("main"),
		"Payload/Demo.app/Frameworks/Shared.dylib":  fakeMachO("nested"),
		"Payload/Demo.app/embedded.mobileprovision": profile,
	})
	got := inspectPath(t, path, false)
	if got.Signing.CodeSignatureVerification.Status != CodeSignatureInvalid || !strings.Contains(got.Signing.CodeSignatureVerification.Reason, "nested signed code signer") {
		t.Fatalf("verification=%#v", got.Signing.CodeSignatureVerification)
	}
}

func TestInspectIPACodeSignToolAbsenceIsExplicitlyNotVerified(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	runCodeSignTool = func(context.Context, string, ...string) ([]byte, error) { return nil, exec.ErrNotFound }
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })
	path := validExecutableIPA(t)
	got := inspectPath(t, path, false)
	if got.Signing.CodeSignatureVerification.Status != CodeSignatureNotVerified {
		t.Fatalf("verification=%#v", got.Signing.CodeSignatureVerification)
	}
}

func TestInspectIPARejectsSignerOutsideEmbeddedProfile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	otherProfile := signedProfile(t, profileFixture{BundleID: "com.example.other", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour)})
	message, err := pkcs7.Parse(otherProfile)
	if err != nil || len(message.Certificates) == 0 {
		t.Fatalf("parse other profile: %v", err)
	}
	otherLeaf := message.Certificates[0].Raw
	runCodeSignTool = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/lipo" {
			return []byte("arm64\n"), nil
		}
		for _, argument := range args {
			if strings.HasPrefix(argument, "--extract-certificates=") {
				return nil, os.WriteFile(strings.TrimPrefix(argument, "--extract-certificates=")+"0", otherLeaf, 0o600)
			}
		}
		if len(args) > 3 && args[1] == "--entitlements" && args[2] == ":-" {
			return plist.Marshal(map[string]any{
				"application-identifier":              "TEAM123.com.example.demo",
				"com.apple.developer.team-identifier": "TEAM123",
			}, plist.XMLFormat)
		}
		return nil, nil
	}
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })
	got := inspectPath(t, validExecutableIPA(t), false)
	if got.Signing.CodeSignatureVerification.Status != CodeSignatureInvalid {
		t.Fatalf("verification=%#v", got.Signing.CodeSignatureVerification)
	}
}

func TestEnumerateMachOFilesIgnoresJavaClassMagicCollision(t *testing.T) {
	appPath := t.TempDir()
	mainPath := filepath.Join(appPath, "Demo")
	fatPath := filepath.Join(appPath, "Universal")
	classPath := filepath.Join(appPath, "Resource.class")
	malformedFatPath := filepath.Join(appPath, "MalformedUniversal")
	if err := os.WriteFile(mainPath, fakeMachO("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fatPath, validFatMachO(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(classPath, []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x3d}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedFatPath, []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := enumerateMachOFiles(appPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{mainPath, fatPath}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("enumerateMachOFiles() = %#v, want %#v", got, want)
	}
}

func TestValidateTeamIdentifierRejectsRequirementInjection(t *testing.T) {
	for _, value := range []string{"TEAM123", "abc123", strings.Repeat("A", 32)} {
		if err := validateTeamIdentifier(value); err != nil {
			t.Fatalf("validateTeamIdentifier(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", `TEAM" or true`, "TEAM 123", "TÉAM123", strings.Repeat("A", 33)} {
		if err := validateTeamIdentifier(value); err == nil {
			t.Fatalf("validateTeamIdentifier(%q) unexpectedly succeeded", value)
		}
	}
}

func TestVerifyMainAppCodeSignatureRejectsUnsafeTeamBeforeTools(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	called := false
	runCodeSignTool = func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, errors.New("unexpected")
	}
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })

	got := verifyMainAppCodeSignature(nil, "Payload/Demo.app", nil, "Demo", parsedProfile{
		embeddedProfile: embeddedProfile{TeamIdentifier: []string{`TEAM" or true`}},
	})
	if got.Status != CodeSignatureInvalid || !strings.Contains(got.Reason, "unsupported characters") || called {
		t.Fatalf("verification=%#v called=%t", got, called)
	}
}

func TestVerifyMainAppCodeSignatureRejectsExpandedExecutableBeforeTools(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign verification is macOS-only")
	}
	member := &zip.File{FileHeader: zip.FileHeader{Name: "Payload/Demo.app/Demo", UncompressedSize64: uint64(maxMainAppExpandedBytes + 1)}}
	called := false
	runCodeSignTool = func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, errors.New("unexpected")
	}
	t.Cleanup(func() { runCodeSignTool = runBoundedTool })
	got := verifyMainAppCodeSignature([]*zip.File{member}, "Payload/Demo.app", nil, "Demo", parsedProfile{})
	if got.Status != CodeSignatureInvalid || called {
		t.Fatalf("verification=%#v called=%t", got, called)
	}
}

func validExecutableIPA(t *testing.T) string {
	t.Helper()
	return writeIPA(t, map[string][]byte{
		"Payload/Demo.app/Info.plist": plistBytes(t, map[string]any{
			"CFBundleIdentifier": "com.example.demo", "CFBundleName": "Demo",
			"CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "CFBundleExecutable": "Demo",
		}),
		"Payload/Demo.app/Demo": fakeMachO("main"),
		"Payload/Demo.app/embedded.mobileprovision": signedProfile(t, profileFixture{
			BundleID: "com.example.demo", Devices: []string{"one"}, Expires: time.Now().Add(time.Hour),
		}),
	})
}

func fakeMachO(payload string) []byte {
	return append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte(payload)...)
}

func validFatMachO() []byte {
	return []byte{
		0xca, 0xfe, 0xba, 0xbe, // FAT_MAGIC
		0x00, 0x00, 0x00, 0x01, // one architecture
		0x01, 0x00, 0x00, 0x0c, // CPU_TYPE_ARM64
		0x00, 0x00, 0x00, 0x00, // CPU subtype
		0x00, 0x00, 0x00, 0x1c, // slice offset
		0x00, 0x00, 0x00, 0x20, // slice size
		0x00, 0x00, 0x00, 0x02, // alignment
		0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64
		0x0c, 0x00, 0x00, 0x01, // CPU_TYPE_ARM64
		0x00, 0x00, 0x00, 0x00, // CPU subtype
		0x02, 0x00, 0x00, 0x00, // MH_EXECUTE
		0x00, 0x00, 0x00, 0x00, // no load commands
		0x00, 0x00, 0x00, 0x00, // load command size
		0x00, 0x00, 0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, // reserved
	}
}

func TestValidateExecutableNameRejectsTraversalAndFormatting(t *testing.T) {
	for _, value := range []string{"../Demo", "PlugIns/Demo", "Demo\u202Eipa", strings.Repeat("a", 256)} {
		if err := validateExecutableName(value); err == nil {
			t.Fatalf("validateExecutableName(%q) unexpectedly succeeded", value)
		}
	}
}

func TestEntitlementValuePermitsExactWildcardAndSubsetOnly(t *testing.T) {
	tests := []struct {
		name    string
		profile any
		signed  any
		want    bool
	}{
		{name: "exact", profile: "TEAM.com.example.app", signed: "TEAM.com.example.app", want: true},
		{name: "terminal wildcard", profile: "TEAM.com.example.*", signed: "TEAM.com.example.app", want: true},
		{name: "wildcard needs suffix", profile: "TEAM.com.example.*", signed: "TEAM.com.example.", want: false},
		{name: "mismatched prefix", profile: "TEAM.com.example.*", signed: "OTHER.com.example.app", want: false},
		{name: "list subset", profile: []any{"group.one", "group.two"}, signed: []any{"group.two"}, want: true},
		{name: "list extra", profile: []any{"group.one"}, signed: []any{"group.two"}, want: false},
		{name: "bool mismatch", profile: false, signed: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := entitlementValuePermits(test.profile, test.signed); got != test.want {
				t.Fatalf("entitlementValuePermits(%#v, %#v) = %t, want %t", test.profile, test.signed, got, test.want)
			}
		})
	}
}
