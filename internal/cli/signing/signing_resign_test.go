package signing

import (
	"archive/zip"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestSigningCommandExposesResign(t *testing.T) {
	command := SigningCommand()
	for _, subcommand := range command.Subcommands {
		if subcommand.Name == "resign" {
			return
		}
	}
	t.Fatal("signing command does not expose resign")
}

func TestSigningResignHelpMarksCommandSpecificFlagsExperimental(t *testing.T) {
	command := SigningResignCommand()
	for _, name := range []string{"ipa", "output", "identity", "identity-password-file", "profiles-manifest"} {
		flagValue := command.FlagSet.Lookup(name)
		if flagValue == nil {
			t.Fatalf("missing --%s flag", name)
		}
		if !strings.HasPrefix(flagValue.Usage, "[experimental] ") {
			t.Fatalf("--%s usage = %q, want [experimental] prefix", name, flagValue.Usage)
		}
	}
}

func TestSigningResignCommandRejectsInvalidFlagShapes(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "positional argument", args: []string{"unexpected"}},
		{name: "missing required flags", args: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := SigningResignCommand().Exec(context.Background(), test.args); !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("SigningResignCommand().Exec() error = %v, want flag.ErrHelp classification", err)
			}
		})
	}
}

func TestSigningResignInvalidManifestDoesNotCreateOutputParent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signing resign is macOS-only")
	}
	temporary := t.TempDir()
	inputPath := filepath.Join(temporary, "input.ipa")
	writeSigningResignMinimalIPA(t, inputPath)
	manifestPath := filepath.Join(temporary, "profiles.json")
	if err := os.WriteFile(manifestPath, []byte(`{"schemaVersion":1,"profiles":`), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(temporary, "not-created", "output.ipa")
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
		return signingResignToolOutput{}, nil
	}
	_, err := executeSigningResignImplementation(context.Background(), signingResignOptions{
		IPAPath: inputPath, OutputPath: outputPath, IdentityPath: filepath.Join(temporary, "identity.p12"), ProfilesManifestPath: manifestPath,
	})
	if err == nil || !strings.Contains(err.Error(), "profiles manifest") {
		t.Fatalf("executeSigningResignImplementation() error = %v, want invalid manifest", err)
	}
	if !isSigningResignUsageError(err) {
		t.Fatalf("executeSigningResignImplementation() error = %v, want usage classification", err)
	}
	if _, statErr := os.Stat(filepath.Dir(outputPath)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid manifest created output parent: stat error = %v", statErr)
	}
}

func TestSigningResignPreflightErrorsMapToUsageExit(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signing resign is macOS-only")
	}
	for _, test := range []struct {
		name         string
		manifest     string
		platformName string
		supported    string
		wantMessage  string
	}{
		{
			name:     "malformed manifest",
			manifest: `{"schemaVersion":1,"profiles":`,
		},
		{
			name:     "duplicate manifest field",
			manifest: `{"schemaVersion":1,"schemaVersion":1,"profiles":[]}`,
		},
		{
			name:     "unknown manifest field",
			manifest: `{"schemaVersion":1,"profiles":[],"unexpected":true}`,
		},
		{
			name:         "unsupported target platform",
			manifest:     `{"schemaVersion":1,"profiles":[]}`,
			platformName: "macosx",
			supported:    "MacOSX",
			wantMessage:  "target platform",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := t.TempDir()
			inputPath := filepath.Join(temporary, "input.ipa")
			if test.platformName == "" {
				writeSigningResignMinimalIPA(t, inputPath)
			} else {
				writeSigningResignMinimalIPAForPlatform(t, inputPath, test.platformName, test.supported)
			}
			manifestPath := filepath.Join(temporary, "profiles.json")
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}

			originalTool := runSigningResignToolFn
			t.Cleanup(func() { runSigningResignToolFn = originalTool })
			runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
				return signingResignToolOutput{}, nil
			}
			original := executeSigningResignFn
			t.Cleanup(func() { executeSigningResignFn = original })
			executeSigningResignFn = executeSigningResignImplementation
			command := SigningResignCommand()
			if err := command.FlagSet.Parse([]string{
				"--ipa", inputPath,
				"--output", filepath.Join(temporary, "output.ipa"),
				"--identity", filepath.Join(temporary, "identity.p12"),
				"--profiles-manifest", manifestPath,
			}); err != nil {
				t.Fatal(err)
			}
			err := command.Exec(context.Background(), nil)
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("SigningResignCommand().Exec() error = %v, want usage/exit-2 classification", err)
			}
			if test.wantMessage != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantMessage)) {
				t.Fatalf("SigningResignCommand().Exec() error = %v, want %q", err, test.wantMessage)
			}
		})
	}
}

func TestSigningResignCommandClassifiesPreflightUsageOnly(t *testing.T) {
	original := executeSigningResignFn
	t.Cleanup(func() { executeSigningResignFn = original })
	makeCommand := func() *ffcli.Command {
		command := SigningResignCommand()
		if err := command.FlagSet.Parse([]string{
			"--ipa", "input.ipa",
			"--output", "output.ipa",
			"--identity", "identity.p12",
			"--profiles-manifest", "profiles.json",
		}); err != nil {
			t.Fatal(err)
		}
		return command
	}

	executeSigningResignFn = func(context.Context, signingResignOptions) (signingResignResult, error) {
		return signingResignResult{}, signingResignUsage(errors.New("profiles manifest contains duplicate fields"))
	}
	if err := makeCommand().Exec(context.Background(), nil); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("preflight usage error = %v, want flag.ErrHelp classification", err)
	}

	executeSigningResignFn = func(context.Context, signingResignOptions) (signingResignResult, error) {
		return signingResignResult{}, errors.New("codesign failed")
	}
	if err := makeCommand().Exec(context.Background(), nil); err == nil || errors.Is(err, flag.ErrHelp) {
		t.Fatalf("operational error = %v, want non-usage error", err)
	}
}

func TestSigningResignOperationalFailuresRemainExecutionErrors(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signing resign is macOS-only")
	}
	original := executeSigningResignFn
	t.Cleanup(func() { executeSigningResignFn = original })
	for _, message := range []string{
		"invalid ZIP archive",
		"unsafe archive entry",
		"missing profile",
		"profile-target mismatch",
		"entitlement preparation failed",
		"codesign failed",
		"verification failed",
	} {
		t.Run(message, func(t *testing.T) {
			executeSigningResignFn = func(context.Context, signingResignOptions) (signingResignResult, error) {
				return signingResignResult{}, errors.New(message)
			}
			command := SigningResignCommand()
			if err := command.FlagSet.Parse([]string{
				"--ipa", "input.ipa",
				"--output", "output.ipa",
				"--identity", "identity.p12",
				"--profiles-manifest", "profiles.json",
			}); err != nil {
				t.Fatal(err)
			}
			err := command.Exec(context.Background(), nil)
			if err == nil || errors.Is(err, flag.ErrHelp) {
				t.Fatalf("SigningResignCommand().Exec() error = %v, want execution failure", err)
			}
		})
	}
}

func TestReadSigningResignManifestFileFailureRemainsExecutionError(t *testing.T) {
	_, err := readSigningResignManifest(filepath.Join(t.TempDir(), "missing-profiles.json"))
	if err == nil || isSigningResignUsageError(err) {
		t.Fatalf("readSigningResignManifest() error = %v, want non-usage file failure", err)
	}
}

func TestSigningResignInvalidFormatDoesNotCreateOutputParent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signing resign is macOS-only")
	}
	temporary := t.TempDir()
	outputPath := filepath.Join(temporary, "not-created", "output.ipa")
	command := SigningResignCommand()
	if err := command.FlagSet.Parse([]string{
		"--ipa", filepath.Join(temporary, "input.ipa"),
		"--output", outputPath,
		"--identity", filepath.Join(temporary, "identity.p12"),
		"--profiles-manifest", filepath.Join(temporary, "profiles.json"),
		"--format", "yaml",
	}); err != nil {
		t.Fatal(err)
	}
	err := command.Exec(context.Background(), nil)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "one of") {
		t.Fatalf("SigningResignCommand().Exec() error = %v, want invalid output format", err)
	}
	if _, statErr := os.Stat(filepath.Dir(outputPath)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid format created output parent: stat error = %v", statErr)
	}
}

func writeSigningResignMinimalIPA(t *testing.T, pathValue string) {
	writeSigningResignMinimalIPAForPlatform(t, pathValue, "iphoneos", "iPhoneOS")
}

func writeSigningResignMinimalIPAForPlatform(t *testing.T, pathValue, platformName, supportedPlatform string) {
	t.Helper()
	info, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleExecutable":         "App",
		"DTPlatformName":             platformName,
		"CFBundleSupportedPlatforms": []string{supportedPlatform},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	executable := []byte{
		0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
		0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Info.plist", data: info},
		{name: "Payload/App.app/App", data: executable},
	})
	if err := os.WriteFile(pathValue, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSigningResignIPAWithNestedExtension(t *testing.T, pathValue string) {
	t.Helper()
	platform := map[string]any{
		"DTPlatformName":             "iphoneos",
		"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
	}
	mainInfo := make(map[string]any, len(platform)+2)
	for key, value := range platform {
		mainInfo[key] = value
	}
	mainInfo["CFBundleIdentifier"] = "com.example.app"
	mainInfo["CFBundleExecutable"] = "App"
	extensionInfo := make(map[string]any, len(platform)+2)
	for key, value := range platform {
		extensionInfo[key] = value
	}
	extensionInfo["CFBundleIdentifier"] = "com.example.app.extension"
	extensionInfo["CFBundleExecutable"] = "Extension"
	mainPlist, err := plist.Marshal(mainInfo, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	extensionPlist, err := plist.Marshal(extensionInfo, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	executable := []byte{
		0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
		0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Info.plist", data: mainPlist},
		{name: "Payload/App.app/App", data: executable, mode: 0o755},
		{name: "Payload/App.app/PlugIns/Extension.appex/Info.plist", data: extensionPlist},
		{name: "Payload/App.app/PlugIns/Extension.appex/Extension", data: executable, mode: 0o755},
	})
	if err := os.WriteFile(pathValue, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeSigningResignManifestStrict(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "valid",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"profiles/app.mobileprovision"}]}`,
		},
		{
			name: "unknown field",
			data: `{"schemaVersion":1,"profiles":[],"extra":true}`,
			want: "decode profiles manifest",
		},
		{
			name: "duplicate field",
			data: `{"schemaVersion":1,"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"app.mobileprovision"}]}`,
			want: "duplicate",
		},
		{
			name: "wildcard bundle",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.*","profilePath":"app.mobileprovision"}]}`,
			want: "non-wildcard",
		},
		{
			name: "traversal profile",
			data: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"../app.mobileprovision"}]}`,
			want: "escapes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, err := decodeSigningResignManifest([]byte(test.data))
			if test.want == "" {
				if err != nil {
					t.Fatalf("decodeSigningResignManifest() error = %v", err)
				}
				if len(manifest.Profiles) != 1 || manifest.Profiles[0].BundleID != "com.example.app" {
					t.Fatalf("decoded manifest = %#v", manifest)
				}
				return
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("decodeSigningResignManifest() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateSigningResignManifestTargetsClassifiesMappingShapeAsUsage(t *testing.T) {
	targetIDs := map[string]struct{}{"com.example.app": {}}
	for _, test := range []struct {
		name     string
		manifest signingResignManifest
	}{
		{
			name: "missing mapping",
			manifest: signingResignManifest{Profiles: []signingResignManifestEntry{
				{BundleID: "com.example.app"},
				{BundleID: "com.example.extension"},
			}},
		},
		{
			name: "extra mapping",
			manifest: signingResignManifest{Profiles: []signingResignManifestEntry{
				{BundleID: "com.example.other"},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSigningResignManifestTargets(test.manifest, targetIDs)
			if err == nil || !isSigningResignUsageError(err) {
				t.Fatalf("validateSigningResignManifestTargets() error = %v, want usage classification", err)
			}
		})
	}
}

func TestSigningResignCommandClassifiesManifestTargetMappingErrorsAsUsage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("signing resign is macOS-only")
	}
	originalTool := runSigningResignToolFn
	originalExecute := executeSigningResignFn
	t.Cleanup(func() {
		runSigningResignToolFn = originalTool
		executeSigningResignFn = originalExecute
	})
	runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
		return signingResignToolOutput{}, nil
	}
	executeSigningResignFn = executeSigningResignImplementation
	for _, test := range []struct {
		name     string
		writeIPA func(*testing.T, string)
		manifest string
	}{
		{
			name:     "missing target mapping",
			writeIPA: writeSigningResignIPAWithNestedExtension,
			manifest: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":"profile.mobileprovision"}]}`,
		},
		{
			name:     "extra target mapping",
			writeIPA: writeSigningResignMinimalIPA,
			manifest: `{"schemaVersion":1,"profiles":[{"bundleId":"com.example.other","profilePath":"profile.mobileprovision"}]}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := t.TempDir()
			inputPath := filepath.Join(temporary, "input.ipa")
			test.writeIPA(t, inputPath)
			manifestPath := filepath.Join(temporary, "profiles.json")
			if err := os.WriteFile(manifestPath, []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			command := SigningResignCommand()
			if err := command.FlagSet.Parse([]string{
				"--ipa", inputPath,
				"--output", filepath.Join(temporary, "output.ipa"),
				"--identity", filepath.Join(temporary, "identity.p12"),
				"--profiles-manifest", manifestPath,
			}); err != nil {
				t.Fatal(err)
			}
			err := command.Exec(context.Background(), nil)
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("SigningResignCommand().Exec() error = %v, want usage/exit-2 classification", err)
			}
		})
	}
}

func TestReadSigningResignManifestPreservesWhitespacePathBytes(t *testing.T) {
	temporary := t.TempDir()
	manifestPath := filepath.Join(temporary, " profiles manifest.json ")
	profilePath := " profiles/profile.mobileprovision "
	manifestData := []byte(`{"schemaVersion":1,"profiles":[{"bundleId":"com.example.app","profilePath":" profiles/profile.mobileprovision "}]}`)
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}

	manifest, err := readSigningResignManifest(manifestPath)
	if err != nil {
		t.Fatalf("readSigningResignManifest() error = %v", err)
	}
	if got := manifest.Profiles[0].ProfilePath; got != profilePath {
		t.Fatalf("manifest profile path = %q, want exact path bytes %q", got, profilePath)
	}
}

func TestSigningResignCommandPreservesPathBytes(t *testing.T) {
	original := executeSigningResignFn
	t.Cleanup(func() { executeSigningResignFn = original })
	var got signingResignOptions
	executeSigningResignFn = func(_ context.Context, options signingResignOptions) (signingResignResult, error) {
		got = options
		return signingResignResult{SchemaVersion: 1, Command: "signing resign"}, nil
	}

	command := SigningResignCommand()
	values := []string{
		"--ipa", " input.ipa ",
		"--output", " output.ipa ",
		"--identity", " identity.p12 ",
		"--identity-password-file", " password file ",
		"--profiles-manifest", " profiles manifest.json ",
		"--format", "json",
	}
	if err := command.FlagSet.Parse(values); err != nil {
		t.Fatal(err)
	}
	if err := command.Exec(context.Background(), nil); err != nil {
		t.Fatalf("SigningResignCommand().Exec() error = %v", err)
	}
	want := signingResignOptions{
		IPAPath:              " input.ipa ",
		OutputPath:           " output.ipa ",
		IdentityPath:         " identity.p12 ",
		IdentityPasswordPath: " password file ",
		ProfilesManifestPath: " profiles manifest.json ",
	}
	if got != want {
		t.Fatalf("command options = %#v, want exact path bytes %#v", got, want)
	}
	if got := signingResignPathOrEmpty("   \t"); got != "" {
		t.Fatalf("whitespace-only optional path = %q, want empty", got)
	}
}

func TestExtractSigningResignCertificateMatchesOnlyLeaf(t *testing.T) {
	leafKey := mustRSAKey(t)
	chainKey := mustRSAKey(t)
	leaf := mustSigningCertificate(t, leafKey, 101)
	chain := mustSigningCertificate(t, chainKey, 102)
	original := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = original })
	runSigningResignToolFn = func(_ context.Context, _ string, args ...string) (signingResignToolOutput, error) {
		for _, arg := range args {
			if prefix, ok := strings.CutPrefix(arg, "--extract-certificates="); ok {
				if err := os.WriteFile(prefix+"0", leaf.Raw, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(prefix+"1", chain.Raw, 0o600); err != nil {
					t.Fatal(err)
				}
				return signingResignToolOutput{}, nil
			}
		}
		return signingResignToolOutput{}, nil
	}

	if err := extractSigningResignCertificate(context.Background(), "/tmp/app", certificateSHA256(leaf)); err != nil {
		t.Fatalf("extractSigningResignCertificate() leaf error = %v", err)
	}
	if err := extractSigningResignCertificate(context.Background(), "/tmp/app", certificateSHA256(chain)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("extractSigningResignCertificate() chain error = %v, want leaf-only mismatch", err)
	}
}

func TestBuildSigningResignEntitlementsReplacesIdentity(t *testing.T) {
	existing := map[string]any{
		"application-identifier":                "OLDTEAM.com.example.app",
		"com.apple.application-identifier":      "OLDTEAM.com.example.app",
		"com.apple.developer.team-identifier":   "OLDTEAM",
		"get-task-allow":                        true,
		"com.apple.security.application-groups": []string{"group.com.example"},
	}
	profile := map[string]any{
		"application-identifier":                "NEWTEAM.com.example.app",
		"com.apple.application-identifier":      "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier":   "NEWTEAM",
		"get-task-allow":                        false,
		"com.apple.security.application-groups": []any{"group.com.example", "group.other"},
	}
	got, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		t.Fatalf("buildSigningResignEntitlements() error = %v", err)
	}
	if got["application-identifier"] != "NEWTEAM.com.example.app" || got["com.apple.developer.team-identifier"] != "NEWTEAM" {
		t.Fatalf("identity entitlements = %#v", got)
	}
	if got["get-task-allow"] != false || len(got) != len(existing) {
		t.Fatalf("rewritten entitlements = %#v", got)
	}
	if !signingResignEntitlementValuePermits(profile["com.apple.security.application-groups"], got["com.apple.security.application-groups"]) {
		t.Fatalf("capability entitlement was not preserved: %#v", got)
	}
}

func TestBuildSigningResignEntitlementsKeepsConcreteValuesForWildcardProfileClaims(t *testing.T) {
	existing := map[string]any{
		"application-identifier":                             "OLDTEAM.com.example.app",
		"com.apple.application-identifier":                   "OLDTEAM.com.example.app",
		"com.apple.developer.team-identifier":                "OLDTEAM",
		"get-task-allow":                                     true,
		"keychain-access-groups":                             []string{"NEWTEAM.com.example.shared"},
		"com.apple.developer.ubiquity-kvstore-identifier":    "NEWTEAM.com.example.app",
		"com.apple.developer.parent-application-identifiers": []string{"NEWTEAM.com.example.parent"},
	}
	profile := map[string]any{
		"application-identifier":                             "NEWTEAM.com.example.app",
		"com.apple.application-identifier":                   "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier":                "NEWTEAM",
		"get-task-allow":                                     false,
		"keychain-access-groups":                             []any{"NEWTEAM.*"},
		"com.apple.developer.ubiquity-kvstore-identifier":    "NEWTEAM.*",
		"com.apple.developer.parent-application-identifiers": []any{"NEWTEAM.*"},
	}

	got, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		t.Fatalf("buildSigningResignEntitlements() error = %v", err)
	}
	for _, key := range []string{
		"keychain-access-groups",
		"com.apple.developer.ubiquity-kvstore-identifier",
		"com.apple.developer.parent-application-identifiers",
	} {
		if !signingResignEntitlementValuesEqual(got[key], existing[key]) {
			t.Fatalf("identity entitlement %s = %#v, want concrete existing value %#v", key, got[key], existing[key])
		}
		if signingResignEntitlementContainsWildcard(got[key]) {
			t.Fatalf("identity entitlement %s retained a wildcard: %#v", key, got[key])
		}
	}
}

func TestValidateSigningResignExistingEntitlementsRequiresCoherentIdentity(t *testing.T) {
	base := map[string]any{
		"application-identifier":              "OLDTEAM.com.example.app",
		"com.apple.developer.team-identifier": "OLDTEAM",
	}
	for _, test := range []struct {
		name       string
		mutate     func(map[string]any)
		wantErr    bool
		wantDetail string
	}{
		{
			name: "coherent old identity",
		},
		{
			name: "contradictory application identifiers",
			mutate: func(values map[string]any) {
				values["com.apple.application-identifier"] = "DIFFERENT.com.example.app"
			},
			wantErr:    true,
			wantDetail: "contradictory",
		},
		{
			name: "application identifier suffix mismatch",
			mutate: func(values map[string]any) {
				values["application-identifier"] = "OLDTEAM.com.example.other"
			},
			wantErr:    true,
			wantDetail: "target bundle identifier",
		},
		{
			name: "legacy prefix differs from old team",
			mutate: func(values map[string]any) {
				values["com.apple.developer.team-identifier"] = "DIFFERENT"
			},
		},
		{
			name: "missing optional synonym",
			mutate: func(values map[string]any) {
				delete(values, "com.apple.application-identifier")
			},
		},
		{
			name: "wildcard application identifier",
			mutate: func(values map[string]any) {
				values["application-identifier"] = "OLDTEAM.com.example.*"
			},
			wantErr:    true,
			wantDetail: "invalid",
		},
		{
			name: "team-only concrete claim",
			mutate: func(values map[string]any) {
				delete(values, "application-identifier")
			},
		},
		{
			name: "wildcard team identifier",
			mutate: func(values map[string]any) {
				values["com.apple.developer.team-identifier"] = "OLD*TEAM"
			},
			wantErr:    true,
			wantDetail: "invalid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]any, len(base)+1)
			for key, value := range base {
				values[key] = value
			}
			if test.mutate != nil {
				test.mutate(values)
			}
			err := validateSigningResignExistingEntitlements(values, "com.example.app")
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSigningResignExistingEntitlements() error = %v, wantErr %v", err, test.wantErr)
			}
			if test.wantDetail != "" && (err == nil || !strings.Contains(err.Error(), test.wantDetail)) {
				t.Fatalf("validateSigningResignExistingEntitlements() error = %v, want %q", err, test.wantDetail)
			}
		})
	}
}

func TestSigningResignExistingOtherTeamCanBeReplaced(t *testing.T) {
	existing := map[string]any{
		"application-identifier":              "OTHERPREFIX.com.example.app",
		"com.apple.developer.team-identifier": "OTHERTEAM",
	}
	if err := validateSigningResignExistingEntitlements(existing, "com.example.app"); err != nil {
		t.Fatalf("validateSigningResignExistingEntitlements() error = %v", err)
	}
	profile := map[string]any{
		"application-identifier":              "NEWTEAM.com.example.app",
		"com.apple.application-identifier":    "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier": "NEWTEAM",
		"get-task-allow":                      false,
	}
	got, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		t.Fatalf("buildSigningResignEntitlements() error = %v", err)
	}
	if got["application-identifier"] != "NEWTEAM.com.example.app" || got["com.apple.developer.team-identifier"] != "NEWTEAM" {
		t.Fatalf("rewritten identity entitlements = %#v", got)
	}
}

func TestPrepareSigningResignTreeRejectsIncoherentInputBeforeMutation(t *testing.T) {
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	profile := signingResignProfile{Data: []byte("profile"), Entitlements: map[string]any{
		"application-identifier":              "NEWTEAM.com.example.app",
		"com.apple.application-identifier":    "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier": "NEWTEAM",
		"get-task-allow":                      false,
	}}
	_, err = prepareSigningResignTree(context.Background(), stageRoot, treeRoot, signingResignArchive{Targets: []signingResignTarget{{
		RelativePath: "Payload/App.app", BundleID: "com.example.app", ExistingEntitlements: map[string]any{
			"application-identifier":              "OLDTEAM.com.example.other",
			"com.apple.developer.team-identifier": "OLDTEAM",
		},
	}}}, map[string]signingResignProfile{"com.example.app": profile})
	if err == nil {
		t.Fatal("prepareSigningResignTree() accepted incoherent input entitlements")
	}
	if _, statErr := os.Stat(filepath.Join(stagePath, "entitlements")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("incoherent input created private entitlements directory: %v", statErr)
	}
}

func TestValidateSigningResignProfileForTarget(t *testing.T) {
	profile := signingResignProfile{
		BundleID: "com.example.app", TeamID: "NEWTEAM", ApplicationIdentifierPrefix: "NEWTEAM",
		Entitlements: map[string]any{
			"application-identifier":              "NEWTEAM.com.example.app",
			"com.apple.application-identifier":    "NEWTEAM.com.example.app",
			"com.apple.developer.team-identifier": "NEWTEAM",
		},
	}
	if err := validateSigningResignProfileForTarget(profile, "com.example.app"); err != nil {
		t.Fatalf("validateSigningResignProfileForTarget() error = %v", err)
	}
	profile.Entitlements["application-identifier"] = "NEWTEAM.com.example.other"
	if err := validateSigningResignProfileForTarget(profile, "com.example.app"); err == nil {
		t.Fatal("validateSigningResignProfileForTarget() accepted mismatched profile identifier")
	}
}

func TestBuildSigningResignEntitlementsRejectsUnpermittedCapability(t *testing.T) {
	_, err := buildSigningResignEntitlements(
		map[string]any{"com.apple.security.application-groups": []string{"group.not-permitted"}},
		map[string]any{
			"application-identifier":                "TEAM.com.example.app",
			"com.apple.developer.team-identifier":   "TEAM",
			"get-task-allow":                        false,
			"com.apple.security.application-groups": []any{"group.allowed"},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("buildSigningResignEntitlements() error = %v, want unpermitted capability", err)
	}
}

func TestValidateSigningResignArchiveRejectsPathCollisions(t *testing.T) {
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/a/file", data: []byte("x")},
		{name: "Payload/App.app/a", data: []byte("not-a-directory")},
	})
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSigningResignArchive(context.Background(), reader); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("validateSigningResignArchive() error = %v, want collision", err)
	}
}

func TestSnapshotSigningResignIPAComputesDigestAndDoesNotRewriteSource(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.ipa")
	contents := []byte("deterministic ipa bytes")
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stagePath := filepath.Join(directory, "stage")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	snapshot, digest, err := snapshotSigningResignIPA(context.Background(), source, int64(len(contents)), stage)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if digest != signingResignSHA256(contents) {
		t.Fatalf("snapshot digest = %q, want %q", digest, signingResignSHA256(contents))
	}
	snapshotData, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshotData, contents) {
		t.Fatalf("snapshot data = %q, want %q", snapshotData, contents)
	}
	sourceData, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sourceData, contents) {
		t.Fatalf("source changed to %q", sourceData)
	}
}

func TestSigningResignToolInvocationsUseExplicitKeychainAndNoDeepMutation(t *testing.T) {
	original := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = original })
	var calls [][]string
	runSigningResignToolFn = func(_ context.Context, executable string, args ...string) (signingResignToolOutput, error) {
		calls = append(calls, append([]string{executable}, args...))
		return signingResignToolOutput{}, nil
	}
	if err := signSigningResignObject(context.Background(), "/tmp/object", "ABC123", "/tmp/keychain", "/tmp/entitlements.plist"); err != nil {
		t.Fatal(err)
	}
	if err := verifySigningResignObject(context.Background(), "/tmp/object", "TEAM", false); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("tool calls = %#v", calls)
	}
	if strings.Contains(strings.Join(calls[0], " "), "--deep") || !strings.Contains(strings.Join(calls[0], " "), "--keychain /tmp/keychain") {
		t.Fatalf("sign invocation = %#v", calls[0])
	}
	if strings.Contains(strings.Join(calls[1], " "), "--deep") {
		t.Fatalf("leaf verify invocation unexpectedly deep = %#v", calls[1])
	}
}

func TestSigningResignResultRedactsInputPath(t *testing.T) {
	result := signingResignResult{
		SchemaVersion: 1,
		Command:       "signing resign",
		Input: signingResignInputResult{
			SizeBytes: 42,
			SHA256:    strings.Repeat("A", 64),
		},
		Output: signingResignArtifactResult{
			Path:      "/safe/output/resigned.ipa",
			SizeBytes: 42,
			SHA256:    strings.Repeat("B", 64),
		},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "source-private-input") {
		t.Fatalf("result unexpectedly contains a source path: %s", encoded)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	var input map[string]any
	if err := json.Unmarshal(decoded["input"], &input); err != nil {
		t.Fatal(err)
	}
	if _, exists := input["path"]; exists {
		t.Fatalf("input result unexpectedly exposes path: %s", encoded)
	}
	if _, exists := decoded["output"]; !exists {
		t.Fatalf("result lost output artifact: %s", encoded)
	}
}

func TestValidateSigningResignPlatformAcceptsWatchOSForWatchTargets(t *testing.T) {
	tests := []struct {
		name    string
		kind    string
		info    map[string]any
		wantErr bool
		usage   bool
	}{
		{
			name: "watch application",
			kind: "watch-application",
			info: map[string]any{
				"DTPlatformName":             "watchos",
				"CFBundleSupportedPlatforms": []string{"WatchOS"},
			},
		},
		{
			name: "watch extension",
			kind: "watch-extension",
			info: map[string]any{
				"DTPlatformName":             "watchos",
				"CFBundleSupportedPlatforms": []string{"WatchOS"},
			},
		},
		{
			name: "watch application platform only",
			kind: "watch-application",
			info: map[string]any{"DTPlatformName": "watchos"},
		},
		{
			name: "iOS application",
			kind: "application",
			info: map[string]any{
				"DTPlatformName":             "iphoneos",
				"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
			},
		},
		{
			name:    "watch metadata on iOS target",
			kind:    "application",
			info:    map[string]any{"DTPlatformName": "watchos"},
			wantErr: true,
			usage:   true,
		},
		{
			name:    "iOS metadata on watch target",
			kind:    "watch-application",
			info:    map[string]any{"DTPlatformName": "iphoneos"},
			wantErr: true,
			usage:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSigningResignPlatform(test.info, test.kind)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSigningResignPlatform() error = %v, wantErr %v", err, test.wantErr)
			}
			if isSigningResignUsageError(err) != test.usage {
				t.Fatalf("validateSigningResignPlatform() usage = %v, want %v (error = %v)", isSigningResignUsageError(err), test.usage, err)
			}
		})
	}
}

func TestSortSigningResignCodePlansIsLeafFirst(t *testing.T) {
	plans := []signingResignCodePlan{
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Outer.framework", "Outer")},
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Outer.framework", "Versions", "A", "Inner")},
		{Path: filepath.Join("tree", "App.app", "Frameworks", "Other.framework", "Other")},
	}
	sortSigningResignCodePlans(plans)
	innerIndex, outerIndex := -1, -1
	for index, plan := range plans {
		if strings.HasSuffix(plan.Path, filepath.Join("Versions", "A", "Inner")) {
			innerIndex = index
		}
		if strings.HasSuffix(plan.Path, filepath.Join("Outer.framework", "Outer")) {
			outerIndex = index
		}
	}
	if innerIndex < 0 || outerIndex < 0 || innerIndex >= outerIndex {
		t.Fatalf("outer framework executable was scheduled before its nested code: %#v", plans)
	}
}

func TestPrepareSigningResignTreePreservesSwiftSupportDylibs(t *testing.T) {
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	appPath := filepath.Join(treePath, "Payload", "App.app")
	if err := os.MkdirAll(appPath, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appPath, "App"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	swiftPath := filepath.Join(treePath, "SwiftSupport", "iphoneos")
	if err := os.MkdirAll(swiftPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(swiftPath, "libswiftCore.dylib"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
		return signingResignToolOutput{}, nil
	}
	profile := signingResignProfile{
		Data: []byte("profile"),
		Entitlements: map[string]any{
			"application-identifier":              "TEAM.com.example.app",
			"com.apple.application-identifier":    "TEAM.com.example.app",
			"com.apple.developer.team-identifier": "TEAM",
			"get-task-allow":                      false,
		},
	}
	prepared, err := prepareSigningResignTree(context.Background(), stageRoot, treeRoot, signingResignArchive{
		MainPath: "Payload/App.app",
		Targets: []signingResignTarget{{
			Kind: "application", RelativePath: "Payload/App.app", BundleID: "com.example.app", Executable: "App", ProfileMode: 0o644,
		}},
	}, map[string]signingResignProfile{"com.example.app": profile})
	if err != nil {
		t.Fatalf("prepareSigningResignTree() error = %v", err)
	}
	if len(prepared.CodePlans) != 0 {
		t.Fatalf("SwiftSupport dylib was scheduled for app signing: %#v", prepared.CodePlans)
	}
	if got := mustReadFile(t, filepath.Join(swiftPath, "libswiftCore.dylib")); !bytes.Equal(got, data) {
		t.Fatal("SwiftSupport dylib changed during preparation")
	}
}

func TestSigningResignPreservedExternalCodeRequiresAppleVerification(t *testing.T) {
	if !isSigningResignPreservedExternalCodePath("/tmp/tree", "/tmp/tree/SwiftSupport/iphoneos/libswiftCore.dylib") {
		t.Fatal("exact SwiftSupport path was not recognized")
	}
	for _, pathValue := range []string{
		"/tmp/tree/SwiftSupport/iphoneos/nested/libswiftCore.dylib",
		"/tmp/tree/SwiftSupport/iphoneos/libswiftCore.DYLIB",
		"/tmp/tree/SwiftSupport/iphoneos/.dylib",
	} {
		if isSigningResignPreservedExternalCodePath("/tmp/tree", pathValue) {
			t.Fatalf("unsafe SwiftSupport path was accepted: %q", pathValue)
		}
	}
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	var calls [][]string
	runSigningResignToolFn = func(_ context.Context, executable string, args ...string) (signingResignToolOutput, error) {
		calls = append(calls, append([]string{executable}, args...))
		return signingResignToolOutput{}, errors.New("code signature is invalid")
	}
	err := verifySigningResignPreservedExternalCode(context.Background(), "/tmp/tree/SwiftSupport/iphoneos/libswiftCore.dylib")
	if err == nil {
		t.Fatal("verifySigningResignPreservedExternalCode() accepted an unverified artifact")
	}
	if len(calls) != 1 || len(calls[0]) < 6 || calls[0][1] != "--verify" || calls[0][2] != "--strict" || calls[0][4] != "-R=anchor apple generic" {
		t.Fatalf("SwiftSupport verification calls = %#v", calls)
	}
}

func TestValidateSigningResignSwiftSupportRejectsTamperedAndNestedEntries(t *testing.T) {
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string
	}{
		{
			name: "unsigned dylib",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "libswiftCore.dylib"), []byte("tampered"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "verify preserved SwiftSupport code",
		},
		{
			name: "nested entry",
			setup: func(t *testing.T, root string) {
				t.Helper()
				nested := filepath.Join(root, "nested")
				if err := os.Mkdir(nested, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(nested, "libswiftCore.dylib"), []byte("nested"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "nested",
		},
		{
			name: "direct non-dylib entry",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, "README"), []byte("unexpected"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "unsupported",
		},
		{
			name: "symbolic link",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "z-libswiftCore-real.dylib")
				if err := os.WriteFile(target, []byte("runtime"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(root, "libswiftCore.dylib")); err != nil {
					t.Skipf("symlink creation unavailable: %v", err)
				}
			},
			want: "nested or symbolic-link",
		},
		{
			name: "root file",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(filepath.Dir(root), "README"), []byte("unexpected"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "only the iphoneos directory",
		},
		{
			name: "other platform directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(filepath.Dir(root), "watchos"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "only the iphoneos directory",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := t.TempDir()
			root := filepath.Join(temporary, "SwiftSupport", "iphoneos")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			test.setup(t, root)
			runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
				return signingResignToolOutput{}, errors.New("code object is not signed")
			}
			err := validateSigningResignSwiftSupport(context.Background(), temporary)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateSigningResignSwiftSupport() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateSigningResignSwiftSupportAcceptsCanonicalLayout(t *testing.T) {
	temporary := t.TempDir()
	root := filepath.Join(temporary, "SwiftSupport", "iphoneos")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "libswiftCore.dylib"), []byte("signed runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	var verified []string
	runSigningResignToolFn = func(_ context.Context, executable string, args ...string) (signingResignToolOutput, error) {
		verified = append(verified, executable+" "+strings.Join(args, " "))
		return signingResignToolOutput{}, nil
	}
	if err := validateSigningResignSwiftSupport(context.Background(), temporary); err != nil {
		t.Fatalf("validateSigningResignSwiftSupport() error = %v", err)
	}
	if len(verified) != 1 || !strings.Contains(verified[0], "--verify") || !strings.Contains(verified[0], "SwiftSupport/iphoneos/libswiftCore.dylib") {
		t.Fatalf("SwiftSupport verification calls = %#v", verified)
	}
}

func TestVerifyPackedSigningResignIPARejectsTamperedSwiftSupportAfterRepack(t *testing.T) {
	info, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleExecutable":         "App",
		"DTPlatformName":             "iphoneos",
		"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	packedData := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Info.plist", data: info},
		{name: "Payload/App.app/App", data: []byte("macho"), mode: 0o755},
		{name: "SwiftSupport/iphoneos/libswiftCore.dylib", data: []byte("tampered runtime"), mode: 0o755},
	})
	temporary := t.TempDir()
	packedPath := filepath.Join(temporary, "packed.ipa")
	if err := os.WriteFile(packedPath, packedData, 0o600); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(temporary)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	runSigningResignToolFn = func(_ context.Context, _ string, args ...string) (signingResignToolOutput, error) {
		if len(args) > 0 && args[0] == "--verify" {
			return signingResignToolOutput{}, errors.New("tampered SwiftSupport runtime is not Apple-signed")
		}
		return signingResignToolOutput{}, nil
	}
	fileInfo, err := os.Stat(packedPath)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyPackedSigningResignIPA(context.Background(), packedPath, fileInfo.Size(), stageRoot, filepath.Join(temporary, "tree"), signingResignPreparedTree{}, "TEAM", strings.Repeat("A", 64))
	if err == nil || !strings.Contains(err.Error(), "SwiftSupport") {
		t.Fatalf("verifyPackedSigningResignIPA() error = %v, want final SwiftSupport provenance failure", err)
	}
}

func TestSigningResignToolContextHonorsCallerDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	caller, cancelCaller := context.WithDeadline(context.Background(), deadline)
	deferred, cancelDeferred := signingResignToolContext(caller, signingResignToolTimeout)
	deferredDeadline, ok := deferred.Deadline()
	if !ok || !deferredDeadline.Equal(deadline) {
		t.Fatalf("caller deadline = %v, want %v", deferredDeadline, deadline)
	}
	cancelDeferred()
	cancelCaller()

	fallback, cancelFallback := signingResignToolContext(context.Background(), signingResignToolTimeout)
	fallbackDeadline, ok := fallback.Deadline()
	if !ok || time.Until(fallbackDeadline) < 4*time.Minute {
		t.Fatalf("fallback deadline = %v, want a realistic multi-minute phase timeout", fallbackDeadline)
	}
	cancelFallback()
}

func TestValidateSigningResignOptionsUsesDeterministicRequiredOrder(t *testing.T) {
	tests := []struct {
		name    string
		options signingResignOptions
		want    string
	}{
		{name: "input", options: signingResignOptions{}, want: "IPA input"},
		{name: "output", options: signingResignOptions{IPAPath: "input.ipa"}, want: "IPA output"},
		{name: "identity", options: signingResignOptions{IPAPath: "input.ipa", OutputPath: "output.ipa"}, want: "signing identity"},
		{name: "manifest", options: signingResignOptions{IPAPath: "input.ipa", OutputPath: "output.ipa", IdentityPath: "identity.p12"}, want: "profiles manifest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSigningResignOptions(test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateSigningResignOptions() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateSigningResignVerifiedEntitlementsRequiresExactGeneratedDocument(t *testing.T) {
	existing := map[string]any{
		"application-identifier":              "OLDTEAM.com.example.app",
		"com.apple.application-identifier":    "OLDTEAM.com.example.app",
		"com.apple.developer.team-identifier": "OLDTEAM",
		"get-task-allow":                      false,
		"keychain-access-groups":              []string{"NEWTEAM.com.example.shared"},
	}
	profile := map[string]any{
		"application-identifier":              "NEWTEAM.com.example.app",
		"com.apple.application-identifier":    "NEWTEAM.com.example.app",
		"com.apple.developer.team-identifier": "NEWTEAM",
		"get-task-allow":                      false,
		"keychain-access-groups":              []any{"NEWTEAM.*"},
	}
	want, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		t.Fatal(err)
	}
	actual := make(map[string]any, len(want))
	for key, value := range want {
		actual[key] = value
	}
	actual["keychain-access-groups"] = []string{"NEWTEAM.other"}
	if !signingResignEntitlementValuePermits(profile["keychain-access-groups"], actual["keychain-access-groups"]) {
		t.Fatal("test setup does not exercise the profile wildcard subset case")
	}
	if err := validateSigningResignVerifiedEntitlements(actual, existing, profile, "com.example.app"); err == nil || !strings.Contains(err.Error(), "exactly match") {
		t.Fatalf("validateSigningResignVerifiedEntitlements() error = %v, want exact-document rejection", err)
	}
}

func TestRebaseSigningResignPreparedTreeKeepsOriginalInventoryAndDocuments(t *testing.T) {
	originalRoot := t.TempDir()
	packedRoot := t.TempDir()
	originalExecutable := filepath.Join(originalRoot, "Payload", "App.app", "Frameworks", "Feature.framework", "Feature")
	nestedEntitlements := filepath.Join(originalRoot, "entitlements", "code-000001.plist")
	targetEntitlements := filepath.Join(originalRoot, "entitlements", "target-000.plist")
	original := signingResignPreparedTree{
		Archive: signingResignArchive{
			MainPath: "Payload/App.app",
			Targets: []signingResignTarget{{
				Kind:                 "application",
				RelativePath:         "Payload/App.app",
				BundleID:             "com.example.app",
				Executable:           "App",
				ProfileMode:          0o644,
				EntitlementsPath:     targetEntitlements,
				ExistingEntitlements: map[string]any{"com.example.capability": "enabled"},
			}},
		},
		CodePlans: []signingResignCodePlan{{Path: originalExecutable, EntitlementsPath: nestedEntitlements}},
	}
	rebased, err := rebaseSigningResignPreparedTree(original, originalRoot, packedRoot)
	if err != nil {
		t.Fatalf("rebaseSigningResignPreparedTree() error = %v", err)
	}
	wantExecutable := filepath.Join(packedRoot, "Payload", "App.app", "Frameworks", "Feature.framework", "Feature")
	if got := rebased.CodePlans[0].Path; got != wantExecutable {
		t.Fatalf("rebased code path = %q, want %q", got, wantExecutable)
	}
	if got := rebased.CodePlans[0].EntitlementsPath; got != nestedEntitlements {
		t.Fatalf("rebased nested entitlements path = %q, want original %q", got, nestedEntitlements)
	}
	if got := rebased.Archive.Targets[0].EntitlementsPath; got != targetEntitlements {
		t.Fatalf("rebased target entitlements path = %q, want original %q", got, targetEntitlements)
	}
	if got := original.CodePlans[0].Path; got != originalExecutable {
		t.Fatalf("original code path mutated to %q", got)
	}
	if got := original.Archive.Targets[0].EntitlementsPath; got != targetEntitlements {
		t.Fatalf("original target entitlements path mutated to %q", got)
	}
}

func TestVerifyPackedSigningResignIPARejectsInventoryChanges(t *testing.T) {
	for _, test := range []struct {
		name           string
		executableName string
		profileData    []byte
		want           string
	}{
		{
			name:           "executable",
			executableName: "Other",
			profileData:    []byte("replacement profile"),
			want:           "Mach-O executable inventory changed",
		},
		{
			name:           "embedded profile",
			executableName: "App",
			profileData:    []byte("different replacement profile"),
			want:           "target profile changed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			baselineProfile := []byte("replacement profile")
			info, err := plist.Marshal(map[string]any{
				"CFBundleIdentifier":         "com.example.app",
				"CFBundleExecutable":         test.executableName,
				"DTPlatformName":             "iphoneos",
				"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
			}, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			executable := []byte{
				0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
				0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}
			packedData := buildSigningResignZip(t, []signingResignZipEntry{
				{name: "Payload/App.app/Info.plist", data: info},
				{name: "Payload/App.app/" + test.executableName, data: executable, mode: 0o755},
				{name: "Payload/App.app/embedded.mobileprovision", data: test.profileData},
			})
			temporary := t.TempDir()
			packedPath := filepath.Join(temporary, "packed.ipa")
			if err := os.WriteFile(packedPath, packedData, 0o600); err != nil {
				t.Fatal(err)
			}
			stageRoot, err := rootfs.New(temporary)
			if err != nil {
				t.Fatal(err)
			}
			defer stageRoot.Close()

			original := signingResignPreparedTree{Archive: signingResignArchive{
				MainPath: "Payload/App.app",
				Targets: []signingResignTarget{{
					Kind:         "application",
					RelativePath: "Payload/App.app",
					BundleID:     "com.example.app",
					Executable:   "App",
					ProfileMode:  0o644,
					Profile: signingResignProfile{
						Data:   baselineProfile,
						SHA256: signingResignSHA256(baselineProfile),
					},
				}},
			}}
			originalTool := runSigningResignToolFn
			t.Cleanup(func() { runSigningResignToolFn = originalTool })
			runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
				return signingResignToolOutput{}, nil
			}
			fileInfo, err := os.Stat(packedPath)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyPackedSigningResignIPA(context.Background(), packedPath, fileInfo.Size(), stageRoot, temporary, original, "TEAM", strings.Repeat("A", 64))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyPackedSigningResignIPA() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateSigningResignPackedCodeInventory(t *testing.T) {
	const targetPath = "Payload/App.app/App"
	machoData := []byte{
		0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
		0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, test := range []struct {
		name       string
		setup      func(t *testing.T, packedRoot, originalRoot string)
		wantErr    bool
		wantPasses bool
	}{
		{
			name: "unchanged inventory",
			setup: func(t *testing.T, packedRoot, _ string) {
				t.Helper()
				writeSigningResignTestMachO(t, packedRoot, targetPath, machoData)
			},
			wantPasses: true,
		},
		{
			name: "extra Mach-O in existing bundle",
			setup: func(t *testing.T, packedRoot, _ string) {
				t.Helper()
				writeSigningResignTestMachO(t, packedRoot, targetPath, machoData)
				writeSigningResignTestMachO(t, packedRoot, "Payload/App.app/Extra", machoData)
			},
			wantErr: true,
		},
		{
			name: "new framework executable",
			setup: func(t *testing.T, packedRoot, _ string) {
				t.Helper()
				writeSigningResignTestMachO(t, packedRoot, targetPath, machoData)
				writeSigningResignTestMachO(t, packedRoot, "Payload/App.app/Frameworks/New.framework/New", machoData)
			},
			wantErr: true,
		},
		{
			name: "missing original nested code plan",
			setup: func(t *testing.T, packedRoot, _ string) {
				t.Helper()
				writeSigningResignTestMachO(t, packedRoot, targetPath, machoData)
			},
			wantErr: true,
		},
		{
			name: "SwiftSupport is separately excluded",
			setup: func(t *testing.T, packedRoot, _ string) {
				t.Helper()
				writeSigningResignTestMachO(t, packedRoot, targetPath, machoData)
				writeSigningResignTestMachO(t, packedRoot, "SwiftSupport/iphoneos/libswiftCore.dylib", machoData)
			},
			wantPasses: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			temporary := t.TempDir()
			packedRoot := filepath.Join(temporary, "packed")
			originalRoot := filepath.Join(temporary, "original")
			if err := os.MkdirAll(packedRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(originalRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			test.setup(t, packedRoot, originalRoot)
			original := signingResignPreparedTree{Archive: signingResignArchive{
				Targets: []signingResignTarget{{RelativePath: "Payload/App.app", Executable: "App"}},
			}}
			if test.name == "missing original nested code plan" {
				original.CodePlans = []signingResignCodePlan{{Path: filepath.Join(originalRoot, "Payload/App.app/Frameworks/Feature.framework/Feature")}}
			}
			err := validateSigningResignPackedCodeInventory(context.Background(), packedRoot, originalRoot, original)
			if (err != nil) != test.wantErr || (err == nil) != test.wantPasses {
				t.Fatalf("validateSigningResignPackedCodeInventory() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func writeSigningResignTestMachO(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	pathValue := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(pathValue), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathValue, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPackedSigningResignIPARejectsDroppedEntitlement(t *testing.T) {
	profileData := []byte("replacement profile")
	profileDigest := signingResignSHA256(profileData)
	info, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleExecutable":         "App",
		"CFBundleSupportedPlatforms": []string{"iPhoneOS"},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	executable := []byte{
		0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01,
		0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	packedData := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Info.plist", data: info},
		{name: "Payload/App.app/App", data: executable, mode: 0o755},
		{name: "Payload/App.app/embedded.mobileprovision", data: profileData},
	})
	stagePath := t.TempDir()
	if err := os.Mkdir(filepath.Join(stagePath, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	packedPath := filepath.Join(stagePath, "packed.ipa")
	if err := os.WriteFile(packedPath, packedData, 0o600); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()

	original := signingResignPreparedTree{
		Archive: signingResignArchive{
			MainPath: "Payload/App.app",
			Targets: []signingResignTarget{{
				Kind:         "application",
				RelativePath: "Payload/App.app",
				BundleID:     "com.example.app",
				Executable:   "App",
				ProfileMode:  0o644,
				ExistingEntitlements: map[string]any{
					"application-identifier":              "TEAM.com.example.app",
					"com.apple.application-identifier":    "TEAM.com.example.app",
					"com.apple.developer.team-identifier": "TEAM",
					"get-task-allow":                      false,
					"com.example.capability":              "enabled",
				},
				Profile: signingResignProfile{
					Data:   profileData,
					SHA256: profileDigest,
					Entitlements: map[string]any{
						"application-identifier":              "TEAM.com.example.app",
						"com.apple.application-identifier":    "TEAM.com.example.app",
						"com.apple.developer.team-identifier": "TEAM",
						"get-task-allow":                      false,
						"com.example.capability":              "enabled",
					},
				},
			}},
		},
	}
	expectedEntitlements, err := plist.Marshal(original.Archive.Targets[0].ExistingEntitlements, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageRoot.WriteFile("expected-entitlements.plist", expectedEntitlements, 0o600); err != nil {
		t.Fatal(err)
	}
	original.Archive.Targets[0].EntitlementsPath = filepath.Join(stagePath, "expected-entitlements.plist")

	droppedEntitlements, err := plist.Marshal(map[string]any{
		"application-identifier":              "TEAM.com.example.app",
		"com.apple.application-identifier":    "TEAM.com.example.app",
		"com.apple.developer.team-identifier": "TEAM",
		"get-task-allow":                      false,
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	originalTool := runSigningResignToolFn
	originalCertificate := extractSigningResignCertificateFn
	t.Cleanup(func() {
		runSigningResignToolFn = originalTool
		extractSigningResignCertificateFn = originalCertificate
	})
	runSigningResignToolFn = func(_ context.Context, _ string, args ...string) (signingResignToolOutput, error) {
		if len(args) > 0 && args[0] == "-d" {
			return signingResignToolOutput{Stdout: droppedEntitlements}, nil
		}
		return signingResignToolOutput{}, nil
	}
	extractSigningResignCertificateFn = func(context.Context, string, string) error { return nil }

	fileInfo, err := os.Stat(packedPath)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyPackedSigningResignIPA(context.Background(), packedPath, fileInfo.Size(), stageRoot, filepath.Join(stagePath, "tree"), original, "TEAM", strings.Repeat("A", 64))
	if err == nil {
		t.Fatal("verifyPackedSigningResignIPA() returned nil for dropped entitlement")
	}
	var operational *signingResignOperationalError
	if !errors.As(err, &operational) || operational.stage != signingResignStageVerification || operational.code != signingResignCodeVerification {
		t.Fatalf("verifyPackedSigningResignIPA() error = %v, want closed verification failure", err)
	}
}

type signingResignZipEntry struct {
	name      string
	data      []byte
	mode      os.FileMode
	modeSet   bool
	directory bool
}

func buildSigningResignZip(t *testing.T, entries []signingResignZipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, item := range entries {
		if item.directory {
			header := &zip.FileHeader{Name: item.name, Method: zip.Store}
			mode := item.mode
			if mode == 0 && !item.modeSet {
				mode = 0o755
			}
			header.SetMode(os.ModeDir | mode)
			if _, err := writer.CreateHeader(header); err != nil {
				t.Fatal(err)
			}
			continue
		}
		mode := item.mode
		if mode != 0 || item.modeSet {
			header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
			header.SetMode(mode)
			file, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(item.data); err != nil {
				t.Fatal(err)
			}
			continue
		}
		file, err := writer.Create(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestMaterializeSigningResignArchivePreservesSafeFileModesThroughRepack(t *testing.T) {
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Resources/data.txt", data: []byte("data"), mode: 0o644},
		{name: "Payload/App.app/Resources/tool", data: []byte("tool"), mode: 0o755},
		{name: "Payload/App.app/Resources/private.txt", data: []byte("private"), mode: 0o640},
		{name: "Payload/App.app/Resources/private-tool", data: []byte("private tool"), mode: 0o750},
	})
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSigningResignArchive(context.Background(), reader); err != nil {
		t.Fatal(err)
	}
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	stageOS, err := stageRoot.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer stageOS.Close()
	treeOS, err := stageOS.OpenRoot("tree")
	if err != nil {
		t.Fatal(err)
	}
	defer treeOS.Close()
	if err := materializeSigningResignArchive(context.Background(), reader, treeOS); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "Payload/App.app/Resources/data.txt", mode: 0o644},
		{name: "Payload/App.app/Resources/tool", mode: 0o755},
		{name: "Payload/App.app/Resources/private.txt", mode: 0o640},
		{name: "Payload/App.app/Resources/private-tool", mode: 0o750},
	} {
		file, err := treeRoot.OpenFile(test.name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := file.Stat()
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != test.mode {
			t.Fatalf("materialized %s mode = %#o, want %#o", test.name, info.Mode().Perm(), test.mode)
		}
	}
	packedPath, _, _, err := repackSigningResignTree(context.Background(), stageRoot, treeRoot)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := os.Open(packedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer packed.Close()
	packedInfo, err := packed.Stat()
	if err != nil {
		t.Fatal(err)
	}
	packedReader, err := zip.NewReader(packed, packedInfo.Size())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "Payload/App.app/Resources/data.txt", mode: 0o644},
		{name: "Payload/App.app/Resources/tool", mode: 0o755},
		{name: "Payload/App.app/Resources/private.txt", mode: 0o640},
		{name: "Payload/App.app/Resources/private-tool", mode: 0o750},
	} {
		var found *zip.File
		for _, member := range packedReader.File {
			if member.Name == test.name {
				found = member
				break
			}
		}
		if found == nil {
			t.Fatalf("packed archive is missing %s", test.name)
		}
		if found.Mode().Perm() != test.mode {
			t.Fatalf("packed %s mode = %#o, want %#o", test.name, found.Mode().Perm(), test.mode)
		}
	}
}

func TestValidateSigningResignArchiveRejectsExplicitWorldWritableMode(t *testing.T) {
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Resources/data.txt", data: []byte("data"), mode: 0o666},
	})
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSigningResignArchive(context.Background(), reader); err == nil || !strings.Contains(err.Error(), "permission mode") {
		t.Fatalf("validateSigningResignArchive() error = %v, want unsafe permission rejection", err)
	}
}

func TestValidateSigningResignArchiveRejectsUnreadableExplicitModes(t *testing.T) {
	for _, test := range []struct {
		name  string
		entry signingResignZipEntry
		want  string
	}{
		{
			name:  "file mode zero",
			entry: signingResignZipEntry{name: "Payload/App.app/Resources/data.txt", data: []byte("data"), modeSet: true},
			want:  "unreadable archive file mode",
		},
		{
			name:  "directory mode zero",
			entry: signingResignZipEntry{name: "Payload/App.app/Resources/", modeSet: true, directory: true},
			want:  "unreadable or untraversable directory mode",
		},
		{
			name:  "setuid file",
			entry: signingResignZipEntry{name: "Payload/App.app/Resources/tool", data: []byte("tool"), mode: os.ModeSetuid | 0o644},
			want:  "special mode",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := buildSigningResignZip(t, []signingResignZipEntry{test.entry})
			reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSigningResignArchive(context.Background(), reader); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateSigningResignArchive() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMaterializeSigningResignArchiveDefaultsDOSModeOnly(t *testing.T) {
	data := buildSigningResignZip(t, []signingResignZipEntry{
		{name: "Payload/App.app/Resources/data.txt", data: []byte("data")},
	})
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if reader.File[0].CreatorVersion>>8 != 0 {
		t.Fatalf("test ZIP unexpectedly declares a Unix creator: %#x", reader.File[0].CreatorVersion)
	}
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	stageOS, err := stageRoot.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer stageOS.Close()
	treeOS, err := stageOS.OpenRoot("tree")
	if err != nil {
		t.Fatal(err)
	}
	defer treeOS.Close()
	if err := materializeSigningResignArchive(context.Background(), reader, treeOS); err != nil {
		t.Fatal(err)
	}
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	file, err := treeRoot.OpenFile("Payload/App.app/Resources/data.txt")
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("DOS-mode materialized permission = %#o, want 0644", got)
	}
}

func TestRepackSigningResignTreeIsDeterministicAndBounded(t *testing.T) {
	stagePath := t.TempDir()
	treePath := filepath.Join(stagePath, "tree")
	if err := os.Mkdir(treePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(treePath, "b.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(treePath, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	stageRoot, err := rootfs.New(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stageRoot.Close()
	treeRoot, err := rootfs.New(treePath)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	packedPath, size, digest, err := repackSigningResignTree(context.Background(), stageRoot, treeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 || digest != signingResignSHA256(mustReadFile(t, packedPath)) {
		t.Fatalf("packed artifact size=%d digest=%q", size, digest)
	}
	if _, err := os.Stat(packedPath); err != nil {
		t.Fatal(err)
	}
}

func TestPublishSigningResignOutputReportsAmbiguousPublication(t *testing.T) {
	contents := []byte("packed IPA")
	for _, test := range []struct {
		name       string
		packedSize int64
		digest     string
	}{
		{name: "size mismatch", packedSize: int64(len(contents)) + 1, digest: signingResignSHA256(contents)},
		{name: "digest mismatch", packedSize: int64(len(contents)), digest: strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			stagePath := t.TempDir()
			packedPath := filepath.Join(stagePath, "packed.ipa")
			if err := os.WriteFile(packedPath, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(t.TempDir(), "output.ipa")
			outputRoot, err := rootfs.New(filepath.Dir(outputPath))
			if err != nil {
				t.Fatal(err)
			}
			defer outputRoot.Close()
			_, err = publishSigningResignOutput(context.Background(), outputRoot, filepath.Base(outputPath), packedPath, test.packedSize, test.digest)
			if err == nil || !errors.Is(err, ErrSigningResignPublicationAmbiguous) {
				t.Fatalf("publishSigningResignOutput() error = %v, want ambiguous publication", err)
			}
			published, readErr := os.ReadFile(outputPath)
			if readErr != nil {
				t.Fatalf("read ambiguous published artifact: %v", readErr)
			}
			if !bytes.Equal(published, contents) {
				t.Fatalf("ambiguous published artifact = %q, want %q", published, contents)
			}
		})
	}
}

func TestSigningResignHashHonorsCancellation(t *testing.T) {
	contents := []byte("large enough staged artifact")
	pathValue := filepath.Join(t.TempDir(), "packed.ipa")
	if err := os.WriteFile(pathValue, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashSigningResignFile(ctx, pathValue, int64(len(contents))); !errors.Is(err, context.Canceled) {
		t.Fatalf("hashSigningResignFile() error = %v, want cancellation", err)
	}
}

func TestPublishSigningResignOutputCancellationAfterPublicationIsAmbiguous(t *testing.T) {
	contents := []byte("packed IPA")
	stagePath := t.TempDir()
	packedPath := filepath.Join(stagePath, "packed.ipa")
	if err := os.WriteFile(packedPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "output.ipa")
	outputRoot, err := rootfs.New(filepath.Dir(outputPath))
	if err != nil {
		t.Fatal(err)
	}
	defer outputRoot.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalHook := signingResignBeforePublishedHashFn
	t.Cleanup(func() { signingResignBeforePublishedHashFn = originalHook })
	signingResignBeforePublishedHashFn = cancel
	artifact, err := publishSigningResignOutput(ctx, outputRoot, filepath.Base(outputPath), packedPath, int64(len(contents)), signingResignSHA256(contents))
	if err == nil || !errors.Is(err, ErrSigningResignPublicationAmbiguous) {
		t.Fatalf("publishSigningResignOutput() error = %v, want ambiguous cancellation", err)
	}
	if artifact.Path != "" {
		t.Fatalf("ambiguous publication returned a success artifact: %#v", artifact)
	}
	if published, readErr := os.ReadFile(outputPath); readErr != nil || !bytes.Equal(published, contents) {
		t.Fatalf("published artifact after cancellation = %q, read error = %v", published, readErr)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSigningResignContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(contextError(ctx), context.Canceled) {
		t.Fatalf("contextError() = %v, want cancellation", contextError(ctx))
	}
}

func TestRunSigningResignEnvironmentNeverInstallsProfiles(t *testing.T) {
	original := signingResignPlatformDepsFn
	t.Cleanup(func() { signingResignPlatformDepsFn = original })
	temporary := t.TempDir()
	var events []string
	signingResignPlatformDepsFn = func() signingRunDeps {
		return signingRunDeps{
			GOOS:        "darwin",
			RandomBytes: func(size int) ([]byte, error) { return bytes.Repeat([]byte{0x42}, size), nil },
			TempDir: func() (string, error) {
				return filepath.Join(temporary, "session"), os.Mkdir(filepath.Join(temporary, "session"), 0o700)
			},
			RemoveTempDir: func(path string) error { events = append(events, "remove-temp"); return os.RemoveAll(path) },
			AcquireLock: func(context.Context) (func() error, error) {
				events = append(events, "lock")
				return func() error { events = append(events, "unlock"); return nil }, nil
			},
			Recover:       func(context.Context) error { events = append(events, "recover"); return nil },
			WriteJournal:  func(signingRunJournal, bool) error { events = append(events, "journal-write"); return nil },
			RemoveJournal: func() error { events = append(events, "journal-remove"); return nil },
			KeychainSearchList: func(context.Context) ([]string, error) {
				events = append(events, "list")
				return []string{"login.keychain-db"}, nil
			},
			CreateKeychain: func(context.Context, string, []byte) error { events = append(events, "create-keychain"); return nil },
			ImportIdentity: func(context.Context, string, []byte, []byte, []byte, string) error {
				events = append(events, "import")
				return nil
			},
			SetKeychainSearchList:     func(context.Context, []string) error { events = append(events, "activate"); return nil },
			RemoveKeychainSearchEntry: func(context.Context, string) error { events = append(events, "remove-search"); return nil },
			DeleteKeychain:            func(context.Context, string) error { events = append(events, "delete-keychain"); return nil },
		}
	}
	identity := testSigningResignIdentity(t)
	if err := runSigningResignEnvironment(context.Background(), identity, func(_ context.Context, keychainPath string) error {
		if keychainPath == "" {
			t.Fatal("callback received an empty keychain path")
		}
		events = append(events, "operation")
		return nil
	}); err != nil {
		t.Fatalf("runSigningResignEnvironment() error = %v", err)
	}
	joined := strings.Join(events, ",")
	if strings.Contains(joined, "install") || strings.Contains(joined, "profile") {
		t.Fatalf("environment unexpectedly touched a profile: %s", joined)
	}
	if !strings.Contains(joined, "create-keychain,remove-search,import") || !strings.Contains(joined, "activate,operation,remove-search,delete-keychain") {
		t.Fatalf("environment events = %s", joined)
	}
}

func testSigningResignIdentity(t *testing.T) *signingRunIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(cryptorand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test", OrganizationalUnit: []string{"TEAM"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &signingRunIdentity{Certificate: certificate, PrivateKey: key, CertificateSHA1: strings.Repeat("A", 40), CertificateSHA256: strings.Repeat("B", 64)}
}
