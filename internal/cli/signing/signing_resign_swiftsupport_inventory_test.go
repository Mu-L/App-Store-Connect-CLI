package signing

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared/errfmt"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

func TestSigningResignSwiftSupportInventoryBindsFinalBytesAndModes(t *testing.T) {
	originalTool := runSigningResignToolFn
	t.Cleanup(func() { runSigningResignToolFn = originalTool })
	runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
		return signingResignToolOutput{}, nil
	}

	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root string)
		match  bool
	}{
		{name: "unchanged", match: true},
		{
			name: "added",
			mutate: func(t *testing.T, root string) {
				writeSigningResignSwiftSupportFixture(t, root, "libswiftUI.dylib", []byte("second runtime"), 0o755)
			},
		},
		{
			name: "dropped",
			mutate: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "SwiftSupport", "iphoneos", "libswiftCore.dylib")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "bytes replaced",
			mutate: func(t *testing.T, root string) {
				if err := os.WriteFile(filepath.Join(root, "SwiftSupport", "iphoneos", "libswiftCore.dylib"), []byte("replacement runtime"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "renamed",
			mutate: func(t *testing.T, root string) {
				oldPath := filepath.Join(root, "SwiftSupport", "iphoneos", "libswiftCore.dylib")
				if err := os.Rename(oldPath, filepath.Join(filepath.Dir(oldPath), "libswiftCore-renamed.dylib")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mode changed",
			mutate: func(t *testing.T, root string) {
				if err := os.Chmod(filepath.Join(root, "SwiftSupport", "iphoneos", "libswiftCore.dylib"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeSigningResignSwiftSupportFixture(t, root, "libswiftCore.dylib", []byte("canonical runtime"), 0o755)
			if err := validateSigningResignSwiftSupport(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			expected, err := captureSigningResignSwiftSupportInventory(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if test.mutate != nil {
				test.mutate(t, root)
			}
			actual, err := captureSigningResignSwiftSupportInventory(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			err = validateSigningResignSwiftSupportInventory(actual, expected)
			if (err == nil) != test.match {
				t.Fatalf("validateSigningResignSwiftSupportInventory() error = %v, want match=%t", err, test.match)
			}
		})
	}
}

func writeSigningResignSwiftSupportFixture(t *testing.T, root, name string, data []byte, mode os.FileMode) {
	t.Helper()
	pathValue := filepath.Join(root, "SwiftSupport", "iphoneos", name)
	if err := os.MkdirAll(filepath.Dir(pathValue), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathValue, data, mode); err != nil {
		t.Fatal(err)
	}
}

func TestSigningResignSwiftSupportInventoryHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeSigningResignSwiftSupportFixture(t, root, "libswiftCore.dylib", []byte("canonical runtime"), 0o755)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := captureSigningResignSwiftSupportInventory(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("captureSigningResignSwiftSupportInventory() error = %v, want cancellation", err)
	}
}

func TestVerifyPackedSigningResignIPAProjectsSwiftSupportMismatchAsClosedVerificationError(t *testing.T) {
	profileData := []byte("replacement profile")
	packedRuntime := []byte("1234567890abcdeg")
	expectedRuntime := []byte("1234567890abcdef")
	info, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.app",
		"CFBundleExecutable":         "App",
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
		{name: "Payload/App.app/App", data: executable, mode: 0o755},
		{name: "Payload/App.app/embedded.mobileprovision", data: profileData},
		{name: "SwiftSupport/iphoneos/libswiftCore.dylib", data: packedRuntime, mode: 0o755},
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
	runSigningResignToolFn = func(_ context.Context, _ string, _ ...string) (signingResignToolOutput, error) {
		return signingResignToolOutput{}, nil
	}
	original := signingResignPreparedTree{
		Archive: signingResignArchive{
			MainPath: "Payload/App.app",
			Targets: []signingResignTarget{{
				Kind:         "application",
				RelativePath: "Payload/App.app",
				BundleID:     "com.example.app",
				Executable:   "App",
				ProfileMode:  0o644,
				Profile: signingResignProfile{
					Data:   profileData,
					SHA256: signingResignSHA256(profileData),
				},
			}},
		},
		SwiftSupport: []signingResignSwiftSupportEntry{{
			RelativePath: "SwiftSupport/iphoneos/libswiftCore.dylib",
			SizeBytes:    int64(len(expectedRuntime)),
			SHA256:       signingResignSHA256(expectedRuntime),
			Mode:         0o755,
		}},
	}
	fileInfo, err := os.Stat(packedPath)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyPackedSigningResignIPA(context.Background(), packedPath, fileInfo.Size(), stageRoot, filepath.Join(temporary, "tree"), original, "TEAM", strings.Repeat("A", 64))
	if err == nil {
		t.Fatal("verifyPackedSigningResignIPA() returned nil for changed SwiftSupport inventory")
	}
	var operational *signingResignOperationalError
	if !errors.As(err, &operational) {
		t.Fatalf("verifyPackedSigningResignIPA() error = %v, want closed operational error", err)
	}
	if operational.stage != signingResignStageVerification || operational.code != signingResignCodeVerification {
		t.Fatalf("operational stage/code = %v/%v, want verification/verification", operational.stage, operational.code)
	}
	if got := err.Error(); got != "signing resign failed during verification (verification)" {
		t.Fatalf("public verification error = %q, want stable stage/code", got)
	}
	if strings.Contains(err.Error(), "libswiftCore.dylib") || strings.Contains(err.Error(), signingResignSHA256(packedRuntime)) || strings.Contains(err.Error(), signingResignSHA256(expectedRuntime)) {
		t.Fatalf("public verification error leaked inventory details: %q", err)
	}

	if runtime.GOOS != "darwin" {
		t.Skip("command projection is macOS-only")
	}
	originalExecute := executeSigningResignFn
	t.Cleanup(func() { executeSigningResignFn = originalExecute })
	executeSigningResignFn = func(context.Context, signingResignOptions) (signingResignResult, error) {
		return signingResignResult{
			Output: signingResignArtifactResult{Path: filepath.Join(temporary, "success-receipt.ipa")},
		}, err
	}
	command := SigningResignCommand()
	if parseErr := command.FlagSet.Parse([]string{
		"--ipa", filepath.Join(temporary, "private-input.ipa"),
		"--output", filepath.Join(temporary, "private-output.ipa"),
		"--identity", filepath.Join(temporary, "private-identity.p12"),
		"--profiles-manifest", filepath.Join(temporary, "private-profiles.json"),
	}); parseErr != nil {
		t.Fatal(parseErr)
	}
	publicErr := command.Exec(context.Background(), nil)
	if publicErr == nil || errors.Is(publicErr, flag.ErrHelp) {
		t.Fatalf("SigningResignCommand().Exec() error = %v, want operational exit 1", publicErr)
	}
	if got := publicErr.Error(); got != "signing resign: signing resign failed during verification (verification)" {
		t.Fatalf("public command error = %q, want stable verification stage/code", got)
	}
	formatted := errfmt.FormatStderr(publicErr)
	if !strings.Contains(formatted, "signing resign failed during verification (verification)") {
		t.Fatalf("formatted stderr = %q, want stable verification stage/code", formatted)
	}
	for _, secret := range []string{"libswiftCore.dylib", signingResignSHA256(packedRuntime), signingResignSHA256(expectedRuntime), filepath.Join(temporary, "private-input.ipa"), filepath.Join(temporary, "private-output.ipa")} {
		if strings.Contains(publicErr.Error(), secret) || strings.Contains(formatted, secret) {
			t.Fatalf("public command output leaked %q: error=%q stderr=%q", secret, publicErr, formatted)
		}
	}
	if _, statErr := os.Stat(filepath.Join(temporary, "success-receipt.ipa")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed command left a success receipt: stat error = %v", statErr)
	}
}
