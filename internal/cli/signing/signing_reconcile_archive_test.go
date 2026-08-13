package signing

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"howett.net/plist"
)

func TestReadCodesignEntitlementsUsesValidatedOpenHandle(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign is available only on macOS")
	}
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign is unavailable")
	}

	dir := t.TempDir()
	original := filepath.Join(dir, "Original")
	replacement := filepath.Join(dir, "Replacement")
	copyAndSignTestMachO(t, "/usr/bin/true", original, "ORIGINALTEAM")
	copyAndSignTestMachO(t, "/usr/bin/true", replacement, "REPLACEMENTTEAM")

	handle, err := shared.OpenExistingNoFollow(original)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	validated := filepath.Join(dir, "Validated")
	if err := os.Rename(original, validated); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, original); err != nil {
		t.Fatal(err)
	}

	entitlements, err := readCodesignEntitlements(handle)
	if err != nil {
		t.Fatalf("readCodesignEntitlements() error = %v", err)
	}
	if got := plistString(entitlements["com.apple.developer.team-identifier"]); got != "ORIGINALTEAM" {
		t.Fatalf("team entitlement = %q, want ORIGINALTEAM", got)
	}
}

func TestSigningArchiveReadersRejectSymlinkedComponents(t *testing.T) {
	archive := t.TempDir()
	external := t.TempDir()
	plistBytes, err := plist.Marshal(map[string]any{"CFBundleIdentifier": "com.example.external"}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(external, "Info.plist"), plistBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(archive, "External.app")); err != nil {
		t.Fatal(err)
	}
	root, err := rootfs.New(archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSigningPlist(root, "External.app/Info.plist"); err == nil {
		t.Fatal("readSigningPlist() followed a symlinked parent")
	}
	if _, err := listBundleDirectories(root, "External.app", ".app"); err == nil {
		t.Fatal("listBundleDirectories() followed a symlinked directory")
	}
	if err := os.Symlink(filepath.Join(external, "Info.plist"), filepath.Join(archive, "Info.plist")); err != nil {
		t.Fatal(err)
	}
	if _, err := readSigningPlist(root, "Info.plist"); err == nil {
		t.Fatal("readSigningPlist() followed a symlinked final file")
	}
}

func TestValidateTargetApplicationIdentifierAllowsLegacyPrefixAndRejectsMismatch(t *testing.T) {
	target := signingTarget{BundleID: "com.example.app", Entitlements: map[string]any{
		"application-identifier": "LEGACYSEED.com.example.app",
	}}
	if err := validateTargetApplicationIdentifier(target); err != nil {
		t.Fatalf("legacy App ID prefix rejected: %v", err)
	}
	target.Entitlements["application-identifier"] = "LEGACYSEED.com.other.app"
	if err := validateTargetApplicationIdentifier(target); err == nil {
		t.Fatal("mismatched application identifier accepted")
	}
	target.Entitlements["application-identifier"] = "LEGACYSEED.com.example.app"
	target.Entitlements["com.apple.application-identifier"] = "OTHER.com.example.app"
	if err := validateTargetApplicationIdentifier(target); err == nil {
		t.Fatal("conflicting application identifiers accepted")
	}
}

func copyAndSignTestMachO(t *testing.T, source, destination, teamID string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o700); err != nil {
		t.Fatal(err)
	}
	entitlements, err := plist.Marshal(map[string]any{
		"com.apple.developer.team-identifier": teamID,
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	entitlementsPath := destination + ".entitlements"
	if err := os.WriteFile(entitlementsPath, entitlements, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", entitlementsPath, destination)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("codesign test Mach-O: %v: %s", err, output)
	}
}
