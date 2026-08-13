package cmdtest

import (
	"archive/zip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/distribution"
)

func TestDistributeCommandsAreRegisteredWithAgentOrientedFlags(t *testing.T) {
	root := RootCommand("1.2.3")
	inspect := findSubcommand(root, "distribute", "inspect")
	prepare := findSubcommand(root, "distribute", "prepare")
	if inspect == nil || prepare == nil {
		t.Fatalf("distribute commands missing: inspect=%v prepare=%v", inspect, prepare)
	}
	for _, name := range []string{"ipa", "include-devices", "output"} {
		if inspect.FlagSet.Lookup(name) == nil {
			t.Errorf("inspect --%s missing", name)
		}
	}
	for _, name := range []string{"ipa", "output-dir", "title", "channel", "source-revision", "source-url", "output"} {
		if prepare.FlagSet.Lookup(name) == nil {
			t.Errorf("prepare --%s missing", name)
		}
	}
}

func TestDistributeInspectRequiresIPAAndRejectsInvalidOutput(t *testing.T) {
	assertUsageExit(t, []string{"distribute", "inspect"}, "--ipa is required")
	assertUsageExit(t, []string{"distribute", "inspect", "--ipa", "missing.ipa", "--output", "yaml"}, "unsupported format")
	assertUsageExit(t, []string{"distribute", "inspect", "unexpected", "--ipa", "missing.ipa"}, "does not accept positional arguments")
}

func TestDistributePrepareRejectsCredentialSourceURLBeforeFilesystemAccess(t *testing.T) {
	assertUsageExit(t, []string{
		"distribute", "prepare", "--ipa", "missing.ipa", "--source-url", "https://token@example.com/revision",
	}, "user information is not allowed")
	assertUsageExit(t, []string{
		"distribute", "prepare", "--ipa", "missing.ipa", "--source-url", "https://example.com/revision?token=secret",
	}, "query and fragment are not allowed")
	assertUsageExit(t, []string{"distribute", "prepare", "unexpected", "--ipa", "missing.ipa"}, "does not accept positional arguments")
}

func TestDistributeInspectJSONPrivacyAndExplicitDisclosure(t *testing.T) {
	ipa := writeDistributionIPA(t, "private-device-udid")
	stdout, stderr, runErr := runRootCommand(t, []string{"distribute", "inspect", "--output", "json", "--ipa", ipa})
	if runErr != nil {
		t.Fatalf("run error = %v; stderr=%s", runErr, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stdout, "private-device-udid") {
		t.Fatalf("default inspect leaked UDID: %s", stdout)
	}
	var result distribution.Inspection
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Preparation.MetadataEligible || result.Signing.DeviceCount != 1 || result.App.BundleID != "com.example.demo" {
		t.Fatalf("unexpected inspection: %#v", result)
	}
	if result.Signing.CodeSignatureVerification.Status != distribution.CodeSignatureInvalid {
		t.Fatalf("unexpected signer verification: %#v", result.Signing.CodeSignatureVerification)
	}

	stdout, stderr, runErr = runRootCommand(t, []string{"distribute", "inspect", "--ipa", ipa, "--include-devices", "--output", "json"})
	if runErr != nil || stderr != "" {
		t.Fatalf("run error=%v stderr=%q", runErr, stderr)
	}
	if !strings.Contains(stdout, "private-device-udid") {
		t.Fatalf("explicit inspect omitted UDID: %s", stdout)
	}
}

func TestDistributeInspectTableAndMarkdown(t *testing.T) {
	ipa := writeDistributionIPA(t, "device")
	for _, format := range []string{"table", "markdown"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, runErr := runRootCommand(t, []string{"distribute", "inspect", "--ipa", ipa, "--output", format})
			if runErr != nil || stderr != "" {
				t.Fatalf("run error=%v stderr=%q", runErr, stderr)
			}
			if !strings.Contains(stdout, "Bundle ID") || !strings.Contains(stdout, "com.example.demo") {
				t.Fatalf("unexpected %s: %s", format, stdout)
			}
		})
	}
}

func TestDistributePrepareFailsClosedForUnverifiedFixture(t *testing.T) {
	ipa := writeDistributionIPA(t, "private-device-udid")
	outputDir := filepath.Join(t.TempDir(), "bundle")
	args := []string{
		"distribute", "prepare", "--ipa", ipa, "--output-dir", outputDir,
		"--title", "Preview", "--channel", "pull-request-7", "--source-revision", "abcdef", "--output", "json",
	}
	stdout, stderr, runErr := runRootCommand(t, args)
	if runErr == nil || !strings.Contains(runErr.Error(), "complete main-app signature verification") {
		t.Fatalf("run error=%v stderr=%q", runErr, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout=%q", stdout)
	}
	if _, err := os.Stat(outputDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified prepare created output: %v", err)
	}
}

func TestDistributeInspectRejectsSymlinkIPA(t *testing.T) {
	ipa := writeDistributionIPA(t, "device")
	link := filepath.Join(t.TempDir(), "linked.ipa")
	if err := os.Symlink(ipa, link); err != nil {
		t.Fatal(err)
	}
	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	var runErr error
	stdout, _ := captureOutput(t, func() {
		if err := root.Parse([]string{"distribute", "inspect", "--ipa", link, "--output", "json"}); err != nil {
			t.Fatal(err)
		}
		runErr = root.Run(context.Background())
	})
	if runErr == nil || errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("expected runtime symlink error, got %v", runErr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func writeDistributionIPA(t *testing.T, device string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Fixture"}, NotBefore: now, NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	profilePlist, err := plist.Marshal(map[string]any{
		"UUID": "fixture-profile", "TeamIdentifier": []string{"TEAM123"}, "ApplicationIdentifierPrefix": []string{"SEED123"},
		"Platform":           []string{"iOS", "visionOS"},
		"ProvisionedDevices": []string{device}, "ExpirationDate": now.Add(48 * time.Hour), "DeveloperCertificates": [][]byte{der},
		"Entitlements": map[string]any{"application-identifier": "SEED123.com.example.demo", "com.apple.developer.team-identifier": "TEAM123", "get-task-allow": false},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(profilePlist)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	profile, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	infoPlist, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier": "com.example.demo", "CFBundleDisplayName": "Demo", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "7", "MinimumOSVersion": "17.0",
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "App.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for name, data := range map[string][]byte{
		"Payload/Demo.app/Info.plist":               infoPlist,
		"Payload/Demo.app/embedded.mobileprovision": profile,
	} {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
