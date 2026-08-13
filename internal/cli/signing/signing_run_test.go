package signing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bitrise-io/go-pkcs12"
	"github.com/bitrise-io/go-xcode/certificateutil"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestSigningCommandIncludesRun(t *testing.T) {
	command := SigningCommand()
	for _, subcommand := range command.Subcommands {
		if subcommand != nil && subcommand.Name == "run" {
			return
		}
	}
	t.Fatal("expected signing run subcommand")
}

func TestInspectSigningRunInputs(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	got, err := inspectSigningRunInputs(
		fixture.identity,
		[]byte(fixture.password),
		fixture.profile,
		fixture.roots,
		fixture.now,
	)
	if err != nil {
		t.Fatalf("inspectSigningRunInputs() error: %v", err)
	}
	if got.ProfileUUID != fixture.profileUUID || got.TeamID != fixture.teamID || got.BundleID != fixture.bundleID {
		t.Fatalf("unexpected inspection: %+v", got)
	}
	if len(got.ProvisionedDevices) != 1 {
		t.Fatalf("provisioned devices = %d, want 1", len(got.ProvisionedDevices))
	}
	if got.CertificateSHA256 == "" || got.ProfileSHA256 == "" {
		t.Fatalf("expected digests: %+v", got)
	}
}

func TestInspectPKCS12IdentityReturnsOnlyPublicCertificateMetadata(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("PKCS#12 identity inspection enforces macOS owner-safe file semantics")
	}
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.p12")
	passwordPath := filepath.Join(dir, "password")
	if err := os.WriteFile(identityPath, fixture.identity, 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := os.WriteFile(passwordPath, []byte(fixture.password+"\r\n"), 0o600); err != nil {
		t.Fatalf("write password: %v", err)
	}

	got, err := InspectPKCS12Identity(context.Background(), PKCS12IdentityOptions{
		IdentityPath: identityPath, IdentityPasswordPath: passwordPath,
	})
	if err != nil {
		t.Fatalf("InspectPKCS12Identity() error: %v", err)
	}
	if got.TeamID != fixture.teamID || got.CertificateSHA1 == "" || got.CertificateSHA256 == "" {
		t.Fatalf("unexpected identity metadata: %+v", got)
	}
	if got.NotBefore.After(fixture.now) || !got.NotAfter.After(fixture.now) {
		t.Fatalf("unexpected certificate validity: %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	for _, forbidden := range []string{fixture.password, "privateKey", "identityPath", "passwordPath"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("metadata contains %q: %s", forbidden, encoded)
		}
	}
}

func TestInspectPKCS12IdentityRejectsCertificateOnlyStore(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("PKCS#12 identity inspection enforces macOS owner-safe file semantics")
	}
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	_, certificate, err := pkcs12.Decode(fixture.identity, fixture.password)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	trustStore, err := pkcs12.EncodeTrustStore(rand.Reader, []*x509.Certificate{certificate}, fixture.password)
	if err != nil {
		t.Fatalf("encode trust store: %v", err)
	}
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.p12")
	passwordPath := filepath.Join(dir, "password")
	if err := os.WriteFile(identityPath, trustStore, 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	if err := os.WriteFile(passwordPath, []byte(fixture.password), 0o600); err != nil {
		t.Fatalf("write password: %v", err)
	}
	_, err = InspectPKCS12Identity(context.Background(), PKCS12IdentityOptions{
		IdentityPath: identityPath, IdentityPasswordPath: passwordPath,
	})
	if err == nil || !strings.Contains(err.Error(), "decode identity") {
		t.Fatalf("error = %v, want certificate-only store rejection", err)
	}
}

func TestInspectSigningRunIdentityRejectsMismatchedPrivateKeyAndExpiredCertificate(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	_, certificate, err := pkcs12.Decode(fixture.identity, fixture.password)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate mismatched key: %v", err)
	}
	mismatched, err := pkcs12.Encode(rand.Reader, otherKey, certificate, nil, fixture.password)
	if err != nil {
		t.Fatalf("encode mismatched identity: %v", err)
	}
	if _, err := inspectSigningRunIdentity(mismatched, []byte(fixture.password), fixture.now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched identity error = %v", err)
	}
	if _, err := inspectSigningRunIdentity(fixture.identity, []byte(fixture.password), certificate.NotAfter); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("expired identity error = %v", err)
	}
}

func TestInspectPKCS12IdentityValidatesBeforeReading(t *testing.T) {
	for _, test := range []struct {
		name    string
		ctx     context.Context
		options PKCS12IdentityOptions
		want    string
	}{
		{name: "identity required", ctx: context.Background(), want: "identity path is required"},
		{name: "canceled", ctx: canceledSigningRunContext(), options: PKCS12IdentityOptions{IdentityPath: "/does/not/exist"}, want: "context canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := InspectPKCS12Identity(test.ctx, test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func canceledSigningRunContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRunEphemeralPinsPurposeAndInvokesCallback(t *testing.T) {
	previous := executeSigningOperationFn
	t.Cleanup(func() { executeSigningOperationFn = previous })
	var got signingRunOptions
	callbackCalls := 0
	executeSigningOperationFn = func(ctx context.Context, options signingRunOptions, operation func(context.Context) error) error {
		got = options
		return operation(ctx)
	}
	err := RunEphemeral(context.Background(), EphemeralRunOptions{
		IdentityPath: "identity.p12", IdentityPasswordPath: "password", ProfilePath: "profile.mobileprovision", ReceiptPath: "receipt.json",
		ExpectedCertificateSHA256: strings.Repeat("a", 64), ExpectedProfileSHA256: strings.Repeat("b", 64),
	}, func(context.Context) error {
		callbackCalls++
		return nil
	})
	if err != nil {
		t.Fatalf("RunEphemeral() error: %v", err)
	}
	if callbackCalls != 1 {
		t.Fatalf("callback calls = %d, want 1", callbackCalls)
	}
	want := signingRunOptions{
		IdentityPath: "identity.p12", IdentityPasswordPath: "password", ProfilePath: "profile.mobileprovision",
		ReceiptPath: "receipt.json", Purpose: signingRunPurposeReleaseTesting,
		ExpectedCertificateSHA256: strings.Repeat("A", 64), ExpectedProfileSHA256: strings.Repeat("B", 64),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("options = %+v, want %+v", got, want)
	}
}

func TestRecoverEphemeralWithLocksAroundRecoveryOnly(t *testing.T) {
	events := []string{}
	deps := signingRunDeps{
		AcquireLock: func(context.Context) (func() error, error) {
			events = append(events, "lock")
			return func() error { events = append(events, "unlock"); return nil }, nil
		},
		Recover: func(context.Context) error {
			events = append(events, "recover")
			return nil
		},
	}
	if err := recoverEphemeralWith(context.Background(), deps); err != nil {
		t.Fatalf("recoverEphemeralWith() error: %v", err)
	}
	if want := []string{"lock", "recover", "unlock"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
}

func TestRecoverEphemeralWithPreservesRecoveryAndUnlockFailures(t *testing.T) {
	recoveryErr := errors.New("recovery failed")
	unlockErr := errors.New("unlock failed")
	deps := signingRunDeps{
		AcquireLock: func(context.Context) (func() error, error) {
			return func() error { return unlockErr }, nil
		},
		Recover: func(context.Context) error { return recoveryErr },
	}
	err := recoverEphemeralWith(context.Background(), deps)
	if !errors.Is(err, recoveryErr) || !errors.Is(err, unlockErr) {
		t.Fatalf("error = %v, want recovery and unlock causes", err)
	}
	var reported shared.ReportedError
	if errors.As(err, &reported) {
		t.Fatalf("recovery errors must remain root-renderable: %v", err)
	}
}

func TestRecoverEphemeralWithDoesNotRecoverWhenLockFails(t *testing.T) {
	lockErr := errors.New("lock failed")
	recoveryCalls := 0
	err := recoverEphemeralWith(context.Background(), signingRunDeps{
		AcquireLock: func(context.Context) (func() error, error) { return nil, lockErr },
		Recover: func(context.Context) error {
			recoveryCalls++
			return nil
		},
	})
	if !errors.Is(err, lockErr) || recoveryCalls != 0 {
		t.Fatalf("error = %v recoveryCalls=%d, want lock failure before recovery", err, recoveryCalls)
	}
}

func TestRunEphemeralRejectsInvalidInputBeforeExecution(t *testing.T) {
	previous := executeSigningOperationFn
	t.Cleanup(func() { executeSigningOperationFn = previous })
	executed := false
	executeSigningOperationFn = func(context.Context, signingRunOptions, func(context.Context) error) error {
		executed = true
		return nil
	}
	tests := []struct {
		name     string
		options  EphemeralRunOptions
		callback func(context.Context) error
		want     string
	}{
		{name: "identity", options: EphemeralRunOptions{ProfilePath: "profile"}, callback: func(context.Context) error { return nil }, want: "identity path is required"},
		{name: "profile", options: EphemeralRunOptions{IdentityPath: "identity"}, callback: func(context.Context) error { return nil }, want: "profile path is required"},
		{name: "certificate digest", options: EphemeralRunOptions{IdentityPath: "identity", ProfilePath: "profile"}, callback: func(context.Context) error { return nil }, want: "expected certificate SHA-256 is required"},
		{name: "certificate digest invalid", options: EphemeralRunOptions{IdentityPath: "identity", ProfilePath: "profile", ExpectedCertificateSHA256: "bad"}, callback: func(context.Context) error { return nil }, want: "expected certificate SHA-256 must be"},
		{name: "profile digest", options: EphemeralRunOptions{IdentityPath: "identity", ProfilePath: "profile", ExpectedCertificateSHA256: strings.Repeat("A", 64)}, callback: func(context.Context) error { return nil }, want: "expected profile SHA-256 is required"},
		{name: "profile digest invalid", options: EphemeralRunOptions{IdentityPath: "identity", ProfilePath: "profile", ExpectedCertificateSHA256: strings.Repeat("A", 64), ExpectedProfileSHA256: "bad"}, callback: func(context.Context) error { return nil }, want: "expected profile SHA-256 must be"},
		{name: "callback", options: EphemeralRunOptions{IdentityPath: "identity", ProfilePath: "profile", ExpectedCertificateSHA256: strings.Repeat("A", 64), ExpectedProfileSHA256: strings.Repeat("B", 64)}, want: "callback is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executed = false
			err := RunEphemeral(context.Background(), test.options, test.callback)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if executed {
				t.Fatal("executor called after validation failure")
			}
			if !shared.IsValidationError(err) {
				t.Fatalf("error = %v, want validation classification", err)
			}
		})
	}
}

func TestValidateSigningRunExpectedDigestsRejectsReplacementBeforeEnvironmentSetup(t *testing.T) {
	inspection := &signingRunInspection{
		CertificateSHA256: strings.Repeat("A", 64),
		ProfileSHA256:     strings.Repeat("B", 64),
	}
	tests := []struct {
		name    string
		options signingRunOptions
		want    string
	}{
		{name: "matching", options: signingRunOptions{ExpectedCertificateSHA256: strings.Repeat("A", 64), ExpectedProfileSHA256: strings.Repeat("B", 64)}},
		{name: "identity replaced", options: signingRunOptions{ExpectedCertificateSHA256: strings.Repeat("C", 64), ExpectedProfileSHA256: strings.Repeat("B", 64)}, want: "certificate changed"},
		{name: "profile replaced", options: signingRunOptions{ExpectedCertificateSHA256: strings.Repeat("A", 64), ExpectedProfileSHA256: strings.Repeat("C", 64)}, want: "profile changed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSigningRunExpectedDigests(test.options, inspection)
			if test.want == "" && err != nil {
				t.Fatalf("error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRunEphemeralDigestMismatchHasNoEnvironmentSideEffects(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("ephemeral signing is macOS-only")
	}
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.p12")
	profilePath := filepath.Join(dir, "profile.mobileprovision")
	passwordPath := filepath.Join(dir, "password")
	for path, data := range map[string][]byte{
		identityPath: fixture.identity, profilePath: fixture.profile, passwordPath: []byte(fixture.password),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", filepath.Base(path), err)
		}
	}
	previousRoots := signingRunSystemRootsFn
	previousEnvironment := signingRunEnvironmentFn
	previousNow := signingRunNowFn
	signingRunSystemRootsFn = func() (*x509.CertPool, error) { return fixture.roots, nil }
	signingRunNowFn = func() time.Time { return fixture.now }
	environmentCalls := 0
	signingRunEnvironmentFn = func(context.Context, signingRunDeps, signingRunOptions, []byte, *signingRunInspection, func(context.Context) error) (signingRunReceipt, error) {
		environmentCalls++
		return signingRunReceipt{}, nil
	}
	t.Cleanup(func() {
		signingRunSystemRootsFn = previousRoots
		signingRunEnvironmentFn = previousEnvironment
		signingRunNowFn = previousNow
	})

	valid, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	for _, test := range []struct {
		name        string
		certificate string
		profile     string
		want        string
	}{
		{name: "identity replaced", certificate: strings.Repeat("C", 64), profile: valid.ProfileSHA256, want: "certificate changed"},
		{name: "profile replaced", certificate: valid.CertificateSHA256, profile: strings.Repeat("C", 64), want: "profile changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			callbackCalls := 0
			err := RunEphemeral(context.Background(), EphemeralRunOptions{
				IdentityPath: identityPath, IdentityPasswordPath: passwordPath, ProfilePath: profilePath,
				ExpectedCertificateSHA256: test.certificate, ExpectedProfileSHA256: test.profile,
			}, func(context.Context) error {
				callbackCalls++
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if environmentCalls != 0 || callbackCalls != 0 {
				t.Fatalf("side effects: environment=%d callback=%d", environmentCalls, callbackCalls)
			}
		})
	}
}

func TestSanitizedChildEnvironmentUsesStrictAllowlist(t *testing.T) {
	base := []string{
		"PATH=/untrusted", "PATH=/usr/bin:/bin", "HOME=/Users/test", "TMPDIR=/private/tmp", "LANG=en_US.UTF-8",
		"DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer", "SDKROOT=iphoneos", "TOOLCHAINS=com.apple.dt.toolchain.XcodeDefault",
		"ASC_PRIVATE_KEY=asc-secret", "ASC_SIGNING_SYNC_PASSWORD=signing-secret", "AWS_SECRET_ACCESS_KEY=aws-secret",
		"GIT_ASKPASS=/tmp/steal", "SSH_AUTH_SOCK=/tmp/agent", "DYLD_INSERT_LIBRARIES=/tmp/inject.dylib",
		"CUSTOM_PASSWORD=other-secret", "UNRECOGNIZED=value", "HOME=/Users/evil\x00INJECTED=1", "=empty", "malformed",
	}
	got := SanitizedChildEnvironment(base)
	want := []string{
		"PATH=/usr/bin:/bin", "HOME=/Users/test", "TMPDIR=/private/tmp", "LANG=en_US.UTF-8",
		"DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer", "SDKROOT=iphoneos", "TOOLCHAINS=com.apple.dt.toolchain.XcodeDefault",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
	base[0] = "PATH=changed"
	if got[0] != "PATH=/usr/bin:/bin" {
		t.Fatalf("sanitized environment aliases input: %v", got)
	}
}

func TestSanitizedChildEnvironmentAllowlistDoesNotDrift(t *testing.T) {
	want := []string{"DEVELOPER_DIR", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "SDKROOT", "TEMP", "TMP", "TMPDIR", "TOOLCHAINS", "TZ"}
	got := make([]string, 0, len(sanitizedSigningChildEnvironmentNames))
	for name := range sanitizedSigningChildEnvironmentNames {
		got = append(got, name)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist = %v, want exact reviewed set %v", got, want)
	}
}

func TestInspectSigningRunInputsRejectsIneligibleOrMismatchedInputs(t *testing.T) {
	tests := []struct {
		name    string
		options signingRunFixtureOptions
		mutate  func(*testing.T, *signingRunFixture)
		wantErr string
	}{
		{name: "wrong password", mutate: func(_ *testing.T, fixture *signingRunFixture) { fixture.password = "wrong" }, wantErr: "decode identity"},
		{name: "expired profile", options: signingRunFixtureOptions{profileExpired: true}, wantErr: "profile is expired"},
		{name: "development profile", options: signingRunFixtureOptions{getTaskAllow: true}, wantErr: "development profile"},
		{name: "no registered devices", options: signingRunFixtureOptions{noDevices: true}, wantErr: "registered devices"},
		{name: "enterprise profile", options: signingRunFixtureOptions{allDevices: true}, wantErr: "enterprise profile"},
		{name: "wrong platform", options: signingRunFixtureOptions{platforms: []string{"macOS"}}, wantErr: "iOS"},
		{name: "identity not embedded", options: signingRunFixtureOptions{differentEmbeddedCertificate: true}, wantErr: "not embedded"},
		{name: "identity team mismatch", options: signingRunFixtureOptions{certificateTeamID: "OTHERTEAM"}, wantErr: "organizational unit"},
		{name: "invalid wildcard", options: signingRunFixtureOptions{bundleID: "com.*.example"}, wantErr: "bundle identifier pattern"},
		{name: "untrusted cms signer", mutate: func(_ *testing.T, fixture *signingRunFixture) { fixture.roots = x509.NewCertPool() }, wantErr: "verify profile signature"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSigningRunFixture(t, test.options)
			if test.mutate != nil {
				test.mutate(t, fixture)
			}
			_, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestInspectSigningRunInputsAcceptsTerminalWildcard(t *testing.T) {
	for _, bundleID := range []string{"*", "com.example.*"} {
		t.Run(bundleID, func(t *testing.T) {
			fixture := newSigningRunFixture(t, signingRunFixtureOptions{bundleID: bundleID})
			got, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
			if err != nil {
				t.Fatalf("inspectSigningRunInputs() error: %v", err)
			}
			if got.BundleID != bundleID {
				t.Fatalf("bundle ID = %q, want %q", got.BundleID, bundleID)
			}
		})
	}
}

type signingRunFixtureOptions struct {
	profileExpired               bool
	getTaskAllow                 bool
	noDevices                    bool
	allDevices                   bool
	platforms                    []string
	differentEmbeddedCertificate bool
	certificateTeamID            string
	bundleID                     string
}

type signingRunFixture struct {
	identity    []byte
	password    string
	profile     []byte
	roots       *x509.CertPool
	now         time.Time
	teamID      string
	bundleID    string
	profileUUID string
}

func newSigningRunFixture(t *testing.T, options signingRunFixtureOptions) *signingRunFixture {
	t.Helper()
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	teamID := "TEAM12345"
	certificateTeamID := options.certificateTeamID
	if certificateTeamID == "" {
		certificateTeamID = teamID
	}
	bundleID := options.bundleID
	if bundleID == "" {
		bundleID = "com.example.app"
	}
	platforms := options.platforms
	if platforms == nil {
		platforms = []string{"iOS", "xrOS", "visionOS"}
	}
	profileExpiry := now.Add(24 * time.Hour)
	if options.profileExpired {
		profileExpiry = now.Add(-time.Hour)
	}

	identityKey, identityCert := makeSigningRunCertificate(t, "Distribution", certificateTeamID, now)
	identity, err := certificateutil.NewCertificateInfo(*identityCert, identityKey).EncodeToP12("secret")
	if err != nil {
		t.Fatalf("encode P12: %v", err)
	}
	embeddedCert := identityCert
	if options.differentEmbeddedCertificate {
		_, embeddedCert = makeSigningRunCertificate(t, "Other", teamID, now)
	}

	profileUUID := "A7EFEF21-3432-404F-A488-083800B570FF"
	devices := []string{"00008140-000104303633001C"}
	if options.noDevices {
		devices = nil
	}
	profilePlist, err := plist.Marshal(map[string]any{
		"UUID":                        profileUUID,
		"Name":                        "Release Testing",
		"Platform":                    platforms,
		"TeamIdentifier":              []string{teamID},
		"ApplicationIdentifierPrefix": []string{teamID},
		"CreationDate":                now.Add(-time.Hour),
		"ExpirationDate":              profileExpiry,
		"ProvisionedDevices":          devices,
		"ProvisionsAllDevices":        options.allDevices,
		"DeveloperCertificates":       [][]byte{embeddedCert.Raw},
		"Entitlements": map[string]any{
			"application-identifier":              teamID + "." + bundleID,
			"com.apple.developer.team-identifier": teamID,
			"get-task-allow":                      options.getTaskAllow,
		},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal profile plist: %v", err)
	}

	cmsKey, cmsCert := makeSigningRunCertificate(t, "Profile Signer", "", now)
	signed, err := pkcs7.NewSignedData(profilePlist)
	if err != nil {
		t.Fatalf("new signed data: %v", err)
	}
	if err := signed.AddSigner(cmsCert, cmsKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("add profile signer: %v", err)
	}
	profile, err := signed.Finish()
	if err != nil {
		t.Fatalf("finish profile CMS: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cmsCert)

	return &signingRunFixture{
		identity:    identity,
		password:    "secret",
		profile:     profile,
		roots:       roots,
		now:         now,
		teamID:      teamID,
		bundleID:    bundleID,
		profileUUID: profileUUID,
	}
}

func makeSigningRunCertificate(t *testing.T, commonName, teamID string, now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, OrganizationalUnit: nonEmptyStrings(teamID)},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func nonEmptyStrings(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func signingRunReceiptJSONKeys(t *testing.T, data []byte) []string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestSigningRunReceiptOmitsSensitiveValues(t *testing.T) {
	receipt := signingRunReceipt{
		SchemaVersion:        1,
		Purpose:              signingRunPurposeReleaseTesting,
		Outcome:              "failed",
		ChildExitCode:        23,
		CertificateSHA256:    strings.Repeat("A", 64),
		ProfileSHA256:        strings.Repeat("B", 64),
		ProfileUUID:          "A7EFEF21-3432-404F-A488-083800B570FF",
		TeamID:               "TEAM12345",
		BundleID:             "com.example.app",
		ProfileCleanupState:  "removed",
		KeychainCleanupState: "deleted",
	}
	data, err := marshalSigningRunReceipt(receipt)
	if err != nil {
		t.Fatalf("marshalSigningRunReceipt: %v", err)
	}
	for _, forbidden := range []string{"secret", "00008140", "xcodebuild", "identityPassword", "childCommand", "devices"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("receipt contains %q: %s", forbidden, data)
		}
	}
	wantKeys := []string{"bundleId", "certificateSha256", "childExitCode", "keychainCleanupState", "outcome", "profileCleanupState", "profileSha256", "profileUuid", "purpose", "schemaVersion", "teamId"}
	if got := signingRunReceiptJSONKeys(t, data); !reflect.DeepEqual(got, wantKeys) {
		t.Fatalf("receipt keys = %v, want %v", got, wantKeys)
	}
}

func TestProcessExitErrorBounds(t *testing.T) {
	for _, test := range []struct {
		input int
		want  int
	}{{input: 42, want: 42}, {input: 130, want: 130}, {input: 0, want: 1}, {input: -1, want: 1}, {input: 256, want: 1}} {
		got, ok := shared.ProcessExitCode(shared.NewProcessExitError(test.input))
		if !ok {
			t.Fatalf("input %d did not return a process exit code", test.input)
		}
		if got != test.want {
			t.Fatalf("input %d returned exit %d, want %d", test.input, got, test.want)
		}
	}
}

func TestWithSigningRunInputDataClearsMutableInputs(t *testing.T) {
	wantFailure := errors.New("stop after observing inputs")
	for _, test := range []struct {
		name         string
		operationErr error
	}{{name: "success"}, {name: "operation failure", operationErr: wantFailure}} {
		t.Run(test.name, func(t *testing.T) {
			inputs := map[string][]byte{
				"identity": []byte("private-pkcs12"),
				"profile":  []byte("profile-with-device-identifiers"),
				"password": []byte("secret-password\r\n"),
			}
			err := withSigningRunInputData(
				signingRunOptions{IdentityPath: "identity", ProfilePath: "profile", IdentityPasswordPath: "password"},
				func(path string, _ int64, _ bool) ([]byte, error) { return inputs[path], nil },
				func(gotIdentity, gotPassword, gotProfile []byte) error {
					if string(gotIdentity) != "private-pkcs12" || string(gotPassword) != "secret-password" || string(gotProfile) != "profile-with-device-identifiers" {
						t.Fatalf("operation inputs were changed too early: identity=%q password=%q profile=%q", gotIdentity, gotPassword, gotProfile)
					}
					return test.operationErr
				},
			)
			if !errors.Is(err, test.operationErr) {
				t.Fatalf("error = %v, want %v", err, test.operationErr)
			}
			for name, data := range inputs {
				if !bytes.Equal(data, make([]byte, len(data))) {
					t.Fatalf("%s input was not cleared: %v", name, data)
				}
			}
		})
	}
}

func TestWithSigningRunInputDataClearsEarlierInputsOnReadFailure(t *testing.T) {
	identity := []byte("private-pkcs12")
	profileErr := errors.New("profile read failed")
	err := withSigningRunInputData(
		signingRunOptions{IdentityPath: "identity", ProfilePath: "profile"},
		func(path string, _ int64, _ bool) ([]byte, error) {
			if path == "identity" {
				return identity, nil
			}
			return nil, profileErr
		},
		func(_, _, _ []byte) error {
			t.Fatal("operation must not run after a read failure")
			return nil
		},
	)
	if !errors.Is(err, profileErr) {
		t.Fatalf("error = %v, want profile read failure", err)
	}
	if !bytes.Equal(identity, make([]byte, len(identity))) {
		t.Fatalf("identity input was not cleared after later read failure: %v", identity)
	}
}

func TestRunSigningEnvironmentOrdinarySetupAndCleanupFailuresRemainRootRenderable(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	setupErr := errors.New("setup exploded")
	cleanupErr := errors.New("cleanup exploded")
	var stderr bytes.Buffer
	events := []string{}
	deps := fakeSigningRunDeps(&events)
	deps.Stderr = &stderr
	deps.CreateKeychain = func(context.Context, string, []byte) error { return setupErr }
	deps.RemoveKeychainSearchEntry = func(context.Context, string) error { return cleanupErr }
	_, runErr := runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
		t.Fatal("callback must not run after setup failure")
		return nil
	})
	if !errors.Is(runErr, setupErr) || !errors.Is(runErr, cleanupErr) {
		t.Fatalf("error = %v, want setup and cleanup causes", runErr)
	}
	if _, ok := shared.ProcessExitCode(runErr); ok {
		t.Fatalf("ordinary setup failure unexpectedly carries a child exit: %v", runErr)
	}
	var reported shared.ReportedError
	if errors.As(runErr, &reported) {
		t.Fatalf("ordinary failures must remain root-renderable: %v", runErr)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want root to render the joined error", stderr.String())
	}
	for _, text := range []string{"setup exploded", "cleanup exploded"} {
		if !strings.Contains(runErr.Error(), text) {
			t.Fatalf("error = %q, want %q", runErr, text)
		}
	}
}

func TestRunSigningEnvironmentChildAndCleanupFailureRendersCompanion(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	cleanupErr := errors.New("cleanup exploded")
	var stderr bytes.Buffer
	events := []string{}
	deps := fakeSigningRunDeps(&events)
	deps.Stderr = &stderr
	removeCalls := 0
	deps.RemoveKeychainSearchEntry = func(context.Context, string) error {
		removeCalls++
		if removeCalls > 1 {
			return cleanupErr
		}
		return nil
	}
	_, runErr := runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
		return shared.NewProcessExitError(42)
	})
	if code, ok := shared.ProcessExitCode(runErr); !ok || code != 42 {
		t.Fatalf("process exit = %d, %t; want 42, true; error=%v", code, ok, runErr)
	}
	if !strings.Contains(stderr.String(), "cleanup exploded") {
		t.Fatalf("stderr = %q, want cleanup cause", stderr.String())
	}
}

func TestRunSigningEnvironmentChildAndUnlockFailureRendersCompanion(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	unlockErr := errors.New("unlock exploded")
	var stderr bytes.Buffer
	events := []string{}
	deps := fakeSigningRunDeps(&events)
	deps.Stderr = &stderr
	deps.AcquireLock = func(context.Context) (func() error, error) { return func() error { return unlockErr }, nil }
	_, runErr := runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
		return shared.NewProcessExitError(42)
	})
	if code, ok := shared.ProcessExitCode(runErr); !ok || code != 42 {
		t.Fatalf("process exit = %d, %t; want 42, true; error=%v", code, ok, runErr)
	}
	if !strings.Contains(stderr.String(), "release signing environment lock: unlock exploded") {
		t.Fatalf("stderr = %q, want unlock cause", stderr.String())
	}
}

func TestFinishSigningRunReceiptReportsFailureAlongsideChildExit(t *testing.T) {
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(receiptPath, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing receipt: %v", err)
	}
	var stderr bytes.Buffer
	err := finishSigningRunReceipt(&stderr, receiptPath, signingRunReceipt{SchemaVersion: 1}, shared.NewProcessExitError(42))
	if code, ok := shared.ProcessExitCode(err); !ok || code != 42 {
		t.Fatalf("process exit = %d, %t; want 42, true; error=%v", code, ok, err)
	}
	if !strings.Contains(stderr.String(), "Error: signing run: write receipt:") {
		t.Fatalf("stderr = %q, want separately rendered receipt failure", stderr.String())
	}
	var reported shared.ReportedError
	if !errors.As(err, &reported) {
		t.Fatalf("error = %v, want already-reported composite", err)
	}
}

func TestRunSigningEnvironmentRestoresStateInReverseOrder(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	events := []string{}
	deps := signingRunDeps{
		GOOS: "darwin",
		RandomBytes: func(size int) ([]byte, error) {
			return []byte(strings.Repeat("a", size)), nil
		},
		TempDir:       func() (string, error) { events = append(events, "temp"); return "/tmp/asc-signing-run/test", nil },
		RemoveTempDir: func(path string) error { events = append(events, "remove-temp:"+path); return nil },
		AcquireLock: func(context.Context) (func() error, error) {
			events = append(events, "lock")
			return func() error { events = append(events, "unlock"); return nil }, nil
		},
		Recover: func(context.Context) error { events = append(events, "recover"); return nil },
		WriteJournal: func(_ signingRunJournal, overwrite bool) error {
			events = append(events, fmt.Sprintf("journal:%t", overwrite))
			return nil
		},
		RemoveJournal: func() error { events = append(events, "remove-journal"); return nil },
		KeychainSearchList: func(context.Context) ([]string, error) {
			events = append(events, "list")
			return []string{"/Users/me/login.keychain-db"}, nil
		},
		CreateKeychain: func(context.Context, string, []byte) error { events = append(events, "create-keychain"); return nil },
		ImportIdentity: func(context.Context, string, []byte, []byte, []byte, string) error {
			events = append(events, "import")
			return nil
		},
		SetKeychainSearchList: func(_ context.Context, paths []string) error {
			events = append(events, "set-list:"+strings.Join(paths, ","))
			return nil
		},
		RemoveKeychainSearchEntry: func(context.Context, string) error { events = append(events, "remove-search-entry"); return nil },
		DeleteKeychain:            func(context.Context, string) error { events = append(events, "delete-keychain"); return nil },
		InstallProfile: func(_ string, _ []byte, _ string, beforeCreate func(signingRunProfileInstall) error) (signingRunProfileInstall, error) {
			events = append(events, "install-profile")
			planned := signingRunProfileInstall{Path: "/profiles/uuid.mobileprovision", Created: true, Digest: inspection.ProfileSHA256}
			if err := beforeCreate(planned); err != nil {
				return signingRunProfileInstall{}, err
			}
			return planned, nil
		},
		RemoveProfile: func(signingRunProfileInstall) error { events = append(events, "remove-profile"); return nil },
	}

	result, err := runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
		events = append(events, "child")
		return nil
	})
	if err != nil {
		t.Fatalf("runSigningEnvironment() error: %v", err)
	}
	if result.Outcome != "succeeded" || result.ChildExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	want := []string{
		"lock", "recover", "temp", "list", "journal:false", "create-keychain", "remove-search-entry", "import",
		"install-profile", "journal:true", "list",
		"set-list:/tmp/asc-signing-run/test/signing.keychain-db,/Users/me/login.keychain-db",
		"child", "remove-profile", "remove-search-entry", "delete-keychain",
		"remove-temp:/tmp/asc-signing-run/test", "remove-journal", "unlock",
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestRunSigningEnvironmentCallbackPanicCleansUpInReverseOrderAndRepanics(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	events := []string{}
	deps := fakeSigningRunDeps(&events)
	deps.InstallProfile = func(_ string, _ []byte, _ string, beforeCreate func(signingRunProfileInstall) error) (signingRunProfileInstall, error) {
		events = append(events, "install-profile")
		planned := signingRunProfileInstall{Path: "/profiles/uuid", Created: true, Digest: inspection.ProfileSHA256}
		if err := beforeCreate(planned); err != nil {
			return signingRunProfileInstall{}, err
		}
		return planned, nil
	}
	panicValue := &struct{ message string }{message: "callback panic sentinel"}
	gotPanic := func() (recovered any) {
		defer func() { recovered = recover() }()
		_, _ = runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
			events = append(events, "callback")
			panic(panicValue)
		})
		return nil
	}()
	if gotPanic != panicValue {
		t.Fatalf("panic = %#v, want original %#v", gotPanic, panicValue)
	}
	wantTail := []string{"callback", "remove-profile", "remove-search-entry", "delete-keychain", "remove-temp", "remove-journal", "unlock"}
	if len(events) < len(wantTail) || !reflect.DeepEqual(events[len(events)-len(wantTail):], wantTail) {
		t.Fatalf("events = %#v, want cleanup tail %#v", events, wantTail)
	}
}

func TestRunSigningEnvironmentRawExecErrorDoesNotOptIntoExactExit(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	execErr := exec.Command("/bin/sh", "-c", "exit 42").Run()
	events := []string{}
	_, runErr := runSigningEnvironment(context.Background(), fakeSigningRunDeps(&events), signingRunOptions{}, fixture.profile, inspection, func(context.Context) error {
		return execErr
	})
	if !errors.Is(runErr, execErr) {
		t.Fatalf("error = %v, want raw exec error", runErr)
	}
	if code, ok := shared.ProcessExitCode(runErr); ok {
		t.Fatalf("raw exec error opted into exact exit %d: %v", code, runErr)
	}
}

func TestRunSigningEnvironmentRestoresAfterEachSetupFailure(t *testing.T) {
	fixture := newSigningRunFixture(t, signingRunFixtureOptions{})
	inspection, err := inspectSigningRunInputs(fixture.identity, []byte(fixture.password), fixture.profile, fixture.roots, fixture.now)
	if err != nil {
		t.Fatalf("inspect fixture: %v", err)
	}
	for _, failStage := range []string{"create-keychain", "import", "set-list", "install-profile", "child"} {
		t.Run(failStage, func(t *testing.T) {
			events := []string{}
			fail := errors.New("boom at " + failStage)
			deps := fakeSigningRunDeps(&events)
			deps.CreateKeychain = func(context.Context, string, []byte) error {
				events = append(events, "create-keychain")
				if failStage == "create-keychain" {
					return fail
				}
				return nil
			}
			deps.ImportIdentity = func(context.Context, string, []byte, []byte, []byte, string) error {
				events = append(events, "import")
				if failStage == "import" {
					return fail
				}
				return nil
			}
			deps.SetKeychainSearchList = func(_ context.Context, paths []string) error {
				events = append(events, "set-list:"+strings.Join(paths, ","))
				if failStage == "set-list" && len(paths) > 1 {
					return fail
				}
				return nil
			}
			deps.InstallProfile = func(_ string, _ []byte, _ string, beforeCreate func(signingRunProfileInstall) error) (signingRunProfileInstall, error) {
				events = append(events, "install-profile")
				if failStage == "install-profile" {
					return signingRunProfileInstall{}, fail
				}
				planned := signingRunProfileInstall{Path: "/profiles/uuid", Created: true, Digest: inspection.ProfileSHA256}
				if err := beforeCreate(planned); err != nil {
					return signingRunProfileInstall{}, err
				}
				return planned, nil
			}
			operation := func(context.Context) error {
				events = append(events, "child")
				if failStage == "child" {
					return fail
				}
				return nil
			}

			_, gotErr := runSigningEnvironment(context.Background(), deps, signingRunOptions{}, fixture.profile, inspection, operation)
			if !errors.Is(gotErr, fail) {
				t.Fatalf("error = %v, want injected failure", gotErr)
			}
			if !slices.Contains(events, "unlock") || !slices.Contains(events, "remove-temp") {
				t.Fatalf("cleanup events missing: %v", events)
			}
			if failStage != "create-keychain" && !slices.Contains(events, "delete-keychain") {
				t.Fatalf("keychain cleanup missing: %v", events)
			}
		})
	}
}

func fakeSigningRunDeps(events *[]string) signingRunDeps {
	return signingRunDeps{
		GOOS:          "darwin",
		Stderr:        io.Discard,
		RandomBytes:   func(size int) ([]byte, error) { return []byte(strings.Repeat("a", size)), nil },
		TempDir:       func() (string, error) { *events = append(*events, "temp"); return "/tmp/signing-run", nil },
		RemoveTempDir: func(string) error { *events = append(*events, "remove-temp"); return nil },
		AcquireLock: func(context.Context) (func() error, error) {
			*events = append(*events, "lock")
			return func() error { *events = append(*events, "unlock"); return nil }, nil
		},
		Recover:       func(context.Context) error { *events = append(*events, "recover"); return nil },
		WriteJournal:  func(signingRunJournal, bool) error { *events = append(*events, "journal"); return nil },
		RemoveJournal: func() error { *events = append(*events, "remove-journal"); return nil },
		KeychainSearchList: func(context.Context) ([]string, error) {
			*events = append(*events, "list")
			return []string{"login"}, nil
		},
		CreateKeychain: func(context.Context, string, []byte) error { *events = append(*events, "create-keychain"); return nil },
		ImportIdentity: func(context.Context, string, []byte, []byte, []byte, string) error {
			*events = append(*events, "import")
			return nil
		},
		SetKeychainSearchList:     func(context.Context, []string) error { *events = append(*events, "set-list"); return nil },
		RemoveKeychainSearchEntry: func(context.Context, string) error { *events = append(*events, "remove-search-entry"); return nil },
		DeleteKeychain:            func(context.Context, string) error { *events = append(*events, "delete-keychain"); return nil },
		InstallProfile: func(string, []byte, string, func(signingRunProfileInstall) error) (signingRunProfileInstall, error) {
			*events = append(*events, "install-profile")
			return signingRunProfileInstall{}, nil
		},
		RemoveProfile: func(signingRunProfileInstall) error { *events = append(*events, "remove-profile"); return nil },
	}
}

func TestSigningRunCommandFlags(t *testing.T) {
	command := SigningRunCommand()
	if !strings.HasPrefix(command.ShortHelp, "[experimental]") {
		t.Fatalf("ShortHelp = %q, want experimental lifecycle label", command.ShortHelp)
	}
	for _, name := range []string{
		"identity",
		"identity-password-file",
		"profile",
		"purpose",
		"receipt",
	} {
		if command.FlagSet.Lookup(name) == nil {
			t.Fatalf("expected --%s flag", name)
		}
	}
	if strings.Contains(command.LongHelp, "--identity-password PASSWORD") {
		t.Fatalf("help must not document an inline password: %s", command.LongHelp)
	}
}

func TestSigningRunCommandThreadsFlagsAndChildArgv(t *testing.T) {
	previous := executeSigningRunFn
	t.Cleanup(func() { executeSigningRunFn = previous })
	var got signingRunOptions
	executeSigningRunFn = func(_ context.Context, options signingRunOptions) error {
		got = options
		return nil
	}
	command := SigningRunCommand()
	command.FlagSet.SetOutput(&strings.Builder{})
	args := []string{
		"--identity", "App.p12",
		"--identity-password-file", "p12-password",
		"--profile", "App.mobileprovision",
		"--purpose", "release-testing",
		"--receipt", "run.json",
		"--", "xcodebuild", "-exportArchive", "--looks-like-a-flag",
	}
	if err := command.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := command.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := signingRunOptions{
		IdentityPath: "App.p12", IdentityPasswordPath: "p12-password",
		ProfilePath: "App.mobileprovision", Purpose: "release-testing",
		ReceiptPath: "run.json", Child: []string{"xcodebuild", "-exportArchive", "--looks-like-a-flag"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("options = %+v, want %+v", got, want)
	}
}

func TestSigningRunCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "identity required", args: []string{"--profile", "App.mobileprovision", "--", "true"}, wantErr: "--identity is required"},
		{name: "profile required", args: []string{"--identity", "App.p12", "--", "true"}, wantErr: "--profile is required"},
		{name: "child required", args: []string{"--identity", "App.p12", "--profile", "App.mobileprovision"}, wantErr: "a child command is required"},
		{name: "invalid purpose", args: []string{"--identity", "App.p12", "--profile", "App.mobileprovision", "--purpose", "development", "--", "true"}, wantErr: `--purpose must be "release-testing"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := SigningRunCommand()
			command.FlagSet.SetOutput(&strings.Builder{})
			if err := command.Parse(test.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			err := command.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("error = %v, want usage error", err)
			}
			if shared.ClassifyUsageError(err) == "" {
				t.Fatalf("error = %v, want classified usage error", err)
			}
		})
	}
}
