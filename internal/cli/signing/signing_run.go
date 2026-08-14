package signing

import (
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bitrise-io/go-pkcs12"
	"github.com/peterbourgon/ff/v3/ffcli"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared/errfmt"
)

const (
	signingRunPurposeReleaseTesting = "release-testing"
	signingRunInputLimit            = 16 << 20
	signingRunPasswordLimit         = 64 << 10
)

type signingRunOptions struct {
	IdentityPath         string
	IdentityPasswordPath string
	ProfilePath          string
	Purpose              string
	ReceiptPath          string
	Child                []string
}

type signingRunInspection struct {
	ProfileUUID        string
	TeamID             string
	BundleID           string
	ProvisionedDevices []string
	CertificateSHA1    string
	CertificateSHA256  string
	ProfileSHA256      string
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
}

type signingRunProfileInstall struct {
	Path       string
	StagedPath string
	Created    bool
	Digest     string
	Device     uint64
	Inode      uint64
}

type signingRunDeps struct {
	GOOS                      string
	Stderr                    io.Writer
	RandomBytes               func(int) ([]byte, error)
	TempDir                   func() (string, error)
	RemoveTempDir             func(string) error
	AcquireLock               func(context.Context) (func() error, error)
	Recover                   func(context.Context) error
	WriteJournal              func(signingRunJournal, bool) error
	RemoveJournal             func() error
	KeychainSearchList        func(context.Context) ([]string, error)
	CreateKeychain            func(context.Context, string, []byte) error
	ImportIdentity            func(context.Context, string, []byte, []byte, []byte, string) error
	SetKeychainSearchList     func(context.Context, []string) error
	RemoveKeychainSearchEntry func(context.Context, string) error
	DeleteKeychain            func(context.Context, string) error
	InstallProfile            func(string, []byte, string, func(signingRunProfileInstall) error) (signingRunProfileInstall, error)
	RemoveProfile             func(signingRunProfileInstall) error
	RunChild                  func(context.Context, []string) error
}

type signingRunJournal struct {
	SchemaVersion     int    `json:"schemaVersion"`
	TempDir           string `json:"tempDir"`
	KeychainPath      string `json:"keychainPath"`
	ProfilePath       string `json:"profilePath,omitempty"`
	StagedProfilePath string `json:"stagedProfilePath,omitempty"`
	ProfileDigest     string `json:"profileDigest,omitempty"`
	ProfileDevice     uint64 `json:"profileDevice,omitempty"`
	ProfileInode      uint64 `json:"profileInode,omitempty"`
	ProfileCreated    bool   `json:"profileCreated,omitempty"`
}

type signingRunMobileProvision struct {
	UUID                        string         `plist:"UUID"`
	TeamIdentifier              []string       `plist:"TeamIdentifier"`
	ApplicationIdentifierPrefix []string       `plist:"ApplicationIdentifierPrefix"`
	Platform                    []string       `plist:"Platform"`
	ProvisionedDevices          []string       `plist:"ProvisionedDevices"`
	ProvisionsAllDevices        bool           `plist:"ProvisionsAllDevices"`
	CreationDate                time.Time      `plist:"CreationDate"`
	ExpirationDate              time.Time      `plist:"ExpirationDate"`
	Entitlements                map[string]any `plist:"Entitlements"`
	DeveloperCertificates       [][]byte       `plist:"DeveloperCertificates"`
}

type signingRunReceipt struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Purpose              string `json:"purpose"`
	Outcome              string `json:"outcome"`
	ChildExitCode        int    `json:"childExitCode"`
	CertificateSHA256    string `json:"certificateSha256"`
	ProfileSHA256        string `json:"profileSha256"`
	ProfileUUID          string `json:"profileUuid"`
	TeamID               string `json:"teamId"`
	BundleID             string `json:"bundleId"`
	ProfileCleanupState  string `json:"profileCleanupState"`
	KeychainCleanupState string `json:"keychainCleanupState"`
}

var signingRunUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var executeSigningRunFn = executeSigningRun

// SigningRunCommand returns the signing run subcommand.
func SigningRunCommand() *ffcli.Command {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	identityPath := fs.String("identity", "", "Path to a PKCS#12 distribution identity")
	identityPasswordPath := fs.String("identity-password-file", "", "Path to a file containing the PKCS#12 password")
	profilePath := fs.String("profile", "", "Path to the provisioning profile to install for the child")
	purpose := fs.String("purpose", signingRunPurposeReleaseTesting, "Signing purpose (release-testing)")
	receiptPath := fs.String("receipt", "", "Write a redacted JSON execution receipt to this path")

	return &ffcli.Command{
		Name:       "run",
		ShortUsage: "asc signing run --identity PATH --profile PATH [flags] -- <command> [args...]",
		ShortHelp:  "[experimental] Run one command with an ephemeral signing identity.",
		LongHelp: `[experimental] Run one command with an ephemeral signing identity and provisioning profile.

The identity is imported into a dedicated temporary keychain and is available
only while the child command runs. The child is executed directly without a
shell and inherits stdin, stdout, and stderr. Put the child command after --.

Examples:
  asc signing run --identity .asc/signing/App.p12 --profile .asc/signing/App.mobileprovision -- xcodebuild -exportArchive
  asc signing run --identity .asc/signing/App.p12 --identity-password-file .asc/secrets/p12-password --profile .asc/signing/App.mobileprovision --receipt .asc/distribution/signing-run.json -- xcodebuild -exportArchive`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			identity := strings.TrimSpace(*identityPath)
			if identity == "" {
				return shared.UsageError("--identity is required")
			}
			profile := strings.TrimSpace(*profilePath)
			if profile == "" {
				return shared.UsageError("--profile is required")
			}
			purposeValue := strings.TrimSpace(*purpose)
			if purposeValue != signingRunPurposeReleaseTesting {
				return shared.UsageError(`--purpose must be "release-testing"`)
			}
			if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
				return shared.UsageError("a child command is required after --")
			}

			return executeSigningRunFn(ctx, signingRunOptions{
				IdentityPath:         identity,
				IdentityPasswordPath: strings.TrimSpace(*identityPasswordPath),
				ProfilePath:          profile,
				Purpose:              purposeValue,
				ReceiptPath:          strings.TrimSpace(*receiptPath),
				Child:                append([]string(nil), args...),
			})
		},
	}
}

func executeSigningRun(ctx context.Context, options signingRunOptions) error {
	deps := platformSigningRunDeps()
	if deps.GOOS != "darwin" {
		return shared.NewValidationError(fmt.Errorf("signing run is supported only on macOS"))
	}
	return withSigningRunInputData(options, readBoundedSigningRunFile, func(identityData, identityPassword, profileData []byte) error {
		roots, err := systemSigningRunRoots()
		if err != nil {
			return fmt.Errorf("signing run: load system certificate roots: %w", err)
		}
		inspection, err := inspectSigningRunInputs(identityData, identityPassword, profileData, roots, time.Now())
		if err != nil {
			return fmt.Errorf("signing run: preflight: %w", err)
		}

		runCtx, stopSignals := platformSigningRunContext(ctx)
		defer stopSignals()
		return withSigningRunReceipt(os.Stderr, options.ReceiptPath, func() (signingRunReceipt, error) {
			return runSigningEnvironment(runCtx, deps, options, profileData, inspection)
		})
	})
}

func withSigningRunReceipt(
	stderr io.Writer,
	path string,
	run func() (signingRunReceipt, error),
) error {
	if err := preflightSigningRunReceipt(path); err != nil {
		return fmt.Errorf("signing run: preflight receipt: %w", err)
	}
	receipt, runErr := run()
	return finishSigningRunReceipt(stderr, path, receipt, runErr)
}

func preflightSigningRunReceipt(path string) error {
	if path == "" {
		return nil
	}
	preflightComplete := errors.New("receipt preflight complete")
	_, err := shared.SafeWriteFileNoSymlink(
		path,
		0o600,
		false,
		".asc-signing-run-receipt-*",
		".asc-signing-run-receipt-backup-*",
		func(*os.File) (int64, error) {
			return 0, preflightComplete
		},
	)
	if errors.Is(err, preflightComplete) {
		return nil
	}
	return err
}

func withSigningRunInputData(
	options signingRunOptions,
	readFile func(string, int64, bool) ([]byte, error),
	operation func(identityData, identityPassword, profileData []byte) error,
) error {
	identityData, err := readFile(options.IdentityPath, signingRunInputLimit, true)
	if err != nil {
		return fmt.Errorf("signing run: read identity: %w", err)
	}
	defer clear(identityData)
	profileData, err := readFile(options.ProfilePath, signingRunInputLimit, false)
	if err != nil {
		return fmt.Errorf("signing run: read profile: %w", err)
	}
	defer clear(profileData)
	var passwordData []byte
	if options.IdentityPasswordPath != "" {
		passwordData, err = readFile(options.IdentityPasswordPath, signingRunPasswordLimit, true)
		if err != nil {
			return fmt.Errorf("signing run: read identity password: %w", err)
		}
	}
	defer clear(passwordData)
	identityPassword := bytes.TrimSuffix(passwordData, []byte("\n"))
	identityPassword = bytes.TrimSuffix(identityPassword, []byte("\r"))
	return operation(identityData, identityPassword, profileData)
}

func finishSigningRunReceipt(stderr io.Writer, path string, receipt signingRunReceipt, runErr error) error {
	if path == "" {
		return runErr
	}
	data, err := marshalSigningRunReceipt(receipt)
	if err == nil {
		_, err = shared.SafeWriteFileNoSymlink(
			path,
			0o600,
			false,
			".asc-signing-run-receipt-*",
			".asc-signing-run-receipt-backup-*",
			func(file *os.File) (int64, error) {
				written, writeErr := file.Write(data)
				return int64(written), writeErr
			},
		)
	}
	if err == nil {
		return runErr
	}
	return joinSigningRunCompanionError(stderr, runErr, fmt.Errorf("signing run: write receipt: %w", err))
}

func joinSigningRunCompanionError(stderr io.Writer, primary, companion error) error {
	if companion == nil {
		return primary
	}
	if _, ok := shared.ProcessExitCode(primary); !ok {
		// Neither error has been rendered. Leave both unreported so the root
		// command prints the complete joined diagnostic once.
		return errors.Join(primary, companion)
	}
	// The child owns stderr and its exact-exit marker tells the root command not
	// to duplicate it. Render every independent companion before joining it;
	// otherwise that marker suppresses the whole composite.
	if stderr == nil {
		stderr = io.Discard
	}
	fmt.Fprint(stderr, errfmt.FormatStderr(companion))
	return errors.Join(primary, shared.NewReportedError(companion))
}

func readBoundedSigningRunFile(path string, limit int64, private bool) ([]byte, error) {
	file, err := shared.OpenExistingNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	if err := validateSigningRunInputPermissions(path, info, private); err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%q exceeds the %d-byte limit", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q exceeds the %d-byte limit", path, limit)
	}
	return data, nil
}

func runSigningEnvironment(
	ctx context.Context,
	deps signingRunDeps,
	options signingRunOptions,
	profileData []byte,
	inspection *signingRunInspection,
) (receipt signingRunReceipt, resultErr error) {
	receipt = signingRunReceipt{
		SchemaVersion:        1,
		Purpose:              options.Purpose,
		Outcome:              "failed",
		CertificateSHA256:    inspection.CertificateSHA256,
		ProfileSHA256:        inspection.ProfileSHA256,
		ProfileUUID:          inspection.ProfileUUID,
		TeamID:               inspection.TeamID,
		BundleID:             inspection.BundleID,
		ProfileCleanupState:  "not-installed",
		KeychainCleanupState: "not-created",
	}
	unlock, err := deps.AcquireLock(ctx)
	if err != nil {
		return receipt, fmt.Errorf("acquire signing environment lock: %w", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			resultErr = joinSigningRunCompanionError(
				deps.Stderr,
				resultErr,
				fmt.Errorf("release signing environment lock: %w", err),
			)
		}
	}()
	if err := deps.Recover(ctx); err != nil {
		return receipt, fmt.Errorf("recover prior signing environment: %w", err)
	}

	tempDir, err := deps.TempDir()
	if err != nil {
		return receipt, fmt.Errorf("create private signing directory: %w", err)
	}
	keychainPath := filepath.Join(tempDir, "signing.keychain-db")
	_, err = deps.KeychainSearchList(ctx)
	if err != nil {
		_ = deps.RemoveTempDir(tempDir)
		return receipt, fmt.Errorf("read user keychain search list: %w", err)
	}
	keychainPassword, err := deps.RandomBytes(32)
	if err != nil {
		_ = deps.RemoveTempDir(tempDir)
		return receipt, fmt.Errorf("generate keychain password: %w", err)
	}
	defer clear(keychainPassword)
	importPassword, err := deps.RandomBytes(32)
	if err != nil {
		_ = deps.RemoveTempDir(tempDir)
		return receipt, fmt.Errorf("generate identity import password: %w", err)
	}
	importPasswordText := []byte(hex.EncodeToString(importPassword))
	clear(importPassword)
	normalizedIdentity, err := pkcs12.Encode(
		cryptorand.Reader,
		inspection.PrivateKey,
		inspection.Certificate,
		nil,
		string(importPasswordText),
	)
	if err != nil {
		clear(importPasswordText)
		_ = deps.RemoveTempDir(tempDir)
		return receipt, fmt.Errorf("normalize identity for temporary import: %w", err)
	}
	defer clear(importPasswordText)
	defer clear(normalizedIdentity)
	journal := signingRunJournal{SchemaVersion: 1, TempDir: tempDir, KeychainPath: keychainPath}
	if err := deps.WriteJournal(journal, false); err != nil {
		_ = deps.RemoveTempDir(tempDir)
		return receipt, fmt.Errorf("write signing environment recovery journal: %w", err)
	}

	keychainAttempted := false
	profileInstall := signingRunProfileInstall{}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var cleanupErr error
		if profileInstall.Created {
			if err := deps.RemoveProfile(profileInstall); err != nil {
				receipt.ProfileCleanupState = "failed"
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove installed provisioning profile: %w", err))
			} else {
				receipt.ProfileCleanupState = "removed"
			}
		}
		if keychainAttempted {
			if err := deps.RemoveKeychainSearchEntry(cleanupCtx, keychainPath); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove temporary keychain from search list: %w", err))
			}
			if err := deps.DeleteKeychain(cleanupCtx, keychainPath); err != nil {
				receipt.KeychainCleanupState = "failed"
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete temporary keychain: %w", err))
			} else {
				receipt.KeychainCleanupState = "deleted"
			}
		}
		if cleanupErr != nil {
			return cleanupErr
		}
		if err := deps.RemoveTempDir(tempDir); err != nil {
			return fmt.Errorf("remove private signing directory: %w", err)
		}
		if err := deps.RemoveJournal(); err != nil {
			return fmt.Errorf("remove signing environment recovery journal: %w", err)
		}
		return nil
	}
	finish := func(primary error) (signingRunReceipt, error) {
		cleanupErr := cleanup()
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("signing run cleanup did not complete; the next run will retry recovery: %w", cleanupErr)
		}
		return receipt, joinSigningRunCompanionError(deps.Stderr, primary, cleanupErr)
	}

	keychainAttempted = true
	receipt.KeychainCleanupState = "pending"
	if err := deps.CreateKeychain(ctx, keychainPath, keychainPassword); err != nil {
		return finish(fmt.Errorf("create temporary keychain: %w", err))
	}
	// Some macOS releases add newly created keychains to the user search list.
	// Remove it immediately; the command adds it back only for the child window.
	if err := deps.RemoveKeychainSearchEntry(ctx, keychainPath); err != nil {
		return finish(fmt.Errorf("isolate temporary keychain: %w", err))
	}
	if err := deps.ImportIdentity(ctx, keychainPath, keychainPassword, normalizedIdentity, importPasswordText, inspection.CertificateSHA1); err != nil {
		return finish(fmt.Errorf("import identity into temporary keychain: %w", err))
	}
	profileInstall, err = deps.InstallProfile(inspection.ProfileUUID, profileData, inspection.ProfileSHA256, func(planned signingRunProfileInstall) error {
		journal.ProfilePath = planned.Path
		journal.StagedProfilePath = planned.StagedPath
		journal.ProfileDigest = planned.Digest
		journal.ProfileDevice = planned.Device
		journal.ProfileInode = planned.Inode
		journal.ProfileCreated = true
		return deps.WriteJournal(journal, true)
	})
	if err != nil {
		return finish(fmt.Errorf("install provisioning profile: %w", err))
	}
	if profileInstall.Created {
		receipt.ProfileCleanupState = "pending"
	} else {
		receipt.ProfileCleanupState = "reused"
	}

	currentSearchList, err := deps.KeychainSearchList(ctx)
	if err != nil {
		return finish(fmt.Errorf("refresh user keychain search list: %w", err))
	}
	expectedSearchList := []string{keychainPath}
	for _, path := range currentSearchList {
		if path != keychainPath {
			expectedSearchList = append(expectedSearchList, path)
		}
	}
	if err := deps.SetKeychainSearchList(ctx, expectedSearchList); err != nil {
		return finish(fmt.Errorf("activate temporary keychain: %w", err))
	}
	childErr := deps.RunChild(ctx, options.Child)
	if childErr != nil {
		receipt.ChildExitCode = childExitCode(childErr)
		return finish(childErr)
	}
	receipt.Outcome = "succeeded"
	return finish(nil)
}

func inspectSigningRunInputs(identityData, identityPassword, profileData []byte, roots *x509.CertPool, now time.Time) (*signingRunInspection, error) {
	privateKeys, certificates, err := pkcs12.DecodeAll(identityData, string(identityPassword))
	if err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if len(privateKeys) != 1 {
		return nil, fmt.Errorf("decode identity: expected exactly one private key, found %d", len(privateKeys))
	}
	signer, ok := privateKeys[0].(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("decode identity: private key is not usable for signing")
	}
	privatePublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("inspect identity private key: %w", err)
	}
	var certificate *x509.Certificate
	for _, candidate := range certificates {
		if candidate == nil {
			continue
		}
		candidatePublic, err := x509.MarshalPKIXPublicKey(candidate.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("inspect identity certificate: %w", err)
		}
		if !bytes.Equal(privatePublic, candidatePublic) {
			continue
		}
		if certificate != nil {
			return nil, fmt.Errorf("decode identity: multiple certificates match the private key")
		}
		certificate = candidate
	}
	if certificate == nil {
		return nil, fmt.Errorf("identity private key does not match its certificate")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, fmt.Errorf("identity certificate is not valid at the current time")
	}

	p7, err := pkcs7.Parse(profileData)
	if err != nil {
		return nil, fmt.Errorf("decode signed provisioning profile: %w", err)
	}
	if roots == nil {
		return nil, fmt.Errorf("load trusted roots for provisioning profile verification")
	}
	if err := p7.VerifyWithChainAtTime(roots, now); err != nil {
		return nil, fmt.Errorf("verify profile signature: %w", err)
	}
	if len(p7.Content) == 0 {
		return nil, fmt.Errorf("decode provisioning profile: signed content is empty")
	}
	var profile signingRunMobileProvision
	if err := plist.NewDecoder(bytes.NewReader(p7.Content)).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode provisioning profile plist: %w", err)
	}

	profile.UUID = strings.TrimSpace(profile.UUID)
	if !signingRunUUIDPattern.MatchString(profile.UUID) {
		return nil, fmt.Errorf("provisioning profile UUID is missing or invalid")
	}
	if profile.ExpirationDate.IsZero() || !now.Before(profile.ExpirationDate) {
		return nil, fmt.Errorf("provisioning profile is expired")
	}
	if !profile.CreationDate.IsZero() && profile.CreationDate.After(now) {
		return nil, fmt.Errorf("provisioning profile creation date is in the future")
	}
	if !slices.ContainsFunc(profile.Platform, func(value string) bool { return strings.EqualFold(strings.TrimSpace(value), "iOS") }) {
		return nil, fmt.Errorf("provisioning profile does not target iOS")
	}
	if profile.ProvisionsAllDevices {
		return nil, fmt.Errorf("provisioning profile is an enterprise profile, not release-testing")
	}
	if value, exists := profile.Entitlements["get-task-allow"]; exists {
		allowed, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("provisioning profile get-task-allow entitlement must be a boolean")
		}
		if allowed {
			return nil, fmt.Errorf("provisioning profile is a development profile, not release-testing")
		}
	}
	devices := make([]string, 0, len(profile.ProvisionedDevices))
	for _, device := range profile.ProvisionedDevices {
		device = strings.TrimSpace(device)
		if device == "" {
			return nil, fmt.Errorf("provisioning profile contains an empty registered device identifier")
		}
		devices = append(devices, device)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("provisioning profile has no registered devices")
	}

	teamID, err := signingRunTeamID(profile.TeamIdentifier)
	if err != nil {
		return nil, err
	}
	if entitlementTeam, exists := profile.Entitlements["com.apple.developer.team-identifier"]; exists {
		value, ok := entitlementTeam.(string)
		if !ok || strings.TrimSpace(value) != teamID {
			return nil, fmt.Errorf("provisioning profile entitlement team identifier does not match TeamIdentifier")
		}
	}
	if !slices.Contains(certificate.Subject.OrganizationalUnit, teamID) {
		return nil, fmt.Errorf("identity certificate organizational unit does not contain profile team %q", teamID)
	}

	bundleID, err := signingRunBundleID(profile, teamID)
	if err != nil {
		return nil, err
	}
	embedded := false
	for _, certificateDER := range profile.DeveloperCertificates {
		if _, err := x509.ParseCertificate(certificateDER); err != nil {
			return nil, fmt.Errorf("decode provisioning profile certificate: %w", err)
		}
		if bytes.Equal(certificate.Raw, certificateDER) {
			embedded = true
		}
	}
	if !embedded {
		return nil, fmt.Errorf("identity certificate is not embedded in provisioning profile")
	}

	certificateDigestSHA1 := sha1.Sum(certificate.Raw)
	certificateDigest := sha256.Sum256(certificate.Raw)
	profileDigest := sha256.Sum256(profileData)
	return &signingRunInspection{
		ProfileUUID:        profile.UUID,
		TeamID:             teamID,
		BundleID:           bundleID,
		ProvisionedDevices: devices,
		CertificateSHA1:    strings.ToUpper(hex.EncodeToString(certificateDigestSHA1[:])),
		CertificateSHA256:  strings.ToUpper(hex.EncodeToString(certificateDigest[:])),
		ProfileSHA256:      strings.ToUpper(hex.EncodeToString(profileDigest[:])),
		Certificate:        certificate,
		PrivateKey:         privateKeys[0],
	}, nil
}

func signingRunTeamID(values []string) (string, error) {
	var teamID string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("provisioning profile contains an empty team identifier")
		}
		if teamID == "" {
			teamID = value
			continue
		}
		if value != teamID {
			return "", fmt.Errorf("provisioning profile contains conflicting team identifiers")
		}
	}
	if teamID == "" {
		return "", fmt.Errorf("provisioning profile team identifier is missing")
	}
	return teamID, nil
}

func signingRunBundleID(profile signingRunMobileProvision, teamID string) (string, error) {
	value, ok := profile.Entitlements["application-identifier"].(string)
	if !ok || strings.TrimSpace(value) == "" {
		value, ok = profile.Entitlements["com.apple.application-identifier"].(string)
	}
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("provisioning profile application identifier is missing")
	}
	applicationID := strings.TrimSpace(value)
	prefixes := append([]string(nil), profile.ApplicationIdentifierPrefix...)
	if len(prefixes) == 0 {
		prefixes = []string{teamID}
	}
	slices.SortFunc(prefixes, func(left, right string) int { return len(right) - len(left) })
	var bundleID string
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && strings.HasPrefix(applicationID, prefix+".") {
			bundleID = strings.TrimPrefix(applicationID, prefix+".")
			break
		}
	}
	if !validSigningRunBundlePattern(bundleID) {
		return "", fmt.Errorf("provisioning profile bundle identifier pattern %q is invalid", bundleID)
	}
	return bundleID, nil
}

func validSigningRunBundlePattern(value string) bool {
	if value == "*" {
		return true
	}
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") {
		return false
	}
	if strings.Count(value, "*") > 0 && !strings.HasSuffix(value, ".*") {
		return false
	}
	base := strings.TrimSuffix(value, ".*")
	if base == "" {
		return false
	}
	for _, component := range strings.Split(base, ".") {
		if component == "" || strings.Contains(component, "*") {
			return false
		}
	}
	return true
}

func marshalSigningRunReceipt(receipt signingRunReceipt) ([]byte, error) {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode signing run receipt: %w", err)
	}
	return append(data, '\n'), nil
}

func childExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
	}
	if code, ok := shared.ProcessExitCode(err); ok {
		return code
	}
	return 1
}
