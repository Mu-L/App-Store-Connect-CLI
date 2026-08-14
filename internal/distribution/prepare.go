package distribution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

var (
	ErrNotEligible    = errors.New("IPA metadata is not eligible for release-testing preparation")
	ErrBundleConflict = errors.New("distribution bundle conflicts with existing output")

	afterOutputParentsCreatedForTest func()
	verifyCompleteSigningForTest     func(*Inspection)
)

type Descriptor struct {
	SchemaVersion      string   `json:"schemaVersion"`
	Platform           string   `json:"platform"`
	DistributionMethod string   `json:"distributionMethod"`
	App                App      `json:"app"`
	Artifact           Artifact `json:"artifact"`
	Signing            Signing  `json:"signing"`
	Source             *Source  `json:"source,omitempty"`
}

type PrepareOptions struct {
	Root           string
	OutputDir      string
	Title          string
	Channel        string
	SourceRevision string
	SourceURL      string
}

type PrepareResult struct {
	BundlePath string     `json:"bundlePath"`
	Reused     bool       `json:"reused"`
	Descriptor Descriptor `json:"descriptor"`
}

// PrepareIPA validates an already-open IPA and publishes an immutable local
// bundle without replacing an existing destination.
func PrepareIPA(file *os.File, size int64, options PrepareOptions) (result PrepareResult, resultErr error) {
	return PrepareIPAContext(context.Background(), file, size, options)
}

// PrepareIPAContext validates an already-open IPA and publishes an immutable
// local bundle, stopping promptly when ctx is canceled.
func PrepareIPAContext(ctx context.Context, file *os.File, size int64, options PrepareOptions) (result PrepareResult, resultErr error) {
	if err := ValidatePrepareOptions(options); err != nil {
		return PrepareResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PrepareResult{}, err
	}
	rootPath := strings.TrimSpace(options.Root)
	if rootPath == "" {
		rootPath = "."
	}
	root, err := rootfs.New(rootPath)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("prepare output root: %w", err)
	}
	defer func() {
		if err := root.Close(); resultErr == nil && err != nil {
			result = PrepareResult{}
			resultErr = fmt.Errorf("close distribution output root: %w", err)
		}
	}()
	// Select and retain the output root before the potentially long snapshot,
	// archive validation, and code-signing work.
	if err := root.MkdirAll(".", 0o755); err != nil {
		return PrepareResult{}, fmt.Errorf("pin distribution output root: %w", err)
	}
	snapshot, digest, cleanup, err := snapshotIPA(ctx, file, size)
	if err != nil {
		return PrepareResult{}, err
	}
	defer cleanup()
	if afterIPASnapshotForTest != nil {
		afterIPASnapshotForTest()
	}
	inspection, err := inspectSnapshot(ctx, snapshot, size, digest, InspectOptions{})
	if err != nil {
		return PrepareResult{}, err
	}
	if verifyCompleteSigningForTest != nil {
		verifyCompleteSigningForTest(&inspection)
	}
	if title := strings.TrimSpace(options.Title); title != "" {
		inspection.App.Title = title
		inspection.Preparation.Issues = withoutIssue(inspection.Preparation.Issues, "app title is missing")
		inspection.Preparation.MetadataEligible = len(inspection.Preparation.Issues) == 0
	}
	if !inspection.Preparation.MetadataEligible {
		return PrepareResult{}, fmt.Errorf("%w: %s", ErrNotEligible, strings.Join(inspection.Preparation.Issues, "; "))
	}
	if inspection.Signing.ProfileIntegrityVerification.Status != CodeSignatureVerified ||
		inspection.Signing.ProfileTrustVerification.Status != CodeSignatureVerified ||
		inspection.Signing.CodeSignatureVerification.Status != CodeSignatureVerified ||
		inspection.Signing.CodeSignatureVerification.Scope != mainCodeSignatureScope {
		return PrepareResult{}, fmt.Errorf("%w: provisioning profile trust and complete main-app signature verification are required", ErrNotEligible)
	}

	descriptor := Descriptor{
		SchemaVersion:      inspection.SchemaVersion,
		Platform:           inspection.Platform,
		DistributionMethod: inspection.DistributionMethod,
		App:                inspection.App,
		Artifact: Artifact{
			RelativePath: "payload/app.ipa",
			SizeBytes:    inspection.Artifact.SizeBytes,
			SHA256:       inspection.Artifact.SHA256,
		},
		Signing: inspection.Signing,
	}
	descriptor.Signing.Devices = nil
	if source := buildSource(options); source != nil {
		descriptor.Source = source
	}
	descriptorData, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return PrepareResult{}, fmt.Errorf("encode bundle descriptor: %w", err)
	}
	descriptorData = append(descriptorData, '\n')

	relativeOutput, err := prepareOutputPath(inspection, options.OutputDir)
	if err != nil {
		return PrepareResult{}, err
	}
	rooted, err := root.OpenRoot()
	if err != nil {
		return PrepareResult{}, fmt.Errorf("open distribution output root: %w", err)
	}
	defer rooted.Close()
	parentRelative := filepath.Dir(relativeOutput)
	if err := rooted.MkdirAll(parentRelative, 0o755); err != nil {
		return PrepareResult{}, fmt.Errorf("create distribution output parent: %w", err)
	}
	if afterOutputParentsCreatedForTest != nil {
		afterOutputParentsCreatedForTest()
	}
	parent, err := rooted.OpenRoot(parentRelative)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("open distribution output parent: %w", err)
	}
	defer parent.Close()
	bundlePath := filepath.Join(root.Path(), relativeOutput)
	finalName := filepath.Base(relativeOutput)
	result = PrepareResult{BundlePath: bundlePath, Descriptor: descriptor}
	if reused, exists, err := exactBundleExists(ctx, parent, finalName, descriptorData, descriptor.Artifact); err != nil {
		return PrepareResult{}, err
	} else if exists {
		if !reused {
			return PrepareResult{}, fmt.Errorf("%w: %s", ErrBundleConflict, bundlePath)
		}
		result.Reused = true
		return result, nil
	}

	stageName, stage, err := createStageDirectory(parent)
	if err != nil {
		return PrepareResult{}, fmt.Errorf("create distribution staging directory: %w", err)
	}
	stageOpen := true
	defer func() {
		if stageOpen {
			_ = stage.Close()
		}
		_ = parent.RemoveAll(stageName)
	}()

	if err := stage.Mkdir("payload", 0o755); err != nil {
		return PrepareResult{}, fmt.Errorf("create staged payload: %w", err)
	}
	payloadRoot, err := stage.OpenRoot("payload")
	if err != nil {
		return PrepareResult{}, fmt.Errorf("open staged payload: %w", err)
	}
	if err := copySectionToNewFile(ctx, payloadRoot, "app.ipa", snapshot, size, descriptor.Artifact.SHA256, 0o644); err != nil {
		_ = payloadRoot.Close()
		return PrepareResult{}, fmt.Errorf("copy IPA into staged bundle: %w", err)
	}
	if err := payloadRoot.Close(); err != nil {
		return PrepareResult{}, fmt.Errorf("close staged payload: %w", err)
	}
	// Write the descriptor last so even the private staging directory never
	// advertises a payload that has not finished copying.
	if err := writeNewRootedFile(stage, "bundle.json", descriptorData, 0o644); err != nil {
		return PrepareResult{}, fmt.Errorf("write staged bundle descriptor: %w", err)
	}
	if err := stage.Close(); err != nil {
		return PrepareResult{}, fmt.Errorf("close distribution staging directory: %w", err)
	}
	stageOpen = false

	if err := ctx.Err(); err != nil {
		return PrepareResult{}, err
	}
	if err := secureopen.RenameNoReplaceInRoot(parent, stageName, finalName); err != nil {
		if errors.Is(err, os.ErrExist) {
			reused, exists, reuseErr := exactBundleExists(ctx, parent, finalName, descriptorData, descriptor.Artifact)
			if ctxErr := ctx.Err(); ctxErr != nil {
				return PrepareResult{}, ctxErr
			}
			if reuseErr == nil && exists && reused {
				result.Reused = true
				return result, nil
			}
			return PrepareResult{}, fmt.Errorf("%w: %s", ErrBundleConflict, bundlePath)
		}
		return PrepareResult{}, fmt.Errorf("publish distribution bundle without replacement: %w", err)
	}
	return result, nil
}

func prepareOutputPath(inspection Inspection, requested string) (string, error) {
	if requested = strings.TrimSpace(requested); requested != "" {
		if err := rootfs.ValidateRelative(requested); err != nil {
			return "", fmt.Errorf("invalid output directory: %w", err)
		}
		return filepath.Clean(requested), nil
	}
	bundleID, err := safePathComponent(inspection.App.BundleID)
	if err != nil {
		return "", fmt.Errorf("invalid bundle identifier path component: %w", err)
	}
	version, err := safePathComponent(inspection.App.Version)
	if err != nil {
		return "", fmt.Errorf("invalid version path component: %w", err)
	}
	build, err := safePathComponent(inspection.App.BuildNumber)
	if err != nil {
		return "", fmt.Errorf("invalid build number path component: %w", err)
	}
	identity := fmt.Sprintf("%s-%s-%s", version, build, inspection.Artifact.SHA256[:12])
	return filepath.Join(".asc", "distribution", bundleID, identity), nil
}

func safePathComponent(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("value is empty")
	}
	var builder strings.Builder
	for _, b := range []byte(value) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' {
			builder.WriteByte(b)
		} else {
			fmt.Fprintf(&builder, "~%02X", b)
		}
	}
	result := builder.String()
	if result == "." || result == ".." {
		result = strings.Repeat("~2E", len(result))
	}
	return result, nil
}

// ValidatePrepareOptions validates optional metadata before preparation opens
// or writes any filesystem path.
func ValidatePrepareOptions(options PrepareOptions) error {
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{name: "--title", value: options.Title, limit: 256},
		{name: "--channel", value: options.Channel, limit: 256},
		{name: "--source-revision", value: options.SourceRevision, limit: 1024},
	} {
		if err := validateDescriptorText(field.name, field.value, field.limit); err != nil {
			return err
		}
	}
	if err := validateDescriptorText("--source-url", options.SourceURL, 2048); err != nil {
		return err
	}
	return validateSourceURL(options.SourceURL)
}

func validateDescriptorText(name, value string, limit int) error {
	if len(value) > limit {
		return fmt.Errorf("invalid %s: must be at most %d bytes", name, limit)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("invalid %s: control characters are not allowed", name)
		}
	}
	return nil
}

func validateSourceURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > 2048 {
		return fmt.Errorf("invalid --source-url: must be at most 2048 bytes")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid --source-url: %w", err)
	}
	if parsed.User != nil {
		return fmt.Errorf("invalid --source-url: user information is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid --source-url: query and fragment are not allowed")
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("invalid --source-url: must be an absolute HTTPS URL")
	}
	return nil
}

func buildSource(options PrepareOptions) *Source {
	result := &Source{Channel: strings.TrimSpace(options.Channel), Revision: strings.TrimSpace(options.SourceRevision), URL: strings.TrimSpace(options.SourceURL)}
	if result.Channel == "" && result.Revision == "" && result.URL == "" {
		return nil
	}
	return result
}

func withoutIssue(issues []string, remove string) []string {
	result := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue != remove {
			result = append(result, issue)
		}
	}
	return result
}

func createStageDirectory(parent *os.Root) (string, *os.Root, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".asc-distribute-stage-" + hex.EncodeToString(random[:])
		if err := parent.Mkdir(name, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return "", nil, err
		}
		child, err := parent.OpenRoot(name)
		if err != nil {
			_ = parent.RemoveAll(name)
			return "", nil, err
		}
		return name, child, nil
	}
	return "", nil, fmt.Errorf("could not allocate a unique staging directory")
}

func writeNewRootedFile(root *os.Root, name string, data []byte, mode os.FileMode) error {
	file, err := secureopen.OpenNewFileNoFollowInRoot(root, name, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func copySectionToNewFile(ctx context.Context, root *os.Root, name string, source *os.File, size int64, expectedSHA256 string, mode os.FileMode) error {
	destination, err := secureopen.OpenNewFileNoFollowInRoot(root, name, mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, err := copyWithContext(ctx, io.MultiWriter(destination, hash), io.NewSectionReader(source, 0, size))
	if err != nil {
		_ = destination.Close()
		return err
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		_ = destination.Close()
		return fmt.Errorf("IPA changed while it was being prepared")
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		return err
	}
	return destination.Close()
}

func exactBundleExists(ctx context.Context, parent *os.Root, name string, wantDescriptor []byte, artifact Artifact) (bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, true, nil
	}
	bundle, err := parent.OpenRoot(name)
	if err != nil {
		return false, true, nil
	}
	defer bundle.Close()
	entries, err := readDirectory(bundle, ".")
	if err != nil || !exactEntries(entries, map[string]bool{"bundle.json": false, "payload": true}) {
		return false, true, nil
	}
	payload, err := bundle.OpenRoot("payload")
	if err != nil {
		return false, true, nil
	}
	defer payload.Close()
	payloadEntries, err := readDirectory(payload, ".")
	if err != nil || !exactEntries(payloadEntries, map[string]bool{"app.ipa": false}) {
		return false, true, nil
	}
	descriptor, err := secureopen.OpenExistingNoFollowInRoot(bundle, "bundle.json")
	if err != nil {
		return false, true, nil
	}
	gotDescriptor, readErr := io.ReadAll(io.LimitReader(descriptor, int64(len(wantDescriptor))+1))
	closeErr := descriptor.Close()
	if readErr != nil || closeErr != nil || string(gotDescriptor) != string(wantDescriptor) {
		return false, true, nil
	}
	ipa, err := secureopen.OpenExistingNoFollowInRoot(payload, "app.ipa")
	if err != nil {
		return false, true, nil
	}
	stat, statErr := ipa.Stat()
	if statErr != nil || stat.Size() != artifact.SizeBytes {
		_ = ipa.Close()
		return false, true, nil
	}
	hash := sha256.New()
	_, hashErr := copyWithContext(ctx, hash, ipa)
	closeErr = ipa.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, true, ctxErr
	}
	if hashErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return false, true, nil
	}
	return true, true, nil
}

func readDirectory(root *os.Root, name string) ([]os.DirEntry, error) {
	dir, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return nil, readErr
	}
	return entries, closeErr
}

func exactEntries(entries []os.DirEntry, expected map[string]bool) bool {
	if len(entries) != len(expected) {
		return false
	}
	for _, entry := range entries {
		wantDir, ok := expected[entry.Name()]
		if !ok || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() != wantDir {
			return false
		}
		if !wantDir && !entry.Type().IsRegular() {
			return false
		}
	}
	return true
}
