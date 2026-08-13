package distribute

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	core "github.com/rudrankriyam/App-Store-Connect-CLI/internal/distribution"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

var (
	loadPreparedBundle = core.LoadPreparedBundle
	newObjectStore     = func(ctx context.Context, config core.S3StoreConfig) (core.ObjectStore, time.Time, error) {
		return core.NewS3Store(ctx, config)
	}
	runPublish          = core.Publish
	reverifyPublication = core.Reverify
)

var regionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// PublishCommand returns the provider-neutral S3-compatible publisher.
func PublishCommand() *ffcli.Command {
	fs := flag.NewFlagSet("distribute publish", flag.ExitOnError)
	bundleDir := fs.String("bundle-dir", "", "Prepared distribution bundle directory (required)")
	endpoint := fs.String("endpoint", "", "S3-compatible HTTPS API endpoint (required)")
	region := fs.String("region", "", "S3 signing region (required)")
	bucket := fs.String("bucket", "", "Existing object-store bucket (required)")
	prefix := fs.String("prefix", "", "Object key prefix owned by this distribution channel (required)")
	downloadEndpoint := fs.String("download-endpoint", "", "Optional S3-compatible HTTPS endpoint used to sign download URLs")
	addressingStyle := fs.String("addressing-style", "path", "Bucket addressing style: path or virtual")
	access := fs.String("access", string(core.AccessPrivate), "Published object access: private or public")
	publicBaseURL := fs.String("public-base-url", "", "Preconfigured anonymous HTTPS base URL (required with --access public)")
	urlTTL := fs.Duration("url-ttl", 24*time.Hour, "Private install-page lifetime (maximum combined lifetime 7d)")
	downloadGrace := fs.Duration("download-grace", time.Hour, "Additional private manifest and IPA download lifetime")
	verifyTimeout := fs.Duration("verify-timeout", 30*time.Second, "Timeout for each published-object verification request")
	receiptPath := fs.String("receipt", "", "Redacted JSON receipt path outside the prepared bundle (required)")
	linkPath := fs.String("link-path", "", "Mode-0600 sensitive link path (required)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "publish",
		ShortUsage: "asc distribute publish --bundle-dir DIR --endpoint URL --region REGION --bucket BUCKET --prefix PREFIX --receipt FILE --link-path FILE [flags]",
		ShortHelp:  "[experimental] Publish an installable bundle to a caller-owned S3-compatible endpoint.",
		LongHelp: `[experimental] Publish an installable bundle to a caller-owned S3-compatible endpoint.

The command reads bundle.json and payload/app.ipa from --bundle-dir. It uploads
the content-addressed IPA first, an Apple installation manifest second, and a
first-party install page last. Existing objects are reused only when their
digest, size, and content type match exactly.

Private access is the default and returns bounded presigned links. Exact links
are bearer credentials and are written only to a mode-0600 link artifact; stdout
and the receipt always redact them. Public
access requires a caller-configured --public-base-url and does not change bucket
ACLs or policies. This command never creates buckets or deletes retained builds.

Credentials use ASC_S3_ACCESS_KEY_ID, ASC_S3_SECRET_ACCESS_KEY, and optional
ASC_S3_SESSION_TOKEN when configured together, otherwise the standard AWS SDK
credential chain.

Examples:
  asc distribute publish --bundle-dir .asc/distribution/com.example.app/1.2-3-abcd1234 --endpoint https://objects.example.com --region auto --bucket ios-builds --prefix team/app --receipt .asc/publishes/app-1.2-3.json --link-path .asc/publishes/app-1.2-3-link.json --output json
  asc distribute publish --bundle-dir .asc/distribution/com.example.app/1.2-3-abcd1234 --endpoint https://objects.example.com --region auto --bucket ios-builds --prefix team/app --access public --public-base-url https://downloads.example.com/ios --receipt .asc/publishes/app-1.2-3.json --link-path .asc/publishes/app-1.2-3-link.json --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				fmt.Fprintln(os.Stderr, "Error: distribute publish does not accept positional arguments")
				return flag.ErrHelp
			}
			result, err := executePublish(ctx, publishRequest{
				BundleDir: *bundleDir, Endpoint: *endpoint, DownloadEndpoint: *downloadEndpoint,
				Region: *region, Bucket: *bucket, Prefix: *prefix, AddressingStyle: *addressingStyle,
				Access: *access, PublicBaseURL: *publicBaseURL, URLTTL: *urlTTL, DownloadGrace: *downloadGrace,
				VerifyTimeout: *verifyTimeout, ReceiptPath: *receiptPath, LinkPath: *linkPath,
				PrivateOptionsExplicit: flagWasSet(fs, "url-ttl") || flagWasSet(fs, "download-grace") || flagWasSet(fs, "download-endpoint"),
				DiagnosticWriter:       os.Stderr,
				ValidateOutput: func() error {
					if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
						return shared.UsageErrorf("%v", err)
					}
					return nil
				},
			})
			if err != nil {
				return err
			}
			return printPublishReceipt(result.Receipt, *output.Output, *output.Pretty, result.Receipt.ReceiptPath, result.Receipt.LinkPath)
		},
	}
}

type artifactPaths struct {
	root          *os.Root
	receipt       string
	link          string
	receiptPath   string
	linkPath      string
	receiptExists bool
	linkExists    bool
}

func preflightArtifactPaths(receiptPath, linkPath string) (artifactPaths, error) {
	receiptAbsolute, err := filepath.Abs(receiptPath)
	if err != nil {
		return artifactPaths{}, err
	}
	linkAbsolute, err := filepath.Abs(linkPath)
	if err != nil {
		return artifactPaths{}, err
	}
	if receiptAbsolute == linkAbsolute {
		return artifactPaths{}, fmt.Errorf("--receipt and --link-path must be distinct")
	}
	common, err := commonPathRoot(filepath.Dir(receiptAbsolute), filepath.Dir(linkAbsolute))
	if err != nil {
		return artifactPaths{}, err
	}
	root, err := openOrCreateAnchoredRoot(common)
	if err != nil {
		return artifactPaths{}, err
	}
	receiptRelative, _ := filepath.Rel(common, receiptAbsolute)
	linkRelative, _ := filepath.Rel(common, linkAbsolute)
	exists := map[string]bool{}
	for _, item := range []struct {
		name, label string
	}{{receiptRelative, "receipt"}, {linkRelative, "sensitive link artifact"}} {
		found, err := inspectExistingProtectedPublishArtifact(root, item.name, item.label)
		if err != nil {
			_ = root.Close()
			return artifactPaths{}, err
		}
		exists[item.name] = found
	}
	return artifactPaths{root: root, receipt: receiptRelative, link: linkRelative, receiptPath: receiptAbsolute, linkPath: linkAbsolute, receiptExists: exists[receiptRelative], linkExists: exists[linkRelative]}, nil
}

func openOrCreateAnchoredRoot(target string) (*os.Root, error) {
	ancestor := filepath.Clean(target)
	var ancestorInfo os.FileInfo
	for {
		info, err := os.Lstat(ancestor)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, fmt.Errorf("artifact parent %s is not a trusted directory", ancestor)
			}
			ancestorInfo = info
			break
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return nil, fmt.Errorf("no existing artifact path ancestor")
		}
		ancestor = parent
	}
	root, err := os.OpenRoot(ancestor)
	if err != nil {
		return nil, err
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(ancestorInfo, openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("artifact parent changed during preflight")
	}
	relative, err := filepath.Rel(ancestor, target)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if relative == "." {
		return root, nil
	}
	if err := root.MkdirAll(relative, 0o700); err != nil {
		_ = root.Close()
		return nil, err
	}
	created, err := root.OpenRoot(relative)
	_ = root.Close()
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (paths artifactPaths) close() {
	if paths.root != nil {
		_ = paths.root.Close()
	}
}

func encodeJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

func validateRecoveredState(state publishState, bundle *core.PreparedBundle, endpoint, downloadEndpoint, publicBaseURL, region, addressing, bucket, prefix string, access core.Access, urlTTL, downloadGrace time.Duration, receiptPath, linkPath string) error {
	receipt := state.Receipt
	normalizedPrefix, _ := core.NormalizePrefix(prefix)
	if receipt.SchemaVersion != "1" || receipt.Endpoint != endpoint || receipt.DownloadEndpoint != downloadEndpoint || receipt.PublicBaseURL != publicBaseURL || receipt.Region != region || receipt.AddressingStyle != addressing || receipt.Bucket != bucket || receipt.Prefix != normalizedPrefix || receipt.Access != access {
		return fmt.Errorf("pending publish state conflicts with requested destination")
	}
	if access == core.AccessPrivate && (receipt.URLTTL != urlTTL.String() || receipt.DownloadGrace != downloadGrace.String()) {
		return fmt.Errorf("pending publish state conflicts with requested link lifetime policy")
	}
	if receipt.Artifact.SHA256 != bundle.IPASHA256 || receipt.Artifact.SizeBytes != bundle.IPASize || receipt.App != bundle.Descriptor.App || !receipt.Signing.MatchesPrepared(bundle.Descriptor.Signing) {
		return fmt.Errorf("pending publish state conflicts with prepared bundle")
	}
	if receipt.ReceiptPath != receiptPath || receipt.LinkPath != linkPath || state.Links.InstallURL == "" {
		return fmt.Errorf("pending publish state conflicts with local artifact paths")
	}
	return nil
}

func printPublishReceipt(receipt core.PublishReceipt, format string, pretty bool, receiptPath, linkPath string) error {
	return shared.PrintOutputWithRenderers(
		receipt, format, pretty,
		func() error {
			asc.RenderTable([]string{"field", "value"}, publishRows(receipt, receiptPath, linkPath))
			return nil
		},
		func() error {
			asc.RenderMarkdown([]string{"field", "value"}, publishRows(receipt, receiptPath, linkPath))
			return nil
		},
	)
}

type publishState struct {
	SchemaVersion string              `json:"schemaVersion"`
	Receipt       core.PublishReceipt `json:"receipt"`
	Links         core.SensitiveLinks `json:"links"`
}

func (paths artifactPaths) loadState() (publishState, bool, error) {
	file, err := secureopen.OpenExistingNoFollowInRoot(paths.root, paths.link)
	if os.IsNotExist(err) {
		return publishState{}, false, nil
	}
	if err != nil {
		return publishState{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return publishState{}, true, err
	}
	if err := validateProtectedPublishArtifact(file, info, "sensitive link artifact"); err != nil {
		return publishState{}, true, err
	}
	if info.Size() > 2<<20 {
		return publishState{}, true, fmt.Errorf("sensitive link artifact exceeds 2 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	found := true
	if err != nil || !found {
		return publishState{}, found, err
	}
	var state publishState
	if err := json.Unmarshal(data, &state); err != nil {
		return publishState{}, true, fmt.Errorf("decode pending publish state: %w", err)
	}
	if state.SchemaVersion != "1" {
		return publishState{}, true, fmt.Errorf("unsupported pending publish state")
	}
	return state, true, nil
}

func (paths artifactPaths) verifyExactReceipt(receipt core.PublishReceipt) error {
	want, err := encodeJSON(receipt)
	if err != nil {
		return err
	}
	file, err := secureopen.OpenExistingNoFollowInRoot(paths.root, paths.receipt)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if err := validateProtectedPublishArtifact(file, info, "receipt"); err != nil {
		return err
	}
	if info.Size() > 2<<20 {
		return fmt.Errorf("receipt must remain bounded to 2 MiB")
	}
	got, err := io.ReadAll(io.LimitReader(file, 2<<20))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("receipt conflicts with sensitive recovery artifact")
	}
	return nil
}

func inspectExistingProtectedPublishArtifact(root *os.Root, name, label string) (bool, error) {
	file, err := secureopen.OpenExistingNoFollowInRoot(root, name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if err := validateProtectedPublishArtifact(file, info, label); err != nil {
		return false, err
	}
	return true, nil
}

func validateProtectedPublishArtifact(file *os.File, info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be owner-private (mode 0600 or stricter)", label)
	}
	if err := validateProtectedPublishArtifactPlatform(file, info); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func (paths artifactPaths) publishReceipt(receipt core.PublishReceipt) error {
	parent, name, err := openAnchoredParent(paths.root, paths.receipt)
	if err != nil {
		return err
	}
	defer parent.Close()
	staged, err := stageFile(parent, name)
	if err != nil {
		return err
	}
	defer staged.cleanup()
	data, err := encodeJSON(receipt)
	if err != nil {
		return err
	}
	return staged.publish(data)
}

type stagedPair struct {
	linkParent, receiptParent *os.Root
	link, receipt             *stagedFile
}

func (paths artifactPaths) stagePair() (*stagedPair, error) {
	linkParent, linkName, err := openAnchoredParent(paths.root, paths.link)
	if err != nil {
		return nil, err
	}
	link, err := stageFile(linkParent, linkName)
	if err != nil {
		_ = linkParent.Close()
		return nil, err
	}
	receiptParent, receiptName, err := openAnchoredParent(paths.root, paths.receipt)
	if err != nil {
		link.cleanup()
		_ = linkParent.Close()
		return nil, err
	}
	receipt, err := stageFile(receiptParent, receiptName)
	if err != nil {
		link.cleanup()
		_ = linkParent.Close()
		_ = receiptParent.Close()
		return nil, err
	}
	return &stagedPair{linkParent: linkParent, receiptParent: receiptParent, link: link, receipt: receipt}, nil
}

func (pair *stagedPair) cleanup() {
	pair.link.cleanup()
	pair.receipt.cleanup()
	_ = pair.linkParent.Close()
	_ = pair.receiptParent.Close()
}

func (pair *stagedPair) publish(state publishState, receipt core.PublishReceipt) error {
	linkData, err := encodeJSON(state)
	if err != nil {
		return err
	}
	receiptData, err := encodeJSON(receipt)
	if err != nil {
		return err
	}
	if err := pair.link.publish(linkData); err != nil {
		return err
	}
	return pair.receipt.publish(receiptData)
}

type stagedFile struct {
	parent              *os.Root
	file                *os.File
	tempName, finalName string
}

func stageFile(parent *os.Root, finalName string) (*stagedFile, error) {
	file, tempName, err := secureopen.CreateTempNoFollowInRoot(parent, ".", ".asc-publish-*", 0o600)
	if err != nil {
		return nil, err
	}
	return &stagedFile{parent: parent, file: file, tempName: tempName, finalName: finalName}, nil
}

func (file *stagedFile) publish(data []byte) error {
	if _, err := file.file.Write(data); err != nil {
		return err
	}
	if err := file.file.Sync(); err != nil {
		return err
	}
	if err := file.file.Close(); err != nil {
		return err
	}
	if err := secureopen.RenameNoReplaceInRoot(file.parent, file.tempName, file.finalName); err != nil {
		return err
	}
	file.tempName = ""
	return syncPublishArtifactDirectory(file.parent)
}

func (file *stagedFile) cleanup() {
	if file == nil {
		return
	}
	if file.file != nil {
		_ = file.file.Close()
	}
	if file.tempName != "" {
		_ = file.parent.Remove(file.tempName)
	}
}

func openAnchoredParent(root *os.Root, relative string) (*os.Root, string, error) {
	parentRelative := filepath.Dir(relative)
	if err := root.MkdirAll(parentRelative, 0o700); err != nil {
		return nil, "", err
	}
	parent, err := root.OpenRoot(parentRelative)
	if err != nil {
		return nil, "", err
	}
	return parent, filepath.Base(relative), nil
}

func commonPathRoot(left, right string) (string, error) {
	for {
		relative, err := filepath.Rel(left, right)
		if err != nil {
			return "", err
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			volumeRoot := filepath.Clean(filepath.VolumeName(left) + string(filepath.Separator))
			if filepath.Clean(left) == volumeRoot {
				return "", fmt.Errorf("artifact paths share only the filesystem root")
			}
			return left, nil
		}
		parent := filepath.Dir(left)
		if parent == left {
			return "", fmt.Errorf("artifact paths do not share a safe parent")
		}
		left = parent
	}
}

func endpointOrigin(raw string) string {
	parsed, err := core.ValidateEndpoint(raw)
	if err != nil {
		return "<invalid>"
	}
	return parsed.Scheme + "://" + parsed.Host
}

func effectiveDownloadEndpoint(endpoint, downloadEndpoint string) string {
	if strings.TrimSpace(downloadEndpoint) == "" {
		return endpointOrigin(endpoint)
	}
	return endpointOrigin(downloadEndpoint)
}

func normalizedPublicBase(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	parsed, err := core.ValidatePublicBaseURL(raw)
	if err != nil {
		return "<invalid>"
	}
	return parsed.String()
}

func rejectBundleContainedArtifacts(bundleDir, receiptPath, linkPath string) error {
	bundleAbsolute, err := filepath.Abs(bundleDir)
	if err != nil {
		return err
	}
	bundlePhysical, err := filepath.EvalSymlinks(bundleAbsolute)
	if err != nil {
		return fmt.Errorf("resolve prepared bundle: %w", err)
	}
	for _, candidate := range []string{receiptPath, linkPath} {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			return err
		}
		physical, err := prospectivePhysicalPath(absolute)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(bundlePhysical, physical)
		if err != nil {
			return err
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return fmt.Errorf("receipt and link paths must be outside the immutable prepared bundle")
		}
	}
	return nil
}

func prospectivePhysicalPath(target string) (string, error) {
	existing := filepath.Clean(target)
	var suffix []string
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", fmt.Errorf("no existing path ancestor for %s", target)
		}
		suffix = append(suffix, filepath.Base(existing))
		existing = parent
	}
	physical, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	for index := len(suffix) - 1; index >= 0; index-- {
		physical = filepath.Join(physical, suffix[index])
	}
	return physical, nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(item *flag.Flag) {
		if item.Name == name {
			found = true
		}
	})
	return found
}

func publishRows(receipt core.PublishReceipt, receiptPath, linkPath string) [][]string {
	expires := ""
	if receipt.ExpiresAt != nil {
		expires = receipt.ExpiresAt.Format(time.RFC3339)
	}
	return [][]string{
		{"install_url", receipt.InstallURL},
		{"access", string(receipt.Access)},
		{"artifact_key", receipt.Artifact.Key},
		{"manifest_key", receipt.Manifest.Key},
		{"page_key", receipt.Page.Key},
		{"expires_at", expires},
		{"verified", fmt.Sprintf("%t", receipt.Verified)},
		{"receipt", receiptPath},
		{"sensitive_link", linkPath},
	}
}
