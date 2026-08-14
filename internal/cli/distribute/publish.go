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
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

var (
	loadPreparedBundle = core.LoadPreparedBundleContext
	newObjectStore     = func(ctx context.Context, config core.S3StoreConfig) (core.ObjectStore, time.Time, error) {
		return core.NewS3Store(ctx, config)
	}
	runPublish          = core.Publish
	reverifyPublication = core.Reverify
)

var regionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

type publicationVerifier struct {
	delegate        core.Verifier
	documentTimeout time.Duration
}

func newPublicationVerifier(documentTimeout time.Duration) (*publicationVerifier, error) {
	delegate, err := core.NewHTTPVerifierWithEnvironmentTrust(0)
	if err != nil {
		return nil, err
	}
	return &publicationVerifier{delegate: delegate, documentTimeout: documentTimeout}, nil
}

func (verifier *publicationVerifier) Verify(ctx context.Context, request core.VerifyRequest) error {
	var verifyCtx context.Context
	var cancel context.CancelFunc
	if request.Kind == core.VerifyIPA {
		verifyCtx, cancel = shared.ContextWithUploadTimeout(ctx)
	} else {
		verifyCtx, cancel = context.WithTimeout(ctx, verifier.documentTimeout)
	}
	defer cancel()
	return verifier.delegate.Verify(verifyCtx, request)
}

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
	verifyTimeout := fs.Duration("verify-timeout", 30*time.Second, "Timeout for manifest and install-page verification; IPA verification uses ASC_UPLOAD_TIMEOUT")
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
			required := []struct{ name, value string }{
				{"bundle-dir", *bundleDir}, {"endpoint", *endpoint}, {"region", *region}, {"bucket", *bucket}, {"prefix", *prefix},
			}
			for _, item := range required {
				if strings.TrimSpace(item.value) == "" {
					fmt.Fprintf(os.Stderr, "Error: --%s is required\n", item.name)
					return shared.MissingRequiredUsageError()
				}
			}
			if _, err := core.ValidateEndpoint(*endpoint); err != nil {
				return shared.UsageErrorf("--endpoint: %v", err)
			}
			if strings.TrimSpace(*downloadEndpoint) != "" {
				if _, err := core.ValidateEndpoint(*downloadEndpoint); err != nil {
					return shared.UsageErrorf("--download-endpoint: %v", err)
				}
			}
			if *addressingStyle != "path" && *addressingStyle != "virtual" {
				return shared.UsageErrorf("--addressing-style must be path or virtual")
			}
			accessMode := core.Access(strings.ToLower(strings.TrimSpace(*access)))
			if accessMode != core.AccessPrivate && accessMode != core.AccessPublic {
				return shared.UsageErrorf("--access must be private or public")
			}
			if accessMode == core.AccessPublic {
				if strings.TrimSpace(*publicBaseURL) == "" {
					return shared.UsageErrorf("--public-base-url is required with --access public")
				}
				if _, err := core.ValidatePublicBaseURL(*publicBaseURL); err != nil {
					return shared.UsageErrorf("--public-base-url: %v", err)
				}
				if flagWasSet(fs, "url-ttl") || flagWasSet(fs, "download-grace") || flagWasSet(fs, "download-endpoint") {
					return shared.UsageErrorf("--url-ttl, --download-grace, and --download-endpoint are only valid with --access private")
				}
			} else if strings.TrimSpace(*publicBaseURL) != "" {
				return shared.UsageErrorf("--public-base-url is only valid with --access public")
			}
			if *urlTTL <= 0 {
				return shared.UsageErrorf("--url-ttl must be positive")
			}
			if *downloadGrace < 0 {
				return shared.UsageErrorf("--download-grace must not be negative")
			}
			if accessMode == core.AccessPrivate && *urlTTL+*downloadGrace > 7*24*time.Hour {
				return shared.UsageErrorf("--url-ttl plus --download-grace must not exceed 7d")
			}
			if *verifyTimeout <= 0 {
				return shared.UsageErrorf("--verify-timeout must be positive")
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageErrorf("%v", err)
			}
			if _, err := core.NormalizePrefix(*prefix); err != nil {
				return shared.UsageErrorf("--prefix: %v", err)
			}
			if !regionPattern.MatchString(*region) {
				return shared.UsageErrorf("--region must be 1-100 letters, digits, dots, underscores, or hyphens")
			}
			if err := core.ValidateBucket(*bucket); err != nil {
				return shared.UsageErrorf("--bucket: %v", err)
			}
			resolvedReceiptPath := strings.TrimSpace(*receiptPath)
			resolvedLinkPath := strings.TrimSpace(*linkPath)
			if resolvedReceiptPath == "" || resolvedLinkPath == "" {
				return shared.UsageErrorf("--receipt and --link-path are required and must be outside --bundle-dir")
			}
			bundleRoot, err := rootfs.New(strings.TrimSpace(*bundleDir))
			if err != nil {
				return fmt.Errorf("distribute publish: open prepared bundle: %w", err)
			}
			defer bundleRoot.Close()
			if err := rejectBundleContainedArtifacts(bundleRoot, resolvedReceiptPath, resolvedLinkPath); err != nil {
				return shared.UsageErrorf("publish artifacts: %v", err)
			}
			artifacts, err := preflightArtifactPaths(resolvedReceiptPath, resolvedLinkPath)
			if err != nil {
				return shared.UsageErrorf("publish artifacts: %v", err)
			}
			defer artifacts.close()
			resolvedReceiptPath = artifacts.receiptPath
			resolvedLinkPath = artifacts.linkPath

			recoveredState, stateFound, err := artifacts.loadState()
			if err != nil {
				return fmt.Errorf("distribute publish: %w", err)
			}
			if artifacts.receiptExists && !stateFound {
				return fmt.Errorf("distribute publish: receipt exists without its sensitive link recovery artifact")
			}
			bundle, err := loadPreparedBundle(ctx, bundleRoot)
			if err != nil {
				return fmt.Errorf("distribute publish: %w", err)
			}
			defer bundle.IPA.Close()
			validatedEndpoint, _ := core.ValidateEndpoint(*endpoint)
			if stateFound {
				if err := validateRecoveredState(recoveredState, bundle, validatedEndpoint.String(), effectiveDownloadEndpoint(*endpoint, *downloadEndpoint), normalizedPublicBase(*publicBaseURL), *region, *addressingStyle, *bucket, *prefix, accessMode, *urlTTL, *downloadGrace, resolvedReceiptPath, resolvedLinkPath); err != nil {
					return fmt.Errorf("distribute publish: %w", err)
				}
				verifier, err := newPublicationVerifier(*verifyTimeout)
				if err != nil {
					return fmt.Errorf("configure publication verifier: %w", err)
				}
				if err := reverifyPublication(ctx, verifier, recoveredState.Receipt, recoveredState.Links, time.Now().UTC()); err != nil {
					return fmt.Errorf("reverify recovered publication: %w", err)
				}
				if artifacts.receiptExists {
					if err := artifacts.verifyExactReceipt(recoveredState.Receipt); err != nil {
						return fmt.Errorf("recover publish receipt: %w", err)
					}
				} else if err := artifacts.publishReceipt(recoveredState.Receipt); err != nil {
					return fmt.Errorf("recover publish receipt: %w", err)
				}
				return printPublishReceipt(recoveredState.Receipt, *output.Output, *output.Pretty, resolvedReceiptPath, resolvedLinkPath)
			}
			staged, err := artifacts.stagePair()
			if err != nil {
				return fmt.Errorf("stage local publish artifacts: %w", err)
			}
			defer staged.cleanup()

			setupCtx, setupCancel := shared.ContextWithUploadTimeout(ctx)
			store, credentialLimit, err := newObjectStore(setupCtx, core.S3StoreConfig{
				Endpoint: *endpoint, DownloadEndpoint: *downloadEndpoint, Region: *region, Bucket: *bucket,
				AddressingStyle: *addressingStyle, RequestTimeout: asc.ResolveUploadTimeout(),
			})
			setupCancel()
			if err != nil {
				return fmt.Errorf("distribute publish: %w", err)
			}
			credentialSource := "standard-sdk-chain"
			if provider, ok := store.(interface{ CredentialSource() string }); ok {
				credentialSource = provider.CredentialSource()
			}
			fmt.Fprintf(os.Stderr, "Publishing to endpoint=%s download-endpoint=%s bucket=%s region=%s addressing=%s prefix=%s access=%s credentials=%s\n", endpointOrigin(*endpoint), effectiveDownloadEndpoint(*endpoint, *downloadEndpoint), *bucket, *region, *addressingStyle, *prefix, accessMode, credentialSource)
			verifier, err := newPublicationVerifier(*verifyTimeout)
			if err != nil {
				return fmt.Errorf("configure publication verifier: %w", err)
			}
			receipt, links, err := runPublish(ctx, bundle.IPA, bundle.Descriptor, core.PublishOptions{
				Store: store, Verifier: verifier, Bucket: *bucket, Prefix: *prefix, Access: accessMode,
				PublicBaseURL: *publicBaseURL, URLTTL: *urlTTL, DownloadGrace: *downloadGrace, CredentialLimit: credentialLimit,
			})
			if err != nil {
				return fmt.Errorf("distribute publish: %w", err)
			}
			receipt.ReceiptPath = resolvedReceiptPath
			receipt.LinkPath = resolvedLinkPath
			receipt.Endpoint = validatedEndpoint.String()
			receipt.DownloadEndpoint = effectiveDownloadEndpoint(*endpoint, *downloadEndpoint)
			receipt.PublicBaseURL = normalizedPublicBase(*publicBaseURL)
			receipt.Region = *region
			receipt.AddressingStyle = *addressingStyle
			if accessMode == core.AccessPrivate {
				receipt.URLTTL = urlTTL.String()
				receipt.DownloadGrace = downloadGrace.String()
			}

			state := publishState{SchemaVersion: "1", Receipt: receipt, Links: links}
			if err := staged.publish(state, receipt); err != nil {
				return fmt.Errorf("write sensitive install link: %w", err)
			}

			return printPublishReceipt(receipt, *output.Output, *output.Pretty, resolvedReceiptPath, resolvedLinkPath)
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
	if pathContains(receiptAbsolute, linkAbsolute) || pathContains(linkAbsolute, receiptAbsolute) {
		return artifactPaths{}, fmt.Errorf("--receipt and --link-path must not contain one another")
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
	for _, name := range []string{receiptRelative, linkRelative} {
		if info, err := root.Lstat(name); err == nil {
			if !info.Mode().IsRegular() {
				_ = root.Close()
				return artifactPaths{}, fmt.Errorf("%s is not a regular file", filepath.Join(common, name))
			}
			if info.Mode().Perm()&0o077 != 0 {
				_ = root.Close()
				return artifactPaths{}, fmt.Errorf("%s must be owner-private (mode 0600 or stricter)", filepath.Join(common, name))
			}
			exists[name] = true
		} else if !os.IsNotExist(err) {
			_ = root.Close()
			return artifactPaths{}, err
		}
	}
	return artifactPaths{root: root, receipt: receiptRelative, link: linkRelative, receiptPath: receiptAbsolute, linkPath: linkAbsolute, receiptExists: exists[receiptRelative], linkExists: exists[linkRelative]}, nil
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
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
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return publishState{}, true, fmt.Errorf("sensitive link artifact must remain a mode-0600 regular file")
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
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 2<<20 {
		return fmt.Errorf("receipt must remain a bounded owner-private regular file")
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
	return nil
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

func rejectBundleContainedArtifacts(bundleRoot rootfs.Root, receiptPath, linkPath string) error {
	for _, candidate := range []string{receiptPath, linkPath} {
		contained, err := bundleRoot.ContainsPath(candidate)
		if err != nil {
			return err
		}
		if contained {
			return fmt.Errorf("receipt and link paths must be outside the immutable prepared bundle")
		}
	}
	return nil
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
