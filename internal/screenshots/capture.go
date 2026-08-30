package screenshots

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

const (
	ProviderAXe   = "axe"
	ProviderMacOS = "macos"
)

// matrixCaptureRootBeforePublishForTest is a narrow test seam for replacing
// the destination pathname after provider capture but before rooted publish.
// Production always leaves it nil.
var matrixCaptureRootBeforePublishForTest func(string)

// Provider captures a single screenshot and returns the path to the PNG.
type Provider interface {
	Capture(ctx context.Context, req CaptureRequest) (pngPath string, err error)
}

// Capture runs the appropriate provider and validates the output file.
func Capture(ctx context.Context, req CaptureRequest) (*CaptureResult, error) {
	return CaptureWithProvider(ctx, req, nil)
}

// CaptureWithProvider runs the given provider (or selects by req.Provider if nil) and validates the output file.
// Used for testing with a mock provider.
func CaptureWithProvider(ctx context.Context, req CaptureRequest, p Provider) (*CaptureResult, error) {
	req.Provider = strings.TrimSpace(strings.ToLower(req.Provider))
	req.Name = strings.TrimSpace(req.Name)
	req.OutputDir = strings.TrimSpace(req.OutputDir)
	if err := validateCaptureDestination(req.Name, req.OutputDir); err != nil {
		return nil, err
	}

	p, err := captureProviderForRequest(req, p)
	if err != nil {
		return nil, err
	}

	pngPath, err := p.Capture(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := asc.ValidateImageFile(pngPath); err != nil {
		return nil, fmt.Errorf("captured file invalid: %w", err)
	}
	dims, err := asc.ReadImageDimensions(pngPath)
	if err != nil {
		return nil, fmt.Errorf("read image dimensions: %w", err)
	}

	absPath, err := filepath.Abs(pngPath)
	if err != nil {
		return nil, fmt.Errorf("resolve captured path: %w", err)
	}
	return &CaptureResult{
		Path:     absPath,
		Provider: req.Provider,
		Width:    dims.Width,
		Height:   dims.Height,
		BundleID: req.BundleID,
		UDID:     req.UDID,
	}, nil
}

func captureProviderForRequest(req CaptureRequest, provider Provider) (Provider, error) {
	if provider != nil {
		return provider, nil
	}
	switch req.Provider {
	case ProviderAXe:
		return &AXeProvider{}, nil
	case ProviderMacOS:
		return newMacOSProvider()
	default:
		return nil, fmt.Errorf("unknown provider %q (allowed: %s, %s)", req.Provider, ProviderAXe, ProviderMacOS)
	}
}

// captureWithRoot runs the ordinary capture provider against a process-private
// scratch directory, then publishes the validated image through the anchored
// destination root. Matrix execution cannot pass its private attempt path to
// an adapter that writes with ordinary path operations: a replaced attempt
// directory would otherwise redirect the provider outside the pinned root.
func captureWithRoot(ctx context.Context, req CaptureRequest, destination rootfs.Root) (*CaptureResult, error) {
	return captureWithRootProvider(ctx, req, destination, nil)
}

func captureWithRootProvider(ctx context.Context, req CaptureRequest, destination rootfs.Root, provider Provider) (result *CaptureResult, returnErr error) {
	req.Provider = strings.TrimSpace(strings.ToLower(req.Provider))
	req.Name = strings.TrimSpace(req.Name)
	req.OutputDir = strings.TrimSpace(req.OutputDir)
	if err := validateCaptureDestination(req.Name, req.OutputDir); err != nil {
		return nil, err
	}
	relativeName := req.Name + ".png"
	outputPath := filepath.Join(req.OutputDir, relativeName)
	relativeOutput, err := relativeMatrixOutputPath(destination.Path(), outputPath)
	if err != nil {
		return nil, fmt.Errorf("matrix capture output escapes rooted destination: %w", err)
	}

	scratchDir, err := os.MkdirTemp("", "asc-shots-capture-")
	if err != nil {
		return nil, fmt.Errorf("create capture scratch directory: %w", err)
	}
	scratchRoot, err := rootfs.New(scratchDir)
	if err != nil {
		return nil, fmt.Errorf("open capture scratch directory: %w", err)
	}
	scratchAnchor, err := scratchRoot.OpenRoot()
	if err != nil {
		_ = scratchRoot.Close()
		return nil, fmt.Errorf("anchor capture scratch directory: %w", err)
	}
	defer func() {
		cleanupErr := cleanupMatrixProviderScratch(scratchAnchor, scratchDir)
		anchorCloseErr := scratchAnchor.Close()
		rootCloseErr := scratchRoot.Close()
		if resourceErr := errors.Join(cleanupErr, anchorCloseErr, rootCloseErr); resourceErr != nil {
			result = nil
			returnErr = errors.Join(returnErr, resourceErr)
		}
	}()
	provider, err = captureProviderForRequest(req, provider)
	if err != nil {
		return nil, err
	}
	req.OutputDir = scratchDir
	pngPath, err := provider.Capture(ctx, req)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(pngPath) == "" {
		return nil, errors.New("capture provider returned no image")
	}
	verifiedScratch, err := scratchRoot.OpenRoot()
	if err != nil {
		return nil, fmt.Errorf("capture scratch directory changed during provider execution: %w", err)
	}
	if err := verifiedScratch.Close(); err != nil {
		return nil, fmt.Errorf("verify capture scratch directory: %w", err)
	}
	absCapturedPath, err := filepath.Abs(pngPath)
	if err != nil {
		return nil, fmt.Errorf("resolve captured path: %w", err)
	}
	scratchRelative, err := filepath.Rel(scratchDir, absCapturedPath)
	if err != nil || scratchRelative == ".." || strings.HasPrefix(scratchRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(scratchRelative) || strings.ContainsAny(scratchRelative, `/\\`) {
		return nil, errors.New("capture provider returned an unsafe image path")
	}
	scratchFile, err := scratchRoot.OpenFile(scratchRelative)
	if err != nil {
		return nil, fmt.Errorf("open captured image: %w", err)
	}
	dimensions, dimensionsErr := readMatrixImageDimensions(scratchFile, absCapturedPath)
	closeErr := scratchFile.Close()
	if dimensionsErr != nil {
		return nil, fmt.Errorf("read captured image: %w", dimensionsErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close captured image: %w", closeErr)
	}
	data, err := scratchRoot.ReadFileLimited(scratchRelative, maxMatrixArtifactBytes)
	if err != nil {
		return nil, fmt.Errorf("read captured image: %w", err)
	}
	if matrixCaptureRootBeforePublishForTest != nil {
		matrixCaptureRootBeforePublishForTest(outputPath)
	}
	if err := destination.WriteFilePreservingMode(relativeOutput, data, 0o644); err != nil {
		return nil, fmt.Errorf("publish captured image: %w", err)
	}

	return &CaptureResult{
		Path:     filepath.Join(destination.Path(), relativeOutput),
		Provider: req.Provider,
		Width:    dimensions.Width,
		Height:   dimensions.Height,
		BundleID: req.BundleID,
		UDID:     req.UDID,
	}, nil
}

func cleanupMatrixProviderScratch(anchor *os.Root, path string) error {
	if anchor == nil {
		return nil
	}
	var cleanupErr error
	entries, err := fs.ReadDir(anchor.FS(), ".")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanupErr = errors.Join(cleanupErr, err)
	} else {
		for _, entry := range entries {
			cleanupErr = errors.Join(cleanupErr, anchor.RemoveAll(entry.Name()))
		}
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.Join(cleanupErr, err)
	}
	identity, err := anchor.Stat(".")
	if err != nil {
		return errors.Join(cleanupErr, err, parent.Close())
	}
	removeErr := removeMatrixExpectedEntry(parent, identity, nil)
	return errors.Join(cleanupErr, removeErr, parent.Close())
}

func validateCaptureDestination(name, outputDir string) error {
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if name == "" {
		return fmt.Errorf("screenshot name is required")
	}
	if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("screenshot name must be a file name without path separators")
	}
	return nil
}
