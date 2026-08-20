package asc

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"strings"
)

const maxAssetFileSize = int64(1024 * 1024 * 1024) // 1GB safety guardrail

// UploadAsset uploads a file using the provided upload operations.
func UploadAsset(ctx context.Context, filePath string, operations []UploadOperation) error {
	file, err := openUploadSourceFile(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	return UploadAssetFromFile(ctx, file, info.Size(), operations)
}

// UploadAssetFromFile uploads a file using the provided upload operations.
// Operations run sequentially through the shared upload executor, so a part
// that hits a transient transport failure or retryable status is retried
// instead of leaving the asset partially uploaded.
func UploadAssetFromFile(ctx context.Context, file *os.File, fileSize int64, operations []UploadOperation) error {
	if len(operations) == 0 {
		return fmt.Errorf("no upload operations provided")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	uploadOpts := UploadOptions{
		Client:    clientWithoutRedirects(newUploadClient()),
		RetryOpts: ResolveRetryOptions(),
	}

	for i, op := range operations {
		if strings.TrimSpace(op.Method) == "" {
			return fmt.Errorf("upload operation %d missing method", i)
		}
		if strings.TrimSpace(op.URL) == "" {
			return fmt.Errorf("upload operation %d missing url", i)
		}
		if op.Offset < 0 || op.Length < 0 {
			return fmt.Errorf("upload operation %d has negative offset/length", i)
		}
		if op.Offset+op.Length > fileSize {
			return fmt.Errorf("upload operation %d exceeds file size", i)
		}

		if err := executeUploadOperation(ctx, file, uploadTask{index: i, op: op}, uploadOpts); err != nil {
			return err
		}
	}

	return nil
}

// ValidateAssetFile validates that a file exists and is safe to read.
func ValidateAssetFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateAssetFileInfo(path, info)
}

func validateAssetFileInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to read symlink %q", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("expected regular file: %q", path)
	}
	if info.Size() <= 0 {
		return fmt.Errorf("file is empty: %q", path)
	}
	if info.Size() > maxAssetFileSize {
		return fmt.Errorf("file size exceeds %d bytes: %q", maxAssetFileSize, path)
	}
	return nil
}

// ValidateImageFile validates that a file exists and is safe to read.
func ValidateImageFile(path string) error {
	return ValidateAssetFile(path)
}

// ImageDimensions represents decoded image dimensions.
type ImageDimensions struct {
	Width  int
	Height int
}

// ReadImageDimensions validates and decodes image dimensions from disk.
func ReadImageDimensions(path string) (ImageDimensions, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ImageDimensions{}, err
	}
	if err := validateAssetFileInfo(path, info); err != nil {
		return ImageDimensions{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return ImageDimensions{}, err
	}
	defer file.Close()

	cfg, _, err := image.DecodeConfig(file)
	if err != nil {
		return ImageDimensions{}, fmt.Errorf("decode image dimensions for %q: %w", path, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return ImageDimensions{}, fmt.Errorf("invalid image dimensions %dx%d for %q", cfg.Width, cfg.Height, path)
	}
	return ImageDimensions{Width: cfg.Width, Height: cfg.Height}, nil
}

// ComputeChecksumFromReader computes a checksum for an io.Reader.
func ComputeChecksumFromReader(reader io.Reader, algorithm ChecksumAlgorithm) (*Checksum, error) {
	var hasher hash.Hash
	switch algorithm {
	case ChecksumAlgorithmMD5:
		hasher = md5.New()
	case ChecksumAlgorithmSHA256:
		hasher = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported checksum algorithm %q", algorithm)
	}

	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}

	return &Checksum{
		Hash:      hex.EncodeToString(hasher.Sum(nil)),
		Algorithm: algorithm,
	}, nil
}
