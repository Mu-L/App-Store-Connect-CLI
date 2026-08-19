package assets

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

const (
	assetDownloadMaxAttempts  = 4
	assetDownloadInitialDelay = 200 * time.Millisecond
	assetDownloadMaxDelay     = 2 * time.Second
	assetDownloadUserAgent    = "curl/8.7.1 App-Store-Connect-CLI/asset-download"
	pngEquivalenceMaxBytes    = 32 << 20
	pngEquivalenceMaxInflated = 256 << 20
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// The screenshot CDN can rewrite resource identifiers and timestamps in these
// non-rendering ancillary chunks on every request. Preserve the operator's
// existing file when every other chunk remains identical.
var volatilePNGChunkTypes = map[string]struct{}{
	"iTXt": {},
	"tEXt": {},
	"tIME": {},
	"zTXt": {},
}

type pngImageHeader struct {
	width     uint32
	height    uint32
	bitDepth  byte
	colorType byte
	interlace byte
}

type downloadHTTPStatusError struct {
	StatusCode int
	Message    string
}

func (e *downloadHTTPStatusError) Error() string {
	return fmt.Sprintf("unexpected status %d (%s)", e.StatusCode, e.Message)
}

func (e *downloadHTTPStatusError) HTTPStatusCode() int {
	if e == nil {
		return 0
	}
	return e.StatusCode
}

func sanitizeBaseFileName(value string) string {
	base := strings.TrimSpace(value)
	if base == "" {
		return ""
	}

	// Defensive: ensure we never write outside the target directory.
	base = filepath.Base(base)
	base = strings.TrimSpace(base)

	if base == "" || base == "." || base == ".." {
		return ""
	}

	// Extra defense: normalize separators across platforms.
	base = strings.ReplaceAll(base, "/", "_")
	base = strings.ReplaceAll(base, "\\", "_")
	base = strings.TrimSpace(base)

	if base == "" || base == "." || base == ".." {
		return ""
	}
	return base
}

func resolveImageAssetDownloadURL(asset *asc.ImageAsset, fileName string) (string, error) {
	if asset == nil {
		return "", fmt.Errorf("image asset is missing")
	}

	template := strings.TrimSpace(asset.TemplateURL)
	if template == "" {
		return "", fmt.Errorf("image asset template URL is missing")
	}
	if asset.Width <= 0 || asset.Height <= 0 {
		return "", fmt.Errorf("image asset dimensions are missing")
	}

	resolved := template
	resolved = strings.ReplaceAll(resolved, "{w}", fmt.Sprintf("%d", asset.Width))
	resolved = strings.ReplaceAll(resolved, "{h}", fmt.Sprintf("%d", asset.Height))
	if strings.Contains(resolved, "{f}") {
		// ASC imageAsset.templateUrl often includes "{f}" for file format.
		// Prefer the extension from the asset filename when available; fall back to png.
		format := ""
		ext := strings.TrimSpace(filepath.Ext(strings.TrimSpace(fileName)))
		if ext != "" {
			format = strings.TrimPrefix(ext, ".")
		}
		if strings.TrimSpace(format) == "" {
			format = "png"
		}
		resolved = strings.ReplaceAll(resolved, "{f}", format)
	}

	// If the URL still contains template braces, it is likely not usable as-is.
	if strings.Contains(resolved, "{") || strings.Contains(resolved, "}") {
		return "", fmt.Errorf("unresolved template URL: %q", template)
	}

	parsed, err := url.Parse(resolved)
	if err != nil {
		return "", fmt.Errorf("parse resolved URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		// ok
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}

	return resolved, nil
}

func downloadURLToFile(ctx context.Context, rawURL string, outputPath string, overwrite bool) (int64, string, error) {
	written, contentType, _, err := downloadURLToFileWithEquivalence(ctx, rawURL, outputPath, overwrite, false)
	return written, contentType, err
}

func downloadScreenshotURLToFile(ctx context.Context, rawURL string, outputPath string, overwrite bool) (int64, string, bool, error) {
	return downloadURLToFileWithEquivalence(ctx, rawURL, outputPath, overwrite, true)
}

func downloadURLToFileWithEquivalence(ctx context.Context, rawURL string, outputPath string, overwrite, preserveEquivalentPNG bool) (int64, string, bool, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return 0, "", false, fmt.Errorf("download URL is required")
	}
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return 0, "", false, fmt.Errorf("output path is required")
	}

	delay := assetDownloadInitialDelay
	var lastErr error
	lastContentType := ""

	for attempt := 1; attempt <= assetDownloadMaxAttempts; attempt++ {
		written, contentType, unchanged, err := downloadURLToFileOnce(ctx, rawURL, outputPath, overwrite, preserveEquivalentPNG)
		if err == nil {
			return written, contentType, unchanged, nil
		}

		lastErr = err
		lastContentType = contentType

		if !isRetryableDownloadError(err) || attempt == assetDownloadMaxAttempts {
			return 0, lastContentType, false, lastErr
		}

		if err := sleepWithContext(ctx, delay); err != nil {
			return 0, lastContentType, false, err
		}

		delay *= 2
		if delay > assetDownloadMaxDelay {
			delay = assetDownloadMaxDelay
		}
	}

	return 0, lastContentType, false, lastErr
}

func downloadURLToFileOnce(ctx context.Context, rawURL string, outputPath string, overwrite, preserveEquivalentPNG bool) (int64, string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", false, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", assetDownloadUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", false, err
	}
	defer resp.Body.Close()

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			msg = strings.Join(strings.Fields(msg), " ")
		}
		if msg == "" {
			msg = strings.TrimSpace(resp.Status)
		}
		return 0, contentType, false, &downloadHTTPStatusError{
			StatusCode: resp.StatusCode,
			Message:    msg,
		}
	}

	if preserveEquivalentPNG && overwrite && isRegularFile(outputPath) {
		written, unchanged, err := writeScreenshotDownload(outputPath, resp.Body)
		return written, contentType, unchanged, err
	}

	n, err := writeDownloadedFile(outputPath, resp.Body, overwrite)
	return n, contentType, false, err
}

func isRegularFile(path string) bool {
	root, err := rootfs.New(filepath.Dir(path))
	if err != nil {
		return false
	}
	defer root.Close()

	file, err := root.OpenFile(filepath.Base(path))
	if err != nil {
		return false
	}
	return file.Close() == nil
}

func writeScreenshotDownload(outputPath string, reader io.Reader) (int64, bool, error) {
	candidate, err := io.ReadAll(io.LimitReader(reader, pngEquivalenceMaxBytes+1))
	if err != nil {
		return int64(len(candidate)), false, err
	}
	if len(candidate) <= pngEquivalenceMaxBytes {
		if equivalentExistingPNG(outputPath, candidate) {
			return 0, true, nil
		}
	}

	written, err := writeDownloadedFile(outputPath, io.MultiReader(bytes.NewReader(candidate), reader), true)
	return written, false, err
}

func equivalentExistingPNG(outputPath string, candidate []byte) bool {
	root, err := rootfs.New(filepath.Dir(outputPath))
	if err != nil {
		return false
	}
	defer root.Close()

	name := filepath.Base(outputPath)
	existing, err := root.OpenFile(name)
	if err != nil {
		return false
	}
	existingInfo, err := existing.Stat()
	if err != nil {
		_ = existing.Close()
		return false
	}
	existingBytes, err := io.ReadAll(io.LimitReader(existing, pngEquivalenceMaxBytes+1))
	closeErr := existing.Close()
	if err != nil || closeErr != nil {
		return false
	}
	if len(existingBytes) > pngEquivalenceMaxBytes || !equivalentPNGBytes(existingBytes, candidate) {
		return false
	}

	current, err := root.OpenFile(name)
	if err != nil {
		return false
	}
	currentInfo, statErr := current.Stat()
	closeErr = current.Close()
	if statErr != nil || closeErr != nil {
		return false
	}
	return os.SameFile(existingInfo, currentInfo)
}

func equivalentPNGBytes(existing, candidate []byte) bool {
	if bytes.Equal(existing, candidate) {
		return true
	}

	existingStable, existingValid := stablePNGDigest(existing)
	candidateStable, candidateValid := stablePNGDigest(candidate)
	return existingValid && candidateValid && existingStable == candidateStable
}

func stablePNGDigest(data []byte) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if len(data) < len(pngSignature) || !bytes.Equal(data[:len(pngSignature)], pngSignature) {
		return digest, false
	}

	stable := sha256.New()
	_, _ = stable.Write(pngSignature)
	offset := len(pngSignature)
	seenHeader := false
	seenPalette := false
	seenImageData := false
	imageDataEnded := false
	var imageHeader pngImageHeader
	var imageData [][]byte
	for {
		if offset+12 > len(data) {
			return digest, false
		}
		header := data[offset : offset+8]
		length := binary.BigEndian.Uint32(header[:4])
		dataEnd := uint64(offset) + 8 + uint64(length)
		chunkEnd := dataEnd + 4
		if chunkEnd > uint64(len(data)) {
			return digest, false
		}
		dataEndIndex := int(dataEnd)
		chunkEndIndex := int(chunkEnd)
		chunkType := string(header[4:])
		if !validPNGChunkType(header[4:]) {
			return digest, false
		}
		if !seenHeader {
			if chunkType != "IHDR" || length != 13 {
				return digest, false
			}
			seenHeader = true
		} else if chunkType == "IHDR" {
			return digest, false
		}
		switch chunkType {
		case "IHDR":
			headerData := data[offset+8 : dataEndIndex]
			if !validPNGIHDR(headerData) {
				return digest, false
			}
			imageHeader = pngImageHeader{
				width:     binary.BigEndian.Uint32(headerData[:4]),
				height:    binary.BigEndian.Uint32(headerData[4:8]),
				bitDepth:  headerData[8],
				colorType: headerData[9],
				interlace: headerData[12],
			}
		case "PLTE":
			if seenPalette || seenImageData || length == 0 || length%3 != 0 || length > 768 {
				return digest, false
			}
			if imageHeader.colorType == 0 || imageHeader.colorType == 4 {
				return digest, false
			}
			if imageHeader.colorType == 3 && length/3 > 1<<imageHeader.bitDepth {
				return digest, false
			}
			seenPalette = true
		case "IDAT":
			if imageDataEnded {
				return digest, false
			}
			seenImageData = true
			imageData = append(imageData, data[offset+8:dataEndIndex])
		case "IEND":
			if length != 0 || !seenImageData {
				return digest, false
			}
			if imageHeader.colorType == 3 && !seenPalette {
				return digest, false
			}
		default:
			if seenImageData {
				imageDataEnded = true
			}
			if header[4]&0x20 == 0 {
				return digest, false
			}
		}

		wantCRC := binary.BigEndian.Uint32(data[dataEndIndex:chunkEndIndex])
		if gotCRC := crc32.ChecksumIEEE(data[offset+4 : dataEndIndex]); gotCRC != wantCRC {
			return digest, false
		}
		if _, volatile := volatilePNGChunkTypes[chunkType]; !volatile {
			_, _ = stable.Write(data[offset:chunkEndIndex])
		}

		if chunkType == "IEND" {
			if chunkEndIndex != len(data) {
				return digest, false
			}
			if !validPNGImageData(imageHeader, imageData) {
				return digest, false
			}
			copy(digest[:], stable.Sum(nil))
			return digest, true
		}
		offset = chunkEndIndex
	}
}

func validPNGChunkType(value []byte) bool {
	if len(value) != 4 {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') {
			return false
		}
	}
	return value[2]&0x20 == 0
}

func validPNGIHDR(header []byte) bool {
	if len(header) != 13 {
		return false
	}
	width := binary.BigEndian.Uint32(header[:4])
	height := binary.BigEndian.Uint32(header[4:8])
	if width == 0 || height == 0 || width > 0x7fffffff || height > 0x7fffffff {
		return false
	}

	bitDepth := header[8]
	switch header[9] {
	case 0:
		if bitDepth != 1 && bitDepth != 2 && bitDepth != 4 && bitDepth != 8 && bitDepth != 16 {
			return false
		}
	case 2, 4, 6:
		if bitDepth != 8 && bitDepth != 16 {
			return false
		}
	case 3:
		if bitDepth != 1 && bitDepth != 2 && bitDepth != 4 && bitDepth != 8 {
			return false
		}
	default:
		return false
	}

	return header[10] == 0 && header[11] == 0 && header[12] <= 1
}

func validPNGImageData(header pngImageHeader, parts [][]byte) bool {
	compressed := bytes.NewReader(bytes.Join(parts, nil))
	decompressor, err := zlib.NewReader(compressed)
	if err != nil {
		return false
	}

	valid := validPNGScanlines(decompressor, header)
	closeErr := decompressor.Close()
	return valid && closeErr == nil && compressed.Len() == 0
}

func validPNGScanlines(reader io.Reader, header pngImageHeader) bool {
	bitsPerPixel := uint64(header.bitDepth) * pngColorChannels(header.colorType)
	passes := [][4]uint32{{0, 0, 1, 1}}
	if header.interlace == 1 {
		passes = [][4]uint32{
			{0, 0, 8, 8},
			{4, 0, 8, 8},
			{0, 4, 4, 8},
			{2, 0, 4, 4},
			{0, 2, 2, 4},
			{1, 0, 2, 2},
			{0, 1, 1, 2},
		}
	}

	remaining := uint64(pngEquivalenceMaxInflated)
	var filter [1]byte
	for _, pass := range passes {
		width := pngPassDimension(header.width, pass[0], pass[2])
		height := pngPassDimension(header.height, pass[1], pass[3])
		if width == 0 || height == 0 {
			continue
		}
		rowBytes := (uint64(width)*bitsPerPixel + 7) / 8
		scanlineBytes := rowBytes + 1
		if scanlineBytes > remaining || uint64(height) > remaining/scanlineBytes {
			return false
		}
		inflatedBytes := uint64(height) * scanlineBytes
		remaining -= inflatedBytes

		for range height {
			if _, err := io.ReadFull(reader, filter[:]); err != nil || filter[0] > 4 {
				return false
			}
			if _, err := io.CopyN(io.Discard, reader, int64(rowBytes)); err != nil {
				return false
			}
		}
	}

	var extra [1]byte
	n, err := reader.Read(extra[:])
	return n == 0 && err == io.EOF
}

func pngColorChannels(colorType byte) uint64 {
	switch colorType {
	case 0, 3:
		return 1
	case 2:
		return 3
	case 4:
		return 2
	case 6:
		return 4
	default:
		return 0
	}
}

func pngPassDimension(size, start, step uint32) uint32 {
	if size <= start {
		return 0
	}
	return (size - start + step - 1) / step
}

func isRetryableDownloadError(err error) bool {
	var statusErr *downloadHTTPStatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusForbidden,
			http.StatusRequestTimeout,
			http.StatusTooManyRequests,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	var netErr net.Error
	return errors.As(err, &netErr)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writeDownloadedFile(path string, reader io.Reader, overwrite bool) (int64, error) {
	return shared.SafeWriteFileNoSymlink(
		path,
		0o600,
		overwrite,
		".asc-download-*",
		".asc-download-backup-*",
		func(f *os.File) (int64, error) {
			return io.Copy(f, reader)
		},
	)
}
