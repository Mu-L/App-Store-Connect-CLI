package assets

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type readerThatFailsAfterFirstRead struct {
	readOnce bool
}

func TestDownloadHTTPStatusErrorExposesHTTPStatus(t *testing.T) {
	err := &downloadHTTPStatusError{StatusCode: 503}

	if got := err.HTTPStatusCode(); got != 503 {
		t.Fatalf("HTTPStatusCode() = %d, want 503", got)
	}
}

func (r *readerThatFailsAfterFirstRead) Read(p []byte) (int, error) {
	if !r.readOnce {
		r.readOnce = true
		return copy(p, "NEW-DATA"), nil
	}
	return 0, errors.New("simulated read failure")
}

func TestWriteDownloadedFile_Overwrite_ErrorPreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	if err := os.WriteFile(path, []byte("OLD-DATA"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	_, err := writeDownloadedFile(path, &readerThatFailsAfterFirstRead{}, true)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error: %v", readErr)
	}
	if string(data) != "OLD-DATA" {
		t.Fatalf("expected existing file contents preserved, got %q", string(data))
	}
}

func TestWriteDownloadedFile_Overwrite_ReplacesExistingFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")

	if err := os.WriteFile(path, []byte("OLD-DATA"), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	written, err := writeDownloadedFile(path, strings.NewReader("NEW-DATA"), true)
	if err != nil {
		t.Fatalf("writeDownloadedFile() error: %v", err)
	}
	if written != int64(len("NEW-DATA")) {
		t.Fatalf("expected written=%d, got %d", len("NEW-DATA"), written)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error: %v", readErr)
	}
	if string(data) != "NEW-DATA" {
		t.Fatalf("expected new file contents, got %q", string(data))
	}
}

func TestEquivalentPNGFiles(t *testing.T) {
	tests := []struct {
		name      string
		existing  []byte
		candidate []byte
		want      bool
	}{
		{
			name:      "byte identical non-PNG",
			existing:  []byte("same bytes"),
			candidate: []byte("same bytes"),
			want:      true,
		},
		{
			name:      "different non-PNG",
			existing:  []byte("first"),
			candidate: []byte("second"),
		},
		{
			name: "volatile metadata differs",
			existing: downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-first")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			candidate: downloadTestPNG(
				downloadTestPNGChunk("tEXt", []byte("asset-id-second")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			want: true,
		},
		{
			name: "Exif metadata differs",
			existing: downloadTestPNG(
				downloadTestPNGChunk("eXIf", []byte("orientation-first")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			candidate: downloadTestPNG(
				downloadTestPNGChunk("eXIf", []byte("orientation-second")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
		},
		{
			name: "pixel data differs",
			existing: downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-first")),
				downloadTestPNGChunk("IDAT", []byte("first-pixels")),
			),
			candidate: downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-second")),
				downloadTestPNGChunk("IDAT", []byte("second-pixels")),
			),
		},
		{
			name: "stable ancillary data differs",
			existing: downloadTestPNG(
				downloadTestPNGChunk("iCCP", []byte("first-profile")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			candidate: downloadTestPNG(
				downloadTestPNGChunk("iCCP", []byte("second-profile")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
		},
		{
			name: "invalid CRC is not equivalent",
			existing: downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-first")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			candidate: corruptDownloadTestPNGCRC(downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-second")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			)),
		},
		{
			name: "truncated PNG is not equivalent",
			existing: downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-first")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			),
			candidate: truncateDownloadTestPNG(downloadTestPNG(
				downloadTestPNGChunk("iTXt", []byte("asset-id-second")),
				downloadTestPNGChunk("IDAT", []byte("same-pixels")),
			)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := equivalentPNGBytes(tt.existing, tt.candidate)
			if got != tt.want {
				t.Fatalf("equivalentPNGBytes() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestWriteScreenshotDownloadReplacesChangedPixels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "screenshot.png")
	existing := downloadTestPNG(downloadTestPNGChunk("IDAT", []byte("old-pixels")))
	candidate := downloadTestPNG(downloadTestPNGChunk("IDAT", []byte("new-pixels")))
	if err := os.WriteFile(path, existing, 0o600); err != nil {
		t.Fatalf("write existing screenshot: %v", err)
	}

	written, unchanged, err := writeScreenshotDownload(path, strings.NewReader(string(candidate)))
	if err != nil {
		t.Fatalf("writeScreenshotDownload() error: %v", err)
	}
	if unchanged {
		t.Fatal("writeScreenshotDownload() marked changed pixels as unchanged")
	}
	if written != int64(len(candidate)) {
		t.Fatalf("writeScreenshotDownload() wrote %d bytes, want %d", written, len(candidate))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced screenshot: %v", err)
	}
	if string(got) != string(candidate) {
		t.Fatal("writeScreenshotDownload() did not replace changed pixels")
	}
}

func TestWriteScreenshotDownloadReplacesUnreadableExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file permissions do not provide a portable unreadable-file fixture")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "screenshot.png")
	if err := os.WriteFile(path, []byte("old screenshot"), 0o600); err != nil {
		t.Fatalf("write existing screenshot: %v", err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatalf("make existing screenshot unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	written, unchanged, err := writeScreenshotDownload(path, strings.NewReader("new screenshot"))
	if err != nil {
		t.Fatalf("writeScreenshotDownload() error: %v", err)
	}
	if unchanged {
		t.Fatal("writeScreenshotDownload() marked unreadable destination as unchanged")
	}
	if written != int64(len("new screenshot")) {
		t.Fatalf("writeScreenshotDownload() wrote %d bytes, want %d", written, len("new screenshot"))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced screenshot: %v", err)
	}
	if string(got) != "new screenshot" {
		t.Fatalf("replaced screenshot = %q, want %q", got, "new screenshot")
	}
}

func TestWriteScreenshotDownloadFailurePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "screenshot.png")
	existing := []byte("existing screenshot")
	if err := os.WriteFile(path, existing, 0o600); err != nil {
		t.Fatalf("write existing screenshot: %v", err)
	}

	_, _, err := writeScreenshotDownload(path, &readerThatFailsAfterFirstRead{})
	if err == nil {
		t.Fatal("writeScreenshotDownload() error = nil, want staged read failure")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read preserved screenshot: %v", readErr)
	}
	if string(got) != string(existing) {
		t.Fatalf("existing screenshot = %q, want %q", got, existing)
	}
	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil {
		t.Fatalf("read output directory: %v", readDirErr)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("output directory entries = %v, want only %q", entries, filepath.Base(path))
	}
}

func TestIsRetryableDownloadError_ContextErrorsAreNotRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "deadline exceeded",
			err:  &url.Error{Op: "Get", URL: "https://example.com", Err: context.DeadlineExceeded},
		},
		{
			name: "context canceled",
			err:  &url.Error{Op: "Get", URL: "https://example.com", Err: context.Canceled},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isRetryableDownloadError(tt.err) {
				t.Fatalf("expected non-retryable error for %q", tt.name)
			}
		})
	}
}

func TestIsRetryableDownloadError_TransientNetworkErrorIsRetryable(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://example.com",
		Err: &net.DNSError{IsTimeout: true},
	}
	if !isRetryableDownloadError(err) {
		t.Fatalf("expected retryable network error")
	}
}

func downloadTestPNG(chunks ...[]byte) []byte {
	png := append([]byte(nil), pngSignature...)
	png = append(png, downloadTestPNGChunk("IHDR", make([]byte, 13))...)
	for _, chunk := range chunks {
		png = append(png, chunk...)
	}
	png = append(png, downloadTestPNGChunk("IEND", nil)...)
	return png
}

func downloadTestPNGChunk(chunkType string, data []byte) []byte {
	chunk := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(chunk[:4], uint32(len(data)))
	copy(chunk[4:8], chunkType)
	copy(chunk[8:8+len(data)], data)
	binary.BigEndian.PutUint32(chunk[8+len(data):], crc32.ChecksumIEEE(chunk[4:8+len(data)]))
	return chunk
}

func corruptDownloadTestPNGCRC(png []byte) []byte {
	corrupt := append([]byte(nil), png...)
	corrupt[len(corrupt)-1] ^= 0xff
	return corrupt
}

func truncateDownloadTestPNG(png []byte) []byte {
	return append([]byte(nil), png[:len(png)-3]...)
}
