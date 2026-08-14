package distribution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

var afterIPASnapshotForTest func()

// snapshotIPA copies the already-open input exactly once into a private,
// immutable-for-this-process file. Metadata parsing, hashing, and publishing
// all consume this snapshot so concurrent writes to the source cannot produce
// a descriptor assembled from different byte generations.
func snapshotIPA(ctx context.Context, source *os.File, size int64) (*os.File, string, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, "", nil, err
	}
	if source == nil {
		return nil, "", nil, fmt.Errorf("IPA file is nil")
	}
	if size < 0 {
		return nil, "", nil, fmt.Errorf("IPA size is invalid")
	}
	if size > MaxIPABytes {
		return nil, "", nil, fmt.Errorf("IPA size %d bytes exceeds supported limit of %d bytes", size, MaxIPABytes)
	}
	info, err := source.Stat()
	if err != nil {
		return nil, "", nil, fmt.Errorf("inspect IPA file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, "", nil, fmt.Errorf("IPA is not a regular file")
	}
	if info.Size() != size {
		return nil, "", nil, fmt.Errorf("IPA size changed before snapshot")
	}

	directory, err := os.MkdirTemp("", ".asc-distribute-snapshot-")
	if err != nil {
		return nil, "", nil, fmt.Errorf("create private IPA snapshot directory: %w", err)
	}
	cleanupDirectory := func() { _ = os.Remove(directory) }
	root, err := os.OpenRoot(directory)
	if err != nil {
		cleanupDirectory()
		return nil, "", nil, fmt.Errorf("open private IPA snapshot directory: %w", err)
	}
	snapshot, err := secureopen.OpenNewFileNoFollowInRoot(root, "app.ipa", 0o600)
	if err != nil {
		_ = root.Close()
		cleanupDirectory()
		return nil, "", nil, fmt.Errorf("create private IPA snapshot: %w", err)
	}
	hash := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(snapshot, hash), io.NewSectionReader(source, 0, size))
	if copyErr == nil && written != size {
		copyErr = fmt.Errorf("copied %d of %d bytes", written, size)
	}
	if copyErr == nil {
		copyErr = snapshot.Sync()
	}
	if copyErr == nil {
		copyErr = snapshot.Close()
	}
	if copyErr != nil {
		_ = snapshot.Close()
		_ = root.Remove("app.ipa")
		_ = root.Close()
		cleanupDirectory()
		return nil, "", nil, fmt.Errorf("snapshot IPA: %w", copyErr)
	}
	snapshot, err = secureopen.OpenExistingNoFollowInRoot(root, "app.ipa")
	if err != nil {
		_ = root.Remove("app.ipa")
		_ = root.Close()
		cleanupDirectory()
		return nil, "", nil, fmt.Errorf("open private IPA snapshot: %w", err)
	}
	cleanup := func() {
		_ = snapshot.Close()
		_ = root.Remove("app.ipa")
		_ = root.Close()
		cleanupDirectory()
	}
	return snapshot, hex.EncodeToString(hash.Sum(nil)), cleanup, nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	var written int64
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			wrote, writeErr := destination.Write(buffer[:count])
			written += int64(wrote)
			if writeErr != nil {
				return written, writeErr
			}
			if wrote != count {
				return written, io.ErrShortWrite
			}
		}
		if err := ctx.Err(); err != nil {
			return written, err
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}
