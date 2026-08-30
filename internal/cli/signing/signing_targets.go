package signing

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

const (
	maxSigningSyncTargetsFileBytes int64 = 64 << 10
	maxSigningSyncTargets                = 32
)

var errSigningSyncTargetsManifestPath = errors.New("targets manifest path is empty")

type signingSyncTargetsManifest struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Targets       []signingSyncTargetRecord `json:"targets"`
}

type signingSyncTargetRecord struct {
	BundleID string `json:"bundleId"`
}

// readSigningSyncTargetsFile reads the non-secret target selector through the
// rooted no-follow filesystem boundary. The manifest is deliberately not
// subject to the owner-only mode check used by secret inputs.
func readSigningSyncTargetsFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errSigningSyncTargetsManifestPath
	}
	if err := rootfs.ValidateRelative(path); err != nil {
		return nil, fmt.Errorf("targets manifest path: %w", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve targets manifest root: %w", err)
	}
	root, err := rootfs.New(workingDirectory)
	if err != nil {
		return nil, fmt.Errorf("resolve targets manifest root: %w", err)
	}
	defer root.Close()

	file, err := root.OpenFile(path)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("open targets manifest: %w", err)
		}
		return nil, fmt.Errorf("open targets manifest without following symlinks: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect targets manifest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("targets manifest must be a regular file")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSigningSyncTargetsFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read targets manifest: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("targets manifest is empty")
	}
	if int64(len(data)) > maxSigningSyncTargetsFileBytes {
		return nil, fmt.Errorf("targets manifest exceeds the 64 KiB size limit")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("targets manifest is not valid UTF-8")
	}

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest signingSyncTargetsManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode targets manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("targets manifest has trailing JSON")
		}
		return nil, fmt.Errorf("targets manifest has trailing data: %w", err)
	}

	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("targets manifest schemaVersion must be 1")
	}
	if len(manifest.Targets) < 1 || len(manifest.Targets) > maxSigningSyncTargets {
		return nil, fmt.Errorf("targets manifest must contain between 1 and %d targets", maxSigningSyncTargets)
	}

	bundleIDs := make([]string, 0, len(manifest.Targets))
	for index, target := range manifest.Targets {
		bundleID, err := validateSigningSyncTargetBundleID(target.BundleID)
		if err != nil {
			return nil, fmt.Errorf("targets manifest target %d: %w", index+1, err)
		}
		for _, prior := range bundleIDs {
			if strings.EqualFold(prior, bundleID) {
				return nil, fmt.Errorf("targets manifest contains duplicate bundleId")
			}
		}
		bundleIDs = append(bundleIDs, bundleID)
	}

	sort.Slice(bundleIDs, func(i, j int) bool {
		left, right := strings.ToLower(bundleIDs[i]), strings.ToLower(bundleIDs[j])
		if left == right {
			return bundleIDs[i] < bundleIDs[j]
		}
		return left < right
	})
	return bundleIDs, nil
}

func validateSigningSyncTargetBundleID(raw string) (string, error) {
	bundleID := strings.TrimSpace(raw)
	if bundleID == "" {
		return "", fmt.Errorf("bundleId must not be empty")
	}
	for _, character := range bundleID {
		if unicode.IsControl(character) {
			return "", fmt.Errorf("bundleId contains control characters")
		}
		if isSigningSyncBidiControl(character) {
			return "", fmt.Errorf("bundleId contains bidi control characters")
		}
	}
	if strings.ContainsAny(bundleID, `/\\:`) {
		return "", fmt.Errorf("bundleId contains path characters")
	}
	return bundleID, nil
}

func isSigningSyncBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}
