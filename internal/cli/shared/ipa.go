package shared

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"

	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/infoplist"
)

type IPABundleInfo struct {
	BundleID    string
	Version     string
	BuildNumber string
}

// ValidateIPAPath ensures an IPA path points to a non-empty regular file and
// rejects symlinks so upload commands don't dereference unexpected files.
func ValidateIPAPath(ipaPath string) (os.FileInfo, error) {
	file, fileInfo, err := OpenValidatedIPAPath(ipaPath)
	if err != nil {
		return nil, err
	}
	_ = file.Close()
	return fileInfo, nil
}

// ValidatePKGPath ensures a PKG path points to a non-empty regular file and
// rejects symlinks before an upload reservation is created.
func ValidatePKGPath(pkgPath string) (os.FileInfo, error) {
	file, fileInfo, err := OpenValidatedPKGPath(pkgPath)
	if err != nil {
		return nil, err
	}
	_ = file.Close()
	return fileInfo, nil
}

// OpenValidatedIPAPath opens and validates an IPA without following a symlink.
// The returned handle pins the validated file across the upload lifecycle.
func OpenValidatedIPAPath(ipaPath string) (*os.File, os.FileInfo, error) {
	return openValidatedBuildArtifactPath(ipaPath, "IPA", "--ipa")
}

// OpenValidatedPKGPath opens and validates a PKG without following a symlink.
// The returned handle pins the validated file across the upload lifecycle.
func OpenValidatedPKGPath(pkgPath string) (*os.File, os.FileInfo, error) {
	return openValidatedBuildArtifactPath(pkgPath, "PKG", "--pkg")
}

func openValidatedBuildArtifactPath(filePath, artifactName, flagName string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat %s: %w", artifactName, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, buildArtifactSymlinkError(filePath, flagName)
	}
	if err := validateBuildArtifactInfo(pathInfo, flagName); err != nil {
		return nil, nil, err
	}

	file, err := OpenExistingNoFollow(filePath)
	if err != nil {
		if latestInfo, statErr := os.Lstat(filePath); statErr == nil && latestInfo.Mode()&os.ModeSymlink != 0 {
			return nil, nil, buildArtifactSymlinkError(filePath, flagName)
		}
		return nil, nil, fmt.Errorf("failed to open %s: %w", artifactName, err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("failed to stat opened %s: %w", artifactName, err)
	}
	if !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s changed while being opened", flagName)
	}
	if err := validateBuildArtifactInfo(fileInfo, flagName); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, fileInfo, nil
}

func validateBuildArtifactInfo(fileInfo os.FileInfo, flagName string) error {
	if fileInfo.IsDir() {
		return fmt.Errorf("%s must be a file", flagName)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", flagName)
	}
	if fileInfo.Size() == 0 {
		return fmt.Errorf("%s must not be empty", flagName)
	}
	return nil
}

func buildArtifactSymlinkError(filePath, flagName string) error {
	return fmt.Errorf("refusing to read symlink %q from %s", filePath, flagName)
}

// ExtractBundleInfoFromIPA reads the top-level app's bundle identifier and
// version metadata from an IPA.
func ExtractBundleInfoFromIPA(ipaPath string) (IPABundleInfo, error) {
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		return IPABundleInfo{}, fmt.Errorf("open IPA: %w", err)
	}
	defer reader.Close()
	return extractBundleInfoFromIPAFiles(reader.File)
}

// ExtractBundleInfoFromIPAFile reads top-level app metadata from an opened IPA.
func ExtractBundleInfoFromIPAFile(file *os.File) (IPABundleInfo, error) {
	if file == nil {
		return IPABundleInfo{}, fmt.Errorf("open IPA: file is required")
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return IPABundleInfo{}, fmt.Errorf("stat IPA: %w", err)
	}
	reader, err := zip.NewReader(file, fileInfo.Size())
	if err != nil {
		return IPABundleInfo{}, fmt.Errorf("open IPA: %w", err)
	}
	return extractBundleInfoFromIPAFiles(reader.File)
}

func extractBundleInfoFromIPAFiles(files []*zip.File) (IPABundleInfo, error) {
	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}
		if !isTopLevelAppInfoPlist(file.Name) {
			continue
		}
		return readBundleInfoFromInfoPlist(file)
	}

	// Keep the canonical casing for the filename, but follow Go error string style.
	return IPABundleInfo{}, fmt.Errorf("missing Info.plist in IPA")
}

func isTopLevelAppInfoPlist(name string) bool {
	cleaned := path.Clean(name)
	if !strings.HasPrefix(cleaned, "Payload/") || !strings.HasSuffix(cleaned, "/Info.plist") {
		return false
	}
	dir := path.Dir(cleaned)
	if !strings.HasSuffix(dir, ".app") {
		return false
	}
	return path.Dir(dir) == "Payload"
}

func readBundleInfoFromInfoPlist(file *zip.File) (IPABundleInfo, error) {
	if err := infoplist.CheckDeclaredSize(file.UncompressedSize64); err != nil {
		return IPABundleInfo{}, fmt.Errorf("read Info.plist: %w", err)
	}

	reader, err := file.Open()
	if err != nil {
		return IPABundleInfo{}, fmt.Errorf("open Info.plist: %w", err)
	}
	defer reader.Close()

	data, err := infoplist.ReadBounded(reader)
	if err != nil {
		return IPABundleInfo{}, fmt.Errorf("read Info.plist: %w", err)
	}
	if err := infoplist.ValidateStructure(data); err != nil {
		return IPABundleInfo{}, fmt.Errorf("decode Info.plist: %w", err)
	}

	var info map[string]any
	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&info); err != nil {
		return IPABundleInfo{}, fmt.Errorf("decode Info.plist: %w", err)
	}

	return IPABundleInfo{
		BundleID:    coercePlistValueToString(info["CFBundleIdentifier"]),
		Version:     coercePlistValueToString(info["CFBundleShortVersionString"]),
		BuildNumber: coercePlistValueToString(info["CFBundleVersion"]),
	}, nil
}

// ResolveBundleInfoForIPA fills missing version/build-number values from the IPA
// and preserves the existing CLI-facing error messages.
func ResolveBundleInfoForIPA(ipaPath, version, buildNumber string) (string, string, error) {
	versionValue := strings.TrimSpace(version)
	buildNumberValue := strings.TrimSpace(buildNumber)
	if versionValue == "" || buildNumberValue == "" {
		info, err := ExtractBundleInfoFromIPA(ipaPath)
		if err != nil {
			missingFlags := make([]string, 0, 2)
			if versionValue == "" {
				missingFlags = append(missingFlags, "--version")
			}
			if buildNumberValue == "" {
				missingFlags = append(missingFlags, "--build-number")
			}
			return "", "", fmt.Errorf("%s required (failed to extract from IPA: %w)", strings.Join(missingFlags, " and "), err)
		}
		if versionValue == "" {
			versionValue = info.Version
		}
		if buildNumberValue == "" {
			buildNumberValue = info.BuildNumber
		}
	}
	if versionValue == "" || buildNumberValue == "" {
		missingFields := make([]string, 0, 2)
		missingFlags := make([]string, 0, 2)
		if versionValue == "" {
			missingFields = append(missingFields, "CFBundleShortVersionString")
			missingFlags = append(missingFlags, "--version")
		}
		if buildNumberValue == "" {
			missingFields = append(missingFields, "CFBundleVersion")
			missingFlags = append(missingFlags, "--build-number")
		}
		return "", "", fmt.Errorf("missing Info.plist keys %s; provide %s", strings.Join(missingFields, " and "), strings.Join(missingFlags, " and "))
	}
	return versionValue, buildNumberValue, nil
}

func coercePlistValueToString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	case int, int8, int16, int32, int64:
		return fmt.Sprint(v)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v)
	case float32, float64:
		return strings.TrimSpace(fmt.Sprint(v))
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}
