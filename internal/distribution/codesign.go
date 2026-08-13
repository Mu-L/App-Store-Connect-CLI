package distribution

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/infoplist"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
	"howett.net/plist"
)

const (
	maxMainAppExpandedBytes int64 = 4 << 30
	maxToolOutputBytes            = 1 << 20
	mainCodeSignatureScope        = "complete-main-app-code-resources-entitlements-and-profile-certificate-binding"
)

var runCodeSignTool = runBoundedTool

func verifyMainAppCodeSignature(members []*zip.File, appDir string, _ *zip.File, executable string, profile parsedProfile) CodeSignatureVerification {
	result := CodeSignatureVerification{Status: CodeSignatureNotVerified, Scope: mainCodeSignatureScope}
	if runtime.GOOS != "darwin" {
		result.Reason = "complete main-app code-signature verification is available only on macOS"
		return result
	}
	if err := validateExecutableName(strings.TrimSpace(executable)); err != nil {
		result.Status, result.Reason = CodeSignatureInvalid, err.Error()
		return result
	}
	directory, err := os.MkdirTemp("", ".asc-distribute-codesign-")
	if err != nil {
		result.Reason = "could not create a private code-signature verification directory"
		return result
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		result.Reason = "could not secure the code-signature verification directory"
		return result
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		result.Reason = "could not open the code-signature verification directory"
		return result
	}
	defer root.Close()
	if err := root.Mkdir("Verify.app", 0o700); err != nil {
		result.Reason = "could not create the code-signature verification app"
		return result
	}
	app, err := root.OpenRoot("Verify.app")
	if err != nil {
		result.Reason = "could not open the code-signature verification app"
		return result
	}
	defer app.Close()
	if err := materializeMainApp(app, members, appDir); err != nil {
		result.Status, result.Reason = CodeSignatureInvalid, "could not safely materialize the complete bounded main app: "+err.Error()
		return result
	}
	appPath := path.Join(directory, "Verify.app")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := runCodeSignTool(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--all-architectures", "--verbose=4", appPath); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			result.Reason = "codesign is unavailable"
			return result
		}
		result.Status, result.Reason = CodeSignatureInvalid, "codesign rejected the complete main app"
		return result
	}
	entitlementsData, err := runCodeSignTool(ctx, "/usr/bin/codesign", "-d", "--entitlements", ":-", appPath)
	if err != nil {
		result.Status, result.Reason = CodeSignatureInvalid, "could not extract signed main-app entitlements"
		return result
	}
	var entitlements map[string]any
	if err := decodeBoundedPlist(entitlementsData, &entitlements); err != nil {
		result.Status, result.Reason = CodeSignatureInvalid, "signed main-app entitlements are invalid"
		return result
	}
	appIdentifier, ok := entitlements["application-identifier"].(string)
	if !ok || strings.TrimSpace(appIdentifier) == "" {
		result.Status, result.Reason = CodeSignatureInvalid, "signed main-app application identifier is missing"
		return result
	}
	teamIdentifier, ok := entitlements["com.apple.developer.team-identifier"].(string)
	if !ok || strings.TrimSpace(teamIdentifier) == "" {
		result.Status, result.Reason = CodeSignatureInvalid, "signed main-app team identifier is missing"
		return result
	}
	profileApplicationID, _ := profile.Entitlements["application-identifier"].(string)
	if strings.TrimSpace(teamIdentifier) != onlyTrimmed(profile.TeamIdentifier) || !entitlementValuePermits(profileApplicationID, appIdentifier) {
		result.Status, result.Reason = CodeSignatureInvalid, "signed main-app entitlements do not match the embedded profile team and application identifier"
		return result
	}
	if profileDebug, ok := profile.Entitlements["get-task-allow"].(bool); !ok {
		result.Status, result.Reason = CodeSignatureInvalid, "embedded profile get-task-allow entitlement is missing or invalid"
		return result
	} else if signedDebug, exists := entitlements["get-task-allow"]; exists {
		debug, ok := signedDebug.(bool)
		if !ok || debug != profileDebug {
			result.Status, result.Reason = CodeSignatureInvalid, "signed get-task-allow entitlement is not permitted by the embedded profile"
			return result
		}
	} else if profileDebug {
		result.Status, result.Reason = CodeSignatureInvalid, "signed get-task-allow entitlement is missing for a development profile"
		return result
	}
	for key, signedValue := range entitlements {
		profileValue, exists := profile.Entitlements[key]
		if !exists || !entitlementValuePermits(profileValue, signedValue) {
			result.Status, result.Reason = CodeSignatureInvalid, "signed main-app entitlement is not permitted by the embedded profile: "+key
			return result
		}
	}

	codePaths, err := enumerateMachOFiles(appPath)
	if err != nil {
		result.Status, result.Reason = CodeSignatureInvalid, "could not enumerate nested signed code: "+err.Error()
		return result
	}
	mainExecutablePath := filepath.Join(appPath, executable)
	if !containsPath(codePaths, mainExecutablePath) {
		result.Status, result.Reason = CodeSignatureInvalid, "CFBundleExecutable is not a Mach-O file in the main app"
		return result
	}
	allowed := certificateFingerprintSet(profile.DeveloperCertificates)
	mainFingerprints, err := codeObjectFingerprints(ctx, directory, 0, mainExecutablePath)
	if err != nil {
		result.Status, result.Reason = codeVerificationFailure(err, "main executable")
		return result
	}
	for _, fingerprint := range mainFingerprints {
		if _, ok := allowed[fingerprint]; !ok {
			result.Status, result.Reason = CodeSignatureInvalid, "main executable signer is not permitted by the embedded profile"
			return result
		}
	}
	mainFingerprintSet := stringSet(mainFingerprints)
	teamRequirement := `anchor apple generic and certificate leaf[subject.OU] = "` + onlyTrimmed(profile.TeamIdentifier) + `"`
	for index, codePath := range codePaths {
		if _, err := runCodeSignTool(ctx, "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R="+teamRequirement, codePath); err != nil {
			result.Status, result.Reason = CodeSignatureInvalid, "nested signed code does not satisfy the main app signing-team requirement"
			return result
		}
		if codePath == mainExecutablePath {
			continue
		}
		fingerprints, err := codeObjectFingerprints(ctx, directory, index+1, codePath)
		if err != nil {
			result.Status, result.Reason = codeVerificationFailure(err, "nested signed code")
			return result
		}
		for _, fingerprint := range fingerprints {
			if _, ok := allowed[fingerprint]; !ok {
				result.Status, result.Reason = CodeSignatureInvalid, "nested signed code signer is not permitted by the embedded profile"
				return result
			}
			if _, ok := mainFingerprintSet[fingerprint]; !ok {
				result.Status, result.Reason = CodeSignatureInvalid, "nested signed code signer differs from the main executable signer"
				return result
			}
		}
	}
	result.Status = CodeSignatureVerified
	result.Reason = "complete main app, every nested Mach-O code object, signed entitlements, and profile certificate binding verified"
	result.SignerCertificateSHA256Fingerprints = canonicalSet(mainFingerprints)
	return result
}

func enumerateMachOFiles(appPath string) ([]string, error) {
	var result []string
	err := filepath.WalkDir(appPath, func(candidate string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link found in materialized app")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file found in materialized app")
		}
		file, err := os.Open(candidate)
		if err != nil {
			return err
		}
		var magic [4]byte
		_, readErr := io.ReadFull(file, magic[:])
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if isMachOMagic(magic) {
			result = append(result, candidate)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(result)
	return result, nil
}

func isMachOMagic(magic [4]byte) bool {
	switch magic {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe},
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe},
		[4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca},
		[4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
		return true
	default:
		return false
	}
}

func codeObjectFingerprints(ctx context.Context, directory string, objectIndex int, codePath string) ([]string, error) {
	archOutput, err := runCodeSignTool(ctx, "/usr/bin/lipo", "-archs", codePath)
	if err != nil {
		return nil, err
	}
	architectures := strings.Fields(string(archOutput))
	if len(architectures) == 0 || len(architectures) > 64 {
		return nil, fmt.Errorf("invalid architecture list")
	}
	var fingerprints []string
	for architectureIndex, architecture := range architectures {
		if err := validateArchitecture(architecture); err != nil {
			return nil, err
		}
		prefix := path.Join(directory, fmt.Sprintf("certificate-%d-%d-", objectIndex, architectureIndex))
		if _, err := runCodeSignTool(ctx, "/usr/bin/codesign", "-d", "-a", architecture, "--extract-certificates="+prefix, codePath); err != nil {
			return nil, err
		}
		leaf, err := os.ReadFile(prefix + "0")
		if err != nil {
			return nil, err
		}
		fingerprint, err := certificateFingerprint(leaf)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	return canonicalSet(fingerprints), nil
}

func codeVerificationFailure(err error, subject string) (CodeSignatureVerificationStatus, string) {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return CodeSignatureNotVerified, "required code-signature tooling is unavailable"
	}
	return CodeSignatureInvalid, "could not verify " + subject + " architectures and signer certificates"
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func containsPath(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func entitlementValuePermits(profileValue, signedValue any) bool {
	profileString, profileIsString := profileValue.(string)
	signedString, signedIsString := signedValue.(string)
	if profileIsString && signedIsString {
		profileString, signedString = strings.TrimSpace(profileString), strings.TrimSpace(signedString)
		if strings.HasSuffix(profileString, "*") {
			prefix := strings.TrimSuffix(profileString, "*")
			return strings.HasPrefix(signedString, prefix) && len(signedString) > len(prefix)
		}
		return signedString == profileString
	}
	profileList, profileIsList := entitlementList(profileValue)
	signedList, signedIsList := entitlementList(signedValue)
	if profileIsList && signedIsList {
		for _, signedItem := range signedList {
			permitted := false
			for _, profileItem := range profileList {
				if entitlementValuePermits(profileItem, signedItem) {
					permitted = true
					break
				}
			}
			if !permitted {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(profileValue, signedValue)
}

func entitlementList(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	case []string:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = item
		}
		return result, true
	default:
		return nil, false
	}
}

func materializeMainApp(destination *os.Root, members []*zip.File, appDir string) error {
	prefix := appDir + "/"
	var total int64
	for _, member := range members {
		if !strings.HasPrefix(member.Name, prefix) {
			continue
		}
		relative := strings.TrimPrefix(member.Name, prefix)
		if relative == "" {
			continue
		}
		if member.FileInfo().IsDir() {
			if err := destination.MkdirAll(strings.TrimSuffix(relative, "/"), 0o700); err != nil {
				return err
			}
			continue
		}
		if member.UncompressedSize64 > uint64(maxMainAppExpandedBytes) || total > maxMainAppExpandedBytes-int64(member.UncompressedSize64) {
			return fmt.Errorf("expanded main app exceeds %d bytes", maxMainAppExpandedBytes)
		}
		total += int64(member.UncompressedSize64)
		if err := destination.MkdirAll(path.Dir(relative), 0o700); err != nil {
			return err
		}
		if err := copyZipMemberToNewFile(destination, relative, member, int64(member.UncompressedSize64)); err != nil {
			return err
		}
	}
	return nil
}

func decodeBoundedPlist(data []byte, destination any) error {
	if len(data) == 0 || len(data) > 4<<20 {
		return fmt.Errorf("plist size is invalid")
	}
	if err := infoplist.ValidateStructure(data); err != nil {
		return err
	}
	_, err := plist.Unmarshal(data, destination)
	return err
}

func certificateFingerprintSet(certificates [][]byte) map[string]struct{} {
	result := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if fingerprint, err := certificateFingerprint(certificate); err == nil {
			result[fingerprint] = struct{}{}
		}
	}
	return result
}

func certificateFingerprint(data []byte) (string, error) {
	if _, err := x509.ParseCertificate(data); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateExecutableName(value string) error {
	if value == "" || len(value) > 255 || path.Base(value) != value || value == "." || value == ".." {
		return fmt.Errorf("CFBundleExecutable is not a single safe filename")
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.In(r, unicode.Bidi_Control) {
			return fmt.Errorf("CFBundleExecutable contains control or formatting characters")
		}
	}
	return nil
}

func validateArchitecture(value string) error {
	if value == "" || len(value) > 64 {
		return fmt.Errorf("invalid architecture")
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return fmt.Errorf("invalid architecture")
		}
	}
	return nil
}

func copyZipMemberToNewFile(root *os.Root, name string, member *zip.File, limit int64) error {
	reader, err := member.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	file, err := secureopen.OpenNewFileNoFollowInRoot(root, name, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(reader, limit+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > limit {
		return fmt.Errorf("expanded member exceeds %d bytes", limit)
	}
	return nil
}

func runBoundedTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, err
	}
	output, readErr := io.ReadAll(io.LimitReader(pipe, maxToolOutputBytes+1))
	waitErr := command.Wait()
	if len(output) > maxToolOutputBytes {
		return nil, fmt.Errorf("tool output exceeded %d bytes", maxToolOutputBytes)
	}
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return output, nil
}
