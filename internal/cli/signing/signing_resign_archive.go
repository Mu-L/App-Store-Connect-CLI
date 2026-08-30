package signing

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"howett.net/plist"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/infoplist"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

const (
	signingResignMaxArchiveEntries              = 20_000
	signingResignMaxArchiveMemberNameLen        = 4096
	signingResignMaxExpandedBytes        uint64 = 16 << 30
	signingResignMaxIPABytes             int64  = 8 << 30
	signingResignMaxTargetCount                 = 256
)

type signingResignTarget struct {
	Kind                 string
	RelativePath         string
	BundleID             string
	Executable           string
	ExistingEntitlements map[string]any
	Profile              signingResignProfile
	EntitlementsPath     string
}

type signingResignArchive struct {
	MainPath string
	Targets  []signingResignTarget
}

func snapshotSigningResignIPA(ctx context.Context, source *os.File, size int64, destination *os.Root) (*os.File, string, error) {
	if err := contextError(ctx); err != nil {
		return nil, "", err
	}
	if source == nil {
		return nil, "", fmt.Errorf("IPA input is missing")
	}
	if size <= 0 || size > signingResignMaxIPABytes {
		return nil, "", fmt.Errorf("IPA size must be between 1 and %d bytes", signingResignMaxIPABytes)
	}
	before, err := source.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("inspect IPA input: %w", err)
	}
	if err := validateSigningResignIPAFileInfo(before, size); err != nil {
		return nil, "", err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return nil, "", fmt.Errorf("seek IPA input: %w", err)
	}
	snapshot, err := secureopen.OpenNewFileNoFollowInRoot(destination, "input.ipa", 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create private IPA snapshot: %w", err)
	}
	hash := newSHA256Writer()
	written, copyErr := copySigningResignWithContext(ctx, io.MultiWriter(snapshot, hash), io.LimitReader(source, size+1), size)
	if copyErr == nil && written != size {
		copyErr = fmt.Errorf("IPA changed while it was being snapshotted")
	}
	if copyErr == nil {
		copyErr = snapshot.Sync()
	}
	closeErr := snapshot.Close()
	if copyErr != nil || closeErr != nil {
		_ = destination.Remove("input.ipa")
		return nil, "", errors.Join(copyErr, closeErr)
	}
	after, err := source.Stat()
	if err != nil {
		_ = destination.Remove("input.ipa")
		return nil, "", fmt.Errorf("reinspect IPA input after snapshot: %w", err)
	}
	if err := validateStableSigningResignIPA(before, after, size); err != nil {
		_ = destination.Remove("input.ipa")
		return nil, "", err
	}
	pinned, err := secureopen.OpenExistingNoFollowInRoot(destination, "input.ipa")
	if err != nil {
		_ = destination.Remove("input.ipa")
		return nil, "", fmt.Errorf("reopen private IPA snapshot: %w", err)
	}
	return pinned, hash.String(), nil
}

type signingResignSHA256Writer struct{ hash hash.Hash }

func newSHA256Writer() *signingResignSHA256Writer {
	return &signingResignSHA256Writer{hash: sha256.New()}
}

func (writer *signingResignSHA256Writer) Write(data []byte) (int, error) {
	return writer.hash.Write(data)
}

func (writer *signingResignSHA256Writer) String() string {
	return strings.ToUpper(fmt.Sprintf("%x", writer.hash.Sum(nil)))
}

func validateSigningResignIPAFileInfo(info os.FileInfo, size int64) error {
	if info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("IPA input is not a regular file")
	}
	if info.Size() != size {
		return fmt.Errorf("IPA size changed before snapshot")
	}
	if err := validateSigningRunInputPermissions("IPA input", info, false); err != nil {
		return err
	}
	return nil
}

func validateStableSigningResignIPA(before, after os.FileInfo, size int64) error {
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("IPA input changed while it was being snapshotted")
	}
	return validateSigningResignIPAFileInfo(after, size)
}

func copySigningResignWithContext(ctx context.Context, destination io.Writer, source io.Reader, expected int64) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	buffer := make([]byte, 64<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			if written > expected-int64(read) {
				return written, fmt.Errorf("IPA exceeds its declared size")
			}
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

func validateSigningResignArchive(ctx context.Context, reader *zip.Reader) error {
	if reader == nil {
		return fmt.Errorf("IPA archive is missing")
	}
	if len(reader.File) > signingResignMaxArchiveEntries {
		return fmt.Errorf("IPA contains too many archive entries")
	}
	seen := make(map[string]bool, len(reader.File))
	descendants := make(map[string]struct{}, len(reader.File))
	var declared uint64
	for _, member := range reader.File {
		if err := validateSigningResignArchiveMember(member); err != nil {
			return err
		}
		if member.UncompressedSize64 > signingResignMaxExpandedBytes-declared {
			return fmt.Errorf("IPA declared expansion exceeds %d bytes", signingResignMaxExpandedBytes)
		}
		declared += member.UncompressedSize64
		key := strings.ToLower(strings.TrimSuffix(member.Name, "/"))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("IPA contains duplicate path")
		}
		isDirectory := member.FileInfo().IsDir()
		for ancestor := path.Dir(key); ancestor != "."; ancestor = path.Dir(ancestor) {
			if ancestorIsDirectory, exists := seen[ancestor]; exists && !ancestorIsDirectory {
				return fmt.Errorf("IPA contains a file/directory path collision")
			}
		}
		if !isDirectory {
			if _, exists := descendants[key]; exists {
				return fmt.Errorf("IPA contains a file/directory path collision")
			}
		}
		seen[key] = isDirectory
		for ancestor := path.Dir(key); ancestor != "."; ancestor = path.Dir(ancestor) {
			descendants[ancestor] = struct{}{}
		}
	}
	var expanded uint64
	for _, member := range reader.File {
		if err := contextError(ctx); err != nil {
			return err
		}
		opened, err := member.Open()
		if err != nil {
			return fmt.Errorf("read IPA archive member: %w", err)
		}
		remaining := signingResignMaxExpandedBytes - expanded
		written, readErr := copySigningResignWithContext(ctx, io.Discard, io.LimitReader(opened, int64(remaining)+1), int64(remaining))
		closeErr := opened.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		if written < 0 || uint64(written) > remaining || uint64(written) != member.UncompressedSize64 {
			return fmt.Errorf("IPA archive member has invalid expanded contents")
		}
		expanded += uint64(written)
		if member.FileInfo().IsDir() && written != 0 {
			return fmt.Errorf("IPA directory member contains data")
		}
	}
	return nil
}

func validateSigningResignArchiveMember(member *zip.File) error {
	if member == nil {
		return fmt.Errorf("IPA contains a missing archive member")
	}
	name := member.Name
	if name == "" || len(name) > signingResignMaxArchiveMemberNameLen || !utf8.ValidString(name) || strings.ContainsRune(name, '\\') {
		return fmt.Errorf("IPA contains an unsafe archive path")
	}
	for _, character := range name {
		if character == 0 || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || unicode.In(character, unicode.Bidi_Control) {
			return fmt.Errorf("IPA contains an unsafe archive path")
		}
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.IsAbs(name) || path.Clean(trimmed) != trimmed || trimmed == ".." || strings.HasPrefix(trimmed, "../") {
		return fmt.Errorf("IPA contains a non-canonical archive path")
	}
	if member.Flags&1 != 0 {
		return fmt.Errorf("IPA contains an encrypted archive member")
	}
	if member.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("IPA contains a symbolic link")
	}
	if !member.FileInfo().IsDir() && !member.Mode().IsRegular() {
		return fmt.Errorf("IPA contains a non-regular member")
	}
	return nil
}

func materializeSigningResignArchive(ctx context.Context, reader *zip.Reader, destination *os.Root) error {
	if err := destination.MkdirAll(".", 0o700); err != nil {
		return err
	}
	members := append([]*zip.File(nil), reader.File...)
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	for _, member := range members {
		if err := contextError(ctx); err != nil {
			return err
		}
		name := filepath.FromSlash(strings.TrimSuffix(member.Name, "/"))
		if member.FileInfo().IsDir() {
			if err := destination.MkdirAll(name, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := destination.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return err
		}
		file, err := secureopen.OpenNewFileNoFollowInRoot(destination, name, 0o600)
		if err != nil {
			return fmt.Errorf("materialize IPA member: %w", err)
		}
		opened, openErr := member.Open()
		if openErr == nil {
			_, openErr = copySigningResignWithContext(ctx, file, io.LimitReader(opened, int64(member.UncompressedSize64)+1), int64(member.UncompressedSize64))
			closeMemberErr := opened.Close()
			openErr = errors.Join(openErr, closeMemberErr)
		}
		if openErr == nil {
			if err := file.Sync(); err != nil {
				openErr = err
			}
		}
		closeErr := file.Close()
		if openErr != nil || closeErr != nil {
			return errors.Join(openErr, closeErr)
		}
		if member.Mode().Perm()&0o111 != 0 {
			if err := destination.Chmod(name, 0o700); err != nil {
				return err
			}
		}
	}
	return nil
}

func discoverSigningResignArchive(ctx context.Context, reader *zip.Reader, tree rootfs.Root) (signingResignArchive, error) {
	if reader == nil || tree.Path() == "" {
		return signingResignArchive{}, fmt.Errorf("IPA archive or staging root is missing")
	}
	directories := make(map[string]struct{})
	for _, member := range reader.File {
		name := strings.TrimSuffix(member.Name, "/")
		for candidate := name; candidate != "." && candidate != ""; candidate = path.Dir(candidate) {
			directories[candidate] = struct{}{}
		}
	}
	var mains []string
	for directory := range directories {
		parts := strings.Split(directory, "/")
		if len(parts) == 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			mains = append(mains, directory)
		}
	}
	if len(mains) != 1 {
		return signingResignArchive{}, fmt.Errorf("IPA must contain exactly one Payload/*.app")
	}
	mainPath := mains[0]
	accepted := map[string]string{mainPath: "application"}
	for directory := range directories {
		if directory == mainPath+"/PlugIns" || directory == mainPath+"/Watch" || directory == mainPath+"/AppClips" {
			continue
		}
		if strings.HasPrefix(directory, mainPath+"/PlugIns/") && strings.Count(strings.TrimPrefix(directory, mainPath+"/PlugIns/"), "/") == 0 && strings.HasSuffix(directory, ".appex") {
			accepted[directory] = "app-extension"
		}
		if strings.HasPrefix(directory, mainPath+"/Watch/") && strings.Count(strings.TrimPrefix(directory, mainPath+"/Watch/"), "/") == 0 && strings.HasSuffix(directory, ".app") {
			accepted[directory] = "watch-application"
		}
		if strings.HasPrefix(directory, mainPath+"/Watch/") && strings.Contains(directory, "/PlugIns/") && strings.HasSuffix(directory, ".appex") {
			relative := strings.TrimPrefix(directory, mainPath+"/Watch/")
			parts := strings.Split(relative, "/")
			if len(parts) == 3 && strings.HasSuffix(parts[0], ".app") && parts[1] == "PlugIns" {
				accepted[directory] = "watch-extension"
			}
		}
		if strings.HasPrefix(directory, mainPath+"/AppClips/") && strings.Count(strings.TrimPrefix(directory, mainPath+"/AppClips/"), "/") == 0 && strings.HasSuffix(directory, ".app") {
			accepted[directory] = "app-clip"
		}
	}
	for directory := range directories {
		if (strings.HasSuffix(directory, ".app") || strings.HasSuffix(directory, ".appex")) && accepted[directory] == "" {
			return signingResignArchive{}, fmt.Errorf("IPA contains an unsupported nested app target")
		}
	}
	if len(accepted) > signingResignMaxTargetCount {
		return signingResignArchive{}, fmt.Errorf("IPA contains too many app-like targets")
	}
	targetPaths := make([]string, 0, len(accepted))
	for targetPath := range accepted {
		targetPaths = append(targetPaths, targetPath)
	}
	sort.Slice(targetPaths, func(i, j int) bool {
		if targetPaths[i] == mainPath {
			return false
		}
		if targetPaths[j] == mainPath {
			return true
		}
		depthI, depthJ := strings.Count(targetPaths[i], "/"), strings.Count(targetPaths[j], "/")
		if depthI != depthJ {
			return depthI > depthJ
		}
		return targetPaths[i] < targetPaths[j]
	})
	archive := signingResignArchive{MainPath: mainPath}
	for _, targetPath := range targetPaths {
		target, err := inspectSigningResignTarget(ctx, tree, targetPath, accepted[targetPath])
		if err != nil {
			return signingResignArchive{}, fmt.Errorf("inspect target %s: %w", targetPath, err)
		}
		archive.Targets = append(archive.Targets, target)
	}
	return archive, nil
}

func inspectSigningResignTarget(ctx context.Context, tree rootfs.Root, relativePath, kind string) (signingResignTarget, error) {
	if err := contextError(ctx); err != nil {
		return signingResignTarget{}, err
	}
	infoPath := filepath.FromSlash(path.Join(relativePath, "Info.plist"))
	data, err := tree.ReadFileLimited(infoPath, infoplist.MaxBytes)
	if err != nil {
		return signingResignTarget{}, fmt.Errorf("read Info.plist: %w", err)
	}
	if err := infoplist.ValidateStructure(data); err != nil {
		return signingResignTarget{}, fmt.Errorf("invalid Info.plist: %w", err)
	}
	var info map[string]any
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return signingResignTarget{}, fmt.Errorf("decode Info.plist")
	}
	bundleID := plistString(info["CFBundleIdentifier"])
	if err := validateSigningResignBundleID(bundleID); err != nil {
		return signingResignTarget{}, err
	}
	executable := plistString(info["CFBundleExecutable"])
	if err := validateSigningResignExecutable(executable); err != nil {
		return signingResignTarget{}, err
	}
	if err := validateSigningResignPlatform(info); err != nil {
		return signingResignTarget{}, err
	}
	executablePath := filepath.FromSlash(path.Join(relativePath, executable))
	file, err := tree.OpenFile(executablePath)
	if err != nil {
		return signingResignTarget{}, fmt.Errorf("open executable: %w", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return signingResignTarget{}, fmt.Errorf("executable is not a regular file")
	}
	if !isSigningResignMachOFile(file, stat.Size()) {
		return signingResignTarget{}, fmt.Errorf("executable is not a loadable Mach-O")
	}
	entitlements, err := readSigningResignEntitlements(ctx, filepath.Join(tree.Path(), executablePath))
	if err != nil {
		return signingResignTarget{}, fmt.Errorf("read signed entitlements: %w", err)
	}
	return signingResignTarget{Kind: kind, RelativePath: relativePath, BundleID: bundleID, Executable: executable, ExistingEntitlements: entitlements}, nil
}

func validateSigningResignExecutable(value string) error {
	if value == "" || len(value) > 255 || filepath.Base(value) != value || value == "." || value == ".." || strings.ContainsAny(value, `/\\`) {
		return fmt.Errorf("CFBundleExecutable is not a safe filename")
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || unicode.In(character, unicode.Bidi_Control) {
			return fmt.Errorf("CFBundleExecutable contains unsupported characters")
		}
	}
	return nil
}

func validateSigningResignPlatform(info map[string]any) error {
	platformName := strings.ToLower(strings.TrimSpace(plistString(info["DTPlatformName"])))
	platforms := plistStrings(info["CFBundleSupportedPlatforms"])
	if platformName == "" && len(platforms) == 0 {
		return fmt.Errorf("target platform metadata is missing")
	}
	if platformName != "" && platformName != "iphoneos" {
		return fmt.Errorf("target platform is not iOS")
	}
	for _, platform := range platforms {
		if !strings.EqualFold(strings.TrimSpace(platform), "iPhoneOS") {
			return fmt.Errorf("target platform is not iOS")
		}
	}
	return nil
}

func enumerateSigningResignMachOFiles(ctx context.Context, rootPath string) ([]string, error) {
	var result []string
	err := filepath.WalkDir(rootPath, func(candidate string, entry os.DirEntry, walkErr error) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("staging tree contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("staging tree contains a non-regular file")
		}
		file, err := os.Open(candidate)
		if err != nil {
			return err
		}
		isMachO := isSigningResignMachOFile(file, info.Size())
		closeErr := file.Close()
		if closeErr != nil {
			return closeErr
		}
		if isMachO {
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

func isSigningResignMachOFile(file *os.File, fileSize int64) bool {
	if file == nil || fileSize < 4 {
		return false
	}
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return false
	}
	switch magic {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe}, [4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}:
		image, err := macho.NewFile(io.NewSectionReader(file, 0, fileSize))
		return err == nil && isSigningResignLoadableMachO(image)
	case [4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca}:
		var order binary.ByteOrder = binary.BigEndian
		if magic == [4]byte{0xbe, 0xba, 0xfe, 0xca} {
			order = binary.LittleEndian
		}
		return classifySigningResignFatMachO(file, fileSize, order, 20)
	case [4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
		var order binary.ByteOrder = binary.BigEndian
		if magic == [4]byte{0xbf, 0xba, 0xfe, 0xca} {
			order = binary.LittleEndian
		}
		return classifySigningResignFatMachO(file, fileSize, order, 32)
	default:
		return false
	}
}

func isSigningResignLoadableMachO(file *macho.File) bool {
	return file != nil && (file.Type == macho.TypeExec || file.Type == macho.TypeDylib || file.Type == macho.TypeBundle)
}

func classifySigningResignFatMachO(file *os.File, fileSize int64, order binary.ByteOrder, headerSize int64) bool {
	var countBytes [4]byte
	if _, err := file.ReadAt(countBytes[:], 4); err != nil {
		return false
	}
	count := order.Uint32(countBytes[:])
	tableEnd := int64(8) + int64(count)*headerSize
	if count == 0 || count > 64 || tableEnd > fileSize {
		return false
	}
	hasLoadable := false
	for index := uint32(0); index < count; index++ {
		header := make([]byte, headerSize)
		if _, err := file.ReadAt(header, int64(8)+int64(index)*headerSize); err != nil {
			return false
		}
		var offset, size uint64
		if headerSize == 20 {
			offset, size = uint64(order.Uint32(header[8:12])), uint64(order.Uint32(header[12:16]))
		} else {
			offset, size = order.Uint64(header[8:16]), order.Uint64(header[16:24])
		}
		if offset < uint64(tableEnd) || size == 0 || offset > uint64(fileSize) || size > uint64(fileSize)-offset {
			return false
		}
		image, err := macho.NewFile(io.NewSectionReader(file, int64(offset), int64(size)))
		if err != nil || !isSigningResignLoadableMachO(image) {
			return false
		}
		if uint32(image.Cpu) != order.Uint32(header[:4]) {
			return false
		}
		hasLoadable = true
	}
	return hasLoadable
}

func buildSigningResignTargetIDs(targets []signingResignTarget) map[string]struct{} {
	result := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		result[target.BundleID] = struct{}{}
	}
	return result
}

func validateSigningResignTargetIDs(targets []signingResignTarget) error {
	seen := make(map[string]string, len(targets))
	for _, target := range targets {
		if previous, exists := seen[target.BundleID]; exists {
			return fmt.Errorf("duplicate bundle identifier in %s and %s", previous, target.RelativePath)
		}
		seen[target.BundleID] = target.RelativePath
	}
	return nil
}

func targetExecutablePath(treeRoot string, target signingResignTarget) string {
	return filepath.Join(treeRoot, filepath.FromSlash(path.Join(target.RelativePath, target.Executable)))
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
