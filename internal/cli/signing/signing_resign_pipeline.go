package signing

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
)

type signingResignCodePlan struct {
	Path             string
	EntitlementsPath string
}

type signingResignPreparedTree struct {
	Archive   signingResignArchive
	CodePlans []signingResignCodePlan
}

func executeSigningResignImplementation(ctx context.Context, options signingResignOptions) (result signingResignResult, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return result, err
	}
	if runtime.GOOS != "darwin" {
		return result, fmt.Errorf("signing resign is supported only on macOS")
	}
	ctx, stopSignals := platformSigningRunContext(ctx)
	defer stopSignals()
	if err := validateSigningResignOptions(options); err != nil {
		return result, err
	}

	inputPath, err := filepath.Abs(filepath.Clean(options.IPAPath))
	if err != nil {
		return result, fmt.Errorf("resolve IPA input: %w", err)
	}
	outputPath, err := filepath.Abs(filepath.Clean(options.OutputPath))
	if err != nil {
		return result, fmt.Errorf("resolve IPA output: %w", err)
	}
	manifestPath, err := filepath.Abs(filepath.Clean(options.ProfilesManifestPath))
	if err != nil {
		return result, fmt.Errorf("resolve profiles manifest: %w", err)
	}
	if filepath.Clean(inputPath) == filepath.Clean(outputPath) {
		return result, fmt.Errorf("IPA input and output must be different paths")
	}

	inputRoot, err := rootfs.New(filepath.Dir(inputPath))
	if err != nil {
		return result, fmt.Errorf("open IPA input directory: %w", err)
	}
	defer inputRoot.Close()
	source, err := inputRoot.OpenFile(filepath.Base(inputPath))
	if err != nil {
		return result, fmt.Errorf("open IPA input: %w", err)
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return result, fmt.Errorf("inspect IPA input: %w", err)
	}

	outputRoot, err := rootfs.New(filepath.Dir(outputPath))
	if err != nil {
		return result, fmt.Errorf("open IPA output directory: %w", err)
	}
	defer outputRoot.Close()
	if err := outputRoot.MkdirAll(".", 0o755); err != nil {
		return result, fmt.Errorf("create IPA output directory: %w", err)
	}
	if err := outputRoot.CheckCreateNewFile(filepath.Base(outputPath)); err != nil {
		return result, fmt.Errorf("preflight IPA output: %w", err)
	}
	if sourceInfo.Mode()&os.ModeSymlink != 0 {
		return result, fmt.Errorf("IPA input is a symbolic link")
	}

	stageDir, err := os.MkdirTemp("", "asc-signing-resign.")
	if err != nil {
		return result, fmt.Errorf("create private re-signing directory: %w", err)
	}
	if err := os.Chmod(stageDir, 0o700); err != nil {
		_ = removeSigningResignStage(stageDir)
		return result, fmt.Errorf("secure private re-signing directory: %w", err)
	}
	defer func() {
		if cleanupErr := removeSigningResignStage(stageDir); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove private re-signing directory: %w", cleanupErr))
		}
	}()

	stageRoot, err := rootfs.New(stageDir)
	if err != nil {
		return result, fmt.Errorf("open private re-signing directory: %w", err)
	}
	defer stageRoot.Close()
	stageOS, err := stageRoot.OpenRoot()
	if err != nil {
		return result, fmt.Errorf("open private re-signing root: %w", err)
	}
	defer stageOS.Close()
	if err := stageRoot.MkdirAll("tree", 0o700); err != nil {
		return result, fmt.Errorf("create private IPA staging tree: %w", err)
	}
	treeRoot, err := rootfs.New(filepath.Join(stageDir, "tree"))
	if err != nil {
		return result, fmt.Errorf("open private IPA staging tree: %w", err)
	}
	defer treeRoot.Close()
	treeOS, err := stageOS.OpenRoot("tree")
	if err != nil {
		return result, fmt.Errorf("open private IPA staging tree root: %w", err)
	}
	defer treeOS.Close()

	snapshot, inputDigest, err := snapshotSigningResignIPA(ctx, source, sourceInfo.Size(), stageOS)
	if err != nil {
		return result, err
	}
	defer snapshot.Close()
	snapshotInfo, err := snapshot.Stat()
	if err != nil {
		return result, fmt.Errorf("inspect IPA snapshot: %w", err)
	}
	archiveReader, err := zip.NewReader(snapshot, snapshotInfo.Size())
	if err != nil {
		return result, fmt.Errorf("read IPA archive: %w", err)
	}
	if err := validateSigningResignArchive(ctx, archiveReader); err != nil {
		return result, err
	}
	if err := materializeSigningResignArchive(ctx, archiveReader, treeOS); err != nil {
		return result, fmt.Errorf("materialize IPA: %w", err)
	}
	archive, err := discoverSigningResignArchive(ctx, archiveReader, treeRoot)
	if err != nil {
		return result, err
	}
	if err := validateSigningResignTargetIDs(archive.Targets); err != nil {
		return result, err
	}

	manifest, err := readSigningResignManifest(manifestPath)
	if err != nil {
		return result, err
	}
	targetIDs := buildSigningResignTargetIDs(archive.Targets)
	if err := validateSigningResignManifestTargets(manifest, targetIDs); err != nil {
		return result, err
	}
	profiles, err := readSigningResignProfiles(manifestPath, manifest)
	if err != nil {
		return result, err
	}
	for _, profile := range profiles {
		defer clear(profile.Data)
	}
	identityData, err := readBoundedSigningRunFile(options.IdentityPath, signingRunInputLimit, true)
	if err != nil {
		return result, fmt.Errorf("read signing identity failed")
	}
	defer clear(identityData)
	var passwordData []byte
	if options.IdentityPasswordPath != "" {
		passwordData, err = readBoundedSigningRunFile(options.IdentityPasswordPath, signingRunPasswordLimit, true)
		if err != nil {
			return result, fmt.Errorf("read signing identity password failed")
		}
		defer clear(passwordData)
	}
	identityPassword := bytes.TrimSuffix(passwordData, []byte("\n"))
	identityPassword = bytes.TrimSuffix(identityPassword, []byte("\r"))
	identity, err := inspectSigningRunIdentity(identityData, identityPassword, signingRunNowFn())
	if err != nil {
		return result, fmt.Errorf("inspect signing identity: %w", err)
	}
	if err := validateSigningResignProfileSet(profiles, identity); err != nil {
		return result, err
	}
	prepared, err := prepareSigningResignTree(ctx, stageRoot, treeRoot, archive, profiles)
	if err != nil {
		return result, err
	}

	teamID, err := signingRunCertificateTeamID(identity.Certificate)
	if err != nil {
		return result, err
	}
	result = signingResignResult{
		SchemaVersion: 1,
		Command:       "signing resign",
		Input: signingResignArtifactResult{
			Path:      inputPath,
			SizeBytes: sourceInfo.Size(),
			SHA256:    strings.ToUpper(inputDigest),
		},
		Identity: signingResignIdentityResult{
			CertificateSHA256: identity.CertificateSHA256,
			TeamID:            teamID,
		},
		Verification: signingResignVerification{
			Status: "pending",
			Scope:  "complete-main-app-code-resources-entitlements-profile-and-certificate-binding",
		},
	}
	result.Targets = make([]signingResignTargetResult, 0, len(prepared.Archive.Targets))
	for _, target := range prepared.Archive.Targets {
		profile := profiles[target.BundleID]
		result.Targets = append(result.Targets, signingResignTargetResult{
			Kind: target.Kind, RelativePath: target.RelativePath, BundleID: target.BundleID,
			ProfileClass: profile.Class, ProfileUUID: profile.UUID, ProfileSHA256: profile.SHA256,
			Status: "pending",
		})
	}

	var outputArtifact signingResignArtifactResult
	if err := runSigningResignEnvironment(ctx, identity, func(signingContext context.Context, keychainPath string) error {
		if err := signSigningResignTree(signingContext, treeRoot.Path(), prepared, identity.CertificateSHA1, keychainPath); err != nil {
			return err
		}
		if err := verifySigningResignTree(signingContext, treeRoot.Path(), prepared, teamID, identity.CertificateSHA256); err != nil {
			return err
		}
		packedPath, packedSize, packedDigest, err := repackSigningResignTree(signingContext, stageRoot, treeRoot)
		if err != nil {
			return err
		}
		if err := validatePackedSigningResignIPA(signingContext, packedPath, packedSize); err != nil {
			return err
		}
		if err := verifyPackedSigningResignIPA(signingContext, packedPath, packedSize, stageRoot, prepared, teamID, identity.CertificateSHA256); err != nil {
			return err
		}
		outputArtifact, err = publishSigningResignOutput(outputRoot, filepath.Base(outputPath), packedPath, packedSize, packedDigest)
		return err
	}); err != nil {
		return result, err
	}
	result.Output = outputArtifact
	result.Verification.Status = "verified"
	for index := range result.Targets {
		result.Targets[index].Status = "verified"
	}
	return result, nil
}

func validateSigningResignOptions(options signingResignOptions) error {
	values := map[string]string{
		"IPA input":         options.IPAPath,
		"IPA output":        options.OutputPath,
		"signing identity":  options.IdentityPath,
		"profiles manifest": options.ProfilesManifestPath,
	}
	for label, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("%s contains a NUL byte", label)
		}
	}
	if strings.ContainsRune(options.IdentityPasswordPath, 0) {
		return fmt.Errorf("identity password path contains a NUL byte")
	}
	return nil
}

func prepareSigningResignTree(ctx context.Context, stageRoot, treeRoot rootfs.Root, archive signingResignArchive, profiles map[string]signingResignProfile) (signingResignPreparedTree, error) {
	if err := contextError(ctx); err != nil {
		return signingResignPreparedTree{}, err
	}
	if err := stageRoot.MkdirAll("entitlements", 0o700); err != nil {
		return signingResignPreparedTree{}, fmt.Errorf("create private entitlements directory failed")
	}
	prepared := signingResignPreparedTree{Archive: archive}
	for index := range prepared.Archive.Targets {
		target := &prepared.Archive.Targets[index]
		profile, ok := profiles[target.BundleID]
		if !ok {
			return signingResignPreparedTree{}, fmt.Errorf("missing profile for target %s", target.BundleID)
		}
		entitlements, err := buildSigningResignEntitlements(target.ExistingEntitlements, profile.Entitlements)
		if err != nil {
			return signingResignPreparedTree{}, fmt.Errorf("target %s entitlements: %w", target.BundleID, err)
		}
		entitlementsData, err := marshalSigningResignEntitlements(entitlements)
		if err != nil {
			return signingResignPreparedTree{}, fmt.Errorf("target %s entitlements: %w", target.BundleID, err)
		}
		entitlementsName := filepath.Join("entitlements", fmt.Sprintf("target-%03d.plist", index))
		if err := stageRoot.WriteFile(entitlementsName, entitlementsData, 0o600); err != nil {
			return signingResignPreparedTree{}, fmt.Errorf("write target %s entitlements failed", target.BundleID)
		}
		profileName := filepath.FromSlash(path.Join(target.RelativePath, "embedded.mobileprovision"))
		if err := treeRoot.WriteFile(profileName, profile.Data, 0o600); err != nil {
			return signingResignPreparedTree{}, fmt.Errorf("embed profile for target %s failed", target.BundleID)
		}
		target.Profile = profile
		target.EntitlementsPath = filepath.Join(stageRoot.Path(), entitlementsName)
	}

	codePaths, err := enumerateSigningResignMachOFiles(ctx, treeRoot.Path())
	if err != nil {
		return signingResignPreparedTree{}, fmt.Errorf("enumerate Mach-O code failed")
	}
	mainPrefix := filepath.Join(treeRoot.Path(), filepath.FromSlash(prepared.Archive.MainPath)) + string(filepath.Separator)
	targetExecutablePaths := make(map[string]struct{}, len(prepared.Archive.Targets))
	for _, target := range prepared.Archive.Targets {
		targetExecutablePaths[targetExecutablePath(treeRoot.Path(), target)] = struct{}{}
	}
	for index, codePath := range codePaths {
		if err := contextError(ctx); err != nil {
			return signingResignPreparedTree{}, err
		}
		if !strings.HasPrefix(codePath, mainPrefix) {
			return signingResignPreparedTree{}, fmt.Errorf("Mach-O code exists outside the main app")
		}
		if _, isTargetExecutable := targetExecutablePaths[filepath.Clean(codePath)]; isTargetExecutable {
			continue
		}
		target, ok := signingResignTargetForCodePath(prepared.Archive.Targets, treeRoot.Path(), codePath)
		if !ok {
			return signingResignPreparedTree{}, fmt.Errorf("Mach-O code is not contained by an app-like target")
		}
		entitlements, err := readSigningResignEntitlements(ctx, codePath)
		if err != nil {
			return signingResignPreparedTree{}, fmt.Errorf("read nested code entitlements failed")
		}
		if err := validateSigningResignNestedEntitlements(entitlements, profiles[target.BundleID].Entitlements); err != nil {
			displayPath, _ := filepath.Rel(treeRoot.Path(), codePath)
			return signingResignPreparedTree{}, fmt.Errorf("nested code %s entitlements: %w", filepath.ToSlash(displayPath), err)
		}
		var entitlementsPath string
		if len(entitlements) > 0 {
			data, err := marshalSigningResignEntitlements(entitlements)
			if err != nil {
				return signingResignPreparedTree{}, err
			}
			name := filepath.Join("entitlements", fmt.Sprintf("code-%06d.plist", index))
			if err := stageRoot.WriteFile(name, data, 0o600); err != nil {
				return signingResignPreparedTree{}, fmt.Errorf("write nested code entitlements failed")
			}
			entitlementsPath = filepath.Join(stageRoot.Path(), name)
		}
		prepared.CodePlans = append(prepared.CodePlans, signingResignCodePlan{Path: codePath, EntitlementsPath: entitlementsPath})
	}
	return prepared, nil
}

func signingResignTargetForCodePath(targets []signingResignTarget, treeRoot, codePath string) (signingResignTarget, bool) {
	var selected signingResignTarget
	selectedLength := -1
	for _, target := range targets {
		prefix := filepath.Join(treeRoot, filepath.FromSlash(target.RelativePath)) + string(filepath.Separator)
		if strings.HasPrefix(codePath, prefix) && len(prefix) > selectedLength {
			selected = target
			selectedLength = len(prefix)
		}
	}
	return selected, selectedLength >= 0
}

func validateSigningResignNestedEntitlements(entitlements, profile map[string]any) error {
	for key, value := range entitlements {
		if _, identityKey := signingResignIdentityEntitlementKeys[key]; identityKey {
			return fmt.Errorf("identity entitlement %s is not allowed on nested non-app code", key)
		}
		profileValue, exists := profile[key]
		if !exists || !signingResignEntitlementValuePermits(profileValue, value) {
			return fmt.Errorf("entitlement %s is not permitted by its target profile", key)
		}
	}
	return nil
}

func signSigningResignTree(ctx context.Context, treePath string, prepared signingResignPreparedTree, identitySHA1, keychainPath string) error {
	plans := append([]signingResignCodePlan(nil), prepared.CodePlans...)
	sortSigningResignCodePlans(plans)
	targetExecutablePaths := make(map[string]struct{}, len(prepared.Archive.Targets))
	for _, target := range prepared.Archive.Targets {
		targetExecutablePaths[targetExecutablePath(treePath, target)] = struct{}{}
	}
	for _, plan := range plans {
		if _, targetExecutable := targetExecutablePaths[filepath.Clean(plan.Path)]; targetExecutable {
			continue
		}
		if err := signSigningResignObject(ctx, plan.Path, identitySHA1, keychainPath, plan.EntitlementsPath); err != nil {
			return fmt.Errorf("sign nested code %s: %w", signingResignDisplayPath(treePath, plan.Path), err)
		}
	}
	containers := signingResignFrameworkContainers(treePath, plans)
	for _, container := range containers {
		if err := signSigningResignObject(ctx, container, identitySHA1, keychainPath, ""); err != nil {
			return fmt.Errorf("sign framework %s: %w", signingResignDisplayPath(treePath, container), err)
		}
	}
	for _, target := range prepared.Archive.Targets {
		targetPath := filepath.Join(treePath, filepath.FromSlash(target.RelativePath))
		if err := signSigningResignObject(ctx, targetPath, identitySHA1, keychainPath, target.EntitlementsPath); err != nil {
			return fmt.Errorf("sign target %s: %w", target.BundleID, err)
		}
	}
	return nil
}

func sortSigningResignCodePlans(plans []signingResignCodePlan) {
	sort.Slice(plans, func(left, right int) bool {
		leftDepth := strings.Count(plans[left].Path, string(filepath.Separator))
		rightDepth := strings.Count(plans[right].Path, string(filepath.Separator))
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return plans[left].Path < plans[right].Path
	})
}

func signingResignFrameworkContainers(treePath string, plans []signingResignCodePlan) []string {
	seen := make(map[string]struct{})
	for _, plan := range plans {
		candidate := filepath.Dir(plan.Path)
		for candidate != treePath && strings.HasPrefix(candidate, treePath+string(filepath.Separator)) {
			if strings.HasSuffix(filepath.Base(candidate), ".framework") {
				seen[candidate] = struct{}{}
			}
			candidate = filepath.Dir(candidate)
		}
	}
	containers := make([]string, 0, len(seen))
	for candidate := range seen {
		containers = append(containers, candidate)
	}
	sort.Slice(containers, func(left, right int) bool {
		leftDepth := strings.Count(strings.TrimPrefix(containers[left], treePath), string(filepath.Separator))
		rightDepth := strings.Count(strings.TrimPrefix(containers[right], treePath), string(filepath.Separator))
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return containers[left] < containers[right]
	})
	return containers
}

func verifySigningResignTree(ctx context.Context, treePath string, prepared signingResignPreparedTree, teamID, certificateSHA256 string) error {
	plans := append([]signingResignCodePlan(nil), prepared.CodePlans...)
	for _, plan := range plans {
		if err := verifySigningResignObject(ctx, plan.Path, teamID, false); err != nil {
			return fmt.Errorf("verify nested code %s: %w", signingResignDisplayPath(treePath, plan.Path), err)
		}
		if err := verifySigningResignCertificate(ctx, plan.Path, certificateSHA256); err != nil {
			return fmt.Errorf("verify nested code certificate: %w", err)
		}
	}
	for _, target := range prepared.Archive.Targets {
		targetPath := filepath.Join(treePath, filepath.FromSlash(target.RelativePath))
		if err := verifySigningResignObject(ctx, targetPath, teamID, false); err != nil {
			return fmt.Errorf("verify target %s: %w", target.BundleID, err)
		}
		if err := verifySigningResignCertificate(ctx, targetPath, certificateSHA256); err != nil {
			return fmt.Errorf("verify target %s certificate: %w", target.BundleID, err)
		}
		entitlements, err := readSigningResignEntitlements(ctx, targetExecutablePath(treePath, target))
		if err != nil {
			return fmt.Errorf("read verified target %s entitlements: %w", target.BundleID, err)
		}
		if err := validateSigningResignVerifiedEntitlements(entitlements, target.ExistingEntitlements, target.Profile.Entitlements, target.BundleID); err != nil {
			return err
		}
		profileData, err := readRootedSigningResignFile(treePath, filepath.FromSlash(path.Join(target.RelativePath, "embedded.mobileprovision")), signingResignProfileMaxBytes)
		if err != nil {
			return fmt.Errorf("read verified target %s profile failed", target.BundleID)
		}
		if digest := signingResignSHA256(profileData); !strings.EqualFold(digest, target.Profile.SHA256) {
			return fmt.Errorf("verified target %s profile digest changed", target.BundleID)
		}
	}
	mainPath := filepath.Join(treePath, filepath.FromSlash(prepared.Archive.MainPath))
	if err := verifySigningResignObject(ctx, mainPath, teamID, true); err != nil {
		return fmt.Errorf("verify complete main app: %w", err)
	}
	return nil
}

func signingResignDisplayPath(rootPath, candidate string) string {
	relative, err := filepath.Rel(rootPath, candidate)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "staged-code"
	}
	return filepath.ToSlash(relative)
}

func validateSigningResignVerifiedEntitlements(actual, existing, profile map[string]any, bundleID string) error {
	want, err := buildSigningResignEntitlements(existing, profile)
	if err != nil {
		return fmt.Errorf("target %s expected entitlements: %w", bundleID, err)
	}
	if len(actual) != len(want) {
		return fmt.Errorf("target %s signed entitlements contain unexpected keys", bundleID)
	}
	for key, expected := range want {
		value, exists := actual[key]
		if !exists || !signingResignEntitlementValuePermits(expected, value) {
			return fmt.Errorf("target %s signed entitlement %s is not the expected value", bundleID, key)
		}
	}
	return nil
}

func readRootedSigningResignFile(rootPath, relativePath string, limit int64) ([]byte, error) {
	root, err := rootfs.New(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFileLimited(relativePath, limit)
}

func signingResignSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

func removeSigningResignStage(stagePath string) error {
	clean := filepath.Clean(stagePath)
	if filepath.Dir(clean) != filepath.Clean(os.TempDir()) || !strings.HasPrefix(filepath.Base(clean), "asc-signing-resign.") {
		return fmt.Errorf("refusing to remove unexpected re-signing directory %q", stagePath)
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing to remove unsafe re-signing directory")
	}
	return os.RemoveAll(clean)
}

func repackSigningResignTree(ctx context.Context, stageRoot, treeRoot rootfs.Root) (string, int64, string, error) {
	if err := contextError(ctx); err != nil {
		return "", 0, "", err
	}
	files := make([]string, 0)
	err := filepath.WalkDir(treeRoot.Path(), func(candidate string, entry os.DirEntry, walkErr error) error {
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
		relative, err := filepath.Rel(treeRoot.Path(), candidate)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("staging tree contains an invalid relative path")
		}
		files = append(files, relative)
		return nil
	})
	if err != nil {
		return "", 0, "", err
	}
	if len(files) == 0 {
		return "", 0, "", fmt.Errorf("staging tree is empty")
	}
	sort.Strings(files)
	stageOS, err := stageRoot.OpenRoot()
	if err != nil {
		return "", 0, "", err
	}
	defer stageOS.Close()
	packed, err := secureopen.OpenNewFileNoFollowInRoot(stageOS, "resigned.ipa", 0o600)
	if err != nil {
		return "", 0, "", fmt.Errorf("create re-signed IPA: %w", err)
	}
	zipWriter := zip.NewWriter(packed)
	var operationErr error
	for _, relative := range files {
		if err := contextError(ctx); err != nil {
			operationErr = err
			break
		}
		file, err := treeRoot.OpenFile(relative)
		if err != nil {
			operationErr = err
			break
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			operationErr = err
			break
		}
		header := &zip.FileHeader{Name: filepath.ToSlash(relative), Method: zip.Deflate}
		header.Modified = time.Unix(0, 0)
		header.SetMode(info.Mode().Perm())
		entry, err := zipWriter.CreateHeader(header)
		if err == nil {
			_, err = copySigningResignWithContext(ctx, entry, io.LimitReader(file, info.Size()+1), info.Size())
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			operationErr = err
			break
		}
	}
	if operationErr == nil {
		operationErr = zipWriter.Close()
	} else {
		_ = zipWriter.Close()
	}
	if operationErr == nil {
		operationErr = packed.Sync()
	}
	closeErr := packed.Close()
	if operationErr != nil || closeErr != nil {
		_ = os.Remove(filepath.Join(stageRoot.Path(), "resigned.ipa"))
		return "", 0, "", errors.Join(operationErr, closeErr)
	}
	packedPath := filepath.Join(stageRoot.Path(), "resigned.ipa")
	info, err := os.Stat(packedPath)
	if err != nil {
		return "", 0, "", err
	}
	digest, err := hashSigningResignFile(packedPath, info.Size())
	if err != nil {
		return "", 0, "", err
	}
	return packedPath, info.Size(), digest, nil
}

func validatePackedSigningResignIPA(ctx context.Context, packedPath string, size int64) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	file, err := os.Open(packedPath)
	if err != nil {
		return fmt.Errorf("open re-signed IPA: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("re-signed IPA changed before publication")
	}
	reader, err := zip.NewReader(file, size)
	if err != nil {
		return fmt.Errorf("read re-signed IPA: %w", err)
	}
	return validateSigningResignArchive(ctx, reader)
}

func verifyPackedSigningResignIPA(ctx context.Context, packedPath string, size int64, stageRoot rootfs.Root, original signingResignPreparedTree, teamID, certificateSHA256 string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	file, err := os.Open(packedPath)
	if err != nil {
		return fmt.Errorf("open re-signed IPA for final verification: %w", err)
	}
	defer file.Close()
	reader, err := zip.NewReader(file, size)
	if err != nil {
		return fmt.Errorf("read re-signed IPA for final verification: %w", err)
	}
	if err := validateSigningResignArchive(ctx, reader); err != nil {
		return err
	}
	if err := stageRoot.MkdirAll("packed-tree", 0o700); err != nil {
		return fmt.Errorf("create final verification tree: %w", err)
	}
	stageOS, err := stageRoot.OpenRoot()
	if err != nil {
		return fmt.Errorf("open final verification root: %w", err)
	}
	defer stageOS.Close()
	packedTreeOS, err := stageOS.OpenRoot("packed-tree")
	if err != nil {
		return fmt.Errorf("open final verification tree: %w", err)
	}
	defer packedTreeOS.Close()
	if err := materializeSigningResignArchive(ctx, reader, packedTreeOS); err != nil {
		return fmt.Errorf("materialize final verification tree: %w", err)
	}
	packedTreeRoot, err := rootfs.New(filepath.Join(stageRoot.Path(), "packed-tree"))
	if err != nil {
		return fmt.Errorf("open final verification tree: %w", err)
	}
	defer packedTreeRoot.Close()
	archive, err := discoverSigningResignArchive(ctx, reader, packedTreeRoot)
	if err != nil {
		return fmt.Errorf("inspect final verification targets: %w", err)
	}
	if archive.MainPath != original.Archive.MainPath || len(archive.Targets) != len(original.Archive.Targets) {
		return fmt.Errorf("re-signed IPA target inventory changed during repack")
	}
	profiles := make(map[string]signingResignProfile, len(original.Archive.Targets))
	for index, target := range archive.Targets {
		want := original.Archive.Targets[index]
		if target.Kind != want.Kind || target.RelativePath != want.RelativePath || target.BundleID != want.BundleID {
			return fmt.Errorf("re-signed IPA target inventory changed during repack")
		}
		profileData, err := readRootedSigningResignFile(packedTreeRoot.Path(), filepath.FromSlash(path.Join(target.RelativePath, "embedded.mobileprovision")), signingResignProfileMaxBytes)
		if err != nil || !strings.EqualFold(signingResignSHA256(profileData), want.Profile.SHA256) {
			return fmt.Errorf("re-signed IPA target profile changed during repack")
		}
		profiles[want.BundleID] = want.Profile
	}
	finalPrepared, err := prepareSigningResignTree(ctx, stageRoot, packedTreeRoot, archive, profiles)
	if err != nil {
		return fmt.Errorf("prepare final verification targets: %w", err)
	}
	if err := verifySigningResignTree(ctx, packedTreeRoot.Path(), finalPrepared, teamID, certificateSHA256); err != nil {
		return fmt.Errorf("verify re-signed IPA after repack: %w", err)
	}
	return nil
}

func publishSigningResignOutput(outputRoot rootfs.Root, name, packedPath string, packedSize int64, packedDigest string) (signingResignArtifactResult, error) {
	file, err := os.Open(packedPath)
	if err != nil {
		return signingResignArtifactResult{}, fmt.Errorf("open staged re-signed IPA: %w", err)
	}
	defer file.Close()
	written, err := outputRoot.CreateNewFrom(name, file, 0o600)
	if err != nil {
		return signingResignArtifactResult{}, fmt.Errorf("publish re-signed IPA: %w", err)
	}
	if written != packedSize {
		return signingResignArtifactResult{}, fmt.Errorf("published re-signed IPA size is inconsistent")
	}
	published, err := outputRoot.OpenFile(name)
	if err != nil {
		return signingResignArtifactResult{}, fmt.Errorf("reopen published re-signed IPA: %w", err)
	}
	defer published.Close()
	info, err := published.Stat()
	if err != nil {
		return signingResignArtifactResult{}, err
	}
	digest, err := hashSigningResignOpenFile(published, info.Size())
	if err != nil {
		return signingResignArtifactResult{}, err
	}
	if !strings.EqualFold(digest, packedDigest) {
		return signingResignArtifactResult{}, fmt.Errorf("published re-signed IPA digest is inconsistent")
	}
	return signingResignArtifactResult{Path: filepath.Join(outputRoot.Path(), name), SizeBytes: info.Size(), SHA256: digest}, nil
}

func hashSigningResignFile(pathValue string, size int64) (string, error) {
	file, err := os.Open(pathValue)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashSigningResignOpenFile(file, size)
}

func hashSigningResignOpenFile(file *os.File, size int64) (string, error) {
	if file == nil || size < 0 {
		return "", fmt.Errorf("hash input is invalid")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	written, err := copySigningResignWithContext(context.Background(), hash, io.LimitReader(file, size+1), size)
	if err != nil {
		return "", err
	}
	if written != size {
		return "", fmt.Errorf("hash input size changed")
	}
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil))), nil
}
