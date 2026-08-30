package signing

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

type signingPullProfile struct {
	file        decryptedSigningFile
	certificate []string
}

func selectSigningPullFiles(files []decryptedSigningFile, bundleIDs []string, profileType string) ([]decryptedSigningFile, []SyncTargetResult, error) {
	requested := uniqueSortedSigningSyncStrings(bundleIDs)
	if len(requested) == 0 {
		return nil, nil, fmt.Errorf("signing pull selection contains no bundle IDs")
	}
	profileType = strings.ToUpper(strings.TrimSpace(profileType))
	if profileType == "" {
		return nil, nil, fmt.Errorf("signing pull selection has no profile type")
	}

	filesByPath := make(map[string]decryptedSigningFile, len(files))
	certificatesByFingerprint := make(map[string]decryptedSigningFile)
	profilesByBundle := make(map[string][]signingPullProfile)
	contextsByBundle := make(map[string][]decryptedSigningFile)
	for _, file := range files {
		path := canonicalSigningPullPath(file.RelativePath)
		filesByPath[path] = file
		switch {
		case strings.HasSuffix(strings.ToLower(path), ".cer"):
			certificate, err := x509.ParseCertificate(file.Plaintext)
			if err != nil {
				return nil, nil, fmt.Errorf("stored certificate %s is invalid", path)
			}
			fingerprint := signingCertificateSHA256(certificate)
			if prior, exists := certificatesByFingerprint[fingerprint]; exists && canonicalSigningPullPath(prior.RelativePath) != path {
				return nil, nil, fmt.Errorf("stored certificate fingerprint appears at multiple repository paths")
			}
			certificatesByFingerprint[fingerprint] = file
		case strings.HasSuffix(strings.ToLower(path), ".mobileprovision"):
			profile, err := parseIdentityMobileProvision(file.Plaintext)
			if err != nil {
				return nil, nil, fmt.Errorf("stored profile %s is invalid: %w", path, err)
			}
			bundleID, err := signingPullProfileBundleID(profile)
			if err != nil {
				return nil, nil, fmt.Errorf("stored profile %s: %w", path, err)
			}
			if !profile.ExpirationDate.After(time.Now()) || !identityProfileTypeMatches(profile, profileType) || !signingPullProfilePlatformMatches(profile, profileType) {
				continue
			}
			fingerprints := make([]string, 0, len(profile.DeveloperCertificates))
			for _, der := range profile.DeveloperCertificates {
				certificate, parseErr := x509.ParseCertificate(der)
				if parseErr != nil {
					return nil, nil, fmt.Errorf("stored profile %s contains an invalid developer certificate", path)
				}
				fingerprints = append(fingerprints, signingCertificateSHA256(certificate))
			}
			if len(fingerprints) == 0 {
				return nil, nil, fmt.Errorf("stored profile %s contains no developer certificates", path)
			}
			profilesByBundle[bundleID] = append(profilesByBundle[bundleID], signingPullProfile{
				file:        file,
				certificate: uniqueSortedSigningSyncStrings(fingerprints),
			})
		case file.Metadata.Kind == "identity-context":
			var binding identityContextBinding
			if err := json.Unmarshal(file.Plaintext, &binding); err != nil {
				return nil, nil, fmt.Errorf("decode identity context for pull selection: %w", err)
			}
			if strings.EqualFold(strings.TrimSpace(binding.ProfileType), profileType) {
				contextsByBundle[binding.BundleID] = append(contextsByBundle[binding.BundleID], file)
			}
		}
	}

	selectedByPath := make(map[string]decryptedSigningFile)
	targets := make([]SyncTargetResult, 0, len(requested))
	missing := make([]string, 0)
	for _, bundleID := range requested {
		profiles := profilesByBundle[bundleID]
		if len(profiles) == 0 {
			missing = append(missing, bundleID)
			continue
		}
		sort.Slice(profiles, func(i, j int) bool {
			return canonicalSigningPullPath(profiles[i].file.RelativePath) < canonicalSigningPullPath(profiles[j].file.RelativePath)
		})

		targetPaths := make(map[string]decryptedSigningFile)
		profilePaths := make([]string, 0, len(profiles))
		for _, profile := range profiles {
			path := canonicalSigningPullPath(profile.file.RelativePath)
			targetPaths[path] = profile.file
			profilePaths = append(profilePaths, path)
			for _, fingerprint := range profile.certificate {
				certificate, exists := certificatesByFingerprint[fingerprint]
				if !exists {
					return nil, nil, fmt.Errorf("selected profile %s has no matching stored public certificate %s", path, fingerprint)
				}
				targetPaths[canonicalSigningPullPath(certificate.RelativePath)] = certificate
			}
		}

		for _, contextFile := range contextsByBundle[bundleID] {
			var binding identityContextBinding
			if err := json.Unmarshal(contextFile.Plaintext, &binding); err != nil {
				return nil, nil, fmt.Errorf("decode selected identity context: %w", err)
			}
			profilePath := canonicalSigningPullPath(binding.ProfilePath)
			if _, selected := targetPaths[profilePath]; !selected {
				return nil, nil, fmt.Errorf("selected identity context for %s does not reference a selected profile", bundleID)
			}
			contextPath := canonicalSigningPullPath(contextFile.RelativePath)
			targetPaths[contextPath] = contextFile
			corePath := canonicalSigningPullPath(filepath.Join("identities", certDirectoryName(binding.ProfileType), binding.CertificateSHA256+".p12"))
			core, exists := filesByPath[corePath]
			if !exists || core.Metadata.Kind != "pkcs12-identity" {
				return nil, nil, fmt.Errorf("selected identity context for %s has no usable core identity", bundleID)
			}
			targetPaths[corePath] = core
		}

		targetFiles := signingPullSortedFiles(targetPaths)
		for _, file := range targetFiles {
			selectedByPath[canonicalSigningPullPath(file.RelativePath)] = file
		}
		targets = append(targets, SyncTargetResult{
			BundleID:       bundleID,
			ProfileType:    profileType,
			ProfilePath:    profilePaths[0],
			ProfilePaths:   profilePaths,
			ProfileCreated: false,
			Files:          signingPullRelativePathsFromFiles(targetFiles),
		})
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("no active %s profile found in encrypted repository for bundle ID(s): %s", profileType, strings.Join(missing, ", "))
	}
	return signingPullSortedFiles(selectedByPath), targets, nil
}

func signingPullProfileBundleID(profile *identityMobileProvision) (string, error) {
	if profile == nil {
		return "", fmt.Errorf("profile is missing")
	}
	applicationIdentifier, _ := profile.Entitlements["application-identifier"].(string)
	if applicationIdentifier == "" {
		applicationIdentifier, _ = profile.Entitlements["com.apple.application-identifier"].(string)
	}
	applicationIdentifier = strings.TrimSpace(applicationIdentifier)
	if applicationIdentifier == "" {
		return "", fmt.Errorf("profile has no application identifier entitlement")
	}
	for _, prefix := range profile.ApplicationIdentifierPrefix {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		bundleID, found := strings.CutPrefix(applicationIdentifier, prefix+".")
		if found && strings.TrimSpace(bundleID) != "" && !strings.Contains(bundleID, "*") {
			return bundleID, nil
		}
	}
	return "", fmt.Errorf("profile application identifier does not match its declared prefix")
}

func signingPullProfilePlatformMatches(profile *identityMobileProvision, profileType string) bool {
	if profile == nil || len(profile.Platform) == 0 {
		return true
	}
	wanted := ""
	switch {
	case strings.HasPrefix(profileType, "IOS_"):
		wanted = "ios"
	case strings.HasPrefix(profileType, "TVOS_"):
		wanted = "tvos"
	case strings.HasPrefix(profileType, "MAC_"), strings.HasPrefix(profileType, "MAC_CATALYST_"):
		wanted = "osx"
	}
	if wanted == "" {
		return true
	}
	for _, platform := range profile.Platform {
		normalized := strings.ToLower(strings.TrimSpace(platform))
		if normalized == wanted || (wanted == "osx" && normalized == "macos") {
			return true
		}
	}
	return false
}

func signingPullSortedFiles(files map[string]decryptedSigningFile) []decryptedSigningFile {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]decryptedSigningFile, 0, len(paths))
	for _, path := range paths {
		result = append(result, files[path])
	}
	return result
}

func signingPullRelativePathsFromFiles(files []decryptedSigningFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, canonicalSigningPullPath(file.RelativePath))
	}
	return uniqueSortedSigningSyncStrings(paths)
}

func canonicalSigningPullPath(path string) string {
	return strings.ReplaceAll(filepath.ToSlash(path), `\`, "/")
}

func preflightSigningPullFiles(outputDir string, files []decryptedSigningFile) error {
	root, err := rootfs.New(outputDir)
	if err != nil {
		return fmt.Errorf("create output root: %w", err)
	}
	defer root.Close()
	return preflightSigningPullFilesInRoot(root, files)
}

func preflightSigningPullFilesInRoot(root rootfs.Root, files []decryptedSigningFile) error {
	for _, file := range files {
		var err error
		if file.Sensitive {
			err = root.CheckCreateNewFile(file.RelativePath)
		} else {
			err = root.CheckWriteFilePreservingMode(file.RelativePath)
		}
		if err != nil {
			return fmt.Errorf("preflight output %s: %w", file.RelativePath, err)
		}
	}
	return nil
}
