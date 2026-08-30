package xcode

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXCConfigRecursiveIncludesHandleCyclesOptionalFilesAndOrder(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "Root.xcconfig")
	sharedPath := filepath.Join(root, "Shared.xcconfig")
	if err := os.WriteFile(rootPath, []byte("#include? \"Missing\"\n#include \"Shared\"\nMARKETING_VERSION = 3.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedPath, []byte("#include \"Root.xcconfig\"\nMARKETING_VERSION = 2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := collectXCConfigFiles(rootPath)
	if err != nil {
		t.Fatalf("collectXCConfigFiles() error = %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %#v, want root and shared", files)
	}
	resolved, err := resolveXCConfigSetting(rootPath, marketingVersionSetting)
	if err != nil {
		t.Fatalf("resolveXCConfigSetting() error = %v", err)
	}
	if !resolved.found || resolved.value != "3.0.0" || resolved.path != rootPath {
		t.Fatalf("unexpected resolved value: %#v", resolved)
	}
}

func TestXCConfigEditorPreservesCommentsQuotesAndMissingFinalNewline(t *testing.T) {
	input := []byte("URL = \"https://example.com/path\" // URL comment\n/* MARKETING_VERSION = 9.9.9 */\nMARKETING_VERSION[sdk=iphoneos*] ?= 1.2.3 // keep me")
	updated, oldValues, changed, err := editXCConfig(input, marketingVersionSetting, "2.0.0")
	if err != nil {
		t.Fatalf("editXCConfig() error = %v", err)
	}
	if !changed || len(oldValues) != 1 || oldValues[0] != "1.2.3" {
		t.Fatalf("unexpected edit metadata changed=%v old=%#v", changed, oldValues)
	}
	got := string(updated)
	if !strings.Contains(got, "URL = \"https://example.com/path\" // URL comment") ||
		!strings.Contains(got, "/* MARKETING_VERSION = 9.9.9 */") ||
		!strings.HasSuffix(got, "MARKETING_VERSION[sdk=iphoneos*] = 2.0.0 // keep me") ||
		strings.HasSuffix(got, "\n") {
		t.Fatalf("lossless edit failed: %q", got)
	}
}

func TestXCConfigInheritedValueAndExactPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Values.xcconfig")
	contents := "OTHER = base\nOTHER = $(inherited)-child\nCURRENT_PROJECT_VERSION[sdk=iphoneos*] = 42\nCURRENT_PROJECT_VERSION = 42\nCURRENT_PROJECT_VERSION[sdk=macosx*] = 42\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	other, err := resolveXCConfigSetting(path, "OTHER")
	if err != nil || other.value != "base-child" {
		t.Fatalf("inherited resolution = %#v, err %v", other, err)
	}
	build, err := resolveXCConfigSetting(path, currentProjectSetting)
	if err != nil || build.value != "42" || !build.exact {
		t.Fatalf("exact resolution = %#v, err %v", build, err)
	}
}

func TestXCConfigResolverRejectsDivergentConditionalOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Values.xcconfig")
	contents := "CURRENT_PROJECT_VERSION = 42\nCURRENT_PROJECT_VERSION[sdk=iphoneos*] = 100\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveXCConfigSetting(path, currentProjectSetting)
	if err == nil || !strings.Contains(err.Error(), "differing conditional") {
		t.Fatalf("expected divergent conditional error, got %v", err)
	}
}

func TestXCConfigOperatorsQuotesAndIncludeOrder(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "Root.xcconfig")
	childPath := filepath.Join(root, "Child.xcconfig")
	if err := os.WriteFile(rootPath, []byte("OTHER = base\n#include \"Child.xcconfig\"\nMARKETING_VERSION ?= \"1.2.3\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childPath, []byte("OTHER += child\nOTHER ?= ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	other, err := resolveXCConfigSetting(rootPath, "OTHER")
	if err != nil || other.value != "base child" {
		t.Fatalf("operator/include resolution = %#v, err %v", other, err)
	}
	version, err := resolveXCConfigSetting(rootPath, marketingVersionSetting)
	if err != nil || version.value != "1.2.3" {
		t.Fatalf("quoted/default resolution = %#v, err %v", version, err)
	}
}

func TestXCConfigEditorNormalizesOperatorsAndPreservesQuotes(t *testing.T) {
	for _, operator := range []string{"+=", "?="} {
		t.Run(operator, func(t *testing.T) {
			input := []byte("MARKETING_VERSION " + operator + " \"1.2.3\" // keep\n")
			updated, oldValues, changed, err := editXCConfig(input, marketingVersionSetting, "2.0.0")
			if err != nil {
				t.Fatalf("editXCConfig() error = %v", err)
			}
			if !changed || len(oldValues) != 1 || oldValues[0] != "1.2.3" {
				t.Fatalf("unexpected edit metadata changed=%v old=%#v", changed, oldValues)
			}
			if got := string(updated); got != "MARKETING_VERSION = \"2.0.0\" // keep\n" {
				t.Fatalf("operator/quote edit = %q", got)
			}
		})
	}
}

func TestXCConfigResolverRejectsConditionalOnlySetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Conditional.xcconfig")
	contents := "CURRENT_PROJECT_VERSION[sdk=iphoneos*] = 41\nCURRENT_PROJECT_VERSION[sdk=macosx*] = 43\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveXCConfigSetting(path, currentProjectSetting)
	if err == nil || !strings.Contains(err.Error(), "conditional") {
		t.Fatalf("expected conditional-only setting error, got %v", err)
	}
}

func TestXCConfigParserRejectsUnterminatedBlockComment(t *testing.T) {
	_, err := parseXCConfig([]byte("MARKETING_VERSION = 1.0\n/* never closed"))
	if err == nil {
		t.Fatal("expected unterminated-comment error")
	}
}

func TestXCConfigRequiredMissingIncludeFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Root.xcconfig")
	if err := os.WriteFile(path, []byte("#include \"Missing.xcconfig\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := collectXCConfigFiles(path)
	if err == nil {
		t.Fatal("expected required-include error")
	}
}

func TestXCConfigOptionalIncludePropagatesMissingRequiredDescendant(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "Root.xcconfig")
	optionalPath := filepath.Join(root, "Optional.xcconfig")
	missingPath := filepath.Join(root, "Missing.xcconfig")
	if err := os.WriteFile(rootPath, []byte("#include? \"Optional.xcconfig\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(root) error = %v", err)
	}
	if err := os.WriteFile(optionalPath, []byte("#include \"Missing.xcconfig\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(optional) error = %v", err)
	}

	seen := make(map[string]bool)
	_, err := collectXCConfigFilesWithHooks(
		rootPath,
		os.ReadFile,
		nil,
		func(path string) { seen[filepath.Clean(path)] = true },
		nil,
	)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("collectXCConfigFilesWithHooks() error = %v, want descendant missing-include error", err)
	}
	for _, path := range []string{rootPath, optionalPath, missingPath} {
		if !seen[path] {
			t.Fatalf("collector did not retain lexical path %q: %#v", path, seen)
		}
	}
}

func TestXCConfigCollectorRecordsMissingIncludeBeforeAccess(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "Root.xcconfig")
	missingPath := filepath.Join(root, "Missing.xcconfig")
	if err := os.WriteFile(rootPath, []byte("#include \"Missing.xcconfig\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(root) error = %v", err)
	}

	seen := make(map[string]bool)
	readPaths := make(map[string]bool)
	var errorsByPath map[string]error
	_, err := collectXCConfigFilesWithHooks(
		rootPath,
		func(path string) ([]byte, error) {
			readPaths[filepath.Clean(path)] = true
			return os.ReadFile(path)
		},
		func(path string) error {
			if path == missingPath && !seen[path] {
				t.Fatalf("missing include was authorized before path was recorded")
			}
			return nil
		},
		func(path string) { seen[filepath.Clean(path)] = true },
		func(path string, collectionErr error) {
			if errorsByPath == nil {
				errorsByPath = make(map[string]error)
			}
			errorsByPath[filepath.Clean(path)] = collectionErr
		},
	)
	if err == nil {
		t.Fatal("collector error = nil, want required missing include failure")
	}
	if !seen[missingPath] {
		t.Fatalf("missing include was not retained by path hook: %#v", seen)
	}
	if !readPaths[missingPath] {
		t.Fatalf("missing include did not use the authorized reader: %#v", readPaths)
	}
	if errorsByPath[missingPath] == nil {
		t.Fatalf("missing include was not retained by error hook: %#v", errorsByPath)
	}
}

func TestXCConfigFileIdentityRequiresAuthorizedCollectionBeforeInspection(t *testing.T) {
	root := t.TempDir()
	externalPath := filepath.Join(root, "external.xcconfig")
	if err := os.WriteFile(externalPath, []byte("CODE_SIGN_STYLE = Manual\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(external) error = %v", err)
	}
	linkPath := filepath.Join(root, "unselected.xcconfig")
	if err := os.Symlink(externalPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	index := xcconfigFileIdentityIndex{}
	_, err := index.identity(linkPath, map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "was not collected") {
		t.Fatalf("identity() error = %v, want collection-membership refusal", err)
	}
	if len(index.entries) != 0 {
		t.Fatalf("identity index entries = %#v, want empty after unauthorized path", index.entries)
	}
}

func TestXCConfigCollectorRejectsUnauthorizedSymlinkBeforeReader(t *testing.T) {
	root := t.TempDir()
	externalRoot := t.TempDir()
	externalPath := filepath.Join(externalRoot, "external.xcconfig")
	if err := os.WriteFile(externalPath, []byte("CODE_SIGN_STYLE = Manual\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(external) error = %v", err)
	}
	selectedPath := filepath.Join(root, "selected.xcconfig")
	if err := os.Symlink(externalPath, selectedPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	readCalls := 0
	paths := make(map[string]bool)
	_, err := collectXCConfigFilesWithHooks(
		selectedPath,
		func(path string) ([]byte, error) {
			readCalls++
			return os.ReadFile(path)
		},
		func(path string) error {
			if path != selectedPath {
				t.Fatalf("authorization path = %q, want %q", path, selectedPath)
			}
			return errors.New("external path not authorized")
		},
		func(path string) { paths[path] = true },
		nil,
	)
	if err == nil {
		t.Fatal("collector error = nil, want authorization refusal")
	}
	if readCalls != 0 {
		t.Fatalf("reader calls = %d, want zero before authorization", readCalls)
	}
	if !paths[selectedPath] {
		t.Fatalf("path hook did not retain unauthorized path: %#v", paths)
	}
}

func TestXCConfigCollectorContinuesSiblingIncludesAfterAuthorizationFailure(t *testing.T) {
	root := t.TempDir()
	rootPath := filepath.Join(root, "Root.xcconfig")
	blockedPath := filepath.Join(root, "Blocked.xcconfig")
	allowedPath := filepath.Join(root, "Allowed.xcconfig")
	if err := os.WriteFile(rootPath, []byte("#include \"Blocked.xcconfig\"\n#include \"Allowed.xcconfig\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(root) error = %v", err)
	}
	if err := os.WriteFile(allowedPath, []byte("CODE_SIGN_STYLE = Manual\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(allowed) error = %v", err)
	}

	paths := make(map[string]bool)
	readPaths := make(map[string]bool)
	_, err := collectXCConfigFilesWithHooks(
		rootPath,
		func(path string) ([]byte, error) {
			readPaths[filepath.Clean(path)] = true
			return os.ReadFile(path)
		},
		func(path string) error {
			if filepath.Clean(path) == blockedPath {
				return errors.New("blocked include")
			}
			return nil
		},
		func(path string) { paths[filepath.Clean(path)] = true },
		nil,
	)
	if err == nil {
		t.Fatal("collector error = nil, want blocked include failure")
	}
	if !paths[rootPath] || !paths[blockedPath] || !paths[allowedPath] {
		t.Fatalf("paths = %#v, want root and both sibling includes", paths)
	}
	if readPaths[blockedPath] {
		t.Fatalf("blocked include was read despite authorization failure: %#v", readPaths)
	}
	if !readPaths[allowedPath] {
		t.Fatalf("allowed sibling include was not read after earlier failure: %#v", readPaths)
	}
}

func TestXCConfigCollectorUsesWindowsCaseInsensitiveTraversalKeys(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "windows"
	t.Cleanup(func() { runtimeGOOS = previousOS })

	root := t.TempDir()
	rootPath := filepath.Join(root, "Config.xcconfig")
	caseVariantPath := filepath.Join(root, "config.xcconfig")

	readCalls := 0
	files, err := collectXCConfigFilesWithReader(rootPath, func(path string) ([]byte, error) {
		readCalls++
		switch filepath.Clean(path) {
		case rootPath:
			return []byte("#include \"config.xcconfig\"\n"), nil
		case caseVariantPath:
			return []byte("CODE_SIGN_STYLE = Manual\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}, nil)
	if err != nil {
		t.Fatalf("collectXCConfigFilesWithReader() error = %v", err)
	}
	if len(files) != 1 || files[0] != rootPath {
		t.Fatalf("files = %#v, want one case-insensitive traversal", files)
	}
	if readCalls != 1 {
		t.Fatalf("read calls = %d, want one for the same Windows path", readCalls)
	}
}

func TestXCConfigCollectorKeepsCaseDistinctFilesOnCaseSensitiveHost(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "linux"
	t.Cleanup(func() { runtimeGOOS = previousOS })

	root := t.TempDir()
	rootPath := filepath.Join(root, "Config.xcconfig")
	caseVariantPath := filepath.Join(root, "config.xcconfig")
	if err := os.WriteFile(rootPath, []byte("#include \"config.xcconfig\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(root) error = %v", err)
	}
	if _, err := os.Lstat(caseVariantPath); err == nil {
		t.Skip("temporary filesystem is case-insensitive")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(case variant) error = %v", err)
	}
	if err := os.WriteFile(caseVariantPath, []byte("CODE_SIGN_STYLE = Manual\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(case variant) error = %v", err)
	}

	readCalls := 0
	files, err := collectXCConfigFilesWithReader(rootPath, func(path string) ([]byte, error) {
		readCalls++
		return os.ReadFile(path)
	}, nil)
	if err != nil {
		t.Fatalf("collectXCConfigFilesWithReader() error = %v", err)
	}
	if len(files) != 2 || files[0] != rootPath || files[1] != caseVariantPath {
		t.Fatalf("files = %#v, want both case-distinct files", files)
	}
	if readCalls != 2 {
		t.Fatalf("read calls = %d, want one per case-distinct file", readCalls)
	}
}
