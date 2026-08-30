package asc

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenAscImports lists first-party packages that internal/asc must not
// import. internal/xcode imports internal/asc so its local Xcode results can
// use the registered camelCase output types, so the reverse edge would create
// an import cycle. That cycle is invisible to a build of this branch alone and
// only appears once both directions exist, so assert the invariant directly.
var forbiddenAscImports = map[string]string{
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode": "internal/xcode imports internal/asc for its registered output types; keep output_*.go free of the domain type and convert in the command layer",
}

func TestAscOutputPackageDoesNotImportDomainPackagesThatImportIt(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fileSet := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, parseErr := parser.ParseFile(fileSet, filepath.Join(".", name), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		for _, importSpec := range file.Imports {
			path, unquoteErr := strconv.Unquote(importSpec.Path.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote import in %s: %v", name, unquoteErr)
			}
			if reason, forbidden := forbiddenAscImports[path]; forbidden {
				t.Errorf("%s imports %s: %s", name, path, reason)
			}
		}
	}
}
