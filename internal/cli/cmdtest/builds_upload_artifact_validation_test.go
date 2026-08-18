package cmdtest

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildsUploadRejectsUnsafePKGBeforeNetwork(t *testing.T) {
	setupAuth(t)
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.pkg")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("write empty PKG: %v", err)
	}
	targetPath := filepath.Join(dir, "target.pkg")
	if err := os.WriteFile(targetPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write PKG target: %v", err)
	}
	linkPath := filepath.Join(dir, "link.pkg")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request for unsafe PKG: %s %s", req.Method, req.URL.String())
		return nil, nil
	})

	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "empty", path: emptyPath, wantErr: "--pkg must not be empty"},
		{name: "symlink", path: linkPath, wantErr: "refusing to read symlink"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := RootCommand("1.2.3")
			root.FlagSet.SetOutput(io.Discard)
			if err := root.Parse([]string{
				"builds", "upload",
				"--app", "123456789",
				"--pkg", test.path,
				"--version", "1.0.0",
				"--build-number", "42",
				"--dry-run",
			}); err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err := root.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}
