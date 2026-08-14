package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeCleanRemovesReleaseDirectory(t *testing.T) {
	workspaceDir := t.TempDir()
	releaseDir := filepath.Join(workspaceDir, "release")
	staleArtifact := filepath.Join(releaseDir, "stale-artifact")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatalf("mkdir release dir: %v", err)
	}
	if err := os.WriteFile(staleArtifact, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale artifact: %v", err)
	}

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cmd := exec.Command("make", "-f", filepath.Join(repoRoot, "Makefile"), "-C", workspaceDir, "clean")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make clean failed: %v\n%s", err, output)
	}

	if _, err := os.Stat(staleArtifact); !os.IsNotExist(err) {
		t.Fatalf("expected make clean to remove %s, stat err=%v\n%s", staleArtifact, err, output)
	}
}

// makeDryRun returns the commands make would execute for a target without
// running them.
func makeDryRun(t *testing.T, target string) string {
	t.Helper()

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cmd := exec.Command("make", "-n", "-f", filepath.Join(repoRoot, "Makefile"), "-C", t.TempDir(), target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s failed: %v\n%s", target, err, output)
	}
	return string(output)
}

func TestMakeBuildAllUsesStrippedTrimmedReleaseFlags(t *testing.T) {
	output := makeDryRun(t, "build-all")
	for _, want := range []string{"-trimpath", `-ldflags "-s -w `} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected build-all recipe to contain %q, got:\n%s", want, output)
		}
	}
}

func TestMakeBuildAllSetsCGOPerTarget(t *testing.T) {
	output := makeDryRun(t, "build-all")
	for _, want := range []string{
		`if [ "$os" = "darwin" ]; then cgo="1"; else cgo="0"; fi`,
		`CGO_ENABLED="$cgo" GOOS="$os" GOARCH="$arch"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected build-all recipe to contain %q, got:\n%s", want, output)
		}
	}
}

func TestMakeBuildAllFailsWhenAnyTargetFails(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	workspaceDir := t.TempDir()
	fakeGo := filepath.Join(workspaceDir, "fake-go")
	script := `#!/bin/sh
if [ "$1" = "env" ]; then
	exit 0
fi
if [ "$GOOS" = "darwin" ]; then
	echo "simulated Darwin Cgo failure" >&2
	exit 42
fi
exit 0
`
	if err := os.WriteFile(fakeGo, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}

	cmd := exec.Command(
		"make",
		"-f",
		filepath.Join(repoRoot, "Makefile"),
		"-C",
		workspaceDir,
		"build-all",
		"GO="+fakeGo,
		"VERSION=1.2.3",
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("make build-all succeeded despite a failed target:\n%s", output)
	}
	if strings.Contains(string(output), "Release binaries written") {
		t.Fatalf("make build-all reported success after a failed target:\n%s", output)
	}
}

func TestMakeBuildAllQuotesCustomReleaseDirectory(t *testing.T) {
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	workspaceDir := t.TempDir()
	releaseDir := filepath.Join(workspaceDir, "release output")

	cmd := exec.Command(
		"make",
		"-n",
		"-f",
		filepath.Join(repoRoot, "Makefile"),
		"-C",
		workspaceDir,
		"build-all",
		"VERSION=1.2.3",
		"RELEASE_DIR="+releaseDir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n build-all with custom output failed: %v\n%s", err, output)
	}
	commands := string(output)
	for _, want := range []string{
		`rm -rf build dist "` + releaseDir + `"`,
		`mkdir -p "` + releaseDir + `"`,
		`-o "` + releaseDir + `/asc_1.2.3_`,
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("custom release directory is not safely quoted in %q; got:\n%s", want, commands)
		}
	}
}

func TestMakeBuildKeepsDebugSymbolsForDevBuilds(t *testing.T) {
	output := makeDryRun(t, "build")
	for _, unwanted := range []string{"-trimpath", "-s -w"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("expected dev build recipe to stay unstripped, found %q in:\n%s", unwanted, output)
		}
	}
	if !strings.Contains(output, "-X main.version=") {
		t.Fatalf("expected dev build recipe to inject version metadata, got:\n%s", output)
	}
}

func TestMakeBuildRebuildsBinaryWhenSourceChanges(t *testing.T) {
	workspaceDir := t.TempDir()
	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	writeWorkspaceFile := func(path, contents string) {
		t.Helper()
		fullPath := filepath.Join(workspaceDir, path)
		if err := os.WriteFile(fullPath, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	writeWorkspaceFile("go.mod", "module example.com/makebuildtest\n\ngo 1.24.0\n")
	writeWorkspaceFile("main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Print(\"first\") }\n")

	runMakeBuild := func() {
		t.Helper()
		cmd := exec.Command("make", "-f", filepath.Join(repoRoot, "Makefile"), "-C", workspaceDir, "build")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make build failed: %v\n%s", err, output)
		}
	}

	runBinary := func() string {
		t.Helper()
		cmd := exec.Command(filepath.Join(workspaceDir, "asc"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run built binary failed: %v\n%s", err, output)
		}
		return string(output)
	}

	runMakeBuild()
	if got := runBinary(); got != "first" {
		t.Fatalf("expected initial binary output %q, got %q", "first", got)
	}

	writeWorkspaceFile("main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Print(\"second\") }\n")

	runMakeBuild()
	if got := runBinary(); got != "second" {
		t.Fatalf("expected rebuilt binary output %q, got %q", "second", got)
	}
}
