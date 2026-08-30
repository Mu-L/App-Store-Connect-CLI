package xcode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAndApplySigningPlanForDirectSettings(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	stateDir := filepath.Join(root, "state")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{
			"name": "App",
			"configurations": [{
				"name": "Debug",
				"settings": {
					"CODE_SIGN_STYLE": "manual",
					"DEVELOPMENT_TEAM": "ABCDE12345",
					"CODE_SIGN_IDENTITY": "Apple Development",
					"PROVISIONING_PROFILE": "01234567-89ab-cdef-0123-456789abcdef",
					"PRODUCT_BUNDLE_IDENTIFIER": "com.example.demo"
				}
			}]
		}]
	}`)

	pbxprojPath := filepath.Join(project, "project.pbxproj")
	before := mustReadVersionTestFile(t, pbxprojPath)
	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath:      project,
		SettingsFilePath: settingsPath,
		StateDir:         stateDir,
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	if !plan.Ready {
		t.Fatalf("expected ready plan, got %#v", plan.Blockers)
	}
	if len(plan.Changes) != 5 {
		t.Fatalf("expected five changes, got %#v", plan.Changes)
	}
	for _, change := range plan.Changes {
		if change.Resolution != "missing" {
			t.Fatalf("new direct setting resolution = %q, want missing", change.Resolution)
		}
	}
	if got := mustReadVersionTestFile(t, pbxprojPath); got != before {
		t.Fatal("planning changed the project")
	}

	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}
	result, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err != nil {
		t.Fatalf("ApplySigningPlan() error = %v", err)
	}
	if len(result.ChangedFiles) != 1 || result.ChangedFiles[0] != pbxprojPath {
		t.Fatalf("unexpected changed files: %#v", result.ChangedFiles)
	}
	updated := mustReadVersionTestFile(t, pbxprojPath)
	for _, expected := range []string{
		`"CODE_SIGN_STYLE" = Manual;`,
		`"DEVELOPMENT_TEAM" = ABCDE12345;`,
		`"CODE_SIGN_IDENTITY" = "Apple Development";`,
		`"PROVISIONING_PROFILE" = "01234567-89ab-cdef-0123-456789abcdef";`,
		`"PRODUCT_BUNDLE_IDENTIFIER" = "com.example.demo";`,
	} {
		if !strings.Contains(updated, expected) {
			t.Fatalf("applied project is missing %q: %s", expected, updated)
		}
	}
	receiptInfo, err := os.Stat(plan.ReceiptPath)
	if err != nil {
		t.Fatalf("Stat(receipt) error = %v", err)
	}
	if receiptInfo.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode = %o, want 600", receiptInfo.Mode().Perm())
	}
	receipt, err := readSigningRegularFile(plan.ReceiptPath, signingPlanMaxBytes)
	if err != nil {
		t.Fatalf("read receipt error = %v", err)
	}
	if !strings.Contains(string(receipt), `"beforeSha256"`) || !strings.Contains(string(receipt), `"afterSha256"`) {
		t.Fatalf("receipt does not contain per-file digests: %s", receipt)
	}
}

func TestSigningPlanRejectsStaleProjectBeforeMutation(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	if err := os.WriteFile(pbxprojPath, append([]byte(mustReadVersionTestFile(t, pbxprojPath)), []byte("\n")...), 0o644); err != nil {
		t.Fatalf("modify project error = %v", err)
	}
	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("expected stale-plan error, got %v", err)
	}
	if strings.Contains(mustReadVersionTestFile(t, pbxprojPath), `"CODE_SIGN_STYLE" = Manual;`) {
		t.Fatal("stale apply mutated the project")
	}
}

func TestSigningPlanUsesExclusiveXCConfigWhenSelected(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte("CODE_SIGN_STYLE = Automatic\r\n"+shared), 0o644); err != nil {
		t.Fatalf("write shared xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}},
			{"name":"Release","settings":{"CODE_SIGN_STYLE":"manual"}}
		]}]
	}`)
	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	if !plan.Ready {
		t.Fatalf("expected ready plan, got %#v", plan.Blockers)
	}
	if len(plan.Changes) != 2 {
		t.Fatalf("expected one scoped change per configuration, got %#v", plan.Changes)
	}
	for _, change := range plan.Changes {
		if change.Source != "xcconfig" || change.Path != sharedPath {
			t.Fatalf("expected shared xcconfig source, got %#v", change)
		}
	}
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath}); err != nil {
		t.Fatalf("ApplySigningPlan() error = %v", err)
	}
	updated := mustReadVersionTestFile(t, sharedPath)
	if !strings.Contains(updated, "CODE_SIGN_STYLE = Manual\r\n") {
		t.Fatalf("shared xcconfig was not updated: %q", updated)
	}
}

func TestSigningSettingsManifestIsStrictAndValidatesValues(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown field",
			body: `{"schemaVersion":1,"extra":true,"targets":[]}`,
			want: "unknown field",
		},
		{
			name: "unsupported setting",
			body: `{"schemaVersion":1,"targets":[{"name":"App","configurations":[{"name":"Debug","settings":{"OTHER":"x"}}]}]}`,
			want: "unsupported signing setting",
		},
		{
			name: "null required value",
			body: `{"schemaVersion":1,"targets":[{"name":"App","configurations":[{"name":"Debug","settings":{"DEVELOPMENT_TEAM":null}}]}]}`,
			want: "does not support null",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			writeSigningSettingsTestFile(t, path, test.body)
			manifest, err := readSigningSettingsManifest(path)
			if err == nil {
				_, _, err = normalizeSigningRequests(manifest)
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readSigningSettingsManifest() error = %v, want %q", err, test.want)
			}
		})
	}
}

func writeSigningSettingsTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
