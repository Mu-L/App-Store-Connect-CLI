package xcode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSigningPlanRejectsPlanAliasToXCConfig(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	planPath := filepath.Join(root, "plan.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	if err := os.Link(sharedPath, planPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, PlanPath: planPath,
		StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "aliases project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want plan alias rejection", err)
	}
	if got := mustReadVersionTestFile(t, sharedPath); got == "" {
		t.Fatal("shared xcconfig unexpectedly disappeared")
	}
}

func TestBuildSigningPlanRejectsReceiptAliasToEntitlements(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	projectRoot := filepath.Dir(project)
	entitlementsPath := filepath.Join(projectRoot, "App.entitlements")
	if err := os.WriteFile(entitlementsPath, []byte("<?xml version=\"1.0\"?>\n"), 0o644); err != nil {
		t.Fatalf("write entitlements file: %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	receiptPath := filepath.Join(root, "receipt.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_ENTITLEMENTS":"App.entitlements"}}]}]
	}`)
	if err := os.Link(entitlementsPath, receiptPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		StateDir: filepath.Join(root, "state"), ReceiptPath: receiptPath,
	})
	if err == nil || !strings.Contains(err.Error(), "aliases project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want receipt alias rejection", err)
	}
	if got := mustReadVersionTestFile(t, entitlementsPath); got == "" {
		t.Fatal("entitlements file unexpectedly disappeared")
	}
}

func TestValidateSigningRelativePathUsesPOSIXRules(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "single component", value: "App.entitlements", valid: true},
		{name: "nested components", value: "Config/App.entitlements", valid: true},
		{name: "parent traversal", value: "../App.entitlements"},
		{name: "embedded traversal", value: "Config/../App.entitlements"},
		{name: "dot component", value: "Config/./App.entitlements"},
		{name: "backslash separator", value: `Config\App.entitlements`},
		{name: "unix absolute", value: "/tmp/App.entitlements"},
		{name: "windows drive relative", value: "C:App.entitlements"},
		{name: "windows drive absolute", value: "C:/App.entitlements"},
		{name: "home shorthand", value: "~/App.entitlements"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSigningRelativePath(test.value)
			if test.valid && err != nil {
				t.Fatalf("validateSigningRelativePath(%q) error = %v", test.value, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("validateSigningRelativePath(%q) unexpectedly accepted", test.value)
			}
		})
	}
}

func TestSigningApplyRejectsSourceChangedAfterPreparation(t *testing.T) {
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
	originalHook := beforeSigningCommitForTest
	beforeSigningCommitForTest = func() {
		beforeSigningCommitForTest = nil
		contents := mustReadVersionTestFile(t, pbxprojPath)
		if err := os.WriteFile(pbxprojPath, append([]byte(contents), '\n'), 0o644); err != nil {
			t.Fatalf("mutate project after preparation: %v", err)
		}
	}
	t.Cleanup(func() { beforeSigningCommitForTest = originalHook })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("ApplySigningPlan() error = %v, want stale-source rejection", err)
	}
	if strings.Contains(mustReadVersionTestFile(t, pbxprojPath), `"CODE_SIGN_STYLE" = Manual;`) {
		t.Fatal("source drift after preparation was applied")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !os.IsNotExist(statErr) {
		t.Fatalf("receipt after source drift = %v, want absent", statErr)
	}
}
