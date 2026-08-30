package xcode

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
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
	if !strings.Contains(string(receipt), `"completed": true`) || !result.Completed {
		t.Fatalf("receipt completion state = result=%t contents=%s, want completed", result.Completed, receipt)
	}
}

func TestSigningPlanWritesCompletedNoOpReceipt(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	firstPlan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "first"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan(first) error = %v", err)
	}
	if err := WriteSigningPlanArtifact(firstPlan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact(first) error = %v", err)
	}
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: firstPlan.PlanPath}); err != nil {
		t.Fatalf("ApplySigningPlan(first) error = %v", err)
	}

	noOpPlan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "no-op"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan(no-op) error = %v", err)
	}
	if !noOpPlan.Ready || len(noOpPlan.Changes) != 0 {
		t.Fatalf("no-op plan = ready=%t changes=%#v blockers=%#v", noOpPlan.Ready, noOpPlan.Changes, noOpPlan.Blockers)
	}
	if err := WriteSigningPlanArtifact(noOpPlan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact(no-op) error = %v", err)
	}
	result, err := ApplySigningPlan(SigningApplyOptions{PlanPath: noOpPlan.PlanPath})
	if err != nil {
		t.Fatalf("ApplySigningPlan(no-op) error = %v", err)
	}
	if !result.Completed || len(result.ChangedFiles) != 0 || len(result.Files) != 0 {
		t.Fatalf("no-op receipt result = %#v, want completed with no changed files", result)
	}
	receipt, err := readSigningRegularFile(noOpPlan.ReceiptPath, signingPlanMaxBytes)
	if err != nil {
		t.Fatalf("read no-op receipt error = %v", err)
	}
	if !strings.Contains(string(receipt), `"completed": true`) {
		t.Fatalf("no-op receipt = %s, want completed", receipt)
	}
}

func TestSigningApplyRefusesExistingReceiptBeforeMutation(t *testing.T) {
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
	const existingReceipt = "existing receipt must remain unchanged\n"
	if err := os.WriteFile(plan.ReceiptPath, []byte(existingReceipt), 0o600); err != nil {
		t.Fatalf("WriteFile(receipt) error = %v", err)
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("ApplySigningPlan() error = %v, want existing-receipt rejection", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("existing receipt rejection mutated the project")
	}
	if after := mustReadVersionTestFile(t, plan.ReceiptPath); after != existingReceipt {
		t.Fatalf("existing receipt changed: %q", after)
	}
}

func TestSigningApplyRollsBackProjectWhenReceiptFinalizationFails(t *testing.T) {
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	beforeInfo, err := os.Stat(pbxprojPath)
	if err != nil {
		t.Fatalf("Stat(project) error = %v", err)
	}
	injectedErr := errors.New("injected receipt finalization failure")
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		if write.createOnly {
			return nil, injectedErr
		}
		return originalCreator(write, data)
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if !errors.Is(err, injectedErr) {
		t.Fatalf("ApplySigningPlan() error = %v, want injected receipt failure", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("receipt finalization failure left project changes behind")
	}
	afterInfo, err := os.Stat(pbxprojPath)
	if err != nil {
		t.Fatalf("Stat(project after rollback) error = %v", err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf("project mode after rollback = %o, want %o", afterInfo.Mode().Perm(), beforeInfo.Mode().Perm())
	}
	if _, err := os.Lstat(plan.ReceiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt after failed transaction = %v, want absent", err)
	}
}

func TestSigningApplyRemovesReceiptWhenPostCreateVerificationFails(t *testing.T) {
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	injectedErr := errors.New("injected post-create receipt verification failure")
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		createdInfo, err := originalCreator(write, data)
		if err != nil || !write.createOnly {
			return createdInfo, err
		}
		return createdInfo, injectedErr
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if !errors.Is(err, injectedErr) {
		t.Fatalf("ApplySigningPlan() error = %v, want post-create verification failure", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("post-create verification failure left project changes behind")
	}
	if _, err := os.Lstat(plan.ReceiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt after post-create verification failure = %v, want absent", err)
	}
}

func TestSigningApplyPreservesReceiptReplacementWhenRollbackIdentityChanges(t *testing.T) {
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	const concurrentReceipt = "concurrent receipt wins\n"
	injectedErr := errors.New("injected post-create receipt verification failure")
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		createdInfo, err := originalCreator(write, data)
		if err != nil || !write.createOnly {
			return createdInfo, err
		}
		if err := os.WriteFile(write.path, []byte(concurrentReceipt), 0o600); err != nil {
			t.Fatalf("replace receipt after publication: %v", err)
		}
		return createdInfo, injectedErr
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if !errors.Is(err, injectedErr) || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("ApplySigningPlan() error = %v, want post-create failure with rollback uncertainty", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("receipt rollback identity failure left project changes behind")
	}
	if after := mustReadVersionTestFile(t, plan.ReceiptPath); after != concurrentReceipt {
		t.Fatalf("concurrent receipt was removed or changed: %q", after)
	}
}

func TestSigningApplyRollsBackProjectWhenReceiptRacesIntoPlace(t *testing.T) {
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	const racingReceipt = "concurrent receipt wins\n"
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		if write.createOnly {
			if err := os.WriteFile(write.path, []byte(racingReceipt), 0o600); err != nil {
				t.Fatalf("create racing receipt: %v", err)
			}
		}
		return originalCreator(write, data)
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("ApplySigningPlan() error = %v, want receipt race rejection", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("receipt race left project changes behind")
	}
	if after := mustReadVersionTestFile(t, plan.ReceiptPath); after != racingReceipt {
		t.Fatalf("racing receipt changed: %q", after)
	}
}

func TestSigningPlanRejectsStaleProjectBeforeMutation(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
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

func TestSigningApplyRechecksSourcesBeforeReceipt(t *testing.T) {
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	originalWriter := atomicWriteVersionFileFn
	mutated := false
	atomicWriteVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		info, err := originalWriter(write, data)
		if err == nil && !write.createOnly && !mutated {
			mutated = true
			settings := mustReadVersionTestFile(t, settingsPath)
			if err := os.WriteFile(settingsPath, []byte(settings+"\n"), 0o600); err != nil {
				t.Fatalf("mutate settings after ordinary write: %v", err)
			}
		}
		return info, err
	}
	t.Cleanup(func() { atomicWriteVersionFileFn = originalWriter })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "before receipt") {
		t.Fatalf("ApplySigningPlan() error = %v, want final source recheck failure", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("source recheck failure left project changes behind")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after final source drift = %v, want absent", statErr)
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

func TestPrepareSigningOperationsMergesWindowsCaseVariantXCConfigMutations(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "windows"
	t.Cleanup(func() { runtimeGOOS = previousOS })

	projectPath := writeStructuredVersionProject(t, false)
	configDir := filepath.Join(filepath.Dir(projectPath), "Configs")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(config) error = %v", err)
	}
	configPath := filepath.Join(configDir, "Config.xcconfig")
	caseVariantPath := filepath.Join(configDir, "config.xcconfig")
	original := []byte("CODE_SIGN_STYLE = Automatic\n")
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	caseVariantExists := false
	if _, err := os.Lstat(caseVariantPath); err == nil {
		caseVariantExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(case variant) error = %v", err)
	}
	if !caseVariantExists {
		if err := os.WriteFile(caseVariantPath, original, 0o640); err != nil {
			t.Fatalf("WriteFile(case variant) error = %v", err)
		}
	}

	project, err := openStructuredVersionProject(projectPath)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	debug, err := signingConfigurationFor(project, "App", "Debug")
	if err != nil {
		t.Fatalf("signingConfigurationFor(Debug) error = %v", err)
	}
	release, err := signingConfigurationFor(project, "App", "Release")
	if err != nil {
		t.Fatalf("signingConfigurationFor(Release) error = %v", err)
	}
	built := &signingPlanBuild{
		plan:    &SigningPlan{AllowExternalXCConfig: false},
		project: project,
		operations: []signingPlanOperation{
			{
				SigningSettingChange: SigningSettingChange{
					Target: "App", Configuration: "Debug", Setting: "CODE_SIGN_STYLE",
					Operation: "set", NewValue: stringPtr("Manual"), Path: configPath, Source: "xcconfig",
				},
				configuration: debug,
			},
			{
				SigningSettingChange: SigningSettingChange{
					Target: "App", Configuration: "Release", Setting: "CODE_SIGN_STYLE",
					Operation: "set", NewValue: stringPtr("Manual"), Path: caseVariantPath, Source: "xcconfig",
				},
				configuration: release,
			},
		},
	}
	prepared, err := prepareSigningOperations(built)
	if err != nil {
		t.Fatalf("prepareSigningOperations() error = %v", err)
	}
	if len(prepared.writes) != 1 {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("prepared writes = %d, want one case-insensitive mutation", len(prepared.writes))
	}
	if prepared.writes[0].path != configPath {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("prepared path = %q, want first operator spelling %q", prepared.writes[0].path, configPath)
	}
	if len(prepared.changedFiles) != 1 || prepared.changedFiles[0] != configPath {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("changed files = %#v, want one first-spelling path", prepared.changedFiles)
	}

	plan := &SigningPlan{Files: []SigningPlanFile{{
		Path: caseVariantPath, SHA256: signingFileDigestBytes(original), Source: "xcconfig",
	}}}
	if err := verifySigningPlanSources(plan, prepared.writes); err != nil {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("verifySigningPlanSources() error = %v, want case-insensitive source match", err)
	}
	fileChanges, err := signingReceiptFileChanges(plan, prepared.writes, []string{caseVariantPath})
	if err != nil {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("signingReceiptFileChanges() error = %v, want case-insensitive source match", err)
	}
	if len(fileChanges) != 1 || fileChanges[0].Path != caseVariantPath {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		t.Fatalf("file changes = %#v, want preserved requested spelling", fileChanges)
	}

	if err := commitVersionWrites(prepared.writes); err != nil {
		_ = prepared.projectRoot.Close()
		t.Fatalf("commitVersionWrites() error = %v, want one successful write", err)
	}
	if err := prepared.projectRoot.Close(); err != nil {
		t.Fatalf("close project root error = %v", err)
	}
	updated := []byte(mustReadVersionTestFile(t, configPath))
	if !strings.Contains(string(updated), "CODE_SIGN_STYLE = Manual") {
		t.Fatalf("case-insensitive mutation did not apply: %q", updated)
	}
	configInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat(config) error = %v", err)
	}
	if info, statErr := os.Stat(caseVariantPath); statErr == nil && !os.SameFile(info, configInfo) {
		if got := mustReadVersionTestFile(t, caseVariantPath); got != string(original) {
			t.Fatalf("case-distinct file changed with Windows-only aliasing: %q", got)
		}
	}

	recheckRoot, err := rootfs.New(configDir)
	if err != nil {
		t.Fatalf("rootfs.New(recheck) error = %v", err)
	}
	defer recheckRoot.Close()
	committed := preparedVersionWrite{
		path: caseVariantPath, name: filepath.Base(configPath), root: recheckRoot,
		original: original, updated: updated,
	}
	if err := verifySigningPlanSourcesBeforeReceipt(plan, []preparedVersionWrite{committed}); err != nil {
		t.Fatalf("verifySigningPlanSourcesBeforeReceipt() error = %v, want case-insensitive source match", err)
	}
}

func TestSigningPlanDoesNotAuthorizeSharedXCConfigPerSelectedConfiguration(t *testing.T) {
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
			{"name":"Release","settings":{"DEVELOPMENT_TEAM":"ABCDE12345"}}
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
		t.Fatalf("expected one target-level change per requested setting, got %#v", plan.Changes)
	}
	for _, change := range plan.Changes {
		if change.Source != "pbxproj" {
			t.Fatalf("shared xcconfig change was authorized by unrelated selected configuration: %#v", change)
		}
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "shared xcconfig") {
		t.Fatalf("expected shared xcconfig safety warning, got %#v", plan.Warnings)
	}
}

func TestSigningPlanDoesNotRewriteSharedXCConfigPastNoOpConsumer(t *testing.T) {
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
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"automatic"}},
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
	if len(plan.Changes) != 1 {
		t.Fatalf("expected only the conflicting Release override, got %#v", plan.Changes)
	}
	change := plan.Changes[0]
	if change.Configuration != "Release" || change.Source != "pbxproj" || change.Setting != "CODE_SIGN_STYLE" {
		t.Fatalf("unexpected no-op consumer resolution: %#v", change)
	}
}

func TestSigningPlanExternalXCConfigRequiresOptInForPlanAndApply(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, externalPath)
	if err := os.WriteFile(externalPath, []byte("CODE_SIGN_STYLE = Automatic\r\n"+shared), 0o640); err != nil {
		t.Fatalf("write external shared xcconfig error = %v", err)
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

	blocked, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "blocked"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() without opt-in error = %v", err)
	}
	if blocked.Ready || len(blocked.Changes) != 0 {
		t.Fatalf("external xcconfig without opt-in = ready=%t changes=%#v blockers=%#v", blocked.Ready, blocked.Changes, blocked.Blockers)
	}
	if !strings.Contains(strings.Join(blocked.Blockers, "\n"), "allow-external-xcconfig") {
		t.Fatalf("external xcconfig blocker = %#v, want opt-in guidance", blocked.Blockers)
	}

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "authorized"),
		AllowExternalXCConfig: true,
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() with opt-in error = %v", err)
	}
	if !plan.Ready || len(plan.Changes) != 2 {
		t.Fatalf("external xcconfig with opt-in = ready=%t changes=%#v blockers=%#v", plan.Ready, plan.Changes, plan.Blockers)
	}
	for _, change := range plan.Changes {
		if change.Source != "xcconfig" || change.Path != externalPath {
			t.Fatalf("authorized external change = %#v, want xcconfig %s", change, externalPath)
		}
	}
	if len(plan.Warnings) == 0 || !strings.Contains(strings.Join(plan.Warnings, "\n"), "external xcconfig") {
		t.Fatalf("authorized external warnings = %#v, want explicit warning", plan.Warnings)
	}
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}

	before := mustReadVersionTestFile(t, externalPath)
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath}); err == nil || !strings.Contains(err.Error(), "allow-external-xcconfig") {
		t.Fatalf("ApplySigningPlan() without opt-in error = %v, want opt-in rejection", err)
	}
	if after := mustReadVersionTestFile(t, externalPath); after != before {
		t.Fatal("external xcconfig changed when apply opt-in was omitted")
	}
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath, AllowExternalXCConfig: true}); err != nil {
		t.Fatalf("ApplySigningPlan() with opt-in error = %v", err)
	}
	if after := mustReadVersionTestFile(t, externalPath); !strings.Contains(after, "CODE_SIGN_STYLE = Manual") {
		t.Fatalf("authorized external xcconfig = %q, want Manual", after)
	}
}

func TestSigningPlanRejectsUnauthorizedMalformedExternalXCConfigBeforeReading(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	if err := os.WriteFile(externalPath, []byte("/* unterminated\n"), 0o640); err != nil {
		t.Fatalf("write malformed external xcconfig error = %v", err)
	}
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
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan without reading unauthorized source", err)
	}
	if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "allow-external-xcconfig") {
		t.Fatalf("unauthorized malformed external xcconfig = ready=%t blockers=%#v", plan.Ready, plan.Blockers)
	}
}

func TestSigningPlanBlocksUnselectedExternalXCConfigWithoutReadingIt(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	if err := os.WriteFile(externalPath, []byte("/* unterminated\n"), 0o640); err != nil {
		t.Fatalf("write malformed external xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "allow-external-xcconfig") {
		t.Fatalf("unselected unauthorized external xcconfig = ready=%t blockers=%#v", plan.Ready, plan.Blockers)
	}
}

func TestSigningPlanBlocksUnselectedEscapingXCConfigSymlink(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	projectRoot := filepath.Dir(project)
	configPath := filepath.Join(projectRoot, "Configs", "App.xcconfig")
	externalPath := filepath.Join(t.TempDir(), "App.xcconfig")
	if err := os.WriteFile(externalPath, []byte("/* unterminated external config\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(external) error = %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatalf("Remove(config) error = %v", err)
	}
	if err := os.Symlink(externalPath, configPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready {
		t.Fatalf("escaping unselected xcconfig symlink produced ready plan: %#v", plan)
	}
}

func TestSigningPlanRejectsUnselectedExternalXCConfigArtifactCollision(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	before := mustReadVersionTestFile(t, externalPath)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, PlanPath: externalPath,
		StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "protected project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want protected-input collision", err)
	}
	if after := mustReadVersionTestFile(t, externalPath); after != before {
		t.Fatalf("external config changed after artifact collision: %q", after)
	}
}

func TestSigningPlanRejectsAllowedUnselectedMalformedExternalArtifactCollision(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	if err := os.WriteFile(externalPath, []byte("/* unterminated\n"), 0o640); err != nil {
		t.Fatalf("write malformed external xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	before := mustReadVersionTestFile(t, externalPath)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, PlanPath: externalPath,
		StateDir: filepath.Join(root, "state"), AllowExternalXCConfig: true,
	})
	if err == nil || !strings.Contains(err.Error(), "protected project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want protected-input collision before artifact inspection", err)
	}
	if after := mustReadVersionTestFile(t, externalPath); after != before {
		t.Fatalf("external malformed config changed after artifact collision: %q", after)
	}
}

func TestSigningPlanRejectsAllowedMissingExternalIncludeArtifactCollision(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	missingInclude := filepath.Join(externalDir, "Missing.xcconfig")
	if err := os.WriteFile(externalPath, []byte("#include \"Missing.xcconfig\"\n"), 0o640); err != nil {
		t.Fatalf("write external xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, ReceiptPath: missingInclude,
		StateDir: filepath.Join(root, "state"), AllowExternalXCConfig: true,
	})
	if err == nil || !strings.Contains(err.Error(), "protected project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want missing-include collision before artifact inspection", err)
	}
	if _, statErr := os.Lstat(missingInclude); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing include after collision = %v, want absent", statErr)
	}
}

func TestSigningPlanRejectsBlockedExternalPlanAliasToMissingEntitlements(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	if err := os.WriteFile(externalPath, []byte("/* unterminated\n"), 0o640); err != nil {
		t.Fatalf("write malformed external xcconfig error = %v", err)
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	marker := `999999999999999999999993 /* App Debug */ = {`
	start := strings.Index(contents, marker)
	if start < 0 {
		t.Fatalf("project fixture is missing App Debug configuration")
	}
	settingMarker := "buildSettings = {  };"
	relative := strings.Index(contents[start:], settingMarker)
	if relative < 0 {
		t.Fatalf("project fixture is missing App Debug build settings")
	}
	settingStart := start + relative
	updatedContents := contents[:settingStart] + "buildSettings = { CODE_SIGN_ENTITLEMENTS = \"plan.json\"; };" + contents[settingStart+len(settingMarker):]
	if err := os.WriteFile(pbxprojPath, []byte(updatedContents), 0o644); err != nil {
		t.Fatalf("write project error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	planPath := filepath.Join(filepath.Dir(project), "plan.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, PlanPath: planPath,
		StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "aliases project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want missing-entitlement alias rejection", err)
	}
	if _, statErr := os.Lstat(planPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing entitlement artifact after collision = %v, want absent", statErr)
	}
}

func TestSigningPlanKeepsAllowedExternalCollectionFailureBlockedWithoutOverwrite(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	before := "/* unterminated\n"
	if err := os.WriteFile(externalPath, []byte(before), 0o640); err != nil {
		t.Fatalf("write malformed external xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	stateDir := filepath.Join(root, "state")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: stateDir,
		AllowExternalXCConfig: true,
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready || len(plan.Blockers) == 0 {
		t.Fatalf("allowed external collection failure = ready=%t blockers=%#v, want blocked plan", plan.Ready, plan.Blockers)
	}
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v, want safe distinct artifact", err)
	}
	if _, err := os.Stat(plan.PlanPath); err != nil {
		t.Fatalf("blocked plan artifact stat error = %v", err)
	}
	if _, err := os.Lstat(plan.ReceiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt after blocked plan = %v, want absent", err)
	}
	if after := mustReadVersionTestFile(t, externalPath); after != before {
		t.Fatalf("external malformed config changed while writing blocked plan: %q", after)
	}
}

func TestSigningPlanContinuesXCConfigProtectionAfterSelectedCollectionFailure(t *testing.T) {
	tests := []struct {
		name          string
		planPath      bool
		receiptPath   bool
		allowExternal bool
	}{
		{name: "base path collides with plan", planPath: true},
		{name: "missing include collides with receipt", receiptPath: true, allowExternal: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project, externalBase, missingInclude := writeSigningMultiConfigFailureProject(t)
			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			stateDir := filepath.Join(root, "state")
			writeSigningSettingsTestFile(t, settingsPath, `{
				"schemaVersion": 1,
				"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
			}`)

			opts := SigningPlanOptions{
				ProjectPath:           project,
				SettingsFilePath:      settingsPath,
				StateDir:              stateDir,
				AllowExternalXCConfig: test.allowExternal,
			}
			if test.planPath {
				opts.PlanPath = externalBase
			}
			if test.receiptPath {
				opts.ReceiptPath = missingInclude
			}

			_, err := BuildSigningPlan(opts)
			if err == nil || !strings.Contains(err.Error(), "protected project input") {
				t.Fatalf("BuildSigningPlan() error = %v, want lexical protected-path collision", err)
			}
			if _, statErr := os.Lstat(filepath.Join(stateDir, "plan.json")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("plan artifact after collision = %v, want absent", statErr)
			}
			if _, statErr := os.Lstat(filepath.Join(stateDir, "receipt.json")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("receipt artifact after collision = %v, want absent", statErr)
			}
			if test.planPath {
				if got := mustReadVersionTestFile(t, externalBase); !strings.Contains(got, "MissingInclude.xcconfig") {
					t.Fatalf("external base changed after collision: %q", got)
				}
			} else if _, statErr := os.Lstat(missingInclude); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("missing include after collision = %v, want absent", statErr)
			}
		})
	}

	project, _, _ := writeSigningMultiConfigFailureProject(t)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	stateDir := filepath.Join(root, "state")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath:           project,
		SettingsFilePath:      settingsPath,
		StateDir:              stateDir,
		AllowExternalXCConfig: true,
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() distinct artifact error = %v, want blocked plan", err)
	}
	if plan.Ready {
		t.Fatalf("distinct artifact produced ready plan: %#v", plan)
	}
	blockers := strings.Join(plan.Blockers, "\n")
	if !strings.Contains(blockers, "MissingSelected.xcconfig") || !strings.Contains(blockers, "MissingInclude.xcconfig") {
		t.Fatalf("blocked plan = %#v, want selected and later collection blockers", plan.Blockers)
	}
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v, want safe blocked artifact", err)
	}
	if _, err := os.Stat(plan.PlanPath); err != nil {
		t.Fatalf("blocked plan artifact stat error = %v", err)
	}
	if _, err := os.Lstat(plan.ReceiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt after blocked plan = %v, want absent", err)
	}
}

func writeSigningMultiConfigFailureProject(t *testing.T) (projectPath, externalBase, missingInclude string) {
	t.Helper()
	projectPath = writeStructuredVersionProject(t, true)
	externalDir := t.TempDir()
	externalBase = filepath.Join(externalDir, "Later.xcconfig")
	missingInclude = filepath.Join(externalDir, "MissingInclude.xcconfig")
	if err := os.WriteFile(externalBase, []byte("#include \"MissingInclude.xcconfig\"\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(external base) error = %v", err)
	}

	pbxprojPath := filepath.Join(projectPath, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	fileReferences := `
			CCCCCCCCCCCCCCCCCCCCCCCC /* MissingSelected.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = Configs/MissingSelected.xcconfig; sourceTree = SOURCE_ROOT; };
			DDDDDDDDDDDDDDDDDDDDDDDD /* Later.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = "` + externalBase + `"; sourceTree = "<absolute>"; };`
	marker := "\t\t111111111111111111111111 /* Project object */ = {"
	if !strings.Contains(contents, marker) {
		t.Fatalf("project fixture is missing project object marker")
	}
	contents = strings.Replace(contents, marker, fileReferences+"\n"+marker, 1)
	selectedOld := "999999999999999999999993 /* App Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = AAAAAAAAAAAAAAAAAAAAAAAA;"
	selectedNew := "999999999999999999999993 /* App Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = CCCCCCCCCCCCCCCCCCCCCCCC;"
	if !strings.Contains(contents, selectedOld) {
		t.Fatalf("project fixture is missing selected App Debug base reference")
	}
	contents = strings.Replace(contents, selectedOld, selectedNew, 1)
	widgetOld := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	widgetNew := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = DDDDDDDDDDDDDDDDDDDDDDDD; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	if !strings.Contains(contents, widgetOld) {
		t.Fatalf("project fixture is missing later Widget Debug configuration")
	}
	contents = strings.Replace(contents, widgetOld, widgetNew, 1)
	if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(project) error = %v", err)
	}
	return projectPath, externalBase, missingInclude
}

func TestSigningApplyUsesMetadataPreservingWrites(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte("CODE_SIGN_STYLE = Automatic\r\n"+shared), 0o640); err != nil {
		t.Fatalf("write shared xcconfig error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}},
			{"name":"Release","settings":{"CODE_SIGN_STYLE":"manual"}}
		]}, {"name":"Widget","configurations":[
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
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}

	originalWriter := atomicWriteVersionFileFn
	var writes []preparedVersionWrite
	atomicWriteVersionFileFn = func(write preparedVersionWrite, data []byte) (os.FileInfo, error) {
		writes = append(writes, write)
		return originalWriter(write, data)
	}
	t.Cleanup(func() { atomicWriteVersionFileFn = originalWriter })
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath}); err != nil {
		t.Fatalf("ApplySigningPlan() error = %v", err)
	}
	if len(writes) != 2 {
		t.Fatalf("observed writes = %d, want project and xcconfig writes", len(writes))
	}
	for _, write := range writes {
		if !write.preserveMetadata {
			t.Fatalf("signing write %s did not request metadata preservation", write.path)
		}
	}
}

func TestSigningApplyPreflightsMetadataPreservationBeforeWrites(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	aliasPath := filepath.Join(t.TempDir(), "project.pbxproj")
	if err := os.Link(pbxprojPath, aliasPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
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
	before := mustReadVersionTestFile(t, pbxprojPath)
	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "multiply linked") {
		t.Fatalf("ApplySigningPlan() error = %v, want metadata preflight refusal", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != before {
		t.Fatal("metadata preflight failure changed project before the transaction")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after metadata preflight failure = %v, want absent", statErr)
	}
}

func TestSigningPlanAnchorsEntitlementsToProjectRoot(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, projectRoot string) string
		wantBlocker string
		wantError   bool
	}{
		{
			name:        "missing",
			setup:       func(_ *testing.T, _ string) string { return "App.entitlements" },
			wantBlocker: "no such file",
		},
		{
			name: "directory",
			setup: func(t *testing.T, projectRoot string) string {
				if err := os.Mkdir(filepath.Join(projectRoot, "App.entitlements"), 0o755); err != nil {
					t.Fatalf("Mkdir() error = %v", err)
				}
				return "App.entitlements"
			},
			wantBlocker: "not a regular file",
			wantError:   true,
		},
		{
			name: "symlink",
			setup: func(t *testing.T, projectRoot string) string {
				target := filepath.Join(t.TempDir(), "real.entitlements")
				if err := os.WriteFile(target, []byte("{}\n"), 0o644); err != nil {
					t.Fatalf("WriteFile(target) error = %v", err)
				}
				link := filepath.Join(projectRoot, "App.entitlements")
				if err := os.Symlink(target, link); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				return "App.entitlements"
			},
			wantBlocker: "symlink",
			wantError:   true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, false)
			projectRoot := filepath.Dir(project)
			entitlements := test.setup(t, projectRoot)
			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			writeSigningSettingsTestFile(t, settingsPath, `{
				"schemaVersion": 1,
				"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_ENTITLEMENTS":"`+entitlements+`"}}]}]
			}`)
			plan, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
			})
			if test.wantError {
				if err == nil {
					t.Fatal("BuildSigningPlan() error = nil, want alias-inspection failure")
				}
				if !strings.Contains(err.Error(), test.wantBlocker) {
					t.Fatalf("BuildSigningPlan() error = %v, want %q", err, test.wantBlocker)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildSigningPlan() error = %v", err)
			}
			if plan.Ready {
				t.Fatalf("entitlements %s unexpectedly produced ready plan: %#v", test.name, plan)
			}
			if !strings.Contains(strings.Join(plan.Blockers, "\n"), test.wantBlocker) {
				t.Fatalf("entitlements blockers = %#v, want %q", plan.Blockers, test.wantBlocker)
			}
		})
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

func TestSigningSettingsManifestRejectsDuplicateNestedJSONKeys(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_STYLE":"manual",
			"CODE_SIGN_STYLE":"automatic"
		}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		StateDir: filepath.Join(filepath.Dir(settingsPath), "state"),
	})
	if err == nil || !IsSigningInputError(err) {
		t.Fatalf("BuildSigningPlan() error = %v, want duplicate-key signing input classification", err)
	}
	if !strings.Contains(err.Error(), "duplicate JSON object key") || !strings.Contains(err.Error(), "CODE_SIGN_STYLE") {
		t.Fatalf("BuildSigningPlan() error = %v, want nested duplicate-key diagnostic", err)
	}
}

func TestSigningSettingsManifestRejectsDuplicateTopLevelJSONKeys(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
	})
	if err == nil || !IsSigningInputError(err) {
		t.Fatalf("BuildSigningPlan() error = %v, want duplicate-key signing input classification", err)
	}
	if !strings.Contains(err.Error(), "duplicate JSON object key") || !strings.Contains(err.Error(), "schemaVersion") {
		t.Fatalf("BuildSigningPlan() error = %v, want top-level duplicate-key diagnostic", err)
	}
}

func TestBuildSigningPlanMarksDeterministicManifestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"schemaVersion":1,"targets": [`},
		{name: "wrong schema", body: `{"schemaVersion":2,"targets":[]}`},
		{name: "unsupported setting", body: `{"schemaVersion":1,"targets":[{"name":"App","configurations":[{"name":"Debug","settings":{"OTHER":"x"}}]}]}`},
		{name: "invalid team ID", body: `{"schemaVersion":1,"targets":[{"name":"App","configurations":[{"name":"Debug","settings":{"DEVELOPMENT_TEAM":"short"}}]}]}`},
		{name: "invalid entitlements path", body: `{"schemaVersion":1,"targets":[{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_ENTITLEMENTS":"../App.entitlements"}}]}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, false)
			settingsPath := filepath.Join(t.TempDir(), "settings.json")
			writeSigningSettingsTestFile(t, settingsPath, test.body)
			_, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath,
			})
			if err == nil || !IsSigningInputError(err) {
				t.Fatalf("BuildSigningPlan() error = %v, want signing input classification", err)
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

// injectSigningDirectBuildSetting adds a direct assignment to one existing
// XCBuildConfiguration so a test can model a project that keeps a pbxproj-level
// setting alongside its base xcconfig.
func injectSigningDirectBuildSetting(t *testing.T, pbxprojPath, assignment string) {
	t.Helper()
	const configurationID = "999999999999999999999993"
	data := mustReadVersionTestFile(t, pbxprojPath)
	start := strings.Index(data, configurationID)
	if start < 0 {
		t.Fatalf("configuration %s not found in project", configurationID)
	}
	const marker = "buildSettings = {"
	offset := strings.Index(data[start:], marker)
	if offset < 0 {
		t.Fatalf("buildSettings not found for configuration %s", configurationID)
	}
	insert := start + offset + len(marker)
	updated := data[:insert] + " " + assignment + data[insert:]
	if err := os.WriteFile(pbxprojPath, []byte(updated), 0o644); err != nil {
		t.Fatalf("WriteFile(project) error = %v", err)
	}
}

func TestSigningPlanRetainsInheritedDirectConsumerInSharedConflict(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte("CODE_SIGN_STYLE = Automatic\r\n"+shared), 0o644); err != nil {
		t.Fatalf("write shared xcconfig error = %v", err)
	}
	// Debug keeps a direct assignment that still defers to the shared value.
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`CODE_SIGN_STYLE = "$(inherited)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"automatic"}},
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
	if len(plan.Changes) != 1 {
		t.Fatalf("expected only the conflicting Release override, got %#v", plan.Changes)
	}
	change := plan.Changes[0]
	if change.Configuration != "Release" {
		t.Fatalf("unexpected configuration in change: %#v", change)
	}
	// Rewriting the shared file would also change Debug's inherited value, so
	// the plan must use a target-level override instead.
	if change.Source != "pbxproj" {
		t.Fatalf("shared xcconfig rewritten past an inherited-direct consumer: %#v", change)
	}
}

func TestSigningPlanDigestsXCConfigsUsedOnlyForResolution(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	configDir := filepath.Join(filepath.Dir(project), "Configs")
	sharedPath := filepath.Join(configDir, "Shared.xcconfig")
	appPath := filepath.Join(configDir, "App.xcconfig")
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

	digested := make(map[string]bool, len(plan.Files))
	for _, file := range plan.Files {
		digested[file.Path] = true
	}
	// Shared.xcconfig carries the assignment and is rewritten. App.xcconfig only
	// includes it, but a later overriding assignment there would change the
	// effective value, so it must be digested and rechecked too.
	if !digested[sharedPath] {
		t.Fatalf("mutated xcconfig missing from plan files: %#v", plan.Files)
	}
	if !digested[appPath] {
		t.Fatalf("resolution-only xcconfig %s missing from plan files: %#v", appPath, plan.Files)
	}
}

func TestSigningPlanRevalidatesNoOpReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	injectSigningDirectBuildSetting(t, pbxprojPath,
		`PRODUCT_BUNDLE_IDENTIFIER = com.example.old; CODE_SIGN_IDENTITY = "$(PRODUCT_BUNDLE_IDENTIFIER)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated a reference-dependent identity as a no-op: %#v", plan.Changes)
	}
	if identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want literal requested value", identityChange)
	}
}

func TestSigningPlanRevalidatesTransitiveNoOpReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`PRODUCT_BUNDLE_IDENTIFIER = com.example.old; IDENTITY_ALIAS = "$(PRODUCT_BUNDLE_IDENTIFIER)"; CODE_SIGN_IDENTITY = "$(IDENTITY_ALIAS)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	stateDir := filepath.Join(root, "state")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated a transitive reference-dependent identity as a no-op: %#v", plan.Changes)
	}
	if identityChange.Source != "pbxproj" || identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want literal target-level value", identityChange)
	}

	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}
	result, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err != nil {
		t.Fatalf("ApplySigningPlan() error = %v", err)
	}
	if result == nil || !result.Completed {
		t.Fatalf("ApplySigningPlan() result = %#v, want completed receipt", result)
	}

	updated, err := openStructuredVersionProject(project)
	if err != nil {
		t.Fatalf("reopen project: %v", err)
	}
	configuration, err := signingConfigurationFor(updated, "App", "Debug")
	if err != nil {
		t.Fatalf("find updated configuration: %v", err)
	}
	identity, _, err := newSigningSettingResolver(updated, nil, false).resolveSetting(configuration, "CODE_SIGN_IDENTITY")
	if err != nil {
		t.Fatalf("resolve applied identity: %v", err)
	}
	if identity != "com.example.old" {
		t.Fatalf("applied identity = %q, want requested no-op value", identity)
	}
}

func TestSigningPlanRevalidatesNoOpXCConfigReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	shared = "PRODUCT_BUNDLE_IDENTIFIER = com.example.old\r\nCODE_SIGN_IDENTITY = \"$(PRODUCT_BUNDLE_IDENTIFIER)\"\r\n" + shared
	if err := os.WriteFile(sharedPath, []byte(shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated an xcconfig reference-dependent identity as a no-op: %#v", plan.Changes)
	}
	if identityChange.Source != "pbxproj" || identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want a literal target-level value", identityChange)
	}
}

func TestSigningPlanRevalidatesTransitiveNoOpXCConfigReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	shared = "PRODUCT_BUNDLE_IDENTIFIER = com.example.old\r\nIDENTITY_ALIAS = \"$(PRODUCT_BUNDLE_IDENTIFIER)\"\r\nCODE_SIGN_IDENTITY = \"$(IDENTITY_ALIAS)\"\r\n" + shared
	if err := os.WriteFile(sharedPath, []byte(shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated a transitive xcconfig identity reference as a no-op: %#v", plan.Changes)
	}
	if identityChange.Source != "pbxproj" || identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want literal target-level value", identityChange)
	}
}

func TestSigningPlanRevalidatesTransitiveNoOpReferenceThroughInheritedAlias(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	shared = "PRODUCT_BUNDLE_IDENTIFIER = com.example.old\r\nIDENTITY_ALIAS = \"$(PRODUCT_BUNDLE_IDENTIFIER)\"\r\n" + shared
	if err := os.WriteFile(sharedPath, []byte(shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`IDENTITY_ALIAS = "$(inherited)"; CODE_SIGN_IDENTITY = "$(IDENTITY_ALIAS)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated an inherited transitive identity reference as a no-op: %#v", plan.Changes)
	}
	if identityChange.Source != "pbxproj" || identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want literal target-level value", identityChange)
	}
}

func TestSigningPlanKeepsStableInheritedAliasNoOp(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	shared = "IDENTITY_ALIAS = \"Apple Development\"\r\n" + shared
	if err := os.WriteFile(sharedPath, []byte(shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`IDENTITY_ALIAS = "$(inherited)"; CODE_SIGN_IDENTITY = "$(IDENTITY_ALIAS)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"Apple Development"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	if len(plan.Changes) != 0 {
		t.Fatalf("stable inherited alias produced a spurious change: %#v", plan.Changes)
	}
}

func TestSigningPlanRevalidatesInheritedNoOpXCConfigReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	shared = "PRODUCT_BUNDLE_IDENTIFIER = com.example.old\r\nCODE_SIGN_IDENTITY = \"$(PRODUCT_BUNDLE_IDENTIFIER)\"\r\n" + shared
	if err := os.WriteFile(sharedPath, []byte(shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	// The direct assignment preserves the target's existing scope while
	// inheriting the effective identity from Shared.xcconfig.
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`CODE_SIGN_IDENTITY = "$(inherited)";`)

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.example.old",
			"PRODUCT_BUNDLE_IDENTIFIER":"com.example.new"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	var identityChange, bundleChange *SigningSettingChange
	for index := range plan.Changes {
		change := &plan.Changes[index]
		switch change.Setting {
		case "CODE_SIGN_IDENTITY":
			identityChange = change
		case "PRODUCT_BUNDLE_IDENTIFIER":
			bundleChange = change
		}
	}
	if bundleChange == nil {
		t.Fatalf("plan omitted dependent bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated an inherited reference-dependent identity as a no-op: %#v", plan.Changes)
	}
	if identityChange.Source != "pbxproj" || identityChange.NewValue == nil || *identityChange.NewValue != "com.example.old" {
		t.Fatalf("identity change = %#v, want a literal target-level value", identityChange)
	}
}

func TestSigningPlanRejectsBuildSettingReferenceModifiers(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	structured, err := openStructuredVersionProject(project)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	configuration, err := signingConfigurationFor(structured, "App", "Debug")
	if err != nil {
		t.Fatalf("signingConfigurationFor() error = %v", err)
	}
	resolver := newSigningSettingResolver(structured, nil, false)
	_, _, err = resolver.expandSettingReferences(configuration, "$(MARKETING_VERSION:rfc1034identifier)", map[string]bool{})
	if err == nil || !strings.Contains(err.Error(), "reference modifier") {
		t.Fatalf("expandSettingReferences() error = %v, want unsupported modifier", err)
	}
}

func TestSigningSettingResolverRejectsIncompleteBuildSettingReferences(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	structured, err := openStructuredVersionProject(project)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	configuration, err := signingConfigurationFor(structured, "App", "Debug")
	if err != nil {
		t.Fatalf("signingConfigurationFor() error = %v", err)
	}
	configuration.buildSettings["KNOWN_SETTING"] = "resolved"
	resolver := newSigningSettingResolver(structured, nil, false)
	tests := []struct {
		name      string
		value     string
		wantError bool
		wantValue string
	}{
		{name: "incomplete parenthesis", value: "$(MISSING", wantError: true},
		{name: "incomplete brace", value: "${MISSING", wantError: true},
		{name: "resolved then truncated", value: "prefix-$(KNOWN_SETTING)-${", wantError: true},
		{name: "ordinary dollar", value: "price $5", wantValue: "price $5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, _, err := resolver.expandSettingReferences(configuration, test.value, map[string]bool{})
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "incomplete build-setting reference") {
					t.Fatalf("expandSettingReferences(%q) error = %v, want incomplete-reference error", test.value, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandSettingReferences(%q) error = %v, want nil", test.value, err)
			}
			if value != test.wantValue {
				t.Fatalf("expandSettingReferences(%q) = %q, want %q", test.value, value, test.wantValue)
			}
		})
	}
}

func TestSigningPlanBlocksIncompleteBuildSettingReference(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"), `CODE_SIGN_IDENTITY = "$(MISSING";`)
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"Apple Development"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready {
		t.Fatalf("incomplete build-setting reference produced ready plan: %#v", plan)
	}
	blockers := strings.Join(plan.Blockers, "\n")
	if !strings.Contains(blockers, "CODE_SIGN_IDENTITY") || !strings.Contains(blockers, "incomplete build-setting reference") {
		t.Fatalf("plan blockers = %#v, want incomplete identity reference blocker", plan.Blockers)
	}
}

func TestSigningPlanDoesNotSwallowProjectFallbackResolutionError(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const projectDebug = "999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Debug; };"
	malformedProjectDebug := `999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = { CODE_SIGN_STYLE = "$(MISSING"; }; name = Debug; };`
	if !strings.Contains(contents, projectDebug) {
		t.Fatalf("project fixture is missing project Debug configuration")
	}
	if err := os.WriteFile(pbxprojPath, []byte(strings.Replace(contents, projectDebug, malformedProjectDebug, 1)), 0o644); err != nil {
		t.Fatalf("write project error = %v", err)
	}
	appXCConfig := filepath.Join(filepath.Dir(project), "Configs", "App.xcconfig")
	appContents := mustReadVersionTestFile(t, appXCConfig)
	if err := os.WriteFile(appXCConfig, []byte("CODE_SIGN_STYLE ?= Automatic\n"+appContents), 0o644); err != nil {
		t.Fatalf("write app xcconfig error = %v", err)
	}
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
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready {
		t.Fatalf("project fallback resolution error was swallowed: %#v", plan)
	}
	blockers := strings.Join(plan.Blockers, "\n")
	if !strings.Contains(blockers, "incomplete build-setting reference") || !strings.Contains(blockers, "CODE_SIGN_STYLE") {
		t.Fatalf("plan blockers = %#v, want project fallback resolution error", plan.Blockers)
	}
}

func TestSigningPlanAllowsOptionalXCConfigAssignmentWithoutProjectFallback(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	appXCConfig := filepath.Join(filepath.Dir(project), "Configs", "App.xcconfig")
	appContents := mustReadVersionTestFile(t, appXCConfig)
	if err := os.WriteFile(appXCConfig, []byte("CODE_SIGN_STYLE ?= Automatic\n"+appContents), 0o644); err != nil {
		t.Fatalf("write app xcconfig error = %v", err)
	}
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
		t.Fatalf("BuildSigningPlan() error = %v, want ready plan", err)
	}
	if !plan.Ready {
		t.Fatalf("optional xcconfig assignment without fallback blocked plan: %#v", plan.Blockers)
	}
}

func TestSigningPlanDoesNotSwallowProjectFallbackForAppendingXCConfig(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const projectDebug = "999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Debug; };"
	malformedProjectDebug := `999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = { CODE_SIGN_STYLE = "$(MISSING"; }; name = Debug; };`
	if !strings.Contains(contents, projectDebug) {
		t.Fatalf("project fixture is missing project Debug configuration")
	}
	if err := os.WriteFile(pbxprojPath, []byte(strings.Replace(contents, projectDebug, malformedProjectDebug, 1)), 0o644); err != nil {
		t.Fatalf("write project error = %v", err)
	}
	appXCConfig := filepath.Join(filepath.Dir(project), "Configs", "App.xcconfig")
	appContents := mustReadVersionTestFile(t, appXCConfig)
	if err := os.WriteFile(appXCConfig, []byte("CODE_SIGN_STYLE += Automatic\n"+appContents), 0o644); err != nil {
		t.Fatalf("write app xcconfig error = %v", err)
	}
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
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready {
		t.Fatalf("appending xcconfig swallowed project fallback resolution error: %#v", plan)
	}
	blockers := strings.Join(plan.Blockers, "\n")
	if !strings.Contains(blockers, "incomplete build-setting reference") || !strings.Contains(blockers, "CODE_SIGN_STYLE") {
		t.Fatalf("plan blockers = %#v, want project fallback resolution error", plan.Blockers)
	}
}

func TestSigningPlanAllowsDirectXCConfigOverrideWithInvalidProjectFallback(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const projectDebug = "999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Debug; };"
	malformedProjectDebug := `999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = { CODE_SIGN_STYLE = "$(MISSING"; }; name = Debug; };`
	if !strings.Contains(contents, projectDebug) {
		t.Fatalf("project fixture is missing project Debug configuration")
	}
	if err := os.WriteFile(pbxprojPath, []byte(strings.Replace(contents, projectDebug, malformedProjectDebug, 1)), 0o644); err != nil {
		t.Fatalf("write project error = %v", err)
	}
	appXCConfig := filepath.Join(filepath.Dir(project), "Configs", "App.xcconfig")
	appContents := mustReadVersionTestFile(t, appXCConfig)
	if err := os.WriteFile(appXCConfig, []byte("CODE_SIGN_STYLE = Automatic\n"+appContents), 0o644); err != nil {
		t.Fatalf("write app xcconfig error = %v", err)
	}
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
		t.Fatalf("BuildSigningPlan() error = %v, want ready plan", err)
	}
	if !plan.Ready {
		t.Fatalf("direct xcconfig override incorrectly inherited project fallback error: %#v", plan.Blockers)
	}
}

func TestSigningPlanDigestsProjectLevelXCConfigUsedForResolution(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	projectRoot := filepath.Dir(project)
	projectConfigPath := filepath.Join(projectRoot, "Configs", "Project.xcconfig")
	if err := os.MkdirAll(filepath.Dir(projectConfigPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(config) error = %v", err)
	}
	if err := os.WriteFile(projectConfigPath, []byte("CODE_SIGN_STYLE = Automatic\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	fileReference := `
		BBBBBBBBBBBBBBBBBBBBBBBB /* Project.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = Configs/Project.xcconfig; sourceTree = SOURCE_ROOT; };`
	marker := "\t\t111111111111111111111111 /* Project object */ = {"
	if !strings.Contains(contents, marker) {
		t.Fatal("project fixture is missing project object marker")
	}
	contents = strings.Replace(contents, marker, fileReference+"\n"+marker, 1)
	projectConfiguration := "999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Debug; };"
	updatedConfiguration := "999999999999999999999991 /* Project Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = BBBBBBBBBBBBBBBBBBBBBBBB; buildSettings = {}; name = Debug; };"
	if !strings.Contains(contents, projectConfiguration) {
		t.Fatal("project fixture is missing project Debug configuration")
	}
	contents = strings.Replace(contents, projectConfiguration, updatedConfiguration, 1)
	if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(project) error = %v", err)
	}

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
	if !plan.Ready {
		t.Fatalf("expected ready plan, got blockers %#v", plan.Blockers)
	}
	for _, file := range plan.Files {
		if file.Path == projectConfigPath {
			return
		}
	}
	t.Fatalf("plan omitted project-level resolution xcconfig %s: %#v", projectConfigPath, plan.Files)
}

func TestOpenStructuredVersionProjectRejectsEscapingSymlinkBeforeParsing(t *testing.T) {
	selectedRoot := t.TempDir()
	outsideRoot := t.TempDir()
	outsideProject := filepath.Join(outsideRoot, "Outside.xcodeproj")
	if err := os.MkdirAll(outsideProject, 0o755); err != nil {
		t.Fatalf("MkdirAll(outside project) error = %v", err)
	}
	// A parser error here proves that the project was opened before its
	// operator-selected root was checked. The preflight must reject the
	// escaping final symlink first.
	if err := os.WriteFile(filepath.Join(outsideProject, "project.pbxproj"), []byte("not a project"), 0o644); err != nil {
		t.Fatalf("WriteFile(outside project) error = %v", err)
	}
	selectedProject := filepath.Join(selectedRoot, "Selected.xcodeproj")
	if err := os.Symlink(outsideProject, selectedProject); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := openStructuredVersionProject(selectedProject)
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("openStructuredVersionProject() error = %v, want rooted symlink rejection", err)
	}
}

func TestSigningPlanProtectsResolvedEntitlementsReference(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	injectSigningDirectBuildSetting(t, pbxprojPath,
		`ENTITLEMENTS_FILE = App.entitlements; CODE_SIGN_ENTITLEMENTS = "$(ENTITLEMENTS_FILE)";`)
	entitlementsPath := filepath.Join(filepath.Dir(project), "App.entitlements")
	if err := os.WriteFile(entitlementsPath, []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(entitlements) error = %v", err)
	}

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
		t.Fatalf("BuildSigningPlan() error = %v, want resolved entitlement reference accepted", err)
	}
	if !plan.Ready {
		t.Fatalf("resolved entitlement reference blocked plan: %#v", plan.Blockers)
	}
	structured, err := openStructuredVersionProject(project)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	paths, _, err := signingProjectInputPaths(structured, settingsPath, nil, []signingRequest{{
		target: "App", configuration: "Debug",
		settings: []signingDesiredSetting{{key: "CODE_SIGN_STYLE", value: stringPtr("manual")}},
	}}, false)
	if err != nil {
		t.Fatalf("signingProjectInputPaths() error = %v", err)
	}
	foundEntitlements := false
	for _, path := range paths {
		if path == entitlementsPath {
			foundEntitlements = true
		}
		if strings.Contains(path, "$(") || strings.Contains(path, "${") {
			t.Fatalf("input path retained unresolved entitlement expression: %q", path)
		}
	}
	if !foundEntitlements {
		t.Fatalf("input paths omitted resolved entitlement input %s: %#v", entitlementsPath, paths)
	}
}
