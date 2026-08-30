package xcode

import (
	"errors"
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) error {
		if write.createOnly {
			return injectedErr
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) error {
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

func TestSigningPlanAnchorsEntitlementsToProjectRoot(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, projectRoot string) string
		wantBlocker string
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
