package xcode

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/secureopen"
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

func TestSigningApplyDoesNotUseStablePortableWriteFallback(t *testing.T) {
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
	before := mustReadVersionTestFile(t, filepath.Join(project, "project.pbxproj"))
	originalWriter := atomicWriteVersionFileFn
	atomicWriteVersionFileFn = func(preparedVersionWrite, []byte) (*rootfs.FileIdentity, error) {
		return nil, secureopen.ErrRenameNoReplaceUnsupported
	}
	t.Cleanup(func() { atomicWriteVersionFileFn = originalWriter })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !errors.Is(err, secureopen.ErrRenameNoReplaceUnsupported) {
		t.Fatalf("ApplySigningPlan() error = %v, want signing transaction refusal", err)
	}
	if after := mustReadVersionTestFile(t, filepath.Join(project, "project.pbxproj")); after != before {
		t.Fatal("failed signing transaction modified the project")
	}
}

func TestSigningApplyUnsupportedOnWindowsLeavesProjectUntouched(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("strict signing apply is unsupported only on Windows")
	}
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
	before := mustReadVersionTestFile(t, pbxprojPath)

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if !errors.Is(err, rootfs.ErrFileIdentityMutationUnsupported) {
		t.Fatalf("ApplySigningPlan() error = %v, want ErrFileIdentityMutationUnsupported", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != before {
		t.Fatal("unsupported signing apply modified the project")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after unsupported signing apply = %v, want absent", statErr)
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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

func TestSigningApplyRejectsUntouchedSourceChangeAfterReceiptPublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict signing apply fails closed before publication on Windows")
	}
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
	beforeProjectInfo, err := os.Stat(pbxprojPath)
	if err != nil {
		t.Fatalf("Stat(project) error = %v", err)
	}
	beforeSettings := mustReadVersionTestFile(t, settingsPath)
	replacementPath := filepath.Join(root, "settings-replacement.json")
	swapped := false
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
		identity, err := originalCreator(write, data)
		if err != nil || !write.createOnly || swapped {
			return identity, err
		}
		// The receipt has been published. Replace an untouched source with the
		// same bytes but a new inode before the post-create source check so the
		// transaction must reject the receipt and preserve this replacement.
		swapped = true
		if err := os.WriteFile(replacementPath, []byte(beforeSettings), 0o600); err != nil {
			t.Fatalf("write racing settings replacement: %v", err)
		}
		if err := os.Rename(replacementPath, settingsPath); err != nil {
			t.Fatalf("install racing settings replacement: %v", err)
		}
		return identity, nil
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "after receipt") {
		t.Fatalf("ApplySigningPlan() error = %v, want post-publication source rejection", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("post-publication source rejection left project changes behind")
	}
	afterProjectInfo, err := os.Stat(pbxprojPath)
	if err != nil {
		t.Fatalf("Stat(project after rollback) error = %v", err)
	}
	if afterProjectInfo.Mode().Perm() != beforeProjectInfo.Mode().Perm() {
		t.Fatalf("project mode after rollback = %o, want %o", afterProjectInfo.Mode().Perm(), beforeProjectInfo.Mode().Perm())
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after post-publication source drift = %v, want absent", statErr)
	}
	if after := mustReadVersionTestFile(t, settingsPath); after != beforeSettings {
		t.Fatalf("racing settings replacement was changed: %q", after)
	}
	settingsInfo, err := os.Stat(settingsPath)
	if err != nil {
		t.Fatalf("Stat(settings replacement) error = %v", err)
	}
	if settingsInfo.Mode().Perm() != 0o600 {
		t.Fatalf("racing settings replacement mode = %o, want 600", settingsInfo.Mode().Perm())
	}
}

func TestSigningApplyRejectsCreateOnlySuccessWithoutIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict signing apply fails closed before receipt creation on Windows")
	}
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
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
		if write.createOnly {
			return nil, nil
		}
		return originalCreator(write, data)
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "created identity unavailable") {
		t.Fatalf("ApplySigningPlan() error = %v, want create-only identity failure", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("create-only identity failure left project changes behind")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after create-only identity failure = %v, want absent", statErr)
	}
}

func TestSigningApplyRejectsReceiptContentChangedAfterPublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict signing apply fails closed before receipt publication on Windows")
	}
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
	const racingReceipt = "racing receipt contents\n"
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
		identity, err := originalCreator(write, data)
		if err != nil || !write.createOnly {
			return identity, err
		}
		if err := os.WriteFile(write.path, []byte(racingReceipt), 0o600); err != nil {
			t.Fatalf("change receipt after publication: %v", err)
		}
		return identity, nil
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "verify created file") || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("ApplySigningPlan() error = %v, want receipt-content rejection with safe rollback uncertainty", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("receipt-content rejection left project changes behind")
	}
	if after := mustReadVersionTestFile(t, plan.ReceiptPath); after != racingReceipt {
		t.Fatalf("racing receipt was removed or changed: %q", after)
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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

func TestSigningApplyRollsBackProjectWhenReceiptIdentityObservationFailsAfterPublication(t *testing.T) {
	// Compose a post-publication error with the proven installed identity and
	// verify receipt cleanup plus ordinary project rollback. Observation failures
	// before the destination identity is proven return a nil identity instead.
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
	const transientObservationFailure = "injected post-publication identity observation failure"
	originalCreator := atomicCreateVersionFileFn
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
		info, err := atomicCreatePreparedVersionFile(write, data)
		if err != nil || !write.createOnly {
			return info, err
		}
		// Publication has already returned a proven installed identity; callers
		// may use it for conditional rollback even though a later check fails.
		return info, errors.New(transientObservationFailure)
	}
	t.Cleanup(func() { atomicCreateVersionFileFn = originalCreator })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), transientObservationFailure) {
		t.Fatalf("ApplySigningPlan() error = %v, want retained-identity observation failure", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("receipt identity observation failure left ordinary project changes behind")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after identity observation failure = %v, want absent", statErr)
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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
	atomicCreateVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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
	atomicWriteVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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

func TestSigningPlanRejectsContinuedXCConfigAssignmentBeforeEditing(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	original := mustReadVersionTestFile(t, sharedPath)
	continued := original + "CODE_SIGN_IDENTITY = Apple \\\n Development\n"
	if err := os.WriteFile(sharedPath, []byte(continued), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_IDENTITY":"Apple Distribution"}},
			{"name":"Release","settings":{"CODE_SIGN_IDENTITY":"Apple Distribution"}}
		]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "line continuation") {
		t.Fatalf("BuildSigningPlan() error = %v, want continued-assignment refusal", err)
	}
	if after := mustReadVersionTestFile(t, sharedPath); after != continued {
		t.Fatal("planning a continued assignment modified the xcconfig")
	}
}

func TestSigningPlanIgnoresUnselectedSigningContinuation(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	widgetPath := attachSigningWidgetXCConfig(t, project, "CODE_SIGN_STYLE = Automatic \\\n+\tcontinued\n")
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}
		]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	if !plan.Ready {
		t.Fatalf("unselected signing continuation blocked plan: %#v", plan.Blockers)
	}
	for _, file := range plan.Files {
		if file.Path == widgetPath {
			return
		}
	}
	t.Fatalf("plan omitted unselected consumer input %s: %#v", widgetPath, plan.Files)
}

func TestSigningPlanBlocksUnterminatedQuotedSigningValue(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	before := `DEVELOPMENT_TEAM = "BROKEN` + "\n" + mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte(before), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"DEVELOPMENT_TEAM":"ABCDEFGHIJ"}}
		]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "unterminated quote") {
		t.Fatalf("BuildSigningPlan() = ready %t, blockers %#v", plan.Ready, plan.Blockers)
	}
	if after := mustReadVersionTestFile(t, sharedPath); after != before {
		t.Fatal("planning a malformed quoted assignment modified the xcconfig")
	}
}

func TestSigningPlanBlocksUnsafeQuotedXCConfigValue(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	sharedPath := filepath.Join(filepath.Dir(project), "Configs", "Shared.xcconfig")
	before := `PROVISIONING_PROFILE_SPECIFIER = "Old Profile"` + "\r\n" + mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte(before), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"PROVISIONING_PROFILE_SPECIFIER":"New Profile\\"}},
			{"name":"Release","settings":{"PROVISIONING_PROFILE_SPECIFIER":"New Profile\\"}}
		]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
	}
	if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "trailing backslash") {
		t.Fatalf("BuildSigningPlan() = ready %t, blockers %#v", plan.Ready, plan.Blockers)
	}
	if after := mustReadVersionTestFile(t, sharedPath); after != before {
		t.Fatal("planning an unsafe quoted value modified the xcconfig")
	}
}

func TestSigningPlanBlocksAmbiguousProjectNames(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{
			name: "duplicate target name",
			mutate: func(contents string) string {
				return strings.Replace(contents, "\t\t\tname = Widget;\n\t\t\tproductName = Widget;", "\t\t\tname = App;\n\t\t\tproductName = Widget;", 1)
			},
			want: `multiple targets named "App"`,
		},
		{
			name: "duplicate configuration name",
			mutate: func(contents string) string {
				const original = "999999999999999999999994 /* App Release */ = {isa = XCBuildConfiguration;  buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Release; };"
				const duplicate = "999999999999999999999994 /* App Release */ = {isa = XCBuildConfiguration;  buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
				return strings.Replace(contents, original, duplicate, 1)
			},
			want: `multiple configurations named "Debug"`,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, false)
			pbxprojPath := filepath.Join(project, "project.pbxproj")
			before := mustReadVersionTestFile(t, pbxprojPath)
			mutated := testCase.mutate(before)
			if mutated == before {
				t.Fatal("fixture mutation did not change the project")
			}
			if err := os.WriteFile(pbxprojPath, []byte(mutated), 0o644); err != nil {
				t.Fatalf("WriteFile(project) error = %v", err)
			}
			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			writeSigningSettingsTestFile(t, settingsPath, `{
				"schemaVersion": 1,
				"targets": [{"name":"App","configurations":[
					{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}
				]}]
			}`)

			plan, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
			})
			if err != nil {
				t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
			}
			if plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), testCase.want) {
				t.Fatalf("BuildSigningPlan() = ready %t, blockers %#v, want %q", plan.Ready, plan.Blockers, testCase.want)
			}
			if after := mustReadVersionTestFile(t, pbxprojPath); after != mutated {
				t.Fatal("planning an ambiguous project modified the pbxproj")
			}
		})
	}
}

func TestSigningPlanRejectsDuplicateProjectConfigurationNames(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const original = "999999999999999999999992 /* Project Release */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Release; };"
	const duplicate = "999999999999999999999992 /* Project Release */ = {isa = XCBuildConfiguration; buildSettings = {}; name = Debug; };"
	if !strings.Contains(contents, original) {
		t.Fatal("project fixture is missing project Release configuration")
	}
	if err := os.WriteFile(pbxprojPath, []byte(strings.Replace(contents, original, duplicate, 1)), 0o644); err != nil {
		t.Fatalf("write project error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), `project contains multiple configurations named "Debug"`) {
		t.Fatalf("BuildSigningPlan() error = %v, want duplicate project configuration rejection", err)
	}
}

func TestPrepareSigningOperationsUsesWindowsXCConfigIdentity(t *testing.T) {
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
	configInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat(config) error = %v", err)
	}
	caseVariantInfo, err := os.Stat(caseVariantPath)
	if err != nil {
		t.Fatalf("Stat(case variant) error = %v", err)
	}
	sameFile := os.SameFile(configInfo, caseVariantInfo)
	secondIdentity := "identity:second"
	if sameFile {
		secondIdentity = "identity:first"
	}
	fileIdentities := map[string]string{
		normalizeSigningLexicalPath(configPath):      "identity:first",
		normalizeSigningLexicalPath(caseVariantPath): secondIdentity,
	}
	built := &signingPlanBuild{
		plan:           &SigningPlan{AllowExternalXCConfig: false},
		project:        project,
		fileIdentities: fileIdentities,
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
	defer func() { _ = closeVersionWrites(prepared.writes) }()
	defer func() { _ = prepared.projectRoot.Close() }()
	wantWrites := 2
	if sameFile {
		wantWrites = 1
	}
	if len(prepared.writes) != wantWrites || len(prepared.changedFiles) != wantWrites {
		t.Fatalf("prepared writes = %d, changed files = %#v, want %d identity-grouped writes", len(prepared.writes), prepared.changedFiles, wantWrites)
	}

	plan := &SigningPlan{Files: []SigningPlanFile{{
		Path: configPath, SHA256: signingFileDigestBytes(original), Source: "xcconfig",
	}}}
	if !sameFile {
		plan.Files = append(plan.Files, SigningPlanFile{
			Path: caseVariantPath, SHA256: signingFileDigestBytes(original), Source: "xcconfig",
		})
	}
	if err := verifySigningPlanSources(plan, prepared.writes, fileIdentities); err != nil {
		t.Fatalf("verifySigningPlanSources() error = %v", err)
	}
	fileChanges, err := signingReceiptFileChanges(plan, prepared.writes, prepared.changedFiles, fileIdentities)
	if err != nil {
		t.Fatalf("signingReceiptFileChanges() error = %v", err)
	}
	if len(fileChanges) != wantWrites {
		t.Fatalf("file changes = %#v, want %d", fileChanges, wantWrites)
	}
	if err := commitVersionWrites(prepared.writes); err != nil {
		t.Fatalf("commitVersionWrites() error = %v", err)
	}
	recheckRoot, err := rootfs.New(configDir)
	if err != nil {
		t.Fatalf("rootfs.New(recheck) error = %v", err)
	}
	defer recheckRoot.Close()
	committed := make([]preparedVersionWrite, 0, len(prepared.writes))
	for _, write := range prepared.writes {
		committedIdentity, captureErr := recheckRoot.CaptureFile(filepath.Base(write.path))
		if captureErr != nil {
			t.Fatalf("CaptureFile(%q) error = %v", write.path, captureErr)
		}
		committed = append(committed, preparedVersionWrite{
			path: write.path, name: filepath.Base(write.path), root: recheckRoot,
			original: write.original, updated: write.updated, committedIdentity: committedIdentity,
		})
	}
	if err := verifySigningPlanSourcesBeforeReceipt(plan, committed, prepared.writes, fileIdentities); err != nil {
		t.Fatalf("verifySigningPlanSourcesBeforeReceipt() error = %v", err)
	}
	for _, path := range []string{configPath, caseVariantPath} {
		if got := mustReadVersionTestFile(t, path); !strings.Contains(got, "CODE_SIGN_STYLE = Manual") {
			t.Fatalf("identity-grouped mutation did not apply to %q: %q", path, got)
		}
	}
}

func TestResolveSigningSharedCandidatesCoalescesCaseVariantSameFile(t *testing.T) {
	root := t.TempDir()
	canonicalPath := filepath.Join(root, "Config.xcconfig")
	caseVariantPath := filepath.Join(root, "config.xcconfig")
	if err := os.WriteFile(canonicalPath, []byte("CODE_SIGN_STYLE = Automatic\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	if err := os.Link(canonicalPath, caseVariantPath); err != nil && !errors.Is(err, os.ErrExist) {
		t.Skipf("hard links unavailable: %v", err)
	}
	canonicalInfo, err := os.Stat(canonicalPath)
	if err != nil {
		t.Fatalf("Stat(canonical) error = %v", err)
	}
	caseVariantInfo, err := os.Stat(caseVariantPath)
	if err != nil {
		t.Fatalf("Stat(case variant) error = %v", err)
	}
	if !os.SameFile(canonicalInfo, caseVariantInfo) {
		t.Skip("case-variant paths are distinct files on this filesystem")
	}

	candidates := []signingCandidate{
		{mode: "xcconfig", desired: stringPtr("Manual"), paths: []string{canonicalPath}},
		{mode: "xcconfig", desired: stringPtr("Automatic"), paths: []string{caseVariantPath}},
	}
	identities := map[string]string{
		signingLexicalPathKey(canonicalPath):   canonicalPath,
		signingLexicalPathKey(caseVariantPath): canonicalPath,
	}
	resolveSigningSharedCandidates(candidates, identities)
	for index, candidate := range candidates {
		if candidate.mode != "pbxproj" || len(candidate.paths) != 0 {
			t.Fatalf("candidate[%d] = %#v, want conflicting same-file operation blocked from shared mutation", index, candidate)
		}
	}
}

func TestResolveSigningSharedCandidatesKeepsProvenWindowsCaseDistinctFilesSeparate(t *testing.T) {
	previousOS := runtimeGOOS
	runtimeGOOS = "windows"
	t.Cleanup(func() { runtimeGOOS = previousOS })

	root := t.TempDir()
	firstPath := filepath.Join(root, "Config.xcconfig")
	secondPath := filepath.Join(root, "config.xcconfig")
	identities := map[string]string{
		normalizeSigningLexicalPath(firstPath):  "identity:first",
		normalizeSigningLexicalPath(secondPath): "identity:second",
	}
	if signingXCConfigOperationKey(firstPath, identities) == signingXCConfigOperationKey(secondPath, identities) {
		t.Fatal("proven-distinct Windows xcconfig identities collapsed to one operation key")
	}

	candidates := []signingCandidate{
		{mode: "xcconfig", setting: "CODE_SIGN_STYLE", desired: stringPtr("Manual"), paths: []string{firstPath}},
		{mode: "xcconfig", setting: "CODE_SIGN_STYLE", desired: stringPtr("Automatic"), paths: []string{secondPath}},
	}
	resolveSigningSharedCandidates(candidates, identities)
	for index, candidate := range candidates {
		if candidate.mode != "xcconfig" || len(candidate.paths) != 1 {
			t.Fatalf("candidate[%d] = %#v, want separate case-sensitive file operation", index, candidate)
		}
	}
}

func TestSigningPathLexicallyContainedAcceptsCaseVariantRootOnInsensitiveVolume(t *testing.T) {
	root := t.TempDir()
	caseInsensitive, known := signingCaseInsensitiveVolumeFor(root)
	if !known || !caseInsensitive {
		t.Skip("temporary filesystem is not known to be case-insensitive")
	}

	name := filepath.Base(root)
	variantName := strings.ToUpper(name[:1]) + name[1:]
	if variantName == name {
		variantName = strings.ToLower(name[:1]) + name[1:]
	}
	if variantName == name {
		t.Skip("temporary directory name has no case variant")
	}
	path := filepath.Join(root, "Config.xcconfig")
	if err := os.WriteFile(path, []byte("CODE_SIGN_STYLE = Manual\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}
	variantPath := filepath.Join(filepath.Dir(root), variantName, filepath.Base(path))
	if _, err := os.Stat(variantPath); err != nil {
		t.Fatalf("Stat(case-variant internal path) error = %v", err)
	}

	project := &structuredVersionProject{rootDir: root}
	if !signingPathLexicallyContained(project, variantPath) {
		t.Fatalf("case-variant internal path %q was classified outside %q", variantPath, root)
	}
}

func TestSigningPlanKeepsUnselectedUnresolvedEntitlementsAsUncertainty(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const widgetMarker = "999999999999999999999995 /* Widget Debug */ = {"
	start := strings.Index(contents, widgetMarker)
	if start < 0 {
		t.Fatalf("project fixture is missing Widget Debug configuration")
	}
	const settingsMarker = "buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; };"
	relative := strings.Index(contents[start:], settingsMarker)
	if relative < 0 {
		t.Fatalf("project fixture is missing Widget Debug build settings")
	}
	settingsStart := start + relative
	updated := `buildSettings = { CODE_SIGN_ENTITLEMENTS = "$(MISSING_ENTITLEMENTS)"; MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; };`
	contents = contents[:settingsStart] + updated + contents[settingsStart+len(settingsMarker):]
	if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(project.pbxproj) error = %v", err)
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
		t.Fatalf("BuildSigningPlan() error = %v, want blocked plan with selected target preserved", err)
	}
	if plan.Ready {
		t.Fatalf("unselected unresolved entitlement produced ready plan: %#v", plan)
	}
	blockers := strings.Join(plan.Blockers, "\n")
	if !strings.Contains(blockers, "Widget") || !strings.Contains(blockers, "CODE_SIGN_ENTITLEMENTS") {
		t.Fatalf("plan blockers = %#v, want unselected entitlement uncertainty", plan.Blockers)
	}
}

func TestSigningPlanIgnoresShadowedUnresolvedXCConfigEntitlements(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		assignments string
	}{
		{
			name:        "later assignment replaces unresolved value",
			assignments: "CODE_SIGN_ENTITLEMENTS = $(MISSING)\nCODE_SIGN_ENTITLEMENTS = App.entitlements\n",
		},
		{
			name:        "skipped conditional assignment follows concrete value",
			assignments: "CODE_SIGN_ENTITLEMENTS = App.entitlements\nCODE_SIGN_ENTITLEMENTS ?= $(MISSING)\n",
		},
		{
			name:        "later concrete assignment replaces SDK conditional default",
			assignments: "CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] ?= $(MISSING)\nCODE_SIGN_ENTITLEMENTS = App.entitlements\n",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, true)
			projectRoot := filepath.Dir(project)
			appXCConfig := filepath.Join(projectRoot, "Configs", "App.xcconfig")
			contents := mustReadVersionTestFile(t, appXCConfig) + testCase.assignments
			if err := os.WriteFile(appXCConfig, []byte(contents), 0o644); err != nil {
				t.Fatalf("WriteFile(App.xcconfig) error = %v", err)
			}
			entitlementsPath := filepath.Join(projectRoot, "App.entitlements")
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
				t.Fatalf("BuildSigningPlan() error = %v", err)
			}
			if !plan.Ready {
				t.Fatalf("shadowed entitlement expression blocked plan: %#v", plan.Blockers)
			}
		})
	}
}

func TestSigningPlanRejectsSelectedUnresolvedEntitlements(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"), `CODE_SIGN_ENTITLEMENTS = "$(MISSING_ENTITLEMENTS)";`)
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(t.TempDir(), "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "unresolved build-setting reference") || !strings.Contains(err.Error(), "CODE_SIGN_ENTITLEMENTS") {
		t.Fatalf("BuildSigningPlan() error = %v, want selected entitlement resolution failure", err)
	}
}

func TestSigningPlanClassifiesXCConfigEntitlementPathByConsumer(t *testing.T) {
	tests := []struct {
		name         string
		selectWidget bool
		wantPlan     bool
		wantReady    bool
		wantError    bool
	}{
		{name: "unselected", wantPlan: true, wantReady: false},
		{name: "selected", selectWidget: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, true)
			projectRoot := filepath.Dir(project)
			widgetXCConfig := filepath.Join(projectRoot, "Configs", "Widget.xcconfig")
			if err := os.WriteFile(widgetXCConfig, []byte("CODE_SIGN_ENTITLEMENTS = ../Widget.entitlements\n"), 0o640); err != nil {
				t.Fatalf("write widget xcconfig error = %v", err)
			}
			pbxprojPath := filepath.Join(project, "project.pbxproj")
			contents := mustReadVersionTestFile(t, pbxprojPath)
			const widgetReference = "BBBBBBBBBBBBBBBBBBBBBBBB"
			fileReference := "\t\t" + widgetReference + " /* Widget.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = Configs/Widget.xcconfig; sourceTree = SOURCE_ROOT; };\n"
			marker := "\t\t111111111111111111111111 /* Project object */ = {"
			if !strings.Contains(contents, marker) {
				t.Fatalf("project fixture is missing project object marker")
			}
			contents = strings.Replace(contents, marker, fileReference+marker, 1)
			widgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
			updatedWidgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = " + widgetReference + "; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
			if !strings.Contains(contents, widgetConfiguration) {
				t.Fatalf("project fixture is missing Widget Debug configuration")
			}
			contents = strings.Replace(contents, widgetConfiguration, updatedWidgetConfiguration, 1)
			if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
				t.Fatalf("write project error = %v", err)
			}

			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			targets := `{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}`
			if test.selectWidget {
				targets += `,{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}`
			}
			writeSigningSettingsTestFile(t, settingsPath, `{"schemaVersion":1,"targets":[`+targets+`]}`)

			plan, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
			})
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "CODE_SIGN_ENTITLEMENTS") {
					t.Fatalf("BuildSigningPlan() error = %v, want selected invalid entitlement failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildSigningPlan() error = %v, want blocked plan", err)
			}
			if (plan != nil) != test.wantPlan || plan == nil || plan.Ready != test.wantReady {
				t.Fatalf("plan = %#v, want present=%t ready=%t", plan, test.wantPlan, test.wantReady)
			}
			if !strings.Contains(strings.Join(plan.Blockers, "\n"), "Widget") || !strings.Contains(strings.Join(plan.Blockers, "\n"), "CODE_SIGN_ENTITLEMENTS") {
				t.Fatalf("plan blockers = %#v, want unselected invalid-entitlement blocker", plan.Blockers)
			}
		})
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

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "blocked"),
	})
	if err == nil || !strings.Contains(err.Error(), "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig") {
		t.Fatalf("BuildSigningPlan() without opt-in error = %v, want generic unauthorized external failure", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "blocked", "plan.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("blocked plan artifact after unauthorized external config = %v, want absent", statErr)
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

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig") {
		t.Fatalf("BuildSigningPlan() error = %v, want generic unauthorized external failure without reading source", err)
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

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig") {
		t.Fatalf("BuildSigningPlan() error = %v, want generic unauthorized external failure", err)
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
	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(t.TempDir(), "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig") {
		t.Fatalf("BuildSigningPlan() error = %v, want generic unauthorized external failure", err)
	}
}

func TestSigningPlanRejectsUnselectedExternalXCConfigArtifactCollision(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	before := mustReadVersionTestFile(t, externalPath)
	previousReader := signingXCConfigReadFileFn
	previousStat := signingXCConfigStatFileFn
	previousProspective := signingResolveProspectivePathFn
	previousArtifactInfo := signingArtifactPathInfoFn
	signingXCConfigReadFileFn = func(path string, limit int64) ([]byte, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig read during artifact collision: %s", path)
		}
		return previousReader(path, limit)
	}
	signingXCConfigStatFileFn = func(path string) (os.FileInfo, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig stat/open during artifact collision: %s", path)
		}
		return previousStat(path)
	}
	signingResolveProspectivePathFn = func(path string) (string, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig prospective inspection during artifact collision: %s", path)
		}
		return previousProspective(path)
	}
	signingArtifactPathInfoFn = func(path string) (os.FileInfo, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig artifact inspection: %s", path)
		}
		return previousArtifactInfo(path)
	}
	t.Cleanup(func() {
		signingXCConfigReadFileFn = previousReader
		signingXCConfigStatFileFn = previousStat
		signingResolveProspectivePathFn = previousProspective
		signingArtifactPathInfoFn = previousArtifactInfo
	})
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
	atomicWriteVersionFileFn = func(write preparedVersionWrite, data []byte) (*rootfs.FileIdentity, error) {
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

func TestSigningApplyRejectsHardLinkAddedAfterPreparation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("strict signing apply fails closed before replacement on Windows")
	}
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
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
	beforeProject := mustReadVersionTestFile(t, pbxprojPath)
	aliasPath := filepath.Join(root, "project-alias.pbxproj")
	originalHook := beforeSigningCommitForTest
	beforeSigningCommitForTest = func() {
		beforeSigningCommitForTest = nil
		if err := os.Link(pbxprojPath, aliasPath); err != nil {
			t.Skipf("hard links are unavailable: %v", err)
		}
	}
	t.Cleanup(func() { beforeSigningCommitForTest = originalHook })

	_, err = ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath})
	if err == nil || !strings.Contains(err.Error(), "hard-link state changed") {
		t.Fatalf("ApplySigningPlan() error = %v, want late hard-link rejection", err)
	}
	if after := mustReadVersionTestFile(t, pbxprojPath); after != beforeProject {
		t.Fatal("late hard-link rejection changed the project")
	}
	if after := mustReadVersionTestFile(t, aliasPath); after != beforeProject {
		t.Fatal("late hard-link rejection changed the alias")
	}
	if _, statErr := os.Lstat(plan.ReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("receipt after late hard-link rejection = %v, want absent", statErr)
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
	injectSigningBuildSetting(t, pbxprojPath, "999999999999999999999993", assignment)
}

func injectSigningBuildSetting(t *testing.T, pbxprojPath, configurationID, assignment string) {
	t.Helper()
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

func TestSigningPlanRevalidatesUnselectedConsumerInput(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	widgetPath := attachSigningWidgetXCConfig(t, project, "CODE_SIGN_STYLE = Automatic\n")
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[
			{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}
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
	if err := WriteSigningPlanArtifact(plan, false); err != nil {
		t.Fatalf("WriteSigningPlanArtifact() error = %v", err)
	}
	if err := os.WriteFile(widgetPath, []byte("CODE_SIGN_STYLE = Manual\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(widget xcconfig) error = %v", err)
	}
	if _, err := ApplySigningPlan(SigningApplyOptions{PlanPath: plan.PlanPath}); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("ApplySigningPlan() error = %v, want stale-plan rejection", err)
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
	identity, _, err := newSigningSettingResolver(updated, nil, false, nil).resolveSetting(configuration, "CODE_SIGN_IDENTITY")
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

func TestSigningPlanRevalidatesProjectXCConfigFallbackReferenceAfterDependentChange(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	projectRoot := filepath.Dir(project)
	projectConfigPath := filepath.Join(projectRoot, "Configs", "Project.xcconfig")
	if err := os.WriteFile(projectConfigPath, []byte("PRODUCT_BUNDLE_IDENTIFIER = com.example.old\r\nIDENTITY_ALIAS = \"$(PRODUCT_BUNDLE_IDENTIFIER)\"\r\nCODE_SIGN_IDENTITY = \"$(IDENTITY_ALIAS)\"\r\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(project xcconfig) error = %v", err)
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
		t.Fatalf("WriteFile(project.pbxproj) error = %v", err)
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
		t.Fatalf("plan omitted project fallback bundle-ID change: %#v", plan.Changes)
	}
	if identityChange == nil {
		t.Fatalf("plan treated a project fallback reference-dependent identity as a no-op: %#v", plan.Changes)
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

func TestSigningSettingResolverExpandsProjectFallbackInSelectedTargetContext(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	// The project-level identity references a setting that the selected target
	// overrides. Xcode expands that reference in the target's effective context,
	// not in the project configuration that supplied the fallback value.
	injectSigningBuildSetting(t, pbxprojPath, "999999999999999999999991",
		`PRODUCT_BUNDLE_IDENTIFIER = com.project; CODE_SIGN_IDENTITY = "$(PRODUCT_BUNDLE_IDENTIFIER)";`)
	injectSigningBuildSetting(t, pbxprojPath, "999999999999999999999993",
		`PRODUCT_BUNDLE_IDENTIFIER = com.target;`)
	structured, err := openStructuredVersionProject(project)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	configuration, err := signingConfigurationFor(structured, "App", "Debug")
	if err != nil {
		t.Fatalf("signingConfigurationFor() error = %v", err)
	}
	resolved, _, err := newSigningSettingResolver(structured, nil, false, nil).resolveSetting(configuration, "CODE_SIGN_IDENTITY")
	if err != nil {
		t.Fatalf("resolveSetting(CODE_SIGN_IDENTITY) error = %v", err)
	}
	if resolved != "com.target" {
		t.Fatalf("resolveSetting(CODE_SIGN_IDENTITY) = %q, want selected-target expansion", resolved)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{
			"CODE_SIGN_IDENTITY":"com.project"
		}}]}]
	}`)

	plan, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath, StateDir: filepath.Join(root, "state"),
	})
	if err != nil {
		t.Fatalf("BuildSigningPlan() error = %v", err)
	}
	for _, change := range plan.Changes {
		if change.Setting != "CODE_SIGN_IDENTITY" {
			continue
		}
		if change.OldValue == nil || *change.OldValue != "com.target" {
			t.Fatalf("CODE_SIGN_IDENTITY old value = %#v, want selected-target expansion", change.OldValue)
		}
		if change.NewValue == nil || *change.NewValue != "com.project" {
			t.Fatalf("CODE_SIGN_IDENTITY new value = %#v, want requested project value", change.NewValue)
		}
		return
	}
	t.Fatalf("plan treated project fallback identity as a no-op: %#v", plan.Changes)
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
	resolver := newSigningSettingResolver(structured, nil, false, nil)
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
	resolver := newSigningSettingResolver(structured, nil, false, nil)
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

func TestSigningPlanAllowsDirectlyMissingOptionalXCConfigInclude(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	appXCConfig := filepath.Join(filepath.Dir(project), "Configs", "App.xcconfig")
	contents := mustReadVersionTestFile(t, appXCConfig)
	contents = strings.Replace(contents, `#include "Shared.xcconfig"`, "#include? \"Missing.xcconfig\"\n#include \"Shared.xcconfig\"", 1)
	if err := os.WriteFile(appXCConfig, []byte(contents), 0o644); err != nil {
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
		t.Fatalf("BuildSigningPlan() error = %v, want optional missing include to be ignored", err)
	}
	if !plan.Ready {
		t.Fatalf("optional missing include blocked plan: %#v", plan.Blockers)
	}
}

func TestSigningSettingResolverDoesNotShareOptionalIncludeAuthorizationBetweenConfigurations(t *testing.T) {
	projectPath := writeStructuredVersionProject(t, true)
	project, err := openStructuredVersionProject(projectPath)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v", err)
	}
	app, err := signingConfigurationFor(project, "App", "Debug")
	if err != nil {
		t.Fatalf("find App configuration: %v", err)
	}
	widget, err := signingConfigurationFor(project, "Widget", "Debug")
	if err != nil {
		t.Fatalf("find Widget configuration: %v", err)
	}
	shared := filepath.Join(filepath.Dir(projectPath), "Configs", "LateShared.xcconfig")
	resolver := newSigningSettingResolver(
		project,
		map[string][]string{
			app.id:    {filepath.Join(filepath.Dir(projectPath), "Configs", "App.xcconfig")},
			widget.id: {shared},
		},
		false,
		map[string][]string{app.id: {shared}},
	)
	if err := os.WriteFile(shared, []byte("CODE_SIGN_STYLE = manual\n"), 0o640); err != nil {
		t.Fatalf("write late optional include: %v", err)
	}

	if _, err := resolver.statXCConfigFor(app, shared); err == nil || !strings.Contains(err.Error(), "appeared after configuration collection") {
		t.Fatalf("App stat error = %v, want late-appearance refusal", err)
	}
	if _, err := resolver.readXCConfigFor(app, shared); err == nil || !strings.Contains(err.Error(), "not collected for this configuration") {
		t.Fatalf("App read error = %v, want configuration-bound refusal", err)
	}
	if _, err := resolver.readXCConfigFor(widget, shared); err != nil {
		t.Fatalf("Widget read error = %v, want collected consumer access", err)
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

func TestOpenSigningStructuredVersionProjectRejectsEscapingSymlinkBeforeParsing(t *testing.T) {
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

	_, err := openSigningStructuredVersionProject(selectedProject)
	if err == nil || !errors.Is(err, rootfs.ErrSymlink) {
		t.Fatalf("openSigningStructuredVersionProject() error = %v, want rooted symlink rejection", err)
	}
}

func TestOpenStructuredVersionProjectPreservesSelectedProjectSymlink(t *testing.T) {
	targetProject := writeStructuredVersionProject(t, false)
	selectedRoot := t.TempDir()
	selectedProject := filepath.Join(selectedRoot, "Selected.xcodeproj")
	if err := os.Symlink(targetProject, selectedProject); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	opened, err := openStructuredVersionProject(selectedProject)
	if err != nil {
		t.Fatalf("openStructuredVersionProject() error = %v, want stable symlink compatibility", err)
	}
	selectedAbsolute, err := filepath.Abs(selectedProject)
	if err != nil {
		t.Fatalf("Abs(selected project) error = %v", err)
	}
	if opened.projectPath != filepath.Clean(selectedAbsolute) {
		t.Fatalf("opened project path = %q, want selected spelling %q", opened.projectPath, selectedAbsolute)
	}
}

func TestSigningPlanProtectsConditionalOnlyEntitlementReference(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	externalDir := t.TempDir()
	externalPath := filepath.Join(externalDir, "Widget.xcconfig")
	protectedPlanPath := filepath.Join(externalDir, "plan.json")
	if err := os.WriteFile(externalPath, []byte("CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] = $(ENTITLEMENTS_FILE)\nENTITLEMENTS_FILE = "+protectedPlanPath+"\n"), 0o640); err != nil {
		t.Fatalf("WriteFile(external xcconfig) error = %v", err)
	}
	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const widgetReference = "BBBBBBBBBBBBBBBBBBBBBBBB"
	fileReference := "\t\t" + widgetReference + " /* Widget.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = \"" + externalPath + "\"; sourceTree = \"<absolute>\"; };\n"
	marker := "\t\t111111111111111111111111 /* Project object */ = {"
	if !strings.Contains(contents, marker) {
		t.Fatalf("project fixture is missing project object marker")
	}
	contents = strings.Replace(contents, marker, fileReference+marker, 1)
	widgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	updatedWidgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = " + widgetReference + "; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	if !strings.Contains(contents, widgetConfiguration) {
		t.Fatalf("project fixture is missing Widget Debug configuration")
	}
	contents = strings.Replace(contents, widgetConfiguration, updatedWidgetConfiguration, 1)
	if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(project.pbxproj) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		PlanPath: protectedPlanPath,
		StateDir: filepath.Join(root, "state"), AllowExternalXCConfig: true,
	})
	if err == nil || !strings.Contains(err.Error(), "protected project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want conditional entitlement alias rejection", err)
	}
}

func TestSigningPlanRejectsUninventoriableConditionalPBXEntitlements(t *testing.T) {
	tests := []struct {
		name       string
		assignment string
	}{
		{
			name:       "unknown reference",
			assignment: `"CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*]" = "$(MISSING_ENTITLEMENTS)";`,
		},
		{
			name: "reference cycle",
			assignment: `ENTITLEMENTS_FILE = "$(OTHER_ENTITLEMENTS)"; OTHER_ENTITLEMENTS = "$(ENTITLEMENTS_FILE)"; ` +
				`"CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*]" = "$(ENTITLEMENTS_FILE)";`,
		},
		{
			name:       "unsupported modifier",
			assignment: `ENTITLEMENTS_FILE = "App.entitlements"; "CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*]" = "$(ENTITLEMENTS_FILE:unsupported)";`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, false)
			injectSigningBuildSetting(t, filepath.Join(project, "project.pbxproj"), "999999999999999999999995", test.assignment)
			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			writeSigningSettingsTestFile(t, settingsPath, `{
				"schemaVersion": 1,
				"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
			}`)
			planPath := filepath.Join(root, "plan.json")
			const existingPlan = "existing plan bytes\n"
			if err := os.WriteFile(planPath, []byte(existingPlan), 0o600); err != nil {
				t.Fatalf("WriteFile(existing plan) error = %v", err)
			}

			plan, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath,
				PlanPath: planPath, StateDir: filepath.Join(root, "state"),
			})
			if err != nil {
				t.Fatalf("BuildSigningPlan() error = %v, want blocked plan with uncertainty", err)
			}
			if plan == nil || plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "unresolved conditional CODE_SIGN_ENTITLEMENTS") {
				t.Fatalf("plan = %#v, want unselected conditional uncertainty blocker", plan)
			}
			if got := mustReadVersionTestFile(t, planPath); got != existingPlan {
				t.Fatalf("existing plan changed after conditional entitlement failure: %q", got)
			}
		})
	}
}

func TestSigningPlanRejectsUninventoriableConditionalXCConfigEntitlements(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name:   "unknown reference",
			config: "CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] = $(MISSING_ENTITLEMENTS)\n",
		},
		{
			name: "reference cycle",
			config: "ENTITLEMENTS_FILE = $(OTHER_ENTITLEMENTS)\n" +
				"OTHER_ENTITLEMENTS = $(ENTITLEMENTS_FILE)\n" +
				"CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] = $(ENTITLEMENTS_FILE)\n",
		},
		{
			name:   "unsupported modifier",
			config: "ENTITLEMENTS_FILE = App.entitlements\nCODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] = $(ENTITLEMENTS_FILE:unsupported)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := writeStructuredVersionProject(t, false)
			attachSigningWidgetXCConfig(t, project, test.config)
			root := t.TempDir()
			settingsPath := filepath.Join(root, "settings.json")
			writeSigningSettingsTestFile(t, settingsPath, `{
				"schemaVersion": 1,
				"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
			}`)
			planPath := filepath.Join(root, "plan.json")
			const existingPlan = "existing plan bytes\n"
			if err := os.WriteFile(planPath, []byte(existingPlan), 0o600); err != nil {
				t.Fatalf("WriteFile(existing plan) error = %v", err)
			}

			plan, err := BuildSigningPlan(SigningPlanOptions{
				ProjectPath: project, SettingsFilePath: settingsPath,
				PlanPath: planPath, StateDir: filepath.Join(root, "state"),
			})
			if err != nil {
				t.Fatalf("BuildSigningPlan() error = %v, want blocked plan with uncertainty", err)
			}
			if plan == nil || plan.Ready || !strings.Contains(strings.Join(plan.Blockers, "\n"), "unresolved conditional CODE_SIGN_ENTITLEMENTS") {
				t.Fatalf("plan = %#v, want unselected conditional uncertainty blocker", plan)
			}
			if got := mustReadVersionTestFile(t, planPath); got != existingPlan {
				t.Fatalf("existing plan changed after conditional entitlement failure: %q", got)
			}
		})
	}
}

func TestSigningPlanRejectsUnauthorizedConditionalEntitlementWithoutReadingIt(t *testing.T) {
	project := writeStructuredVersionProject(t, false)
	projectRoot := filepath.Dir(project)
	externalDir := t.TempDir()
	externalPath := filepath.Join(externalDir, "Widget.xcconfig")
	const canary = "UNAUTHORIZED_CONDITIONAL_ENTITLEMENT_CANARY"
	if err := os.WriteFile(externalPath, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(external xcconfig) error = %v", err)
	}
	previousReader := signingXCConfigReadFileFn
	signingXCConfigReadFileFn = func(path string, limit int64) ([]byte, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig was read: %s", path)
		}
		return previousReader(path, limit)
	}
	t.Cleanup(func() { signingXCConfigReadFileFn = previousReader })

	pbxprojPath := filepath.Join(project, "project.pbxproj")
	contents := mustReadVersionTestFile(t, pbxprojPath)
	const widgetReference = "BBBBBBBBBBBBBBBBBBBBBBBB"
	fileReference := "\t\t" + widgetReference + " /* Widget.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = \"" + externalPath + "\"; sourceTree = \"<absolute>\"; };\n"
	marker := "\t\t111111111111111111111111 /* Project object */ = {"
	if !strings.Contains(contents, marker) {
		t.Fatalf("project fixture is missing project object marker")
	}
	contents = strings.Replace(contents, marker, fileReference+marker, 1)
	widgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	updatedWidgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = " + widgetReference + "; buildSettings = { \"CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*]\" = \"$(EXTERNAL_ENTITLEMENTS_FILE)\"; MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	if !strings.Contains(contents, widgetConfiguration) {
		t.Fatalf("project fixture is missing Widget Debug configuration")
	}
	contents = strings.Replace(contents, widgetConfiguration, updatedWidgetConfiguration, 1)
	if err := os.WriteFile(pbxprojPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(project.pbxproj) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	planPath := filepath.Join(root, "plan.json")
	const existingPlan = "existing plan bytes\n"
	if err := os.WriteFile(planPath, []byte(existingPlan), 0o600); err != nil {
		t.Fatalf("WriteFile(existing plan) error = %v", err)
	}

	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		PlanPath: planPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), signingUnauthorizedExternalXCConfigMessage) {
		t.Fatalf("BuildSigningPlan() error = %v, want generic unauthorized external failure", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("BuildSigningPlan() error exposed unauthorized xcconfig contents: %v", err)
	}
	if got := mustReadVersionTestFile(t, planPath); got != existingPlan {
		t.Fatalf("existing plan changed after unauthorized conditional entitlement failure: %q", got)
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "plan.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("project plan artifact after failure = %v, want absent", err)
	}
}

func TestSigningPlanRejectsHiddenConditionalExternalXCConfigWithoutFilesystemAccess(t *testing.T) {
	project, externalDir := externalXCConfigProject(t)
	externalPath := filepath.Join(externalDir, "App.xcconfig")
	root := t.TempDir()
	planPath := filepath.Join(root, "plan.json")
	receiptPath := filepath.Join(root, "receipt.json")
	const existingPlan = "existing plan bytes\n"
	const existingReceipt = "existing receipt bytes\n"
	if err := os.WriteFile(planPath, []byte(existingPlan), 0o600); err != nil {
		t.Fatalf("WriteFile(existing plan) error = %v", err)
	}
	if err := os.WriteFile(receiptPath, []byte(existingReceipt), 0o600); err != nil {
		t.Fatalf("WriteFile(existing receipt) error = %v", err)
	}
	if err := os.WriteFile(externalPath, []byte(
		"CODE_SIGN_ENTITLEMENTS[sdk=iphoneos*] = $(HIDDEN_ENTITLEMENTS)\n"+"HIDDEN_ENTITLEMENTS = "+planPath+"\n"+"HIDDEN_EXTERNAL_CONDITIONAL_CANARY\n",
	), 0o600); err != nil {
		t.Fatalf("WriteFile(external xcconfig) error = %v", err)
	}

	previousReader := signingXCConfigReadFileFn
	previousStat := signingXCConfigStatFileFn
	previousProspective := signingResolveProspectivePathFn
	signingXCConfigReadFileFn = func(path string, limit int64) ([]byte, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig read: %s", path)
		}
		return previousReader(path, limit)
	}
	signingXCConfigStatFileFn = func(path string) (os.FileInfo, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig stat/open: %s", path)
		}
		return previousStat(path)
	}
	signingResolveProspectivePathFn = func(path string) (string, error) {
		if signingLexicalPathEqual(path, externalPath) {
			t.Fatalf("unauthorized external xcconfig prospective path was inspected: %s", path)
		}
		return previousProspective(path)
	}
	t.Cleanup(func() {
		signingXCConfigReadFileFn = previousReader
		signingXCConfigStatFileFn = previousStat
		signingResolveProspectivePathFn = previousProspective
	})

	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"Widget","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		PlanPath: planPath, ReceiptPath: receiptPath,
		StateDir: filepath.Join(root, "state"),
	})
	const wantUnauthorizedExternal = "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig"
	if err == nil || !strings.Contains(err.Error(), wantUnauthorizedExternal) {
		t.Fatalf("BuildSigningPlan() error = %v, want generic unauthorized external failure", err)
	}
	if strings.Contains(err.Error(), "conditional CODE_SIGN_ENTITLEMENTS") {
		t.Fatalf("BuildSigningPlan() classified unread external contents as observed conditional input: %v", err)
	}
	if strings.Contains(err.Error(), "HIDDEN_EXTERNAL_CONDITIONAL_CANARY") || strings.Contains(err.Error(), planPath) {
		t.Fatalf("BuildSigningPlan() exposed hidden external content/path: %v", err)
	}
	if got := mustReadVersionTestFile(t, planPath); got != existingPlan {
		t.Fatalf("existing plan changed after hidden conditional external failure: %q", got)
	}
	if got := mustReadVersionTestFile(t, receiptPath); got != existingReceipt {
		t.Fatalf("existing receipt changed after hidden conditional external failure: %q", got)
	}
}

func attachSigningWidgetXCConfig(t *testing.T, project, contents string) string {
	t.Helper()
	projectRoot := filepath.Dir(project)
	configDir := filepath.Join(projectRoot, "Configs")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(config) error = %v", err)
	}
	configPath := filepath.Join(configDir, "Widget.xcconfig")
	if err := os.WriteFile(configPath, []byte(contents), 0o640); err != nil {
		t.Fatalf("WriteFile(widget xcconfig) error = %v", err)
	}

	pbxprojPath := filepath.Join(project, "project.pbxproj")
	projectContents := mustReadVersionTestFile(t, pbxprojPath)
	const widgetReference = "CCCCCCCCCCCCCCCCCCCCCCCC"
	fileReference := "\t\t" + widgetReference + " /* Widget.xcconfig */ = {isa = PBXFileReference; lastKnownFileType = text.xcconfig; path = Configs/Widget.xcconfig; sourceTree = SOURCE_ROOT; };\n"
	marker := "\t\t111111111111111111111111 /* Project object */ = {"
	if !strings.Contains(projectContents, marker) {
		t.Fatalf("project fixture is missing project object marker")
	}
	projectContents = strings.Replace(projectContents, marker, fileReference+marker, 1)
	widgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	updatedWidgetConfiguration := "999999999999999999999995 /* Widget Debug */ = {isa = XCBuildConfiguration; baseConfigurationReference = " + widgetReference + "; buildSettings = { MARKETING_VERSION = 1.2.3; CURRENT_PROJECT_VERSION = 42; }; name = Debug; };"
	if !strings.Contains(projectContents, widgetConfiguration) {
		t.Fatalf("project fixture is missing Widget Debug configuration")
	}
	projectContents = strings.Replace(projectContents, widgetConfiguration, updatedWidgetConfiguration, 1)
	if err := os.WriteFile(pbxprojPath, []byte(projectContents), 0o644); err != nil {
		t.Fatalf("WriteFile(project.pbxproj) error = %v", err)
	}
	return configPath
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
	paths, _, _, err := signingProjectInputPaths(structured, settingsPath, nil, nil, []signingRequest{{
		target: "App", configuration: "Debug",
		settings: []signingDesiredSetting{{key: "CODE_SIGN_STYLE", value: stringPtr("manual")}},
	}}, false, nil)
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

func TestSigningPlanExpandsInheritedDirectEntitlementForProtectedInputs(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	projectRoot := filepath.Dir(project)
	sharedPath := filepath.Join(projectRoot, "Configs", "Shared.xcconfig")
	shared := mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte("CODE_SIGN_ENTITLEMENTS = App.entitlements\n"+shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	injectSigningDirectBuildSetting(t, filepath.Join(project, "project.pbxproj"),
		`CODE_SIGN_ENTITLEMENTS = "$(inherited)";`)
	entitlementsPath := filepath.Join(projectRoot, "App.entitlements")
	if err := os.WriteFile(entitlementsPath, []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(entitlements) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		PlanPath: entitlementsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "aliases project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want inherited direct entitlement alias protection", err)
	}
}

func TestSigningPlanExpandsInheritedXCConfigEntitlementForProtectedInputs(t *testing.T) {
	project := writeStructuredVersionProject(t, true)
	projectRoot := filepath.Dir(project)
	appPath := filepath.Join(projectRoot, "Configs", "App.xcconfig")
	sharedPath := filepath.Join(projectRoot, "Configs", "Shared.xcconfig")
	app := mustReadVersionTestFile(t, appPath)
	app = strings.Replace(app, "#include \"Shared.xcconfig\"", "#include \"Shared.xcconfig\"\nCODE_SIGN_ENTITLEMENTS = $(inherited)", 1)
	if err := os.WriteFile(appPath, []byte(app), 0o640); err != nil {
		t.Fatalf("WriteFile(App xcconfig) error = %v", err)
	}
	shared := mustReadVersionTestFile(t, sharedPath)
	if err := os.WriteFile(sharedPath, []byte("CODE_SIGN_ENTITLEMENTS = App.entitlements\n"+shared), 0o640); err != nil {
		t.Fatalf("WriteFile(shared xcconfig) error = %v", err)
	}
	entitlementsPath := filepath.Join(projectRoot, "App.entitlements")
	if err := os.WriteFile(entitlementsPath, []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(entitlements) error = %v", err)
	}

	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	writeSigningSettingsTestFile(t, settingsPath, `{
		"schemaVersion": 1,
		"targets": [{"name":"App","configurations":[{"name":"Debug","settings":{"CODE_SIGN_STYLE":"manual"}}]}]
	}`)
	_, err := BuildSigningPlan(SigningPlanOptions{
		ProjectPath: project, SettingsFilePath: settingsPath,
		PlanPath: entitlementsPath, StateDir: filepath.Join(root, "state"),
	})
	if err == nil || !strings.Contains(err.Error(), "aliases project input") {
		t.Fatalf("BuildSigningPlan() error = %v, want inherited xcconfig entitlement alias protection", err)
	}
}
