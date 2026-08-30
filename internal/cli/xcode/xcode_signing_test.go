package xcode

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

func TestXcodeHelpScopesMacOSRequirementToXcodeTooling(t *testing.T) {
	command := XcodeCommand()
	if strings.Contains(command.ShortHelp, "macOS only") {
		t.Fatalf("Xcode short help overstates platform restriction: %q", command.ShortHelp)
	}
	if !strings.Contains(command.ShortHelp, "signing-settings helpers") {
		t.Fatalf("Xcode short help omits signing helpers: %q", command.ShortHelp)
	}
	if !strings.Contains(command.LongHelp, "build/archive/export commands") || !strings.Contains(command.LongHelp, "are supported\non macOS only") {
		t.Fatalf("Xcode long help does not scope macOS requirement to Xcode tooling: %q", command.LongHelp)
	}
	if !strings.Contains(command.LongHelp, "signing plan/apply helpers") || !strings.Contains(command.LongHelp, "supported on every platform") {
		t.Fatalf("Xcode long help does not advertise cross-platform signing helpers: %q", command.LongHelp)
	}
}

func TestXcodeSigningApplyRequiresConfirm(t *testing.T) {
	command := xcodeSigningApplyCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.FlagSet.Parse([]string{"--plan", "plan.json"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	err := command.Exec(context.Background(), nil)
	if !isUsageError(err) {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestXcodeSigningPlanWritesBlockedPlan(t *testing.T) {
	originalBuild := runBuildSigningPlan
	originalWrite := writeSigningPlanArtifact
	t.Cleanup(func() {
		runBuildSigningPlan = originalBuild
		writeSigningPlanArtifact = originalWrite
	})
	calledWrite := false
	runBuildSigningPlan = func(localxcode.SigningPlanOptions) (*localxcode.SigningPlan, error) {
		return &localxcode.SigningPlan{Ready: false, Blockers: []string{"blocked"}, PlanPath: "plan.json"}, nil
	}
	writeSigningPlanArtifact = func(*localxcode.SigningPlan, bool) error {
		calledWrite = true
		return nil
	}
	command := xcodeSigningPlanCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.FlagSet.Parse([]string{"--project", "App.xcodeproj", "--settings-file", "settings.json", "--output", "json"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if err := command.Exec(context.Background(), nil); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if !calledWrite {
		t.Fatal("blocked plan was not written")
	}
}

func TestXcodeSigningPlanValidatesOutputBeforeBuildOrWrite(t *testing.T) {
	originalBuild := runBuildSigningPlan
	originalWrite := writeSigningPlanArtifact
	t.Cleanup(func() {
		runBuildSigningPlan = originalBuild
		writeSigningPlanArtifact = originalWrite
	})
	calledBuild := false
	calledWrite := false
	runBuildSigningPlan = func(localxcode.SigningPlanOptions) (*localxcode.SigningPlan, error) {
		calledBuild = true
		return &localxcode.SigningPlan{Ready: true, PlanPath: "plan.json"}, nil
	}
	writeSigningPlanArtifact = func(*localxcode.SigningPlan, bool) error {
		calledWrite = true
		return nil
	}
	command := xcodeSigningPlanCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.FlagSet.Parse([]string{
		"--project", "App.xcodeproj", "--settings-file", "settings.json", "--output", "table", "--pretty",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	err := command.Exec(context.Background(), nil)
	if !isUsageError(err) {
		t.Fatalf("expected output usage error, got %v", err)
	}
	if calledBuild || calledWrite {
		t.Fatalf("invalid output reached side effects: build=%t write=%t", calledBuild, calledWrite)
	}
}

func TestXcodeSigningApplyValidatesOutputBeforeApply(t *testing.T) {
	originalApply := runApplySigningPlan
	t.Cleanup(func() { runApplySigningPlan = originalApply })
	calledApply := false
	runApplySigningPlan = func(localxcode.SigningApplyOptions) (*localxcode.SigningApplyResult, error) {
		calledApply = true
		return &localxcode.SigningApplyResult{PlanPath: "plan.json"}, nil
	}
	command := xcodeSigningApplyCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.FlagSet.Parse([]string{"--plan", "plan.json", "--confirm", "--output", "invalid"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	err := command.Exec(context.Background(), nil)
	if !isUsageError(err) {
		t.Fatalf("expected output usage error, got %v", err)
	}
	if calledApply {
		t.Fatal("invalid output reached apply side effect")
	}
}

func TestXcodeSigningPlanMapsManifestValidationToReportedUsage(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{name: "malformed JSON", message: "decode settings file: unexpected end of JSON input"},
		{name: "wrong schema", message: "settings file schemaVersion must be 1"},
		{name: "unsupported setting", message: "unsupported signing setting OTHER"},
		{name: "invalid team ID", message: "DEVELOPMENT_TEAM must be a 10-character alphanumeric team ID"},
		{name: "invalid entitlements path", message: "CODE_SIGN_ENTITLEMENTS: path must stay within the project"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalBuild := runBuildSigningPlan
			originalWrite := writeSigningPlanArtifact
			t.Cleanup(func() {
				runBuildSigningPlan = originalBuild
				writeSigningPlanArtifact = originalWrite
			})
			inputErr := localxcode.NewSigningInputError(errors.New(test.message))
			calledWrite := false
			runBuildSigningPlan = func(localxcode.SigningPlanOptions) (*localxcode.SigningPlan, error) {
				return nil, inputErr
			}
			writeSigningPlanArtifact = func(*localxcode.SigningPlan, bool) error {
				calledWrite = true
				return nil
			}
			command := xcodeSigningPlanCommand()
			command.FlagSet.SetOutput(io.Discard)
			if err := command.FlagSet.Parse([]string{
				"--project", "App.xcodeproj", "--settings-file", "settings.json", "--output", "json",
			}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			err := command.Exec(context.Background(), nil)
			if !shared.IsReportedUsageError(err) || errors.Is(err, flag.ErrHelp) {
				t.Fatalf("command error = %v, want reported usage without help wrapping", err)
			}
			if calledWrite {
				t.Fatal("manifest validation reached plan write")
			}
		})
	}
}

func TestXcodeSigningPlanLeavesParseAndFilesystemFailuresUnclassified(t *testing.T) {
	originalBuild := runBuildSigningPlan
	originalWrite := writeSigningPlanArtifact
	t.Cleanup(func() {
		runBuildSigningPlan = originalBuild
		writeSigningPlanArtifact = originalWrite
	})
	runBuildSigningPlan = func(localxcode.SigningPlanOptions) (*localxcode.SigningPlan, error) {
		return nil, errors.New("parse project: permission denied")
	}
	writeSigningPlanArtifact = func(*localxcode.SigningPlan, bool) error {
		t.Fatal("filesystem failure reached plan write")
		return nil
	}
	command := xcodeSigningPlanCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.FlagSet.Parse([]string{
		"--project", "App.xcodeproj", "--settings-file", "settings.json", "--output", "json",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	err := command.Exec(context.Background(), nil)
	if err == nil || shared.IsReportedUsageError(err) || errors.Is(err, flag.ErrHelp) {
		t.Fatalf("command error = %v, want unclassified runtime error", err)
	}
}

func isUsageError(err error) bool {
	return err != nil && (errors.Is(err, flag.ErrHelp) || shared.IsReportedUsageError(err) || strings.Contains(err.Error(), "required"))
}

func TestXcodeSigningPlanRejectsEmptyStateDir(t *testing.T) {
	originalBuild := runBuildSigningPlan
	originalWrite := writeSigningPlanArtifact
	t.Cleanup(func() {
		runBuildSigningPlan = originalBuild
		writeSigningPlanArtifact = originalWrite
	})
	calledBuild := false
	runBuildSigningPlan = func(localxcode.SigningPlanOptions) (*localxcode.SigningPlan, error) {
		calledBuild = true
		return &localxcode.SigningPlan{Ready: true, PlanPath: "plan.json"}, nil
	}
	writeSigningPlanArtifact = func(*localxcode.SigningPlan, bool) error { return nil }

	for _, stateDir := range []string{"", "   "} {
		command := xcodeSigningPlanCommand()
		command.FlagSet.SetOutput(io.Discard)
		if err := command.FlagSet.Parse([]string{
			"--project", "App.xcodeproj",
			"--settings-file", "settings.json",
			"--state-dir", stateDir,
		}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		err := command.Exec(context.Background(), nil)
		if !isUsageError(err) {
			t.Fatalf("--state-dir=%q: expected usage error, got %v", stateDir, err)
		}
		if calledBuild {
			t.Fatalf("--state-dir=%q silently fell back to the default directory", stateDir)
		}
	}
}
