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

func isUsageError(err error) bool {
	return err != nil && (errors.Is(err, flag.ErrHelp) || shared.IsReportedUsageError(err) || strings.Contains(err.Error(), "required"))
}
