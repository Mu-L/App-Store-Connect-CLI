package cmdtest

import (
	"strings"
	"testing"
)

func TestXcodeSigningPlanApplyCommandsExist(t *testing.T) {
	root := RootCommand("1.2.3")

	group := findSubcommand(root, "xcode", "signing")
	if group == nil {
		t.Fatal("expected xcode signing command group")
	}
	if !strings.HasPrefix(group.ShortHelp, "[experimental]") {
		t.Fatalf("xcode signing group ShortHelp = %q, want experimental marker", group.ShortHelp)
	}

	plan := findSubcommand(root, "xcode", "signing", "plan")
	if plan == nil {
		t.Fatal("expected xcode signing plan command")
	}
	apply := findSubcommand(root, "xcode", "signing", "apply")
	if apply == nil {
		t.Fatal("expected xcode signing apply command")
	}
	if !strings.HasPrefix(plan.ShortHelp, "[experimental]") {
		t.Fatalf("xcode signing plan ShortHelp = %q, want experimental marker", plan.ShortHelp)
	}
	if !strings.HasPrefix(apply.ShortHelp, "[experimental]") {
		t.Fatalf("xcode signing apply ShortHelp = %q, want experimental marker", apply.ShortHelp)
	}
}
