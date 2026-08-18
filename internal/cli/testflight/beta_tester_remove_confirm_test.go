package testflight

import (
	"context"
	"errors"
	"flag"
	"testing"
)

func TestBetaTestersRemoveCommand_RequiresConfirm(t *testing.T) {
	isolateTestFlightAuthEnvForAddTests(t)

	cmd := BetaTestersRemoveCommand()
	if err := cmd.FlagSet.Parse([]string{
		"--app", "123456789",
		"--email", "tester@example.com",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	err := cmd.Exec(context.Background(), []string{})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("remove without --confirm should fail validation, got %v", err)
	}
}

func TestBetaTestersRemoveCommand_ConfirmPassesValidation(t *testing.T) {
	isolateTestFlightAuthEnvForAddTests(t)

	cmd := BetaTestersRemoveCommand()
	if err := cmd.FlagSet.Parse([]string{
		"--app", "123456789",
		"--email", "tester@example.com",
		"--confirm",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	err := cmd.Exec(context.Background(), []string{})
	if errors.Is(err, flag.ErrHelp) {
		t.Fatalf("remove with --confirm should pass validation, got %v", err)
	}
}
