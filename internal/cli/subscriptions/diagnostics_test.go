package subscriptions

import (
	"context"
	"errors"
	"flag"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestSubscriptionsMissingRequiredInputExposesStructuredDiagnostic(t *testing.T) {
	err := SubscriptionsLocalizationsGetCommand().ParseAndRun(context.Background(), nil)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp contract", err)
	}

	diagnostic, ok := shared.DiagnosticFromError(err)
	if !ok {
		t.Fatalf("DiagnosticFromError(%v) did not find metadata", err)
	}
	if diagnostic.Code != shared.DiagnosticRequiredInputMissing || diagnostic.Parameter != "--id" {
		t.Fatalf("diagnostic = %+v, want required_input_missing for --id", diagnostic)
	}
}

func TestSubscriptionsConflictingInputExposesStructuredDiagnostic(t *testing.T) {
	err := SubscriptionsGroupsVersionLocalizationsUpdateCommand().ParseAndRun(context.Background(), []string{
		"--id", "localization-1",
		"--name", "Premium",
		"--clear-name",
	})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp contract", err)
	}

	diagnostic, ok := shared.DiagnosticFromError(err)
	if !ok {
		t.Fatalf("DiagnosticFromError(%v) did not find metadata", err)
	}
	if diagnostic.Code != shared.DiagnosticConflictingInput || diagnostic.Parameter != "--name" {
		t.Fatalf("diagnostic = %+v, want conflicting_input for --name", diagnostic)
	}
}
