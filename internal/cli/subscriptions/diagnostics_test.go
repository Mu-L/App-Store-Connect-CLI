package subscriptions

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestSubscriptionsMissingRequiredInputExposesStructuredDiagnostic(t *testing.T) {
	var err error
	stderr := captureSubscriptionsDiagnosticStderr(t, func() {
		err = SubscriptionsLocalizationsGetCommand().ParseAndRun(context.Background(), nil)
	})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp contract", err)
	}
	if got, want := err.Error(), "--id"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if want := "Error: --id is required\n"; !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want diagnostic %q", stderr, want)
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
	var err error
	stderr := captureSubscriptionsDiagnosticStderr(t, func() {
		err = SubscriptionsGroupsVersionLocalizationsUpdateCommand().ParseAndRun(context.Background(), []string{
			"--id", "localization-1",
			"--name", "Premium",
			"--clear-name",
		})
	})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp contract", err)
	}
	if got, want := err.Error(), flag.ErrHelp.Error(); got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if want := "Error: --name cannot be used with --clear-name\n"; !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want diagnostic %q", stderr, want)
	}

	diagnostic, ok := shared.DiagnosticFromError(err)
	if !ok {
		t.Fatalf("DiagnosticFromError(%v) did not find metadata", err)
	}
	if diagnostic.Code != shared.DiagnosticConflictingInput || diagnostic.Parameter != "--name" {
		t.Fatalf("diagnostic = %+v, want conflicting_input for --name", diagnostic)
	}
}

func TestSubscriptionsAlternativeSelectorsLeaveDiagnosticParameterEmpty(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")
	tests := []struct {
		name    string
		command func() interface {
			ParseAndRun(context.Context, []string) error
		}
		wantMessage string
	}{
		{
			name: "subscription list",
			command: func() interface {
				ParseAndRun(context.Context, []string) error
			} {
				return SubscriptionsListCommand()
			},
			wantMessage: "Error: --group-id or --app is required (or set ASC_APP_ID)\n",
		},
		{
			name: "availability view",
			command: func() interface {
				ParseAndRun(context.Context, []string) error
			} {
				return SubscriptionsAvailabilityViewCommand()
			},
			wantMessage: "Error: --availability-id or --subscription-id is required\n",
		},
		{
			name: "availability territories",
			command: func() interface {
				ParseAndRun(context.Context, []string) error
			} {
				return SubscriptionsAvailabilityAvailableTerritoriesCommand()
			},
			wantMessage: "Error: --availability-id or --subscription-id is required\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			stderr := captureSubscriptionsDiagnosticStderr(t, func() {
				err = test.command().ParseAndRun(context.Background(), nil)
			})
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("error = %v, want flag.ErrHelp contract", err)
			}
			if !strings.Contains(stderr, test.wantMessage) {
				t.Fatalf("stderr = %q, want diagnostic %q", stderr, test.wantMessage)
			}
			diagnostic, ok := shared.DiagnosticFromError(err)
			if !ok {
				t.Fatalf("DiagnosticFromError(%v) did not find metadata", err)
			}
			if diagnostic.Code != shared.DiagnosticRequiredInputMissing || diagnostic.Parameter != "" {
				t.Fatalf("diagnostic = %+v, want required_input_missing without a parameter", diagnostic)
			}
		})
	}
}

func captureSubscriptionsDiagnosticStderr(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = original
		_ = reader.Close()
		_ = writer.Close()
	}()

	fn()
	_ = writer.Close()
	os.Stderr = original
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(data)
}
