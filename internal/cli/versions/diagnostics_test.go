package versions

import (
	"context"
	"errors"
	"flag"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestVersionsMissingRequiredInputExposesStructuredDiagnostic(t *testing.T) {
	err := VersionsViewCommand().ParseAndRun(context.Background(), nil)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want flag.ErrHelp contract", err)
	}

	diagnostic, ok := shared.DiagnosticFromError(err)
	if !ok {
		t.Fatalf("DiagnosticFromError(%v) did not find metadata", err)
	}
	if diagnostic.Code != shared.DiagnosticRequiredInputMissing || diagnostic.Parameter != "--version-id" {
		t.Fatalf("diagnostic = %+v, want required_input_missing for --version-id", diagnostic)
	}
}
