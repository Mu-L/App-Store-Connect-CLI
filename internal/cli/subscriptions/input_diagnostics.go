package subscriptions

import (
	"flag"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func requiredPositiveIntegerUsageError(fs *flag.FlagSet, name string) error {
	parameter := "--" + name
	err := shared.MissingRequiredUsageError(parameter)
	if flagWasProvided(fs, name) {
		return shared.WithDiagnostic(err, shared.DiagnosticInvalidInput, parameter)
	}
	return err
}
