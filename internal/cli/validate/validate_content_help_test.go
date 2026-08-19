package validate

import (
	"strings"
	"testing"
)

func TestValidateHelpDocumentsPlaceholderWarningScope(t *testing.T) {
	cmd := ValidateCommand()
	for _, want := range []string{
		"Placeholder copy in localized listing fields",
		"warning; --strict to block",
	} {
		if !strings.Contains(cmd.LongHelp, want) {
			t.Fatalf("LongHelp missing %q:\n%s", want, cmd.LongHelp)
		}
	}
}
