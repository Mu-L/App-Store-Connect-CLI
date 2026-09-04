package cmdtest

import (
	"strings"
	"testing"
)

func requireStderrContainsWarning(t *testing.T, stderr, warning string) {
	t.Helper()
	if !strings.Contains(stderr, warning) {
		t.Fatalf("expected stderr to contain warning %q, got %q", warning, stderr)
	}
}
