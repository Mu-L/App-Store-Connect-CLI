package xcodecloud

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXcodeCloudDoctorValidatesOutputBeforeSaveSideEffects(t *testing.T) {
	saveDirectory := filepath.Join(t.TempDir(), "logs")
	command := XcodeCloudDoctorCommand()
	command.FlagSet.SetOutput(io.Discard)
	if err := command.Parse([]string{
		"--run-id", "run-1",
		"--save-logs", saveDirectory,
		"--output", "table",
		"--pretty",
	}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	err := command.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--pretty") {
		t.Fatalf("run error = %v, want invalid output combination", err)
	}
	if _, statErr := os.Stat(saveDirectory); !os.IsNotExist(statErr) {
		t.Fatalf("save directory stat error = %v, want no filesystem side effect", statErr)
	}
}
