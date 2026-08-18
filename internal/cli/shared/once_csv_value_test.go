package shared

import (
	"flag"
	"strings"
	"testing"
)

func TestOnceCSVValue_RejectsRepeatedUse(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	value := BindOnceCSVFlag(fs, "ids", "Comma-separated IDs")

	if err := value.Set("a,b"); err != nil {
		t.Fatalf("first Set() error: %v", err)
	}
	if got := value.String(); got != "a,b" {
		t.Fatalf("String() = %q, want %q", got, "a,b")
	}

	err := value.Set("c")
	if err == nil {
		t.Fatal("second Set() should fail")
	}
	if !strings.Contains(err.Error(), "--ids") || !strings.Contains(err.Error(), "comma-separated") {
		t.Fatalf("second Set() error should mention --ids and comma-separated usage, got %q", err.Error())
	}
	if got := value.String(); got != "a,b" {
		t.Fatalf("rejected Set() must not overwrite value, got %q", got)
	}
}

func TestOnceCSVValue_ParseRejectsRepeatedFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(nopWriter{})
	BindOnceCSVFlag(fs, "ids", "Comma-separated IDs")

	err := fs.Parse([]string{"--ids", "a", "--ids", "b"})
	if err == nil {
		t.Fatal("parse with repeated --ids should fail")
	}
	if !strings.Contains(err.Error(), "specified multiple times") {
		t.Fatalf("parse error should explain the repetition, got %q", err.Error())
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
