package signing

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunSigningResignToolNamesFallbackTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX sleep executable")
	}
	output, err := runSigningResignToolWithFallback(context.Background(), 50*time.Millisecond, "/bin/sleep", "1")
	if err == nil {
		t.Fatal("runSigningResignToolWithFallback() error = nil, want fallback timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runSigningResignToolWithFallback() error = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "sleep timed out after 50ms") {
		t.Fatalf("runSigningResignToolWithFallback() error = %v, want the tool and timeout named", err)
	}
	if len(output.Stdout) != 0 {
		t.Fatalf("runSigningResignToolWithFallback() stdout = %q, want empty", output.Stdout)
	}
}

func TestRunSigningResignToolKeepsCallerCancellationBare(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on a POSIX sleep executable")
	}
	callerContext, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	defer cancel()
	_, err := runSigningResignToolWithFallback(callerContext, time.Minute, "/bin/sleep", "1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runSigningResignToolWithFallback() error = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Fatalf("runSigningResignToolWithFallback() error = %v, want caller cancellation without a timeout label", err)
	}
}
