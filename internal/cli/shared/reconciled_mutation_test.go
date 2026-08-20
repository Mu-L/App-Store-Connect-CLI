package shared

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestRunReconciledMutationReadsAgainBeforeReplay(t *testing.T) {
	t.Setenv("ASC_MAX_RETRIES", "1")
	t.Setenv("ASC_BASE_DELAY", "1ms")
	t.Setenv("ASC_MAX_DELAY", "1ms")
	mutations := 0
	readbacks := 0

	value, status, err := RunReconciledMutation(
		context.Background(),
		func(context.Context) (string, error) {
			mutations++
			return "", &asc.RetryableError{Err: errors.New("ambiguous timeout")}
		},
		func(context.Context) (string, bool, error) {
			readbacks++
			return "localization-id", readbacks == 2, nil
		},
	)
	if err != nil {
		t.Fatalf("RunReconciledMutation() error: %v", err)
	}
	if value != "localization-id" || status != ReconciledMutationRecovered || mutations != 1 || readbacks != 2 {
		t.Fatalf("unexpected recovery: value=%q status=%q mutations=%d readbacks=%d", value, status, mutations, readbacks)
	}
}

func TestRunReconciledMutationDoesNotRetryRateLimitRejection(t *testing.T) {
	t.Setenv("ASC_MAX_RETRIES", "1")
	t.Setenv("ASC_BASE_DELAY", "1ms")
	t.Setenv("ASC_MAX_DELAY", "1ms")

	mutations := 0
	readbacks := 0
	_, _, err := RunReconciledMutation(
		context.Background(),
		func(context.Context) (string, error) {
			mutations++
			return "", &asc.RetryableError{
				Err: &asc.APIError{Code: "RATE_LIMIT_EXCEEDED", StatusCode: http.StatusTooManyRequests},
			}
		},
		func(context.Context) (string, bool, error) {
			readbacks++
			return "", false, nil
		},
	)
	if err == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
	if mutations != 1 {
		t.Fatalf("expected one mutation invocation after the client retry budget was exhausted, got %d", mutations)
	}
	if readbacks != 1 {
		t.Fatalf("expected one reconciliation readback for a rejected request, got %d", readbacks)
	}
	if !asc.IsRetryable(err) {
		t.Fatalf("expected retryable rate-limit error, got %v", err)
	}
	var statusErr interface{ HTTPStatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.HTTPStatusCode() != http.StatusTooManyRequests {
		t.Fatalf("expected status 429 to remain inspectable, got %v", err)
	}
}

func TestRunReconciledMutationUsesFreshTimeoutForReplay(t *testing.T) {
	t.Setenv("ASC_TIMEOUT", "20ms")
	t.Setenv("ASC_MAX_RETRIES", "1")
	t.Setenv("ASC_BASE_DELAY", "1ms")
	t.Setenv("ASC_MAX_DELAY", "1ms")
	mutations := 0
	readbacks := 0

	value, status, err := RunReconciledMutation(
		context.Background(),
		func(ctx context.Context) (string, error) {
			mutations++
			if mutations == 1 {
				<-ctx.Done()
				return "", ctx.Err()
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("replay received expired context: %v", err)
			}
			return "localization-id", nil
		},
		func(context.Context) (string, bool, error) {
			readbacks++
			return "", false, nil
		},
	)
	if err != nil {
		t.Fatalf("RunReconciledMutation() error: %v", err)
	}
	if value != "localization-id" || status != ReconciledMutationApplied || mutations != 2 || readbacks != 2 {
		t.Fatalf("unexpected replay: value=%q status=%q mutations=%d readbacks=%d", value, status, mutations, readbacks)
	}
}

func TestRunReconciledMutationStopsDuringBackoffCancellation(t *testing.T) {
	t.Setenv("ASC_MAX_RETRIES", "1")
	t.Setenv("ASC_BASE_DELAY", "1h")
	t.Setenv("ASC_MAX_DELAY", "1h")
	ctx, cancel := context.WithCancel(context.Background())
	readbackDone := make(chan struct{})

	go func() {
		<-readbackDone
		cancel()
	}()
	_, _, err := RunReconciledMutation(
		ctx,
		func(context.Context) (string, error) {
			return "", &asc.RetryableError{Err: errors.New("temporary")}
		},
		func(context.Context) (string, bool, error) {
			close(readbackDone)
			return "", false, nil
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestRunReconciledMutationRetriesReadbackChildDeadline(t *testing.T) {
	t.Setenv("ASC_TIMEOUT", "10ms")
	t.Setenv("ASC_MAX_RETRIES", "1")
	t.Setenv("ASC_BASE_DELAY", "1ms")
	t.Setenv("ASC_MAX_DELAY", "1ms")
	readbacks := 0

	value, status, err := RunReconciledMutation(
		context.Background(),
		func(context.Context) (string, error) {
			return "", &asc.RetryableError{Err: errors.New("ambiguous")}
		},
		func(ctx context.Context) (string, bool, error) {
			value, readErr := RetryReadWithFreshTimeout(ctx, func(requestCtx context.Context) (string, error) {
				readbacks++
				if readbacks == 1 {
					<-requestCtx.Done()
					return "", requestCtx.Err()
				}
				return "localization-id", nil
			})
			return value, value != "", readErr
		},
	)
	if err != nil {
		t.Fatalf("RunReconciledMutation() error: %v", err)
	}
	if value != "localization-id" || status != ReconciledMutationRecovered || readbacks != 2 {
		t.Fatalf("unexpected recovery: value=%q status=%q readbacks=%d", value, status, readbacks)
	}
}

func TestRunReconciledMutationDoesNotStartAfterParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	mutations := 0

	_, _, err := RunReconciledMutation(
		ctx,
		func(context.Context) (string, error) {
			mutations++
			return "", nil
		},
		func(context.Context) (string, bool, error) { return "", false, nil },
	)
	if !errors.Is(err, context.DeadlineExceeded) || mutations != 0 {
		t.Fatalf("expected parent deadline before mutation, err=%v mutations=%d", err, mutations)
	}
}
