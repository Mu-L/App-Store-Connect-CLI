package itunes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

// do executes a public App Store request and hands a successful response to
// handle.
//
// Apple's public endpoints rate limit aggressively, so rate-limited and
// server-side failures are retried with the shared exponential backoff engine.
// Only idempotent reads are replayed. Terminal failures keep the original
// *httpStatusError so callers, output, and telemetry continue to observe the
// public storefront status.
func (c *Client) do(ctx context.Context, operation string, req *http.Request, handle func(*http.Response) error) error {
	retrySafe := req.Method == http.MethodGet || req.Method == http.MethodHead

	// A zero value disables retries, which keeps non-idempotent requests on the
	// single-attempt path.
	var options asc.RetryOptions
	if retrySafe {
		options = asc.ResolveRetryOptions()
	}

	_, err := asc.WithRetry(ctx, func() (struct{}, error) {
		return struct{}{}, c.doOnce(ctx, operation, req, handle, retrySafe, options.MaxDelay)
	}, options)
	return unwrapRetryableError(err)
}

func (c *Client) doOnce(
	ctx context.Context,
	operation string,
	req *http.Request,
	handle func(*http.Response) error,
	retrySafe bool,
	maxDelay time.Duration,
) error {
	resp, err := c.httpClient().Do(req.Clone(ctx))
	if err != nil {
		return fmt.Errorf("%s request failed: %w", operation, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		statusErr := &httpStatusError{operation: operation, statusCode: resp.StatusCode}
		if retrySafe && isRetryablePublicStatus(resp.StatusCode) {
			retryAfter := publicRetryDelay(resp.Header, time.Now(), maxDelay)
			if retryFitsDeadline(ctx, retryAfter) {
				return &asc.RetryableError{Err: statusErr, RetryAfter: retryAfter}
			}
		}
		return statusErr
	}

	return handle(resp)
}

// unwrapRetryableError keeps retry bookkeeping internal so an exhausted retry
// budget surfaces the same error a single attempt would have returned.
func unwrapRetryableError(err error) error {
	if err == nil {
		return nil
	}
	if retryErr, ok := errors.AsType[*asc.RetryableError](err); ok {
		return retryErr.Err
	}
	return err
}

// retryFitsDeadline reports whether waiting out a Retry-After hint still leaves
// the caller time to replay the request. Sleeping past the deadline would only
// trade a storefront status for a deadline error, which callers such as
// `asc reviews ratings --all` escalate instead of skipping the storefront.
func retryFitsDeadline(ctx context.Context, delay time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return time.Until(deadline) > delay
}

// isRetryablePublicStatus reports whether replaying the request could succeed:
// 429 for storefront rate limiting and any 5xx for storefront-side failures.
func isRetryablePublicStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || (statusCode >= 500 && statusCode <= 599)
}

// publicRetryDelay reads the Retry-After hint, which Apple sends either as a
// delay in seconds or as an HTTP date, and caps it at maxDelay.
func publicRetryDelay(headers http.Header, now time.Time, maxDelay time.Duration) time.Duration {
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value == "" {
		return 0
	}

	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return publicRetryDelayFromSeconds(seconds, maxDelay)
	}
	if deadline, err := http.ParseTime(value); err == nil {
		if delay := deadline.Sub(now); delay > 0 {
			return capPublicRetryDelay(delay, maxDelay)
		}
	}
	return 0
}

func publicRetryDelayFromSeconds(seconds int64, maxDelay time.Duration) time.Duration {
	if seconds <= 0 {
		return 0
	}
	if maxDelay > 0 && seconds > int64(maxDelay/time.Second) {
		return maxDelay
	}

	const maxDuration = time.Duration(1<<63 - 1)
	if seconds > int64(maxDuration/time.Second) {
		return maxDuration
	}
	return time.Duration(seconds) * time.Second
}

func capPublicRetryDelay(delay, maxDelay time.Duration) time.Duration {
	if delay > 0 && maxDelay > 0 && delay > maxDelay {
		return maxDelay
	}
	return delay
}
