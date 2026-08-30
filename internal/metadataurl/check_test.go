package metadataurl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

type fakeChecker struct {
	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeChecker) Check(_ context.Context, rawURL string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[rawURL]++
	return Result{FinalURL: mustParseURL(rawURL), StatusCode: http.StatusOK}, nil
}

func TestCheckAllTrimsSortsAndDeduplicatesURLs(t *testing.T) {
	checker := &fakeChecker{}
	outcomes, err := CheckAll(context.Background(), checker, []string{
		" https://example.com/b ",
		"https://example.com/a",
		"https://example.com/a",
		" ",
	})
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if len(outcomes) != 2 || checker.calls["https://example.com/a"] != 1 || checker.calls["https://example.com/b"] != 1 {
		t.Fatalf("outcomes = %+v, calls = %+v, want two unique trimmed checks", outcomes, checker.calls)
	}
}

func TestCheckAllPreservesIndividualErrorsAndContextCancellation(t *testing.T) {
	checker := checkerFunc(func(ctx context.Context, rawURL string) (Result, error) {
		if rawURL == "https://example.com/fail" {
			return Result{}, errors.New("request failed")
		}
		return Result{FinalURL: mustParseURL(rawURL), StatusCode: http.StatusOK}, nil
	})
	outcomes, err := CheckAll(context.Background(), checker, []string{"https://example.com/fail"})
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if outcomes["https://example.com/fail"].Err == nil {
		t.Fatal("expected individual request error to be retained")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = CheckAll(ctx, checker, []string{"https://example.com/cancel"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckAll() error = %v, want context cancellation", err)
	}
}

type checkerFunc func(context.Context, string) (Result, error)

func (f checkerFunc) Check(ctx context.Context, rawURL string) (Result, error) {
	return f(ctx, rawURL)
}

func TestRedirectPolicyRejectsUnsafeAndExcessiveRedirects(t *testing.T) {
	publicRequest, err := http.NewRequest(http.MethodGet, "https://8.8.8.8/support", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error: %v", err)
	}
	if err := RedirectPolicy(publicRequest, nil); err != nil {
		t.Fatalf("RedirectPolicy() public error: %v", err)
	}

	privateRequest, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/support", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error: %v", err)
	}
	if err := RedirectPolicy(privateRequest, nil); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("RedirectPolicy() private error = %v, want ErrUnsafeTarget", err)
	}

	via := make([]*http.Request, MaxRedirects)
	if err := RedirectPolicy(publicRequest, via); err == nil || err.Error() != "metadata URL exceeded 10 redirects" {
		t.Fatalf("RedirectPolicy() limit error = %v, want redirect limit", err)
	}
}

func TestPublicDialControlRejectsPrivateAddresses(t *testing.T) {
	if err := PublicDialControl(context.Background(), "tcp4", "127.0.0.1:443", nil); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("PublicDialControl() private error = %v, want ErrUnsafeTarget", err)
	}
	if err := PublicDialControl(context.Background(), "tcp4", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("PublicDialControl() public error = %v", err)
	}
}

func mustParseURL(rawURL string) *url.URL {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsed
}
