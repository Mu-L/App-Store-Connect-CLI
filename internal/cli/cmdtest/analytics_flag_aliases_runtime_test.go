package cmdtest

import (
	"errors"
	"flag"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyticsRankedStringAliasesMatchCanonicalCommands(t *testing.T) {
	setupAuth(t)
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	originalTransport := http.DefaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})
	http.DefaultTransport = analyticsAliasTransport(t)

	tests := []struct {
		name          string
		canonicalArgs []string
		aliasArgs     []string
		alias         string
		canonical     string
	}{
		{
			name:          "subscriptions view subscription id",
			canonicalArgs: []string{"subscriptions", "view", "--id", "sub-1"},
			aliasArgs:     []string{"subscriptions", "view", "--subscription-id", "sub-1"},
			alias:         "subscription-id",
			canonical:     "id",
		},
		{
			name:          "subscription screenshot id",
			canonicalArgs: []string{"subscriptions", "review", "screenshots", "delete", "--screenshot-id", "shot-1", "--confirm"},
			aliasArgs:     []string{"subscriptions", "review", "screenshots", "delete", "--id", "shot-1", "--confirm"},
			alias:         "id",
			canonical:     "screenshot-id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonicalStdout, canonicalStderr, canonicalErr := runCommand(t, test.canonicalArgs)
			if canonicalErr != nil {
				t.Fatalf("canonical command error: %v", canonicalErr)
			}
			assertOnlyDeprecatedCommandWarnings(t, canonicalStderr)

			aliasStdout, aliasStderr, aliasErr := runCommand(t, test.aliasArgs)
			if aliasErr != nil {
				t.Fatalf("alias command error: %v", aliasErr)
			}
			warning := "Warning: `--" + test.alias + "` is deprecated. Use `--" + test.canonical + "`."
			requireStderrContainsWarning(t, aliasStderr, warning)
			assertOnlyDeprecatedCommandWarnings(t, aliasStderr)
			if aliasStdout != canonicalStdout {
				t.Fatalf("alias stdout differs from canonical output:\ncanonical: %q\nalias: %q", canonicalStdout, aliasStdout)
			}
		})
	}
}

func TestAnalyticsRankedStringAliasesRejectConflictingValues(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		alias     string
		canonical string
	}{
		{name: "subscriptions view", args: []string{"subscriptions", "view", "--id", "one", "--subscription-id", "two"}, alias: "subscription-id", canonical: "id"},
		{name: "subscriptions screenshots delete", args: []string{"subscriptions", "review", "screenshots", "delete", "--screenshot-id", "one", "--id", "two", "--confirm"}, alias: "id", canonical: "screenshot-id"},
	}

	originalTransport := http.DefaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("conflicting aliases must fail before HTTP: %s %s", req.Method, req.URL.String())
		return nil, errors.New("unexpected request")
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, runErr := runCommand(t, test.args)
			if !errors.Is(runErr, flag.ErrHelp) {
				t.Fatalf("run error = %v, want usage error", runErr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			want := "Error: --" + test.alias + " conflicts with --" + test.canonical + "; use only --" + test.canonical
			if !strings.Contains(stderr, want) {
				t.Fatalf("stderr = %q, want containing %q", stderr, want)
			}
			warning := "Warning: `--" + test.alias + "` is deprecated. Use `--" + test.canonical + "`."
			requireStderrContainsWarning(t, stderr, warning)
		})
	}
}

func analyticsAliasTransport(t *testing.T) http.RoundTripper {
	t.Helper()

	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v1/subscriptions/sub-1":
			return analyticsAliasJSONResponse(http.StatusOK, `{"data":{"type":"subscriptions","id":"sub-1","attributes":{"name":"Subscription"}}}`), nil
		case req.Method == http.MethodDelete && req.URL.Path == "/v1/subscriptionAppStoreReviewScreenshots/shot-1":
			return analyticsAliasJSONResponse(http.StatusNoContent, ""), nil
		default:
			t.Fatalf("unexpected alias test request: %s %s", req.Method, req.URL.String())
			return nil, errors.New("unexpected request")
		}
	})
}

func analyticsAliasJSONResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}
