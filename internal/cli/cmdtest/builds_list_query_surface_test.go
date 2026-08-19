package cmdtest

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
)

// buildsListQuerySurfaceStub installs a transport that captures the query of the
// single builds request the CLI issues and replies with a minimal envelope.
func buildsListQuerySurfaceStub(t *testing.T) func() (string, url.Values) {
	t.Helper()

	setupAuth(t)
	t.Setenv("ASC_APP_ID", "")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))

	originalTransport := http.DefaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	var capturedPath string
	var capturedQuery url.Values

	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		capturedPath = req.URL.Path
		capturedQuery = req.URL.Query()
		body := `{"data":[{"type":"builds","id":"build-1","attributes":{"version":"42"}}]}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}, nil
	})

	return func() (string, url.Values) {
		return capturedPath, capturedQuery
	}
}

func runBuildsListQuerySurface(t *testing.T, args ...string) (string, string, error) {
	t.Helper()

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)

	var runErr error
	stdout, stderr := captureOutput(t, func() {
		if err := root.Parse(args); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		runErr = root.Run(context.Background())
	})

	return stdout, stderr, runErr
}

func TestBuildsListBetaReviewStateEmitsFilter(t *testing.T) {
	captured := buildsListQuerySurfaceStub(t)

	stdout, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--beta-review-state", "WAITING_FOR_REVIEW,IN_REVIEW",
	)
	if err != nil {
		t.Fatalf("run error: %v (stderr=%q)", err, stderr)
	}

	path, query := captured()
	if path != "/v1/builds" {
		t.Fatalf("expected /v1/builds path, got %q", path)
	}
	if got := query.Get("filter[betaAppReviewSubmission.betaReviewState]"); got != "WAITING_FOR_REVIEW,IN_REVIEW" {
		t.Fatalf("expected beta review state filter, got %q", got)
	}
	if got := query.Get("filter[app]"); got != "123456789" {
		t.Fatalf("expected filter[app]=123456789, got %q", got)
	}
	if !strings.Contains(stdout, `"id":"build-1"`) {
		t.Fatalf("expected build envelope, got %q", stdout)
	}
}

func TestBuildsListBetaReviewStateNormalizesCase(t *testing.T) {
	captured := buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--beta-review-state", "approved",
	)
	if err != nil {
		t.Fatalf("run error: %v (stderr=%q)", err, stderr)
	}

	_, query := captured()
	if got := query.Get("filter[betaAppReviewSubmission.betaReviewState]"); got != "APPROVED" {
		t.Fatalf("expected normalized APPROVED, got %q", got)
	}
}

func TestBuildsListBetaReviewStateRejectsUnknownValue(t *testing.T) {
	buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--beta-review-state", "WAITING_FOR_REVIEW,PENDING",
	)

	if got := rootcmd.ExitCodeFromError(err); got != rootcmd.ExitUsage {
		t.Fatalf("exit code = %d, want %d (err=%v)", got, rootcmd.ExitUsage, err)
	}
	for _, want := range []string{"--beta-review-state", "WAITING_FOR_REVIEW", "IN_REVIEW", "REJECTED", "APPROVED"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected stderr to mention %q, got %q", want, stderr)
		}
	}
}

func TestBuildsListIncludeDefaultsToPreReleaseVersion(t *testing.T) {
	captured := buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(t, "builds", "list", "--app", "123456789")
	if err != nil {
		t.Fatalf("run error: %v (stderr=%q)", err, stderr)
	}

	_, query := captured()
	if got := query.Get("include"); got != "preReleaseVersion" {
		t.Fatalf("expected default include=preReleaseVersion, got %q", got)
	}
}

func TestBuildsListIncludeUnionsWithPreReleaseVersion(t *testing.T) {
	captured := buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--include", "app,buildBetaDetail",
	)
	if err != nil {
		t.Fatalf("run error: %v (stderr=%q)", err, stderr)
	}

	_, query := captured()
	if got := query.Get("include"); got != "preReleaseVersion,app,buildBetaDetail" {
		t.Fatalf("expected include to union the table default, got %q", got)
	}
}

func TestBuildsListIncludeDoesNotDuplicatePreReleaseVersion(t *testing.T) {
	captured := buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--include", "preReleaseVersion,betaGroups,preReleaseVersion",
	)
	if err != nil {
		t.Fatalf("run error: %v (stderr=%q)", err, stderr)
	}

	_, query := captured()
	if got := query.Get("include"); got != "preReleaseVersion,betaGroups" {
		t.Fatalf("expected deduplicated include, got %q", got)
	}
}

func TestBuildsListIncludeRejectsUnknownValue(t *testing.T) {
	buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--include", "app,buildBundle",
	)

	if got := rootcmd.ExitCodeFromError(err); got != rootcmd.ExitUsage {
		t.Fatalf("exit code = %d, want %d (err=%v)", got, rootcmd.ExitUsage, err)
	}
	for _, want := range []string{"--include", "preReleaseVersion", "buildBundles", "buildUpload"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("expected stderr to mention %q, got %q", want, stderr)
		}
	}
}

func TestBuildsListSortAcceptsEveryDocumentedKey(t *testing.T) {
	for _, sortValue := range []string{
		"version",
		"-version",
		"uploadedDate",
		"-uploadedDate",
		"preReleaseVersion",
		"-preReleaseVersion",
	} {
		t.Run(sortValue, func(t *testing.T) {
			captured := buildsListQuerySurfaceStub(t)

			_, stderr, err := runBuildsListQuerySurface(
				t,
				"builds", "list",
				"--app", "123456789",
				"--sort", sortValue,
			)
			if err != nil {
				t.Fatalf("run error: %v (stderr=%q)", err, stderr)
			}

			_, query := captured()
			if got := query.Get("sort"); got != sortValue {
				t.Fatalf("expected sort=%q, got %q", sortValue, got)
			}
		})
	}
}

func TestBuildsListSortRejectsUnknownKey(t *testing.T) {
	buildsListQuerySurfaceStub(t)

	_, stderr, err := runBuildsListQuerySurface(
		t,
		"builds", "list",
		"--app", "123456789",
		"--sort", "expirationDate",
	)

	if err == nil {
		t.Fatal("expected an error for an unsupported sort key")
	}
	if !strings.Contains(err.Error(), "--sort must be one of") {
		t.Fatalf("expected sort validation error, got %v (stderr=%q)", err, stderr)
	}
	for _, want := range []string{"version", "uploadedDate", "preReleaseVersion"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to mention %q, got %v", want, err)
		}
	}
}
