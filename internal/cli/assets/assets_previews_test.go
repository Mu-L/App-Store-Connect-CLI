package assets

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestAssetsPreviewsListHelpOnlyDocumentsSupportedFlags(t *testing.T) {
	cmd := AssetsPreviewsListCommand()

	for _, unsupported := range []string{"--replace", "--confirm", "--dry-run"} {
		if strings.Contains(cmd.LongHelp, unsupported) {
			t.Errorf("list help must not document unsupported flag %s", unsupported)
		}
	}
}

func TestAssetsPreviewsUploadCommandRejectsSkipExistingWithReplace(t *testing.T) {
	cmd := AssetsPreviewsUploadCommand()
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.FlagSet.Parse([]string{
		"--version-localization", "LOC_ID",
		"--path", "./previews",
		"--device-type", "IPHONE_65",
		"--skip-existing",
		"--replace",
	}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var runErr error
	stdout, stderr := captureOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})

	if stdout != "" {
		t.Fatalf("expected empty stdout, got %q", stdout)
	}
	if !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("expected flag.ErrHelp, got %v", runErr)
	}
	if !strings.Contains(stderr, "--skip-existing and --replace are mutually exclusive") {
		t.Fatalf("expected mutually exclusive error in stderr, got %q", stderr)
	}
}

func TestAssetsPreviewsUploadCommandRejectsUnsupportedFileBeforeAuth(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a-preview.mov", "b-poster.png"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not-empty"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	clientCalled := false
	cmd := assetsPreviewsUploadCommandWithDependencies(previewUploadDependencies{
		GetClient: func() (*asc.Client, error) {
			clientCalled = true
			return &asc.Client{}, nil
		},
	})
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.FlagSet.Parse([]string{
		"--version-localization", "LOC_ID",
		"--path", dir,
		"--device-type", "IPHONE_65",
		"--replace",
		"--confirm",
	}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var runErr error
	stdout, _ := captureOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})

	if stdout != "" {
		t.Fatalf("expected empty stdout, got %q", stdout)
	}
	if runErr == nil {
		t.Fatal("expected unsupported preview file error")
	}
	if !strings.Contains(runErr.Error(), `unsupported preview file extension ".png"`) {
		t.Fatalf("expected local file-type error before auth, got %v", runErr)
	}
	if clientCalled {
		t.Fatal("expected preview file validation before auth/client creation")
	}
}

func TestAssetsPreviewsUploadCommandRejectsMoreThanThreeFilesBeforeAuth(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("preview-%d.mov", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	clientCalled := false
	cmd := assetsPreviewsUploadCommandWithDependencies(previewUploadDependencies{
		GetClient: func() (*asc.Client, error) {
			clientCalled = true
			return &asc.Client{}, nil
		},
	})
	cmd.FlagSet.SetOutput(io.Discard)
	if err := cmd.FlagSet.Parse([]string{
		"--version-localization", "LOC_ID",
		"--path", dir,
		"--device-type", "IPHONE_65",
	}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var runErr error
	stdout, _ := captureOutput(t, func() {
		runErr = cmd.Exec(context.Background(), cmd.FlagSet.Args())
	})

	if stdout != "" {
		t.Fatalf("expected empty stdout, got %q", stdout)
	}
	if runErr == nil {
		t.Fatal("expected preview capacity error")
	}
	if !strings.Contains(runErr.Error(), "at most 3 files") {
		t.Fatalf("expected preview capacity error before auth, got %v", runErr)
	}
	if clientCalled {
		t.Fatal("expected preview capacity validation before auth/client creation")
	}
}

func TestDetectPreviewMimeTypeRejectsRegisteredNonVideoMIME(t *testing.T) {
	_, err := detectPreviewMimeType("poster.png")
	if err == nil {
		t.Fatal("expected unsupported preview file error")
	}
	if !strings.Contains(err.Error(), `unsupported preview file extension ".png"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetectPreviewMimeTypeUsesSupportedVideoMapping(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "preview.mov", want: "video/quicktime"},
		{path: "preview.m4v", want: "video/x-m4v"},
		{path: "preview.MP4", want: "video/mp4"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := detectPreviewMimeType(tt.path)
			if err != nil {
				t.Fatalf("detectPreviewMimeType(%q) error: %v", tt.path, err)
			}
			if got != tt.want {
				t.Fatalf("detectPreviewMimeType(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestUploadPreviewsRejectsUnsupportedFileBeforeRequests(t *testing.T) {
	tests := []struct {
		name    string
		replace bool
		dryRun  bool
	}{
		{name: "replace", replace: true},
		{name: "dry run", dryRun: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "poster.png")
			if err := os.WriteFile(filePath, []byte("not-empty"), 0o600); err != nil {
				t.Fatalf("write invalid preview: %v", err)
			}

			requests := 0
			deleteRequests := 0
			client := newAssetsUploadTestServerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method == http.MethodDelete {
					deleteRequests++
				}
				writeAssetsTestJSON(w, http.StatusInternalServerError, `{"errors":[{"status":"500","detail":"unexpected request"}]}`)
			}))

			_, err := uploadPreviews(
				context.Background(),
				client,
				"LOC_ID",
				"IPHONE_65",
				[]string{filePath},
				false,
				tt.replace,
				tt.dryRun,
			)
			if err == nil {
				t.Fatal("expected unsupported preview file error")
			}
			if !strings.Contains(err.Error(), `unsupported preview file extension ".png"`) {
				t.Fatalf("unexpected error: %v", err)
			}
			if requests != 0 {
				t.Fatalf("requests = %d, want 0", requests)
			}
			if deleteRequests != 0 {
				t.Fatalf("DELETE requests = %d, want 0", deleteRequests)
			}
		})
	}
}

func TestUploadPreviewsRejectsAppendThatWouldExceedSetCapacityBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	files := make([]string, 0, 2)
	for _, name := range []string{"new-1.mov", "new-2.mov"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		files = append(files, path)
	}

	requests := make([]string, 0, 2)
	client := newAssetsUploadTestServerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/appStoreVersionLocalizations/LOC_ID/appPreviewSets":
			writeAssetsTestJSON(w, http.StatusOK, `{"data":[{"type":"appPreviewSets","id":"set-1","attributes":{"previewType":"IPHONE_65"}}]}`)
		case "/v1/appPreviewSets/set-1/appPreviews":
			writeAssetsTestJSON(w, http.StatusOK, `{"data":[{"type":"appPreviews","id":"existing-1","attributes":{"fileName":"old-1.mov"}},{"type":"appPreviews","id":"existing-2","attributes":{"fileName":"old-2.mov"}}]}`)
		default:
			writeAssetsTestJSON(w, http.StatusInternalServerError, `{"errors":[{"status":"500","detail":"unexpected mutation"}]}`)
		}
	}))

	_, err := uploadPreviews(context.Background(), client, "LOC_ID", "IPHONE_65", files, false, false, false)
	if err == nil {
		t.Fatal("expected preview capacity error")
	}
	if !strings.Contains(err.Error(), "would exceed the preview set limit of 3") {
		t.Fatalf("unexpected error: %v", err)
	}
	wantRequests := []string{
		"GET /v1/appStoreVersionLocalizations/LOC_ID/appPreviewSets",
		"GET /v1/appPreviewSets/set-1/appPreviews",
	}
	if fmt.Sprint(requests) != fmt.Sprint(wantRequests) {
		t.Fatalf("requests = %v, want %v", requests, wantRequests)
	}
}

func TestUploadPreviewsAppliesSkipExistingBeforeCapacityCheck(t *testing.T) {
	dir := t.TempDir()
	matchingPath := filepath.Join(dir, "matching.mov")
	matchingContents := []byte("matching-preview")
	if err := os.WriteFile(matchingPath, matchingContents, 0o600); err != nil {
		t.Fatalf("write matching preview: %v", err)
	}
	newPath := filepath.Join(dir, "new.mov")
	if err := os.WriteFile(newPath, []byte("new-preview"), 0o600); err != nil {
		t.Fatalf("write new preview: %v", err)
	}
	matchingChecksum, err := computeFileChecksum(matchingPath)
	if err != nil {
		t.Fatalf("checksum matching preview: %v", err)
	}

	client := newAssetsUploadTestServerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/appStoreVersionLocalizations/LOC_ID/appPreviewSets":
			writeAssetsTestJSON(w, http.StatusOK, `{"data":[{"type":"appPreviewSets","id":"set-1","attributes":{"previewType":"IPHONE_65"}}]}`)
		case "/v1/appPreviewSets/set-1/appPreviews":
			writeAssetsTestJSON(w, http.StatusOK, fmt.Sprintf(`{"data":[{"type":"appPreviews","id":"existing-1","attributes":{"fileName":"matching.mov","sourceFileChecksum":%q}},{"type":"appPreviews","id":"existing-2","attributes":{"fileName":"old.mov","sourceFileChecksum":"old-checksum"}}]}`, matchingChecksum))
		default:
			writeAssetsTestJSON(w, http.StatusInternalServerError, `{"errors":[{"status":"500","detail":"unexpected request"}]}`)
		}
	}))

	result, err := uploadPreviews(context.Background(), client, "LOC_ID", "IPHONE_65", []string{matchingPath, newPath}, true, false, true)
	if err != nil {
		t.Fatalf("uploadPreviews() error: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(result.Results))
	}
	states := map[string]string{}
	for _, item := range result.Results {
		states[item.FileName] = item.State
	}
	if states["matching.mov"] != "skipped" || states["new.mov"] != "would-upload" {
		t.Fatalf("unexpected result states: %v", states)
	}
}

func TestUploadPreviewFilesRollsBackCreatedItemsOnConflict(t *testing.T) {
	requests := make([]string, 0, 1)
	client := newAssetsUploadTestServerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/appPreviews/created-1" {
			writeAssetsTestJSON(w, http.StatusInternalServerError, `{"errors":[{"status":"500","detail":"unexpected request"}]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	uploadCalls := 0
	capacityErr := &asc.APIError{
		Code:       "ENTITY_ERROR.RELATIONSHIP.INVALID",
		Detail:     "The preview set is full.",
		StatusCode: http.StatusConflict,
	}
	_, err := uploadPreviewFiles(
		context.Background(),
		client,
		"set-1",
		[]string{"first.mov", "second.mov"},
		func(_ context.Context, _ *asc.Client, _, filePath string) (asc.AssetUploadResultItem, error) {
			uploadCalls++
			if filePath == "first.mov" {
				return asc.AssetUploadResultItem{AssetID: "created-1"}, nil
			}
			return asc.AssetUploadResultItem{}, capacityErr
		},
	)
	if !errors.Is(err, asc.ErrConflict) {
		t.Fatalf("uploadPreviewFiles() error = %v, want conflict", err)
	}
	if !strings.Contains(err.Error(), "The preview set is full") {
		t.Fatalf("uploadPreviewFiles() error = %v, want original API detail", err)
	}
	if uploadCalls != 2 {
		t.Fatalf("upload calls = %d, want 2", uploadCalls)
	}
	wantRequests := []string{"DELETE /v1/appPreviews/created-1"}
	if fmt.Sprint(requests) != fmt.Sprint(wantRequests) {
		t.Fatalf("requests = %v, want %v", requests, wantRequests)
	}
}

func TestNormalizePreviewTypeCanonicalizesIPhone69Alias(t *testing.T) {
	testCases := []string{
		"IPHONE_69",
		"APP_IPHONE_69",
		" app_iphone_69 ",
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			got, err := normalizePreviewType(input)
			if err != nil {
				t.Fatalf("normalizePreviewType(%q) error: %v", input, err)
			}
			if got != "IPHONE_67" {
				t.Fatalf("normalizePreviewType(%q) = %q, want %q", input, got, "IPHONE_67")
			}
		})
	}
}

func TestNormalizePreviewTypeRejectsUnknownType(t *testing.T) {
	_, err := normalizePreviewType("IPHONE_70")
	if err == nil {
		t.Fatal("normalizePreviewType() expected an error")
	}
	if !strings.Contains(err.Error(), `unsupported preview type "IPHONE_70"`) {
		t.Fatalf("normalizePreviewType() error = %q", err)
	}
}

func TestIsValidPreviewFrameTimeCode(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "frame format", value: "00:00:05:00", want: true},
		{name: "millisecond format", value: "00:00:05.000", want: true},
		{name: "frame upper bound", value: "99:59:59:29", want: true},
		{name: "non numeric", value: "abc", want: false},
		{name: "missing component", value: "00:00:05", want: false},
		{name: "invalid minute", value: "00:60:05:00", want: false},
		{name: "invalid second", value: "00:00:60.000", want: false},
		{name: "invalid frame", value: "00:00:05:30", want: false},
		{name: "invalid millisecond width", value: "00:00:05.00", want: false},
		{name: "invalid separator", value: "00-00-05-00", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidPreviewFrameTimeCode(tt.value); got != tt.want {
				t.Fatalf("isValidPreviewFrameTimeCode(%q) = %t, want %t", tt.value, got, tt.want)
			}
		})
	}
}
