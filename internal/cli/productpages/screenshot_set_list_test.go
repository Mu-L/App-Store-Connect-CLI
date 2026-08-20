package productpages

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestScreenshotSetListResultFetchesNestedScreenshots(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/appScreenshotSets/set-1/appScreenshots" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.String())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":[{"type":"appScreenshots","id":"screenshot-1","attributes":{"fileName":"01-home.png"}}]}`)
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	httpClient := server.Client()
	httpClient.Transport = customPageBaseURLRoundTripper{target: serverURL, next: httpClient.Transport}
	client := newCustomPageTestClientWithHTTPClient(t, httpClient)

	result, err := screenshotSetListResult(context.Background(), client, "custom-loc-1", &asc.AppScreenshotSetsResponse{
		Data: []asc.Resource[asc.AppScreenshotSetAttributes]{
			{ID: "set-1", Attributes: asc.AppScreenshotSetAttributes{ScreenshotDisplayType: "APP_IPHONE_65"}},
		},
	})
	if err != nil {
		t.Fatalf("screenshotSetListResult() error: %v", err)
	}
	if result.LocalizationID != "custom-loc-1" || len(result.Sets) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.Sets[0].Screenshots) != 1 || result.Sets[0].Screenshots[0].ID != "screenshot-1" {
		t.Fatalf("nested screenshots = %#v", result.Sets[0].Screenshots)
	}
}
