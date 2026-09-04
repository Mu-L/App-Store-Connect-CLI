package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAppDistributionBuildsExpectedRequest(t *testing.T) {
	var gotPath string
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"type": "apps",
				"id": "app-123",
				"attributes": {
					"name": "Example",
					"bundleId": "com.example.app",
					"distributionType": "CUSTOM",
					"educationDiscountType": "NOT_APPLICABLE"
				}
			}
		}`))
	}))
	defer server.Close()

	got, err := testWebClient(server).GetAppDistribution(context.Background(), "app-123")
	if err != nil {
		t.Fatalf("GetAppDistribution() error = %v", err)
	}
	if gotPath != "/apps/app-123" {
		t.Fatalf("path = %q, want /apps/app-123", gotPath)
	}
	if gotQuery != "" {
		t.Fatalf("query = %q, want empty", gotQuery)
	}
	if got.AppID != "app-123" {
		t.Fatalf("appID = %q, want app-123", got.AppID)
	}
	if got.DistributionType != "CUSTOM" {
		t.Fatalf("distributionType = %q, want CUSTOM", got.DistributionType)
	}
	if got.EducationDiscountType != "NOT_APPLICABLE" {
		t.Fatalf("educationDiscountType = %q, want NOT_APPLICABLE", got.EducationDiscountType)
	}
	if got.BundleID != "com.example.app" {
		t.Fatalf("bundleId = %q, want com.example.app", got.BundleID)
	}
}

func TestGetAppDistributionOmitsMissingAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": {"type": "apps", "id": "app-456", "attributes": {"name": "Example"}}}`))
	}))
	defer server.Close()

	got, err := testWebClient(server).GetAppDistribution(context.Background(), "app-456")
	if err != nil {
		t.Fatalf("GetAppDistribution() error = %v", err)
	}
	if got.DistributionType != "" || got.EducationDiscountType != "" {
		t.Fatalf("expected empty distribution attributes, got %+v", got)
	}
	if got.AppID != "app-456" {
		t.Fatalf("appID = %q, want app-456", got.AppID)
	}
}

func TestGetAppDistributionRequiresAppID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL.Path)
	}))
	defer server.Close()

	if _, err := testWebClient(server).GetAppDistribution(context.Background(), "  "); err == nil {
		t.Fatal("expected error for empty app id")
	}
}

func TestGetAppDistributionPropagatesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":[{"status":"403","code":"FORBIDDEN_ERROR","title":"Access denied","detail":"no access"}]}`))
	}))
	defer server.Close()

	if _, err := testWebClient(server).GetAppDistribution(context.Background(), "app-123"); err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestSetAppDistributionBuildsJSONAPIRequestAndVerifiesWithoutTouchingRecipients(t *testing.T) {
	var requestCount int
	var gotQuery string
	var gotPatch struct {
		Data struct {
			ID         string            `json:"id"`
			Type       string            `json:"type"`
			Attributes map[string]string `json:"attributes"`
		} `json:"data"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != "/apps/app-123" {
			t.Fatalf("unexpected path %s; custom recipient endpoints must not be called", r.URL.Path)
		}
		switch r.Method {
		case http.MethodGet:
			gotQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			if requestCount == 1 {
				_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"CUSTOM","educationDiscountType":"NOT_APPLICABLE"}}}`))
		case http.MethodPatch:
			if err := json.NewDecoder(r.Body).Decode(&gotPatch); err != nil {
				t.Fatalf("decode PATCH: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	result, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeCustom,
		EducationDiscountType: "",
	})
	if err != nil {
		t.Fatalf("SetAppDistribution() error = %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want preflight GET, PATCH, and verification GET", requestCount)
	}
	if gotQuery != "fields[apps]=distributionType,educationDiscountType" {
		t.Fatalf("query = %q, want captured Apple fields query", gotQuery)
	}
	if gotPatch.Data.ID != "app-123" || gotPatch.Data.Type != "apps" {
		t.Fatalf("unexpected JSON:API resource: %+v", gotPatch.Data)
	}
	if gotPatch.Data.Attributes["distributionType"] != AppDistributionTypeCustom || gotPatch.Data.Attributes["educationDiscountType"] != AppDistributionEducationNotApplicable {
		t.Fatalf("unexpected PATCH attributes: %+v", gotPatch.Data.Attributes)
	}
	if result == nil || !result.Changed || !result.Verified || result.Status != "verified" {
		t.Fatalf("unexpected verified receipt: %+v", result)
	}
}

func TestSetAppDistributionEducationOnlyPatchOmitsDistributionType(t *testing.T) {
	var requestCount int
	var gotAttributes map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if requestCount == 1 {
				_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"NOT_DISCOUNTED"}}}`))
		case http.MethodPatch:
			var payload struct {
				Data struct {
					Attributes map[string]string `json:"attributes"`
				} `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode PATCH: %v", err)
			}
			gotAttributes = payload.Data.Attributes
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	result, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeAppStore,
		EducationDiscountType: AppDistributionEducationNotDiscounted,
	})
	if err != nil {
		t.Fatalf("SetAppDistribution() error = %v", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want preflight GET, PATCH, and verification GET", requestCount)
	}
	if _, ok := gotAttributes["distributionType"]; ok {
		t.Fatalf("education-only PATCH unexpectedly included distributionType: %+v", gotAttributes)
	}
	if gotAttributes["educationDiscountType"] != AppDistributionEducationNotDiscounted {
		t.Fatalf("educationDiscountType = %q, want %s", gotAttributes["educationDiscountType"], AppDistributionEducationNotDiscounted)
	}
	if result == nil || !result.Changed || !result.Verified || result.Status != "verified" {
		t.Fatalf("unexpected verified receipt: %+v", result)
	}
}

func TestSetAppDistributionNoOpSkipsPatch(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected %s request for no-op update", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"NOT_DISCOUNTED"}}}`))
	}))
	defer server.Close()

	result, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:            "app-123",
		DistributionType: AppDistributionTypeAppStore,
	})
	if err != nil {
		t.Fatalf("SetAppDistribution() error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want one preflight GET", requestCount)
	}
	if result == nil || result.Changed || !result.Verified || result.Status != "unchanged" {
		t.Fatalf("unexpected no-op receipt: %+v", result)
	}
}

func TestSetAppDistributionRejectsDirectURLBeforePatch(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected %s request after DIRECT_URL preflight", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"DIRECT_URL","educationDiscountType":"NOT_APPLICABLE"}}}`))
	}))
	defer server.Close()

	_, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:            "app-123",
		DistributionType: AppDistributionTypeCustom,
	})
	if err == nil || !strings.Contains(err.Error(), "DIRECT_URL") {
		t.Fatalf("error = %v, want DIRECT_URL refusal", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want preflight GET only", requestCount)
	}
}

func TestSetAppDistributionMarksServerErrorUncertain(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`))
	}))
	defer server.Close()

	result, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeCustom,
		EducationDiscountType: "",
	})
	var uncertainErr *AppDistributionUnverifiedError
	if !errors.As(err, &uncertainErr) {
		t.Fatalf("error = %v, want AppDistributionUnverifiedError", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want preflight GET, failed PATCH, and verification GET", requestCount)
	}
	if result == nil || result.Status != "uncertain" || result.Verified {
		t.Fatalf("unexpected uncertain receipt: %+v", result)
	}
}

func TestSetAppDistributionMarksTransportFailureUncertain(t *testing.T) {
	var requestCount int
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requestCount++
			if r.Method == http.MethodPatch {
				return nil, errors.New("connection reset by peer")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`)),
				Request:    r,
			}, nil
		})},
		baseURL: "https://example.test",
	}

	result, err := client.SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeCustom,
		EducationDiscountType: "",
	})
	var uncertainErr *AppDistributionUnverifiedError
	if !errors.As(err, &uncertainErr) {
		t.Fatalf("error = %v, want AppDistributionUnverifiedError", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want preflight GET, failed PATCH, and verification GET", requestCount)
	}
	if result == nil || result.Status != "uncertain" || result.Verified {
		t.Fatalf("unexpected uncertain receipt: %+v", result)
	}
}

func TestSetAppDistributionDoesNotRetryAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var requestCount int
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requestCount++
			if requestCount > 2 {
				t.Fatalf("unexpected request %d after context cancellation", requestCount)
			}
			if r.Method == http.MethodPatch {
				cancel()
				return nil, context.Canceled
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`)),
				Request:    r,
			}, nil
		})},
		baseURL: "https://example.test",
	}

	result, err := client.SetAppDistribution(ctx, AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeCustom,
		EducationDiscountType: "",
	})
	var uncertainErr *AppDistributionUnverifiedError
	if !errors.As(err, &uncertainErr) {
		t.Fatalf("error = %v, want AppDistributionUnverifiedError", err)
	}
	if !strings.Contains(err.Error(), "verification unavailable because command context expired/canceled; inspect state before retry") {
		t.Fatalf("error = %v, want expired-context diagnostic", err)
	}
	if result == nil || result.Status != "uncertain" || result.Verified {
		t.Fatalf("unexpected uncertain receipt: %+v", result)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want preflight GET and PATCH only", requestCount)
	}
}

func TestSetAppDistributionMarksVerificationMismatchUncertain(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.Method {
		case http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"type":"apps","id":"app-123","attributes":{"distributionType":"APP_STORE","educationDiscountType":"DISCOUNTED"}}}`))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	result, err := testWebClient(server).SetAppDistribution(context.Background(), AppDistributionSetRequest{
		AppID:                 "app-123",
		DistributionType:      AppDistributionTypeCustom,
		EducationDiscountType: "",
	})
	var uncertainErr *AppDistributionUnverifiedError
	if !errors.As(err, &uncertainErr) {
		t.Fatalf("error = %v, want AppDistributionUnverifiedError", err)
	}
	if !strings.Contains(err.Error(), `app distribution update was accepted by Apple but app "app-123" does not report the requested distribution state`) {
		t.Fatalf("error = %v, want accepted-update mismatch diagnostic", err)
	}
	if requestCount != 3 {
		t.Fatalf("request count = %d, want preflight GET, PATCH, and verification GET", requestCount)
	}
	if result == nil || result.Status != "uncertain" || result.Verified {
		t.Fatalf("unexpected mismatch receipt: %+v", result)
	}
}
