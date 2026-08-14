package cmdtest

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdsPlatformAppCampaignReportRequest(t *testing.T) {
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "AD_ACCOUNT")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))
	payloadPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(payloadPath, []byte(`{"startTime":"2026-08-01","endTime":"2026-08-14"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	installDefaultTransport(t, adsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Host != "api.ads.apple.com" || req.URL.Path != "/v1/reports/apps/campaigns/query" || req.URL.RawQuery != "" {
			t.Fatalf("request = %s %s", req.Method, req.URL.String())
		}
		if got := req.Header.Get("X-AP-Context"); got != "adAccountId=AD_ACCOUNT;" {
			t.Fatalf("X-AP-Context = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["startTime"] != "2026-08-01" || body["endTime"] != "2026-08-14" {
			t.Fatalf("request body = %+v", body)
		}
		return adsJSONResponse(200, `{"result":{"row":[{"campaignId":"123"}]},"pagination":{"totalResults":1}}`), nil
	}))

	root := RootCommand("dev")
	if err := root.Parse([]string{"ads", "platform", "reports", "apps", "campaigns", "--file", payloadPath, "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	stdout, stderr := captureOutput(t, func() {
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if _, ok := output["pagination"]; !ok {
		t.Fatalf("stdout omitted raw pagination envelope: %s", stdout)
	}
}

func TestAdsPlatformChangeHistoryDetailRequest(t *testing.T) {
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "AD_ACCOUNT")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))

	installDefaultTransport(t, adsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/change-history/Campaign.444555666.txn_abc123def456" {
			t.Fatalf("request = %s %s", req.Method, req.URL.String())
		}
		if got := req.URL.Query().Get("limit"); got != "25" {
			t.Fatalf("limit = %q", got)
		}
		if got := req.URL.Query().Get("offset"); got != "10" {
			t.Fatalf("offset = %q", got)
		}
		return adsJSONResponse(200, `{"result":{"detailId":"Campaign.444555666.txn_abc123def456","changes":[]}}`), nil
	}))

	root := RootCommand("dev")
	if err := root.Parse([]string{"ads", "platform", "change-history", "view", "--detail-id", "Campaign.444555666.txn_abc123def456", "--limit", "25", "--offset", "10", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	_, stderr := captureOutput(t, func() {
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestAdsPlatformRecommendationApplyRequiresConfirmBeforeFileAuthOrNetwork(t *testing.T) {
	isolateAdsGuideEnv(t)
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "")
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))
	installDefaultTransport(t, adsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected network request: %s %s", req.Method, req.URL.String())
		return nil, nil
	}))

	root := RootCommand("dev")
	if err := root.Parse([]string{"ads", "platform", "recommendations", "daily-budgets", "apply", "--file", filepath.Join(t.TempDir(), "missing.json")}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	var runErr error
	_, stderr := captureOutput(t, func() {
		runErr = root.Run(context.Background())
	})
	if !errors.Is(runErr, flag.ErrHelp) || !strings.Contains(stderr, "--confirm is required") {
		t.Fatalf("run error = %v stderr = %q, want confirm usage error", runErr, stderr)
	}
}

func TestAdsPlatformReportRequiresFileBeforeAuthOrNetwork(t *testing.T) {
	isolateAdsGuideEnv(t)
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "")
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.json"))
	installDefaultTransport(t, adsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected network request: %s %s", req.Method, req.URL.String())
		return nil, nil
	}))

	root := RootCommand("dev")
	if err := root.Parse([]string{"ads", "platform", "insights", "impression-share", "find"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	var runErr error
	_, stderr := captureOutput(t, func() {
		runErr = root.Run(context.Background())
	})
	if !errors.Is(runErr, flag.ErrHelp) || !strings.Contains(stderr, "--file is required") {
		t.Fatalf("run error = %v stderr = %q, want file usage error", runErr, stderr)
	}
}
