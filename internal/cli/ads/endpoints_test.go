package ads

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/config"
)

func TestAdsCommandRegistersEveryEndpointSpec(t *testing.T) {
	root := AdsCommand()
	for _, spec := range appleads.EndpointSpecs() {
		cmd := findCommand(root, spec.CommandPath...)
		if cmd == nil {
			t.Fatalf("missing command asc ads %s", strings.Join(spec.CommandPath, " "))
		}
		if cmd.Exec == nil {
			t.Fatalf("command asc ads %s has no Exec", strings.Join(spec.CommandPath, " "))
		}
		assertSpecFlags(t, cmd, spec)

		if spec.DefaultListAlias {
			alias := findCommand(root, spec.CommandPath[0])
			if alias == nil {
				t.Fatalf("missing default list alias asc ads %s", spec.CommandPath[0])
			}
			if alias.Exec == nil {
				t.Fatalf("default list alias asc ads %s has no Exec", spec.CommandPath[0])
			}
			assertSpecFlags(t, alias, spec)
		}
	}
}

func TestPlatformCommandRegistersAccountAndAppEndpointSpecs(t *testing.T) {
	root := AdsCommand()
	for _, spec := range appleads.PlatformEndpointSpecs() {
		path := append([]string{"platform"}, spec.CommandPath...)
		cmd := findCommand(root, path...)
		if cmd == nil || cmd.Exec == nil {
			t.Fatalf("missing executable command asc ads %s", strings.Join(path, " "))
		}
		assertSpecFlags(t, cmd, spec)
		if spec.Context == appleads.ContextAdAccount && cmd.FlagSet.Lookup("ad-account") == nil {
			t.Fatalf("asc ads %s missing --ad-account", strings.Join(path, " "))
		}
		if cmd.FlagSet.Lookup("org") != nil {
			t.Fatalf("asc ads %s must not expose legacy --org", strings.Join(path, " "))
		}
		if (strings.Join(spec.CommandPath, " ") == "ad-accounts view" || strings.Join(spec.CommandPath, " ") == "ad-accounts update") && cmd.FlagSet.Lookup("id") != nil {
			t.Fatalf("asc ads %s must use --ad-account for both the path and context", strings.Join(path, " "))
		}
	}
}

func TestPlatformAppSearchValidationAndRepeatedStoreFronts(t *testing.T) {
	spec, ok := appleads.PlatformEndpointByCommandPath("apps", "search")
	if !ok {
		t.Fatal("missing platform apps search")
	}
	fs, flags := bindEndpointFlags(spec, "test")
	if _, err := collectQuery(spec, flags); err == nil || !strings.Contains(err.Error(), "--query, --cpids, or --return-owned-apps") {
		t.Fatalf("empty search error = %v", err)
	}
	if err := fs.Set("query", "ab"); err != nil {
		t.Fatal(err)
	}
	if _, err := collectQuery(spec, flags); err == nil || !strings.Contains(err.Error(), "at least 3 characters") {
		t.Fatalf("short query error = %v", err)
	}
	if err := fs.Set("query", "test app"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("store-fronts", "us, gB"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("store-fronts", "ca"); err != nil {
		t.Fatal(err)
	}
	query, err := collectQuery(spec, flags)
	if err != nil {
		t.Fatalf("collectQuery() error: %v", err)
	}
	if got := query["storeFronts"]; len(got) != 3 || got[0] != "US" || got[1] != "GB" || got[2] != "CA" {
		t.Fatalf("storeFronts = %#v, want repeated US, GB, and CA", got)
	}
}

func TestPlatformAppSearchRejectsInvalidStoreFronts(t *testing.T) {
	spec, _ := appleads.PlatformEndpointByCommandPath("apps", "search")
	for _, storefronts := range []string{"US,,GB", "USA", "U1"} {
		t.Run(storefronts, func(t *testing.T) {
			fs, flags := bindEndpointFlags(spec, "test")
			if err := fs.Set("query", "test"); err != nil {
				t.Fatal(err)
			}
			if err := fs.Set("store-fronts", storefronts); err != nil {
				t.Fatal(err)
			}
			if _, err := collectQuery(spec, flags); err == nil {
				t.Fatalf("storefronts %q unexpectedly accepted", storefronts)
			}
		})
	}
}

func TestPlatformAppSearchRejectsInvalidRepeatedStoreFrontOccurrence(t *testing.T) {
	spec, ok := appleads.PlatformEndpointByCommandPath("apps", "search")
	if !ok {
		t.Fatal("missing platform apps search")
	}
	fs, flags := bindEndpointFlags(spec, "test")
	if err := fs.Set("query", "test"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("store-fronts", "US"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("store-fronts", "CA,USA"); err != nil {
		t.Fatal(err)
	}
	if _, err := collectQuery(spec, flags); err == nil {
		t.Fatal("invalid storefront in a later repeated occurrence unexpectedly accepted")
	}
}

func TestPlatformAdAccountUpdateBodySafeguards(t *testing.T) {
	spec, ok := appleads.PlatformEndpointByCommandPath("ad-accounts", "update")
	if !ok {
		t.Fatal("missing platform ad-account update")
	}

	if err := validateEndpointBody(spec, json.RawMessage(`{"productFeatures":["APPSTORE_APP_MANUAL"]}`), true); err == nil || !strings.Contains(err.Error(), "productFeatures") {
		t.Fatalf("productFeatures error = %v", err)
	}
	delegations := json.RawMessage(`{"delegations":[{"resourceId":"123","resourceType":"CONTENT_PROVIDER"}]}`)
	if err := validateEndpointBody(spec, delegations, false); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("delegation confirm error = %v", err)
	}
	if err := validateEndpointBody(spec, delegations, true); err != nil {
		t.Fatalf("confirmed delegations error: %v", err)
	}
	if err := validateEndpointBody(spec, json.RawMessage(`{"delegations":[{"resourceId":"123"}]}`), true); err == nil || !strings.Contains(err.Error(), "resourceType") {
		t.Fatalf("delegation shape error = %v", err)
	}
	if spec.RequiresConfirm {
		t.Fatal("ad-account update must not require confirmation for every payload")
	}
	if err := validateEndpointBody(spec, json.RawMessage(`{"name":"Renamed"}`), false); err != nil {
		t.Fatalf("name-only update without confirmation error: %v", err)
	}
}

func TestPlatformAdAccountCreateRequiresOneProductFeature(t *testing.T) {
	spec, _ := appleads.PlatformEndpointByCommandPath("ad-accounts", "create")
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "empty", body: `{"name":"Account","productFeatures":[]}`, wantErr: true},
		{name: "both", body: `{"name":"Account","productFeatures":["APPSTORE_APP_MANUAL","BUSINESS_BRAND_MANUAL"]}`, wantErr: true},
		{name: "invalid", body: `{"name":"Account","productFeatures":["OTHER"]}`, wantErr: true},
		{name: "app", body: `{"name":"Account","productFeatures":["APPSTORE_APP_MANUAL"]}`},
		{name: "brand", body: `{"name":"Account","productFeatures":["BUSINESS_BRAND_MANUAL"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateEndpointBody(spec, json.RawMessage(test.body), false)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestPlatformCampaignDeleteCommandsRequireConfirmationFirst(t *testing.T) {
	for _, command := range [][]string{
		{"campaigns", "delete"},
		{"ad-groups", "delete"},
		{"ads", "delete"},
		{"targeting-keywords", "delete"},
		{"negative-keywords", "delete"},
		{"budget-orders", "delete"},
	} {
		spec, ok := appleads.PlatformEndpointByCommandPath(command...)
		if !ok {
			t.Fatalf("missing %q", strings.Join(command, " "))
		}
		_, flags := bindEndpointFlags(spec, "test")
		if err := executeEndpoint(context.Background(), spec, flags); !errors.Is(err, flag.ErrHelp) || !strings.Contains(err.Error(), "--confirm is required") {
			t.Errorf("%q unconfirmed error = %v, want confirmation usage error", strings.Join(command, " "), err)
		}
	}
}

func TestPlatformGeoSearchSerializesFixtureQueryNames(t *testing.T) {
	spec, ok := appleads.PlatformEndpointByCommandPath("geo", "search")
	if !ok {
		t.Fatal("missing geo search")
	}
	fs, flags := bindEndpointFlags(spec, "test")
	if err := fs.Parse([]string{
		"--supply-source", "appstore",
		"--query", "San Francisco",
		"--entity", "Locality",
		"--country-code", "us",
		"--eligible",
		"--offset", "20",
		"--page-size", "50",
	}); err != nil {
		t.Fatal(err)
	}
	query, err := collectQuery(spec, flags)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := query.Encode(), "countrycode=US&eligible=true&entity=Locality&offset=20&pageSize=50&query=San+Francisco&supplySource=APPSTORE"; got != want {
		t.Fatalf("geo query = %q, want %q", got, want)
	}
	if err := fs.Set("page-size", "0"); err != nil {
		t.Fatal(err)
	}
	if _, err := collectQuery(spec, flags); err == nil || !strings.Contains(err.Error(), "--page-size must be greater than 0") {
		t.Fatalf("zero page size error = %v, want pre-network validation", err)
	}
	_, flags = bindEndpointFlags(spec, "test")
	*flags.queryStrings["supplySource"] = "MAPS"
	*flags.queryStrings["query"] = "x"
	if _, err := collectQuery(spec, flags); err == nil || !strings.Contains(err.Error(), "at least 2 characters") {
		t.Fatalf("short geo query error = %v", err)
	}
}

func TestPlatformCampaignPathIDsAreStringsButAdamIDIsNumeric(t *testing.T) {
	campaign, _ := appleads.PlatformEndpointByCommandPath("campaigns", "view")
	fs, flags := bindEndpointFlags(campaign, "test")
	if err := fs.Set("campaign", "campaign_external_01"); err != nil {
		t.Fatal(err)
	}
	params, err := collectPathParams(campaign, flags)
	if err != nil || params["id"] != "campaign_external_01" {
		t.Fatalf("campaign path params = %#v, error = %v", params, err)
	}

	locales, _ := appleads.PlatformEndpointByCommandPath("apps", "locales", "find")
	fs, flags = bindEndpointFlags(locales, "test")
	if err := fs.Set("adam-id", "not-a-number"); err != nil {
		t.Fatal(err)
	}
	if _, err := collectPathParams(locales, flags); err == nil || !strings.Contains(err.Error(), "--adam-id must be an integer") {
		t.Fatalf("adam ID error = %v", err)
	}
}

func TestPlatformCampaignPauseResumeWorkflowsUseStringIDsAndConfirm(t *testing.T) {
	root := AdsCommand()
	for _, name := range []string{"pause", "resume"} {
		command := findCommand(root, "platform", "campaigns", name)
		if command == nil || command.Exec == nil {
			t.Fatalf("missing executable platform campaigns %s", name)
		}
		if command.FlagSet.Lookup("ad-account") == nil || command.FlagSet.Lookup("org") != nil {
			t.Fatalf("platform campaigns %s context flags are incorrect", name)
		}
		if err := command.FlagSet.Set("campaign", "campaign_external_01"); err != nil {
			t.Fatal(err)
		}
		err := command.Exec(context.Background(), nil)
		if !errors.Is(err, flag.ErrHelp) || !strings.Contains(err.Error(), "--confirm is required") {
			t.Fatalf("platform campaigns %s unconfirmed error = %v", name, err)
		}
		if !strings.Contains(command.LongHelp, `{"status":"`) || !strings.Contains(command.LongHelp, "PUT v1/campaigns/{id}") {
			t.Fatalf("platform campaigns %s help must document its direct v1 status payload: %q", name, command.LongHelp)
		}
	}
}

func TestAdsCampaignsHelpReadsAsManagementSurface(t *testing.T) {
	root := AdsCommand()
	campaigns := findCommand(root, "campaigns")
	if campaigns == nil {
		t.Fatal("missing campaigns command")
	}
	if campaigns.ShortHelp != "Manage Apple Ads campaigns." {
		t.Fatalf("campaigns ShortHelp = %q, want management surface", campaigns.ShortHelp)
	}
	if campaigns.FlagSet.Lookup("campaign") != nil {
		t.Fatal("campaigns list alias should not expose workflow-only --campaign flag")
	}

	resume := findCommand(root, "campaigns", "resume")
	if resume == nil {
		t.Fatal("missing campaigns resume command")
	}
	campaignFlag := resume.FlagSet.Lookup("campaign")
	if campaignFlag == nil {
		t.Fatal("resume command missing --campaign flag")
	}
	if got := campaignFlag.Usage; got != "Apple Ads campaign ID (required)" {
		t.Fatalf("resume --campaign usage = %q, want operator-friendly wording", got)
	}
	if !strings.Contains(resume.LongHelp, "--campaign CAMPAIGN_ID --confirm --org ORG_ID") {
		t.Fatalf("resume LongHelp = %q, want campaign ID example", resume.LongHelp)
	}
}

func TestAdsCampaignUpdateHelpDocumentsRequiredEnvelope(t *testing.T) {
	root := AdsCommand()
	update := findCommand(root, "campaigns", "update")
	if update == nil {
		t.Fatal("missing campaigns update command")
	}

	for _, want := range []string{
		`Apple requires a "campaign" envelope for campaign updates.`,
		`{"campaign":{"status":"PAUSED"}}`,
	} {
		if !strings.Contains(update.LongHelp, want) {
			t.Fatalf("campaigns update LongHelp = %q, want %q", update.LongHelp, want)
		}
	}
}

func TestPlatformConditionalConfirmationAppearsOnceInHelp(t *testing.T) {
	root := AdsCommand()
	update := findCommand(root, "platform", "ad-accounts", "update")
	if update == nil {
		t.Fatal("missing platform ad-account update command")
	}

	if got := strings.Count(update.LongHelp, "--confirm"); got != 1 {
		t.Fatalf("ad-accounts update LongHelp contains --confirm %d times, want once: %q", got, update.LongHelp)
	}
	if !strings.Contains(update.LongHelp, "[--confirm]") {
		t.Fatalf("ad-accounts update LongHelp = %q, want optional --confirm example", update.LongHelp)
	}
}

func TestCollectQueryValidatesEndpointSpecificLimitsAndEnums(t *testing.T) {
	customReports, _ := appleads.EndpointByCommandPath("impression-share-reports", "list")
	fs, flags := bindEndpointFlags(customReports, "test")
	if err := fs.Parse([]string{"--limit", "0"}); err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if _, err := collectQuery(customReports, flags); err == nil || !strings.Contains(err.Error(), "--limit must be between 1 and 50") {
		t.Fatalf("custom reports explicit zero limit error = %v, want min 1 error", err)
	}

	_, flags = bindEndpointFlags(customReports, "test")
	*flags.queryInts["limit"] = 51
	if _, err := collectQuery(customReports, flags); err == nil || !strings.Contains(err.Error(), "--limit must be between 1 and 50") {
		t.Fatalf("custom reports limit error = %v, want max 50 error", err)
	}

	productPages, _ := appleads.EndpointByCommandPath("product-pages", "list")
	_, flags = bindEndpointFlags(productPages, "test")
	*flags.pathStrings["adamId"] = "123456789"
	*flags.queryStrings["states"] = "VISIBLE,PAUSED"
	if _, err := collectQuery(productPages, flags); err == nil || !strings.Contains(err.Error(), "--states must be one of: HIDDEN, VISIBLE") {
		t.Fatalf("states error = %v, want enum validation", err)
	}
}

func TestCollectPathParamsRequiresDocumentedIdentifiers(t *testing.T) {
	campaign, _ := appleads.EndpointByCommandPath("campaigns", "view")
	_, flags := bindEndpointFlags(campaign, "test")
	if _, err := collectPathParams(campaign, flags); err == nil || !strings.Contains(err.Error(), "--campaign is required") {
		t.Fatalf("path error = %v, want campaign required", err)
	}

	*flags.pathStrings["campaignId"] = "123"
	params, err := collectPathParams(campaign, flags)
	if err != nil {
		t.Fatalf("collectPathParams() error: %v", err)
	}
	if params["campaignId"] != "123" {
		t.Fatalf("campaignId = %q, want 123", params["campaignId"])
	}

	*flags.pathStrings["campaignId"] = "not-a-number"
	if _, err := collectPathParams(campaign, flags); err == nil || !strings.Contains(err.Error(), "--campaign must be an integer") {
		t.Fatalf("path error = %v, want integer validation", err)
	}
}

func TestRawRequestRequiresOrgGuardrails(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		requiresOrg bool
		wantErr     string
	}{
		{name: "me does not need org", path: "v5/me", requiresOrg: false},
		{name: "me with query does not need org", path: "v5/me?fields=id", requiresOrg: false},
		{name: "acls does not need org", path: "https://api.searchads.apple.com/api/v5/acls", requiresOrg: false},
		{name: "absolute me with query does not need org", path: "https://api.searchads.apple.com/api/v5/me?fields=id", requiresOrg: false},
		{name: "campaigns needs org", path: "v5/campaigns", requiresOrg: true},
		{name: "reject non apple host", path: "https://example.com/api/v5/campaigns", wantErr: "Apple Ads v5 URL"},
		{name: "reject path traversal", path: "v5/../campaigns", wantErr: "path traversal"},
		{name: "reject wrong version", path: "v4/campaigns", wantErr: "start with v5/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requiresOrg, err := rawRequestRequiresOrg(tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want contains %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("rawRequestRequiresOrg() error: %v", err)
			}
			if requiresOrg != tt.requiresOrg {
				t.Fatalf("requiresOrg = %t, want %t", requiresOrg, tt.requiresOrg)
			}
		})
	}
}

func TestRawPlatformRequestRequiresAdAccount(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		requires bool
		wantErr  string
	}{
		{name: "me", method: "GET", path: "v1/me", requires: false},
		{name: "acls absolute", method: "GET", path: "https://api.ads.apple.com/v1/acls", requires: false},
		{name: "org", method: "GET", path: "v1/orgs/123", requires: false},
		{name: "advertiser resources", method: "GET", path: "v1/advertiser-resources?resourceType=APP", requires: false},
		{name: "create ad account", method: "POST", path: "v1/ad-accounts", requires: false},
		{name: "list ad accounts defaults scoped", method: "GET", path: "v1/ad-accounts", requires: true},
		{name: "view ad account", method: "GET", path: "v1/ad-accounts/123", requires: true},
		{name: "update ad account", method: "PUT", path: "v1/ad-accounts/123", requires: true},
		{name: "unknown defaults scoped", method: "GET", path: "v1/future-resource", requires: true},
		{name: "reject wrong host", method: "GET", path: "https://example.com/v1/me", wantErr: "Apple Ads Platform API v1 URL"},
		{name: "reject userinfo", method: "GET", path: "https://example.com@api.ads.apple.com/v1/me", wantErr: "Apple Ads Platform API v1 URL"},
		{name: "reject legacy version", method: "GET", path: "v5/me", wantErr: "start with v1/"},
		{name: "reject traversal", method: "GET", path: "v1/../me", wantErr: "path traversal"},
		{name: "reject encoded traversal", method: "GET", path: "v1/%2e%2e/campaigns", wantErr: "path traversal"},
		{name: "reject network path", method: "GET", path: "v1//example.com/campaigns", wantErr: "must not escape"},
		{name: "reject embedded absolute URL", method: "GET", path: "v1/https://example.com/campaigns", wantErr: "must not escape"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requires, err := rawPlatformRequestRequiresAdAccount(tt.method, tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("rawPlatformRequestRequiresAdAccount() error: %v", err)
			}
			if requires != tt.requires {
				t.Fatalf("requires = %t, want %t", requires, tt.requires)
			}
		})
	}
}

func TestResolveAdAccountIDPrecedenceDoesNotUseLegacyOrg(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "ENV_ACCOUNT")
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{
		OrgID:       "LEGACY_ORG",
		AdAccountID: "CONFIG_ACCOUNT",
	}}); err != nil {
		t.Fatalf("SaveAt() error: %v", err)
	}

	explicit := "FLAG_ACCOUNT"
	got, source, err := resolveAdAccountIDWithSource(commonFlags{AdAccount: &explicit}, appleads.Credentials{OrgID: "PROFILE_ORG", AdAccountID: "PROFILE_ACCOUNT"})
	if err != nil || got != "FLAG_ACCOUNT" || source != "--ad-account" {
		t.Fatalf("explicit resolution = %q %q %v", got, source, err)
	}
	got, source, err = resolveAdAccountIDWithSource(commonFlags{}, appleads.Credentials{OrgID: "PROFILE_ORG", AdAccountID: "PROFILE_ACCOUNT"})
	if err != nil || got != "ENV_ACCOUNT" || source != "ASC_ADS_AD_ACCOUNT_ID" {
		t.Fatalf("env resolution = %q %q %v", got, source, err)
	}
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "")
	got, source, err = resolveAdAccountIDWithSource(commonFlags{}, appleads.Credentials{Profile: "ads", OrgID: "PROFILE_ORG", AdAccountID: "PROFILE_ACCOUNT"})
	if err != nil || got != "PROFILE_ACCOUNT" || source != "Ads profile ad_account_id" {
		t.Fatalf("profile resolution = %q %q %v", got, source, err)
	}
	got, source, err = resolveAdAccountIDWithSource(commonFlags{}, appleads.Credentials{Profile: "profile-without-account", OrgID: "PROFILE_ORG"})
	if err != nil || got != "" || source != "" {
		t.Fatalf("empty named profile must not inherit root ad account: %q %q %v", got, source, err)
	}
	got, source, err = resolveAdAccountIDWithSource(commonFlags{}, appleads.Credentials{OrgID: "PROFILE_ORG"})
	if err != nil || got != "CONFIG_ACCOUNT" || source != "ads.ad_account_id" {
		t.Fatalf("config resolution = %q %q %v", got, source, err)
	}
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{OrgID: "LEGACY_ORG"}}); err != nil {
		t.Fatalf("SaveAt(legacy) error: %v", err)
	}
	got, source, err = resolveAdAccountIDWithSource(commonFlags{}, appleads.Credentials{OrgID: "PROFILE_ORG"})
	if err != nil || got != "" || source != "" {
		t.Fatalf("legacy org must not resolve as ad account: %q %q %v", got, source, err)
	}
}

func TestNamedAdsProfileWithoutAdAccountDoesNotInheritAnotherProfileDefault(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	setAdsResolverTestEnv(t)
	t.Setenv("ASC_ADS_AD_ACCOUNT_ID", "")
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{
		DefaultKeyName: "profile-a",
		AdAccountID:    "ACCOUNT_A",
		Keys: []config.AdsCredential{
			{Name: "profile-a", ClientID: "A", TeamID: "T", KeyID: "K", PrivateKeyPath: "a.pem", AdAccountID: "ACCOUNT_A"},
			{Name: "profile-b", ClientID: "B", TeamID: "T", KeyID: "K", PrivateKeyPath: "b.pem"},
		},
	}}); err != nil {
		t.Fatalf("SaveAt() error: %v", err)
	}

	profile := "profile-b"
	credentials, err := resolveCredentials(commonFlags{AdsProfile: &profile})
	if err != nil {
		t.Fatalf("resolveCredentials() error: %v", err)
	}
	got, source, err := resolveAdAccountIDWithSource(commonFlags{}, credentials)
	if err != nil || got != "" || source != "" {
		t.Fatalf("profile-b ad account = %q source=%q error=%v, want no inherited account", got, source, err)
	}
}

func TestAdsAuthDiscoveryPreservesInt64Identifiers(t *testing.T) {
	const largeID = "9007199254740993"
	if got := discoveryUserSummary(json.RawMessage(`{"userId":` + largeID + `}`)); got != largeID {
		t.Fatalf("discoveryUserSummary() = %q, want %q", got, largeID)
	}

	accounts, err := summarizeACLAccounts(
		appleads.RawResponse(`{"data":[{"orgId":`+largeID+`,"orgName":"Large","roleNames":["Admin"]}]}`),
		largeID,
	)
	if err != nil {
		t.Fatalf("summarizeACLAccounts() error: %v", err)
	}
	if len(accounts) != 1 || accounts[0].OrgID != largeID || accounts[0].Name != "Large" || !accounts[0].Active {
		t.Fatalf("accounts = %+v, want exact active int64 identifiers", accounts)
	}
	if got := strings.Join(accounts[0].Roles, ","); got != "Admin" {
		t.Fatalf("roles = %q, want Admin", got)
	}
}

func TestPlatformOptionalBodyAndUnboundedLimit(t *testing.T) {
	spec := appleads.EndpointSpec{
		Name:         "platform-query",
		Method:       "POST",
		Path:         "v1/resources/query",
		Version:      appleads.APIVersionPlatformV1,
		Context:      appleads.ContextAdAccount,
		BodyKind:     appleads.BodyObject,
		BodyOptional: true,
		QueryParams: []appleads.ParamSpec{{
			Name: "limit",
			Flag: "limit",
			Type: appleads.ParamInt,
		}},
	}
	fs, flags := bindEndpointFlags(spec, "platform query")
	body, err := readBody(spec, flags)
	if err != nil || body != nil {
		t.Fatalf("optional body = %s error = %v, want nil", body, err)
	}
	if err := fs.Set("limit", "50000"); err != nil {
		t.Fatalf("Set(limit) error: %v", err)
	}
	query, err := collectQuery(spec, flags)
	if err != nil || query.Get("limit") != "50000" {
		t.Fatalf("query = %v error = %v", query, err)
	}
	if got := appleads.MaxPageLimit(spec); got != 0 {
		t.Fatalf("MaxPageLimit() = %d, want no v5 cap", got)
	}
}

func TestCollectQueryHonorsGenericIntegerMax(t *testing.T) {
	spec := appleads.EndpointSpec{
		Name:    "platform-page-size",
		Method:  "GET",
		Path:    "v1/resources",
		Version: appleads.APIVersionPlatformV1,
		QueryParams: []appleads.ParamSpec{{
			Name: "pageSize",
			Flag: "page-size",
			Type: appleads.ParamInt,
			Max:  50,
		}},
	}
	_, flags := bindEndpointFlags(spec, "platform page-size")
	*flags.queryInts["pageSize"] = 50
	query, err := collectQuery(spec, flags)
	if err != nil {
		t.Fatalf("collectQuery(max) error: %v", err)
	}
	if got := query.Get("pageSize"); got != "50" {
		t.Fatalf("pageSize at max = %q, want 50", got)
	}

	*flags.queryInts["pageSize"] = 51
	if _, err := collectQuery(spec, flags); err == nil || !strings.Contains(err.Error(), "--page-size must be at most 50") {
		t.Fatalf("collectQuery(max+1) error = %v, want max validation", err)
	}

	spec.QueryParams[0].Max = 0
	*flags.queryInts["pageSize"] = 50000
	query, err = collectQuery(spec, flags)
	if err != nil {
		t.Fatalf("collectQuery(unbounded) error: %v", err)
	}
	if got := query.Get("pageSize"); got != "50000" {
		t.Fatalf("unbounded pageSize = %q, want 50000", got)
	}
}

func TestResolveCredentialsPrefersExplicitProfileAndStrictRejectsMixedSources(t *testing.T) {
	asc.ResetConfigCacheForTest()
	t.Cleanup(asc.ResetConfigCacheForTest)

	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
	if err := appleads.StoreCredentialsConfigAt("profile-a", appleads.Credentials{
		ClientID:       "CLIENT",
		TeamID:         "TEAM",
		KeyID:          "KEY",
		PrivateKeyPath: "private-key.pem",
		OrgID:          "ORG",
	}, configPath); err != nil {
		t.Fatalf("StoreCredentialsConfigAt() error: %v", err)
	}

	profileName := "profile-a"
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	credentials, err := resolveCredentials(commonFlags{AdsProfile: &profileName})
	if err != nil {
		t.Fatalf("resolveCredentials() error: %v", err)
	}
	if credentials.Profile != "profile-a" || credentials.AccessToken != "" || credentials.ClientID != "CLIENT" {
		t.Fatalf("credentials = %+v, want stored profile over access token", credentials)
	}

	t.Setenv("ASC_ADS_STRICT_AUTH", "1")
	_, err = resolveCredentials(commonFlags{AdsProfile: &profileName})
	if err == nil || !strings.Contains(err.Error(), "mixed Apple Ads authentication sources") {
		t.Fatalf("strict mixed source error = %v", err)
	}
}

func TestResolveClientRequiresOrgForOrgScopedEndpoints(t *testing.T) {
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	_, err := resolveClient(context.Background(), commonFlags{}, true)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("resolveClient() error = %v, want usage error", err)
	}

	org := "123456"
	client, err := resolveClient(context.Background(), commonFlags{Org: &org}, true)
	if err != nil {
		t.Fatalf("resolveClient() with org error: %v", err)
	}
	if client == nil {
		t.Fatal("expected client")
	}
}

func TestResolveClientUsesStoredAdsOrgWithAccessToken(t *testing.T) {
	asc.ResetConfigCacheForTest()
	t.Cleanup(asc.ResetConfigCacheForTest)

	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	if err := config.SaveAt(configPath, &config.Config{
		Ads: config.AdsConfig{OrgID: "CONFIG_ORG"},
	}); err != nil {
		t.Fatalf("SaveAt() error: %v", err)
	}

	client, err := resolveClient(context.Background(), commonFlags{}, true)
	if err != nil {
		t.Fatalf("resolveClient() error: %v", err)
	}
	if client == nil {
		t.Fatal("expected client")
	}
}

func TestEnvCredentialsRejectsInvalidPrivateKeyBase64(t *testing.T) {
	t.Setenv("ASC_ADS_CLIENT_ID", "CLIENT")
	t.Setenv("ASC_ADS_TEAM_ID", "TEAM")
	t.Setenv("ASC_ADS_KEY_ID", "KEY")
	t.Setenv("ASC_ADS_PRIVATE_KEY_B64", "not-base64")

	_, _, err := envCredentials()
	if err == nil || !strings.Contains(err.Error(), "ASC_ADS_PRIVATE_KEY_B64 is not valid base64") {
		t.Fatalf("envCredentials() error = %v, want invalid base64 error", err)
	}
}

func TestResolveCredentialsStrictRejectsAccessTokenAndKeyEnv(t *testing.T) {
	t.Setenv("ASC_ADS_ACCESS_TOKEN", "ACCESS")
	t.Setenv("ASC_ADS_STRICT_AUTH", "1")
	t.Setenv("ASC_ADS_CLIENT_ID", "CLIENT")
	t.Setenv("ASC_ADS_TEAM_ID", "TEAM")
	t.Setenv("ASC_ADS_KEY_ID", "KEY")
	t.Setenv("ASC_ADS_PRIVATE_KEY_PATH", "private-key.pem")

	_, err := resolveCredentials(commonFlags{})
	if err == nil || !strings.Contains(err.Error(), "mixed Apple Ads authentication sources") {
		t.Fatalf("resolveCredentials() error = %v, want mixed source error", err)
	}
}

func TestResolveCredentialsRejectsPartialEnvBeforeStoredFallback(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_ADS_CLIENT_ID", "CLIENT")
	if err := appleads.StoreCredentialsConfigAt("profile-a", appleads.Credentials{
		ClientID:       "STORED_CLIENT",
		TeamID:         "STORED_TEAM",
		KeyID:          "STORED_KEY",
		PrivateKeyPath: "stored-private-key.pem",
		OrgID:          "ORG",
	}, configPath); err != nil {
		t.Fatalf("StoreCredentialsConfigAt() error: %v", err)
	}

	_, err := resolveCredentials(commonFlags{})
	if err == nil || !strings.Contains(err.Error(), "incomplete Apple Ads environment credentials") {
		t.Fatalf("resolveCredentials() error = %v, want incomplete env error", err)
	}
}

func TestCollectQueryIncludesAllowedValidValues(t *testing.T) {
	productPages, _ := appleads.EndpointByCommandPath("product-pages", "list")
	_, flags := bindEndpointFlags(productPages, "test")
	*flags.queryStrings["states"] = "HIDDEN,VISIBLE"
	query, err := collectQuery(productPages, flags)
	if err != nil {
		t.Fatalf("collectQuery() error: %v", err)
	}
	want := url.Values{"states": {"HIDDEN,VISIBLE"}}
	if query.Encode() != want.Encode() {
		t.Fatalf("query = %s, want %s", query.Encode(), want.Encode())
	}
}

func TestEndpointHelpUsesOperatorFriendlyAuthDiscoveryNames(t *testing.T) {
	root := AdsCommand()
	tests := []struct {
		path []string
		want string
	}{
		{path: []string{"me"}, want: "View the current Apple Ads user."},
		{path: []string{"me", "view"}, want: "View the current Apple Ads user."},
		{path: []string{"acls"}, want: "List Apple Ads account ACLs."},
		{path: []string{"acls", "list"}, want: "List Apple Ads account ACLs."},
	}
	for _, test := range tests {
		cmd := findCommand(root, test.path...)
		if cmd == nil {
			t.Fatalf("missing command asc ads %s", strings.Join(test.path, " "))
		}
		if cmd.ShortHelp != test.want {
			t.Fatalf("asc ads %s ShortHelp = %q, want %q", strings.Join(test.path, " "), cmd.ShortHelp, test.want)
		}
	}
}

func TestPlatformOptimizationHelpUsesOperatorFriendlyVerbs(t *testing.T) {
	root := AdsCommand()
	tests := []struct {
		path []string
		want string
	}{
		{path: []string{"platform", "recommendations", "target-cpas", "apply"}, want: "Apply target cpa recommendations."},
		{path: []string{"platform", "recommendations", "daily-budgets", "dismiss"}, want: "Dismiss daily budget recommendations."},
		{path: []string{"platform", "suggestions", "keywords", "find"}, want: "Find keyword suggestions."},
	}
	for _, test := range tests {
		cmd := findCommand(root, test.path...)
		if cmd == nil {
			t.Fatalf("missing command asc ads %s", strings.Join(test.path, " "))
		}
		if cmd.ShortHelp != test.want {
			t.Fatalf("asc ads %s ShortHelp = %q, want %q", strings.Join(test.path, " "), cmd.ShortHelp, test.want)
		}
	}
}

func findCommand(root *ffcli.Command, path ...string) *ffcli.Command {
	current := root
	for _, part := range path {
		var next *ffcli.Command
		for _, sub := range current.Subcommands {
			if sub.Name == part {
				next = sub
				break
			}
		}
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

func assertSpecFlags(t *testing.T, cmd *ffcli.Command, spec appleads.EndpointSpec) {
	t.Helper()
	for _, name := range []string{"ads-profile", "output"} {
		if cmd.FlagSet.Lookup(name) == nil {
			t.Fatalf("asc ads %s missing --%s", strings.Join(spec.CommandPath, " "), name)
		}
	}
	if spec.RequiresOrg && cmd.FlagSet.Lookup("org") == nil {
		t.Fatalf("asc ads %s missing --org", strings.Join(spec.CommandPath, " "))
	}
	for _, param := range spec.PathParams {
		if cmd.FlagSet.Lookup(param.Flag) == nil {
			t.Fatalf("asc ads %s missing --%s", strings.Join(spec.CommandPath, " "), param.Flag)
		}
	}
	for _, param := range spec.QueryParams {
		if cmd.FlagSet.Lookup(param.Flag) == nil {
			t.Fatalf("asc ads %s missing --%s", strings.Join(spec.CommandPath, " "), param.Flag)
		}
	}
	if spec.BodyKind != appleads.BodyNone && cmd.FlagSet.Lookup("file") == nil {
		t.Fatalf("asc ads %s missing --file", strings.Join(spec.CommandPath, " "))
	}
	if spec.RequiresConfirm && cmd.FlagSet.Lookup("confirm") == nil {
		t.Fatalf("asc ads %s missing --confirm", strings.Join(spec.CommandPath, " "))
	}
	if spec.SupportsPaginate && cmd.FlagSet.Lookup("paginate") == nil {
		t.Fatalf("asc ads %s missing --paginate", strings.Join(spec.CommandPath, " "))
	}
}
