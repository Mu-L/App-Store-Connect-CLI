package ads

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuthPlatformEndpointSpecReportsMissingCommand(t *testing.T) {
	_, err := authPlatformEndpointSpec("missing", "view")
	if err == nil || !strings.Contains(err.Error(), "internal error: missing Apple Ads Platform endpoint spec for command \"missing view\"") {
		t.Fatalf("authPlatformEndpointSpec() error = %v, want a clear missing-endpoint programming error", err)
	}
}

func TestAuthPlatformEndpointSpecResolvesAuthEndpoints(t *testing.T) {
	for _, path := range [][]string{{"me", "view"}, {"acls", "list"}} {
		if _, err := authPlatformEndpointSpec(path...); err != nil {
			t.Fatalf("authPlatformEndpointSpec(%q) error: %v", strings.Join(path, " "), err)
		}
	}
}

func TestAuthDiscoverHelpUsesUserAndAdAccountWording(t *testing.T) {
	if got := AuthDiscoverCommand().ShortHelp; got != "Discover Apple Ads user and ad account access." {
		t.Fatalf("AuthDiscoverCommand().ShortHelp = %q, want user/ad-account wording", got)
	}
}

func TestNormalizePlatformDiscoveryMePreservesSourceNameAndStableShape(t *testing.T) {
	withName, err := normalizePlatformDiscoveryMe(json.RawMessage(`{"userId":1001,"name":"Marketing User","orgId":987654}`))
	if err != nil {
		t.Fatalf("normalizePlatformDiscoveryMe() with name error: %v", err)
	}
	var named map[string]any
	if err := json.Unmarshal(withName, &named); err != nil {
		t.Fatalf("named normalized me is not JSON: %v", err)
	}
	if got, ok := named["name"].(string); !ok || got != "Marketing User" {
		t.Fatalf("normalized name = %#v, want source name", named["name"])
	}

	withoutName, err := normalizePlatformDiscoveryMe(json.RawMessage(`{"userId":1001,"orgId":987654}`))
	if err != nil {
		t.Fatalf("normalizePlatformDiscoveryMe() without name error: %v", err)
	}
	var unnamed map[string]any
	if err := json.Unmarshal(withoutName, &unnamed); err != nil {
		t.Fatalf("unnamed normalized me is not JSON: %v", err)
	}
	if got, ok := unnamed["name"].(string); !ok || got != "" {
		t.Fatalf("normalized absent name = %#v, want stable empty name field", unnamed["name"])
	}
}
