package ads

import (
	"path/filepath"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/config"
)

func TestNamedAdsProfileWithoutOrgDoesNotInheritAnotherProfileDefault(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	setAdsResolverTestEnv(t)
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{
		DefaultKeyName: "profile-a",
		OrgID:          "ORG_A",
		Keys: []config.AdsCredential{
			{Name: "profile-a", ClientID: "A", TeamID: "T", KeyID: "K", PrivateKeyPath: "a.pem", OrgID: "ORG_A"},
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
	got, source, err := resolveOrgIDWithSource(commonFlags{}, credentials)
	if err != nil || got != "" || source != "" {
		t.Fatalf("profile-b org = %q source=%q error=%v, want no inherited org", got, source, err)
	}
}

func TestProfilelessCredentialsCanUseRootOrgContext(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ASC_CONFIG_PATH", configPath)
	setAdsResolverTestEnv(t)
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{OrgID: "ROOT_ORG"}}); err != nil {
		t.Fatalf("SaveAt() error: %v", err)
	}

	got, source, err := resolveOrgIDWithSource(commonFlags{}, appleads.Credentials{AccessToken: "ACCESS"})
	if err != nil || got != "ROOT_ORG" || source != "ads.org_id" {
		t.Fatalf("profileless org = %q source=%q error=%v, want root context", got, source, err)
	}
}

func setAdsResolverTestEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ASC_ADS_ACCESS_TOKEN",
		"ASC_ADS_CLIENT_ID",
		"ASC_ADS_TEAM_ID",
		"ASC_ADS_KEY_ID",
		"ASC_ADS_PRIVATE_KEY_PATH",
		"ASC_ADS_PRIVATE_KEY",
		"ASC_ADS_PRIVATE_KEY_B64",
		"ASC_ADS_ORG_ID",
		"ASC_ADS_AD_ACCOUNT_ID",
		"ASC_ADS_PROFILE",
		"ASC_ADS_STRICT_AUTH",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
}
