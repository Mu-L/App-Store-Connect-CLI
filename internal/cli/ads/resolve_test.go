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
	t.Setenv("ASC_ADS_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_ADS_ORG_ID", "")
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
	if err := config.SaveAt(configPath, &config.Config{Ads: config.AdsConfig{OrgID: "ROOT_ORG"}}); err != nil {
		t.Fatalf("SaveAt() error: %v", err)
	}

	got, source, err := resolveOrgIDWithSource(commonFlags{}, appleads.Credentials{AccessToken: "ACCESS"})
	if err != nil || got != "ROOT_ORG" || source != "ads.org_id" {
		t.Fatalf("profileless org = %q source=%q error=%v, want root context", got, source, err)
	}
}
