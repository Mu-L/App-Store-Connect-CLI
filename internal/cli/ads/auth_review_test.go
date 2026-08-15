package ads

import (
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
)

func TestAuthPlatformEndpointSpecReportsMissingCommand(t *testing.T) {
	_, err := authPlatformEndpointSpec("missing", "view")
	if err == nil || !strings.Contains(err.Error(), "internal error: missing Apple Ads Platform endpoint spec for command \"missing view\"") {
		t.Fatalf("authPlatformEndpointSpec() error = %v, want a clear missing-endpoint programming error", err)
	}
}

func TestAuthPlatformEndpointSpecResolvesAuthEndpoints(t *testing.T) {
	for _, path := range [][]string{{"me", "view"}, {"acls", "list"}} {
		spec, err := authPlatformEndpointSpec(path...)
		if err != nil {
			t.Fatalf("authPlatformEndpointSpec(%q) error: %v", strings.Join(path, " "), err)
		}
		if spec.Version != appleads.APIVersionPlatformV1 {
			t.Fatalf("authPlatformEndpointSpec(%q) version = %q, want Platform API v1", strings.Join(path, " "), spec.Version)
		}
	}
}

func TestAuthDiscoverHelpDocumentsPlatformTransport(t *testing.T) {
	command := AuthDiscoverCommand()
	if command.ShortHelp != "Discover Apple Ads user and ad account access." {
		t.Fatalf("AuthDiscoverCommand().ShortHelp = %q, want user/ad-account wording", command.ShortHelp)
	}
	if !strings.Contains(command.LongHelp, "GET v1/me") || !strings.Contains(command.LongHelp, "GET v1/acls") {
		t.Fatalf("AuthDiscoverCommand().LongHelp = %q, want Platform API v1 endpoints", command.LongHelp)
	}
	if strings.Contains(command.LongHelp, "GET v5/") {
		t.Fatalf("AuthDiscoverCommand().LongHelp = %q, must not claim legacy v5 transport", command.LongHelp)
	}
}

func TestSummarizePlatformACLAccountsUsesAdAccountSelection(t *testing.T) {
	accounts, err := summarizePlatformACLAccounts(appleads.RawResponse(`{"result":{"acls":[{"adAccount":{"id":111,"orgId":987654,"name":"Primary"},"roles":["Admin"]},{"adAccount":{"id":222,"orgId":987654,"name":"Secondary"},"roles":["ReadOnly"]}]}}`), "222")
	if err != nil {
		t.Fatalf("summarizePlatformACLAccounts() error: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("accounts = %+v, want two ACL rows", accounts)
	}
	if accounts[0].AdAccountID != "111" || accounts[0].Active {
		t.Fatalf("first account = %+v, want account 111 inactive", accounts[0])
	}
	if accounts[1].AdAccountID != "222" || !accounts[1].Active {
		t.Fatalf("second account = %+v, want account 222 active", accounts[1])
	}
}
