package ads

import (
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
)

func TestAuthLegacyEndpointSpecReportsMissingCommand(t *testing.T) {
	_, err := authLegacyEndpointSpec("missing", "view")
	if err == nil || !strings.Contains(err.Error(), "internal error: missing Apple Ads Campaign Management endpoint spec for command \"missing view\"") {
		t.Fatalf("authLegacyEndpointSpec() error = %v, want a clear missing-endpoint programming error", err)
	}
}

func TestAuthLegacyEndpointSpecResolvesDiscoveryEndpoints(t *testing.T) {
	for _, path := range [][]string{{"me", "view"}, {"acls", "list"}} {
		spec, err := authLegacyEndpointSpec(path...)
		if err != nil {
			t.Fatalf("authLegacyEndpointSpec(%q) error: %v", strings.Join(path, " "), err)
		}
		if spec.Version == appleads.APIVersionPlatformV1 {
			t.Fatalf("authLegacyEndpointSpec(%q) selected Platform API v1", strings.Join(path, " "))
		}
	}
}

func TestAuthValidationUsesLegacyEndpointSpec(t *testing.T) {
	spec, err := authLegacyEndpointSpec("me", "view")
	if err != nil {
		t.Fatalf("authLegacyEndpointSpec(me view) error: %v", err)
	}
	if spec.Version == appleads.APIVersionPlatformV1 || spec.Path != "v5/me" {
		t.Fatalf("auth validation spec = version %q path %q, want legacy Campaign Management v5 path", spec.Version, spec.Path)
	}
}

func TestAuthDiscoverHelpDocumentsVersionNeutralLegacyTransport(t *testing.T) {
	command := AuthDiscoverCommand()
	if command.ShortHelp != "Discover Apple Ads user and organization access." {
		t.Fatalf("AuthDiscoverCommand().ShortHelp = %q, want organization wording", command.ShortHelp)
	}
	if !strings.Contains(command.LongHelp, "GET v5/me") || !strings.Contains(command.LongHelp, "GET v5/acls") {
		t.Fatalf("AuthDiscoverCommand().LongHelp = %q, want legacy v5 endpoints", command.LongHelp)
	}
	if strings.Contains(command.LongHelp, "GET v1/") {
		t.Fatalf("AuthDiscoverCommand().LongHelp = %q, must not claim Platform v1 transport", command.LongHelp)
	}
}
