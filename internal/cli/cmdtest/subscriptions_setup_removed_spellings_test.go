package cmdtest

import (
	"errors"
	"flag"
	"io"
	"net/http"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/offercodes"
)

// The hidden compatibility spellings on `subscriptions setup` were removed in
// 5.0.0. They now fail as generic unknown flags (exit 2) before any client is
// resolved.
func TestSubscriptionsSetupRemovedSpellingsAreUnknownFlags(t *testing.T) {
	t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_APP_ID", "")

	stubTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("removed flag must fail before HTTP: %s %s", req.Method, req.URL.String())
		return nil, errors.New("unexpected request")
	}))

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "setup name",
			args:    []string{"subscriptions", "setup", "--group-id", "group-1", "--reference-name", "Pro", "--product-id", "com.example.pro", "--subscription-period", "ONE_MONTH", "--name", "Pro"},
			wantErr: "Error: unknown flag `--name` for `asc subscriptions setup`",
		},
		{
			name:    "setup ref-name",
			args:    []string{"subscriptions", "setup", "--group-id", "group-1", "--ref-name", "Pro", "--product-id", "com.example.pro", "--subscription-period", "ONE_MONTH"},
			wantErr: "Error: unknown flag `--ref-name` for `asc subscriptions setup`",
		},
		{
			name:    "setup group-ref-name",
			args:    []string{"subscriptions", "setup", "--app", "app-1", "--group-ref-name", "Pro", "--reference-name", "Pro", "--product-id", "com.example.pro", "--subscription-period", "ONE_MONTH"},
			wantErr: "Error: unknown flag `--group-ref-name` for `asc subscriptions setup`",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr := captureOutput(t, func() {
				if code := rootcmd.Run(test.args, "5.0.0"); code != rootcmd.ExitUsage {
					t.Fatalf("exit code = %d, want %d", code, rootcmd.ExitUsage)
				}
			})
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, test.wantErr) {
				t.Fatalf("stderr = %q, want unknown-flag error %q", stderr, test.wantErr)
			}
			if strings.Contains(stderr, "must match when both are provided") || strings.Contains(stderr, "Deprecated") {
				t.Fatalf("stderr = %q, want no compatibility guidance for a removed flag", stderr)
			}
		})
	}
}

// The `offercodes.OfferCodesCreateCommand` leaf is not attached to the root
// tree, so it is exercised directly like the other legacy offer-codes tests.
func TestOfferCodesCreateRemovedPriceIDIsUnknownFlag(t *testing.T) {
	t.Setenv("ASC_BYPASS_KEYCHAIN", "1")

	stubTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("removed flag must fail before HTTP: %s %s", req.Method, req.URL.String())
		return nil, errors.New("unexpected request")
	}))

	command := offercodes.OfferCodesCreateCommand()
	if command.FlagSet.Lookup("prices") == nil {
		t.Fatal("canonical flag --prices not found")
	}
	if command.FlagSet.Lookup("price-id") != nil {
		t.Fatal("removed flag --price-id is still bound")
	}

	command.FlagSet.Init(command.FlagSet.Name(), flag.ContinueOnError)
	command.FlagSet.SetOutput(io.Discard)
	err := command.Parse([]string{
		"--subscription-id", "sub-1",
		"--name", "SPRING",
		"--customer-eligibilities", "NEW",
		"--offer-eligibility", "STACK_WITH_INTRO_OFFERS",
		"--duration", "ONE_MONTH",
		"--offer-mode", "FREE_TRIAL",
		"--number-of-periods", "1",
		"--price-id", "USA",
	})
	if err == nil || !strings.Contains(err.Error(), "-price-id") {
		t.Fatalf("parse error = %v, want unknown flag -price-id", err)
	}
}

func TestSubscriptionsSetupRemovedSpellingsAreNotBound(t *testing.T) {
	root := RootCommand("5.0.0")
	tests := []struct {
		removed   string
		canonical string
	}{
		{removed: "group-ref-name", canonical: "group-reference-name"},
		{removed: "ref-name", canonical: "reference-name"},
		{removed: "name", canonical: "display-name"},
	}

	command := findSubcommand(root, "subscriptions", "setup")
	if command == nil {
		t.Fatal("command \"subscriptions setup\" not found")
	}
	for _, test := range tests {
		t.Run("--"+test.removed, func(t *testing.T) {
			if command.FlagSet.Lookup(test.canonical) == nil {
				t.Fatalf("canonical flag --%s not found", test.canonical)
			}
			if command.FlagSet.Lookup(test.removed) != nil {
				t.Fatalf("removed flag --%s is still bound", test.removed)
			}
		})
	}
}
