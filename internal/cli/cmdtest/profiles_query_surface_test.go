package cmdtest

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	rootcmd "github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func TestProfilesListSendsQuerySurface(t *testing.T) {
	setupAuth(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/profiles" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		values := req.URL.Query()
		checks := map[string]string{
			"filter[name]":         "Development,Store",
			"filter[id]":           "profile-1,profile-2",
			"filter[profileType]":  "IOS_APP_DEVELOPMENT,IOS_APP_STORE",
			"filter[profileState]": "ACTIVE,INVALID",
			"sort":                 "name,-id",
			"fields[profiles]":     "name,expirationDate",
			"fields[bundleIds]":    "identifier",
			"fields[devices]":      "name,udid",
			"fields[certificates]": "displayName,serialNumber",
			"include":              "bundleId,devices,certificates",
			"limit[devices]":       "7",
			"limit[certificates]":  "9",
			"limit":                "5",
		}
		for key, want := range checks {
			if got := values.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	t.Cleanup(server.Close)
	installProfilesQueryTestClient(t, server)

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	stdout, stderr := captureOutput(t, func() {
		if err := root.Parse([]string{
			"profiles", "list",
			"--name", "Development, Store",
			"--id", "profile-1, profile-2",
			"--profile-type", "IOS_APP_DEVELOPMENT, IOS_APP_STORE",
			"--profile-state", "ACTIVE, INVALID",
			"--sort", "name,-id",
			"--fields", "name,expirationDate",
			"--bundle-id-fields", "identifier",
			"--device-fields", "name,udid",
			"--certificate-fields", "displayName,serialNumber",
			"--include", "bundleId,devices,certificates",
			"--limit-devices", "7",
			"--limit-certificates", "9",
			"--limit", "5",
			"--output", "json",
		}); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if stdout != `{"data":[],"links":{}}`+"\n" {
		t.Fatalf("stdout = %q, want empty profiles response", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestProfilesListQuerySurfacePaginatesFromServerNextURL(t *testing.T) {
	setupAuth(t)

	const nextURL = "https://api.appstoreconnect.apple.com/v1/profiles?cursor=next&limit=200"
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount++
		if req.Method != http.MethodGet || req.URL.Path != "/v1/profiles" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		if requestCount == 1 {
			if got := req.URL.Query().Get("filter[name]"); got != "Development" {
				t.Fatalf("first filter[name] = %q, want Development", got)
			}
			if got := req.URL.Query().Get("include"); got != "devices" {
				t.Fatalf("first include = %q, want devices", got)
			}
			if got := req.URL.Query().Get("fields[devices]"); got != "name" {
				t.Fatalf("first fields[devices] = %q, want name", got)
			}
			if got := req.URL.Query().Get("limit[devices]"); got != "3" {
				t.Fatalf("first limit[devices] = %q, want 3", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":[{"type":"profiles","id":"profile-1"}],"links":{"next":"`+nextURL+`"}}`)
			return
		}
		if requestCount != 2 {
			t.Fatalf("unexpected request count: %d", requestCount)
		}
		const wantContinuation = "/v1/profiles?cursor=next&limit=200"
		if got := req.URL.String(); got != wantContinuation {
			t.Fatalf("continuation URL = %q, want %q", got, wantContinuation)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"type":"profiles","id":"profile-2"}],"links":{"next":""}}`)
	}))
	t.Cleanup(server.Close)
	installProfilesQueryTestClient(t, server)

	root := RootCommand("1.2.3")
	root.FlagSet.SetOutput(io.Discard)
	stdout, stderr := captureOutput(t, func() {
		if err := root.Parse([]string{
			"profiles", "list", "--name", "Development", "--include", "devices", "--device-fields", "name", "--limit-devices", "3", "--paginate", "--output", "json",
		}); err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := root.Run(context.Background()); err != nil {
			t.Fatalf("run error: %v", err)
		}
	})
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if !strings.Contains(stdout, `"id":"profile-1"`) || !strings.Contains(stdout, `"id":"profile-2"`) {
		t.Fatalf("stdout = %q, want both profile pages", stdout)
	}
}

func TestProfilesListRejectsInvalidQueryValuesBeforeAuth(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		concise bool
	}{
		{name: "sort", args: []string{"profiles", "list", "--sort", "createdDate"}, want: "--sort must be one of:"},
		{name: "profile fields", args: []string{"profiles", "list", "--fields", "notAField"}, want: "--fields must be one of:"},
		{name: "bundle fields", args: []string{"profiles", "list", "--bundle-id-fields", "uuid"}, want: "--bundle-id-fields must be one of:"},
		{name: "device fields", args: []string{"profiles", "list", "--device-fields", "uuid"}, want: "--device-fields must be one of:"},
		{name: "certificate fields", args: []string{"profiles", "list", "--certificate-fields", "uuid"}, want: "--certificate-fields must be one of:"},
		{name: "include", args: []string{"profiles", "list", "--include", "app"}, want: "--include must be one of:"},
		{name: "device limit", args: []string{"profiles", "list", "--limit-devices", "51"}, want: "--limit-devices must be between 1 and 50"},
		{name: "certificate limit", args: []string{"profiles", "list", "--limit-certificates", "51"}, want: "--limit-certificates must be between 1 and 50"},
		{name: "bundle fields dependency", args: []string{"profiles", "list", "--bundle-id-fields", "identifier"}, want: "--bundle-id-fields requires --include bundleId", concise: true},
		{name: "device fields dependency", args: []string{"profiles", "list", "--device-fields", "name"}, want: "--device-fields requires --include devices", concise: true},
		{name: "certificate fields dependency", args: []string{"profiles", "list", "--certificate-fields", "name"}, want: "--certificate-fields requires --include certificates", concise: true},
		{name: "device limit dependency", args: []string{"profiles", "list", "--limit-devices", "7"}, want: "--limit-devices requires --include devices", concise: true},
		{name: "certificate limit dependency", args: []string{"profiles", "list", "--limit-certificates", "7"}, want: "--limit-certificates requires --include certificates", concise: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			restore := shared.SetASCClientFactoryForTesting(func() (*asc.Client, error) {
				called = true
				return nil, errors.New("client factory must not run during validation")
			})
			t.Cleanup(restore)

			root := RootCommand("1.2.3")
			root.FlagSet.SetOutput(io.Discard)
			stdout, stderr := captureOutput(t, func() {
				if err := root.Parse(test.args); err != nil {
					t.Fatalf("parse error: %v", err)
				}
				err := root.Run(context.Background())
				if err == nil {
					t.Fatal("run error = nil, want validation error")
				}
				if test.concise {
					if errors.Is(err, flag.ErrHelp) || !shared.IsReportedUsageError(err) {
						t.Fatalf("expected concise reported usage error without flag.ErrHelp, got %v", err)
					}
					if got := rootcmd.ExitCodeFromError(err); got != rootcmd.ExitUsage {
						t.Fatalf("exit code = %d, want %d", got, rootcmd.ExitUsage)
					}
				}
			})
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if test.concise {
				want := "Error: " + test.want + "\n"
				if stderr != want {
					t.Fatalf("stderr = %q, want exact concise diagnostic %q", stderr, want)
				}
			} else if !strings.Contains(stderr, test.want) {
				t.Fatalf("stderr = %q, want %q", stderr, test.want)
			}
			if called {
				t.Fatal("client factory ran before validation")
			}
		})
	}
}

func TestProfilesListRejectsNextQueryConflictsBeforeAuth(t *testing.T) {
	const next = "https://api.appstoreconnect.apple.com/v1/profiles?cursor=abc"
	tests := []struct {
		name  string
		flag  string
		value string
	}{
		{name: "name", flag: "--name", value: "Development"},
		{name: "id", flag: "--id", value: "profile-1"},
		{name: "profile type", flag: "--profile-type", value: "IOS_APP_STORE"},
		{name: "profile state", flag: "--profile-state", value: "ACTIVE"},
		{name: "sort", flag: "--sort", value: "name"},
		{name: "fields", flag: "--fields", value: "name"},
		{name: "bundle fields", flag: "--bundle-id-fields", value: "identifier"},
		{name: "device fields", flag: "--device-fields", value: "name"},
		{name: "certificate fields", flag: "--certificate-fields", value: "name"},
		{name: "include", flag: "--include", value: "devices"},
		{name: "device limit", flag: "--limit-devices", value: "7"},
		{name: "certificate limit", flag: "--limit-certificates", value: "7"},
		{name: "limit", flag: "--limit", value: "7"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			restore := shared.SetASCClientFactoryForTesting(func() (*asc.Client, error) {
				called = true
				return nil, errors.New("client factory must not run during validation")
			})
			t.Cleanup(restore)

			root := RootCommand("1.2.3")
			root.FlagSet.SetOutput(io.Discard)
			stdout, stderr := captureOutput(t, func() {
				args := []string{"profiles", "list", "--next", next, test.flag, test.value}
				if err := root.Parse(args); err != nil {
					t.Fatalf("parse error: %v", err)
				}
				err := root.Run(context.Background())
				if !errors.Is(err, flag.ErrHelp) {
					t.Fatalf("run error = %v, want flag.ErrHelp", err)
				}
			})
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			want := "profiles list: --next cannot be combined with " + test.flag
			if !strings.Contains(stderr, want) {
				t.Fatalf("stderr = %q, want %q", stderr, want)
			}
			if called {
				t.Fatal("client factory ran before --next conflict validation")
			}
		})
	}
}

func installProfilesQueryTestClient(t *testing.T, server *httptest.Server) {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		cloned := req.Clone(req.Context())
		cloned.URL.Scheme = serverURL.Scheme
		cloned.URL.Host = serverURL.Host
		return server.Client().Transport.RoundTrip(cloned)
	})
	client, err := asc.NewClientWithHTTPClient(
		os.Getenv("ASC_KEY_ID"),
		os.Getenv("ASC_ISSUER_ID"),
		os.Getenv("ASC_PRIVATE_KEY_PATH"),
		&http.Client{Transport: transport},
	)
	if err != nil {
		t.Fatalf("create profiles query test client: %v", err)
	}
	t.Cleanup(shared.SetASCClientFactoryForTesting(func() (*asc.Client, error) {
		return client, nil
	}))
}
