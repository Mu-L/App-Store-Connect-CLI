package testflight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func TestOnceCSVFlag_RejectsRepeatedUse(t *testing.T) {
	value := onceCSVFlag{flagName: "group"}

	if err := value.Set("Beta"); err != nil {
		t.Fatalf("first Set() error: %v", err)
	}
	if got := value.String(); got != "Beta" {
		t.Fatalf("String() = %q, want %q", got, "Beta")
	}

	err := value.Set("QA")
	if err == nil {
		t.Fatal("second Set() should fail")
	}
	if !strings.Contains(err.Error(), "--group") || !strings.Contains(err.Error(), "comma-separated") {
		t.Fatalf("second Set() error should mention --group and comma-separated usage, got %q", err.Error())
	}
	if got := value.String(); got != "Beta" {
		t.Fatalf("rejected Set() must not overwrite value, got %q", got)
	}
}

func TestBetaTestersAddCommand_CSVGroupsPassValidation(t *testing.T) {
	isolateTestFlightAuthEnvForAddTests(t)

	cmd := BetaTestersAddCommand()
	if err := cmd.FlagSet.Parse([]string{
		"--app", "123456789",
		"--email", "tester@example.com",
		"--group", "Beta,QA Team",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	err := cmd.Exec(context.Background(), []string{})
	if errors.Is(err, flag.ErrHelp) {
		t.Fatalf("comma-separated groups should pass validation, got %v", err)
	}
}

func TestResolveBetaGroupIDs_SingleFetchResolvesAllTokens(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", req.Method)
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if req.URL.Path != "/v1/apps/123456789/betaGroups" {
			t.Errorf("unexpected request path %q", req.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"type": "betaGroups", "id": "group-beta", "attributes": map[string]any{"name": "Beta"}},
				{"type": "betaGroups", "id": "group-ios27", "attributes": map[string]any{"name": "iOS 27"}},
				{"type": "betaGroups", "id": "group-qa", "attributes": map[string]any{"name": "QA Team"}},
			},
			"links": map[string]string{},
		}); err != nil {
			t.Fatalf("marshal response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client := newBetaGroupResolutionClient(t, server)

	got, err := resolveBetaGroupIDs(context.Background(), client, "123456789", []string{
		"group-beta",
		"ios 27",
		"QA Team",
	})
	if err != nil {
		t.Fatalf("resolveBetaGroupIDs() error: %v", err)
	}

	want := []string{"group-beta", "group-ios27", "group-qa"}
	if len(got) != len(want) {
		t.Fatalf("resolveBetaGroupIDs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("resolveBetaGroupIDs()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	if requests != 1 {
		t.Fatalf("beta group fetches = %d, want 1", requests)
	}
}

func TestResolveBetaGroupIDs_UnknownTokenFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"type": "betaGroups", "id": "group-beta", "attributes": map[string]any{"name": "Beta"}},
			},
			"links": map[string]string{},
		}); err != nil {
			t.Fatalf("marshal response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client := newBetaGroupResolutionClient(t, server)

	_, err := resolveBetaGroupIDs(context.Background(), client, "123456789", []string{"Beta", "Nope"})
	if err == nil {
		t.Fatal("unknown group token should fail")
	}
	if !strings.Contains(err.Error(), "Nope") {
		t.Fatalf("error should name the unresolved group, got %q", err.Error())
	}
}

func newBetaGroupResolutionClient(t *testing.T, server *httptest.Server) *asc.Client {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "AuthKey.p8")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport type = %T, want *http.Transport", server.Client().Transport)
	}
	transport = transport.Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}

	client, err := asc.NewClientWithHTTPClient("KEY123", "ISS456", keyPath, &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("NewClientWithHTTPClient() error: %v", err)
	}
	return client
}
