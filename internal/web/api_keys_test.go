package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientCreateAPIKeySendsTeamKeyPayload(t *testing.T) {
	var requestBody map[string]any
	var requestMethod, requestPath, requestCSRF string
	var requestDecodeErr error
	client := newAPIKeyHTTPTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMethod = r.Method
		requestPath = r.URL.Path
		requestCSRF = r.Header.Get("X-CSRF-ITC")
		requestDecodeErr = json.NewDecoder(r.Body).Decode(&requestBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
					"data": {
						"type": "apiKeys",
						"id": "ABC123XYZ",
						"attributes": {
							"nickname": "Release automation",
							"roles": ["APP_MANAGER"],
							"allAppsVisible": true,
							"canDownload": true,
							"isActive": true,
							"keyType": "PUBLIC_API"
						}
					}
				}`))
	}))

	key, err := client.CreateAPIKey(context.Background(), APIKeyCreateAttributes{
		Nickname: "Release automation",
		Role:     "APP_MANAGER",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error: %v", err)
	}
	if requestMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", requestMethod)
	}
	if requestPath != "/iris/v1/apiKeys" {
		t.Fatalf("expected /iris/v1/apiKeys, got %s", requestPath)
	}
	if requestCSRF != "[asc-ui]" {
		t.Fatalf("expected integrations CSRF header, got %q", requestCSRF)
	}
	if requestDecodeErr != nil {
		t.Fatalf("decode request: %v", requestDecodeErr)
	}
	if key.KeyID != "ABC123XYZ" || key.Name != "Release automation" {
		t.Fatalf("unexpected key: %#v", key)
	}

	data, ok := requestBody["data"].(map[string]any)
	if !ok {
		t.Fatalf("expected JSON:API data object, got %#v", requestBody)
	}
	if data["type"] != "apiKeys" {
		t.Fatalf("expected apiKeys type, got %#v", data["type"])
	}
	attrs, ok := data["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("expected attributes object, got %#v", data)
	}
	if attrs["nickname"] != "Release automation" || attrs["keyType"] != "PUBLIC_API" || attrs["allAppsVisible"] != true {
		t.Fatalf("unexpected attributes: %#v", attrs)
	}
	roles, ok := attrs["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "APP_MANAGER" {
		t.Fatalf("unexpected roles: %#v", attrs["roles"])
	}
}

func TestClientDownloadAPIKeyDecodesP8(t *testing.T) {
	p8 := generateP256PKCS8PEM(t)
	var requestMethod, requestPath, requestedField string
	client := newAPIKeyHTTPTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMethod = r.Method
		requestPath = r.URL.Path
		requestedField = r.URL.Query().Get("fields[apiKeys]")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiKeyDownloadJSON("ABC123XYZ", p8))
	}))

	got, err := client.DownloadAPIKey(context.Background(), "ABC123XYZ")
	if err != nil {
		t.Fatalf("DownloadAPIKey() error: %v", err)
	}
	if requestMethod != http.MethodGet {
		t.Fatalf("expected GET, got %s", requestMethod)
	}
	if requestPath != "/iris/v1/apiKeys/ABC123XYZ" {
		t.Fatalf("unexpected path %q", requestPath)
	}
	if requestedField != "privateKey" {
		t.Fatalf("unexpected private-key field %q", requestedField)
	}
	if !bytes.Equal(got, p8) {
		t.Fatalf("unexpected decoded P8 length %d, want %d", len(got), len(p8))
	}
	assertErrorHasNoKeyMaterial(t, err, p8)
}

func TestClientDownloadAPIKeyRejectsInvalidP8Payloads(t *testing.T) {
	valid := generateP256PKCS8PEM(t)
	truncated := truncatedPKCS8PEM(t, valid)
	rsaKey := generateRSAPKCS8PEM(t)
	p384 := generateP384PKCS8PEM(t)
	multi := append(append([]byte{}, valid...), valid...)
	trailing := append(append([]byte{}, valid...), []byte("trailing-not-a-block\n")...)
	marker := []byte("-----BEGIN PRIVATE KEY-----\nfixture-secret\n-----END PRIVATE KEY-----\n")

	tests := []struct {
		name string
		id   string
		p8   []byte
	}{
		{name: "truncated", id: "ABC123XYZ", p8: truncated},
		{name: "non-pem", id: "ABC123XYZ", p8: []byte("not a key")},
		{name: "non-pkcs8 marker", id: "ABC123XYZ", p8: marker},
		{name: "rsa key type", id: "ABC123XYZ", p8: rsaKey},
		{name: "p384 key type", id: "ABC123XYZ", p8: p384},
		{name: "multi-block", id: "ABC123XYZ", p8: multi},
		{name: "trailing data", id: "ABC123XYZ", p8: trailing},
		{name: "leading data", id: "ABC123XYZ", p8: append(append([]byte{}, []byte("leading-junk\n")...), valid...)},
		{name: "mismatched resource id", id: "OTHERKEY", p8: valid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newAPIKeyHTTPTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(apiKeyDownloadJSON(tt.id, tt.p8))
			}))
			got, err := client.DownloadAPIKey(context.Background(), "ABC123XYZ")
			if !errors.Is(err, ErrAPIKeyResponseInvalid) {
				t.Fatalf("expected invalid P8 response error, got %v", err)
			}
			if got != nil {
				t.Fatalf("expected no decoded P8, got %d bytes", len(got))
			}
			assertErrorHasNoKeyMaterial(t, err, valid, tt.p8)
		})
	}
}

func TestClientGetAPIKeyParsesIssuerID(t *testing.T) {
	var includedResource string
	client := newAPIKeyHTTPTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		includedResource = r.URL.Query().Get("include")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
					"data": {
						"type": "apiKeys",
						"id": "ABC123XYZ",
						"attributes": {"nickname":"Release automation","roles":["ADMIN"],"allAppsVisible":true,"isActive":true,"keyType":"PUBLIC_API"},
						"relationships": {"provider":{"data":{"type":"contentProviders","id":"69a6de00-aaaa-bbbb-cccc-123456789abc"}}}
					}
				}`))
	}))

	key, err := client.GetAPIKey(context.Background(), "ABC123XYZ")
	if err != nil {
		t.Fatalf("GetAPIKey() error: %v", err)
	}
	if includedResource != "provider" {
		t.Fatalf("expected provider include, got %q", includedResource)
	}
	if key.IssuerID != "69a6de00-aaaa-bbbb-cccc-123456789abc" {
		t.Fatalf("unexpected issuer ID %q", key.IssuerID)
	}
}

func TestIsAPIKeyDownloadRetryable(t *testing.T) {
	if IsAPIKeyDownloadRetryable(nil) {
		t.Fatal("expected nil error not to be retryable")
	}
	if !IsAPIKeyDownloadRetryable(fmt.Errorf("temporary transport failure")) {
		t.Fatal("expected generic transport error to be retryable")
	}
	if IsAPIKeyDownloadRetryable(fmt.Errorf("download failed: %w", ErrAPIKeyResponseInvalid)) {
		t.Fatal("expected invalid download response not to be retryable")
	}
	for _, status := range []int{http.StatusNotFound, http.StatusConflict, http.StatusTooManyRequests, http.StatusBadGateway} {
		if !IsAPIKeyDownloadRetryable(&APIError{Status: status}) {
			t.Fatalf("expected status %d to be retryable", status)
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		if IsAPIKeyDownloadRetryable(&APIError{Status: status}) {
			t.Fatalf("expected status %d not to be retryable", status)
		}
	}
}

type apiKeyRewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t apiKeyRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	requestURL := *request.URL
	requestURL.Scheme = t.target.Scheme
	requestURL.Host = t.target.Host
	clone.URL = &requestURL
	return t.base.RoundTrip(clone)
}

func generateP256PKCS8PEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return marshalPKCS8PEM(t, key)
}

func generateP384PKCS8PEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	return marshalPKCS8PEM(t, key)
}

func generateRSAPKCS8PEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return marshalPKCS8PEM(t, key)
}

func marshalPKCS8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func truncatedPKCS8PEM(t *testing.T, valid []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(valid)
	if block == nil || len(block.Bytes) < 8 {
		t.Fatal("expected a decodable PKCS#8 PEM fixture")
	}
	truncated := append([]byte{}, block.Bytes[:len(block.Bytes)/2]...)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: truncated})
}

func apiKeyDownloadJSON(id string, p8 []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(p8)
	return []byte(`{"data":{"type":"apiKeys","id":"` + id + `","attributes":{"privateKey":"` + encoded + `"}}}`)
}

func assertErrorHasNoKeyMaterial(t *testing.T, err error, payloads ...[]byte) {
	t.Helper()
	text := ""
	if err != nil {
		text = err.Error()
	}
	for _, payload := range payloads {
		assertNoKeyMaterial(t, payload, text)
	}
}

func assertNoKeyMaterial(t *testing.T, p8 []byte, outputs ...string) {
	t.Helper()
	if len(p8) == 0 {
		return
	}
	full := strings.TrimSpace(string(p8))
	block, _ := pem.Decode(p8)
	for _, out := range outputs {
		if out == "" {
			continue
		}
		if full != "" && strings.Contains(out, full) {
			t.Fatal("output contained P8 contents")
		}
		if strings.Contains(out, "-----BEGIN PRIVATE KEY-----") || strings.Contains(out, "-----END PRIVATE KEY-----") {
			t.Fatal("output contained PEM boundary")
		}
		if block != nil && len(block.Bytes) > 0 {
			if strings.Contains(out, base64.StdEncoding.EncodeToString(block.Bytes)) {
				t.Fatal("output contained PKCS#8 DER")
			}
		}
	}
}

func newAPIKeyHTTPTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &Client{
		httpClient: &http.Client{Transport: apiKeyRewriteTransport{
			target: target,
			base:   server.Client().Transport,
		}},
	}
}
