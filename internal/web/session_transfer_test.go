package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
)

func withFileSessionCache(t *testing.T) {
	t.Helper()
	withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "file")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))
}

func persistTestSession(t *testing.T, appleID string, cookies ...*http.Cookie) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	target, err := url.Parse("https://appstoreconnect.apple.com/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	jar.SetCookies(target, cookies)
	if err := PersistSession(&AuthSession{Client: &http.Client{Jar: jar}, UserEmail: appleID}); err != nil {
		t.Fatalf("PersistSession() error = %v", err)
	}
}

func TestExportSessionBundleRoundTripsThroughImport(t *testing.T) {
	withFileSessionCache(t)
	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	persistTestSession(
		t, "user@example.com",
		&http.Cookie{Name: "myacinfo", Value: "token-value", Path: "/", Expires: expires},
		&http.Cookie{Name: "itctx", Value: "ctx-value", Path: "/", Expires: expires.Add(time.Hour)},
	)

	bundle, ok, err := ExportSessionBundle("user@example.com")
	if err != nil {
		t.Fatalf("ExportSessionBundle() error = %v", err)
	}
	if !ok || bundle == nil {
		t.Fatal("ExportSessionBundle() ok = false, want a cached session")
	}
	if bundle.Kind != SessionBundleKind || bundle.Version != SessionBundleVersion {
		t.Fatalf("unexpected bundle envelope: kind=%q version=%d", bundle.Kind, bundle.Version)
	}
	if bundle.AppleID != "user@example.com" {
		t.Fatalf("AppleID = %q, want user@example.com", bundle.AppleID)
	}
	if len(bundle.Cookies) != 2 {
		t.Fatalf("len(Cookies) = %d, want 2", len(bundle.Cookies))
	}
	// Cookies are ordered deterministically so exports are reproducible.
	if bundle.Cookies[0].Name != "itctx" || bundle.Cookies[1].Name != "myacinfo" {
		t.Fatalf("unexpected cookie order: %q, %q", bundle.Cookies[0].Name, bundle.Cookies[1].Name)
	}
	// net/http/cookiejar returns only name and value, so the session cache never
	// records cookie expiry and an export from the cache cannot report one.
	if bundle.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil for a cache-backed export", bundle.ExpiresAt)
	}
	for _, cookie := range bundle.Cookies {
		if cookie.Expires != nil {
			t.Fatalf("cookie %q carries an expiry the cookie jar cannot preserve", cookie.Name)
		}
	}

	// Import into a second, empty cache and confirm the session resumes.
	withFileSessionCache(t)
	if _, ok, err := ExportSessionBundle("user@example.com"); err != nil || ok {
		t.Fatalf("ExportSessionBundle() on empty cache = (%v, %v), want (false, nil)", ok, err)
	}

	summary, err := ImportSessionBundle(bundle)
	if err != nil {
		t.Fatalf("ImportSessionBundle() error = %v", err)
	}
	if summary.AppleID != "user@example.com" || summary.CookieCount != 2 || summary.SkippedExpired != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	loaded, ok, err := LoadCachedSession("user@example.com")
	if err != nil {
		t.Fatalf("LoadCachedSession() error = %v", err)
	}
	if !ok || loaded == nil {
		t.Fatal("LoadCachedSession() ok = false, want the imported session")
	}
	target, _ := url.Parse("https://appstoreconnect.apple.com/")
	values := map[string]string{}
	for _, cookie := range loaded.Client.Jar.Cookies(target) {
		values[cookie.Name] = cookie.Value
	}
	if values["myacinfo"] != "token-value" || values["itctx"] != "ctx-value" {
		t.Fatalf("imported cookie jar = %#v, want the exported values", values)
	}

	// The imported session is also the last cached session.
	last, ok, err := LoadLastCachedSession()
	if err != nil || !ok || last == nil {
		t.Fatalf("LoadLastCachedSession() = (%v, %v, %v), want the imported session", last, ok, err)
	}
	if last.UserEmail != "user@example.com" {
		t.Fatalf("last session UserEmail = %q, want user@example.com", last.UserEmail)
	}
}

func TestExportSessionBundleUsesLastCachedSessionWithoutAppleID(t *testing.T) {
	withFileSessionCache(t)
	persistTestSession(
		t, "last@example.com",
		&http.Cookie{Name: "myacinfo", Value: "token", Path: "/", Expires: time.Now().Add(time.Hour)},
	)

	bundle, ok, err := ExportSessionBundle("")
	if err != nil || !ok || bundle == nil {
		t.Fatalf("ExportSessionBundle(\"\") = (%v, %v, %v), want the last cached session", bundle, ok, err)
	}
	if bundle.AppleID != "last@example.com" {
		t.Fatalf("AppleID = %q, want last@example.com", bundle.AppleID)
	}
}

func TestExportSessionBundleReportsDisabledCache(t *testing.T) {
	withFileSessionCache(t)
	t.Setenv(webSessionCacheEnabledEnv, "0")

	if _, _, err := ExportSessionBundle("user@example.com"); !errors.Is(err, ErrSessionCacheDisabled) {
		t.Fatalf("ExportSessionBundle() error = %v, want ErrSessionCacheDisabled", err)
	}
}

func TestImportSessionBundleReportsDisabledCache(t *testing.T) {
	withFileSessionCache(t)
	t.Setenv(webSessionBackendEnv, "off")

	bundle := validTestBundle(time.Now().Add(time.Hour))
	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionCacheDisabled) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionCacheDisabled", err)
	}
}

func validTestBundle(expires time.Time) *SessionBundle {
	expiry := expires.UTC()
	return &SessionBundle{
		Kind:       SessionBundleKind,
		Version:    SessionBundleVersion,
		ExportedAt: time.Now().UTC(),
		AppleID:    "user@example.com",
		Cookies: []SessionBundleCookie{{
			URL:     "https://appstoreconnect.apple.com/",
			Name:    "myacinfo",
			Value:   "token",
			Path:    "/",
			Expires: &expiry,
		}},
	}
}

func fakeSessionInfoValidator(t *testing.T, status int, body string) (sessionInfoValidator, *int) {
	t.Helper()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet {
			t.Errorf("session info method = %s, want GET", r.Method)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	return func(ctx context.Context, client *http.Client) (string, error) {
		target, err := url.Parse(olympusSessionURL)
		if err != nil {
			return "", err
		}
		if client == nil || client.Jar == nil || len(client.Jar.Cookies(target)) == 0 {
			return "", errors.New("session info validator received no imported cookies")
		}
		info, err := getSessionInfoAt(ctx, client, server.URL)
		if err != nil {
			return "", err
		}
		return info.User.EmailAddress, nil
	}, &calls
}

func TestImportSessionBundleValidatesWithFakeSessionInfoServer(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	validator, calls := fakeSessionInfoValidator(t, http.StatusOK, `{"provider":{"providerId":42},"user":{"emailAddress":"user@example.com"}}`)

	summary, err := importSessionBundleWithValidator(context.Background(), bundle, false, validator)
	if err != nil {
		t.Fatalf("importSessionBundleWithValidator() error = %v", err)
	}
	if summary.AppleID != bundle.AppleID {
		t.Fatalf("summary AppleID = %q, want %q", summary.AppleID, bundle.AppleID)
	}
	if *calls != 1 {
		t.Fatalf("fake session info calls = %d, want 1", *calls)
	}
	if _, ok, err := readSessionFromFile(webSessionCacheKey(bundle.AppleID)); err != nil || !ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want the validated session", ok, err)
	}
}

func TestImportSessionBundleRejectsUnvalidatedSessionBeforePersistence(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"error":"unauthorized"}`},
		{name: "forbidden", status: http.StatusForbidden, body: `{"error":"forbidden"}`},
		{name: "malformed response", status: http.StatusOK, body: "{"},
		{name: "trailing response", status: http.StatusOK, body: `{"user":{"emailAddress":"user@example.com"}} trailing`},
		{name: "apple id mismatch", status: http.StatusOK, body: `{"user":{"emailAddress":"other@example.com"}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFileSessionCache(t)
			bundle := validTestBundle(time.Now().Add(time.Hour))
			validator, calls := fakeSessionInfoValidator(t, tc.status, tc.body)

			if _, err := importSessionBundleWithValidator(context.Background(), bundle, false, validator); !errors.Is(err, ErrSessionBundleValidationFailed) {
				t.Fatalf("importSessionBundleWithValidator() error = %v, want ErrSessionBundleValidationFailed", err)
			}
			if *calls != 1 {
				t.Fatalf("fake session info calls = %d, want 1", *calls)
			}
			if _, ok, err := readSessionFromFile(webSessionCacheKey(bundle.AppleID)); err != nil || ok {
				t.Fatalf("readSessionFromFile() = (%v, %v), want no persisted session", ok, err)
			}
		})
	}
}

func TestImportSessionBundleDoesNotOverwriteExistingSessionWhenValidationFails(t *testing.T) {
	withFileSessionCache(t)
	persistTestSession(
		t,
		"user@example.com",
		&http.Cookie{Name: "myacinfo", Value: "old-token", Path: "/", Expires: time.Now().Add(time.Hour)},
	)
	bundle := validTestBundle(time.Now().Add(2 * time.Hour))
	validator, _ := fakeSessionInfoValidator(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)

	if _, err := importSessionBundleWithValidator(context.Background(), bundle, true, validator); !errors.Is(err, ErrSessionBundleValidationFailed) {
		t.Fatalf("importSessionBundleWithValidator() error = %v, want ErrSessionBundleValidationFailed", err)
	}
	loaded, ok, err := LoadCachedSession(bundle.AppleID)
	if err != nil || !ok || loaded == nil {
		t.Fatalf("LoadCachedSession() = (%v, %v, %v), want the prior session", loaded, ok, err)
	}
	target, _ := url.Parse("https://appstoreconnect.apple.com/")
	values := loaded.Client.Jar.Cookies(target)
	if len(values) != 1 || values[0].Value != "old-token" {
		t.Fatalf("cached cookies = %#v, want old-token", values)
	}
}

func TestImportSessionBundleRejectsSessionInfoTransportError(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close()
	validator := func(ctx context.Context, client *http.Client) (string, error) {
		info, err := getSessionInfoAt(ctx, client, endpoint)
		if err != nil {
			return "", err
		}
		return info.User.EmailAddress, nil
	}

	if _, err := importSessionBundleWithValidator(context.Background(), bundle, false, validator); !errors.Is(err, ErrSessionBundleValidationFailed) {
		t.Fatalf("importSessionBundleWithValidator() error = %v, want ErrSessionBundleValidationFailed", err)
	}
	if _, ok, err := readSessionFromFile(webSessionCacheKey(bundle.AppleID)); err != nil || ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want no persisted session", ok, err)
	}
}

func TestImportSessionBundleSkipsExpiredCookies(t *testing.T) {
	withFileSessionCache(t)
	live := time.Now().Add(time.Hour).UTC()
	stale := time.Now().Add(-time.Hour).UTC()
	bundle := validTestBundle(live)
	bundle.Cookies = append(bundle.Cookies, SessionBundleCookie{
		URL:     "https://idmsa.apple.com/",
		Name:    "expired",
		Value:   "gone",
		Expires: &stale,
	})

	summary, err := ImportSessionBundle(bundle)
	if err != nil {
		t.Fatalf("ImportSessionBundle() error = %v", err)
	}
	if summary.CookieCount != 1 || summary.SkippedExpired != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestImportSessionBundleRefusesFullyExpiredBundle(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(-time.Hour))

	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionBundleUnusable) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionBundleUnusable", err)
	}
	if _, ok, err := LoadCachedSession("user@example.com"); err != nil || ok {
		t.Fatalf("LoadCachedSession() = (%v, %v), want no cached session after a refused import", ok, err)
	}
}

func TestDecodeSessionBundleRejectsInvalidDocuments(t *testing.T) {
	live := time.Now().Add(time.Hour).UTC()

	cases := []struct {
		name    string
		mutate  func(*SessionBundle)
		wantErr string
	}{
		{
			name:    "wrong kind",
			mutate:  func(b *SessionBundle) { b.Kind = "cookies.txt" },
			wantErr: "kind",
		},
		{
			name:    "unsupported version",
			mutate:  func(b *SessionBundle) { b.Version = 99 },
			wantErr: "version",
		},
		{
			name:    "missing apple id",
			mutate:  func(b *SessionBundle) { b.AppleID = "  " },
			wantErr: "appleId",
		},
		{
			name:    "no cookies",
			mutate:  func(b *SessionBundle) { b.Cookies = nil },
			wantErr: "no cookies",
		},
		{
			name:    "missing cookie name",
			mutate:  func(b *SessionBundle) { b.Cookies[0].Name = "" },
			wantErr: "missing name",
		},
		{
			name:    "unsupported origin",
			mutate:  func(b *SessionBundle) { b.Cookies[0].URL = "https://evil.example.com/" },
			wantErr: "unsupported url",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := validTestBundle(live)
			tc.mutate(bundle)
			if err := bundle.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want a validation failure")
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeSessionBundleParsesExportedDocument(t *testing.T) {
	document := []byte(`{
  "kind": "asc-web-session",
  "version": 1,
  "exportedAt": "2026-09-02T10:00:00Z",
  "appleId": "user@example.com",
  "cookies": [
    {"url": "https://appstoreconnect.apple.com/", "name": "myacinfo", "value": "token", "path": "/", "secure": true, "httpOnly": true}
  ]
}`)

	bundle, err := DecodeSessionBundle(document)
	if err != nil {
		t.Fatalf("DecodeSessionBundle() error = %v", err)
	}
	if bundle.AppleID != "user@example.com" || len(bundle.Cookies) != 1 {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
	if !bundle.Cookies[0].Secure || !bundle.Cookies[0].HTTPOnly {
		t.Fatalf("cookie attributes were dropped: %+v", bundle.Cookies[0])
	}
}

func TestDecodeSessionBundleRejectsMalformedJSON(t *testing.T) {
	if _, err := DecodeSessionBundle([]byte("not json")); err == nil {
		t.Fatal("DecodeSessionBundle() error = nil, want a decode failure")
	}
	if _, err := DecodeSessionBundle(nil); err == nil {
		t.Fatal("DecodeSessionBundle(nil) error = nil, want a decode failure")
	}
}

func TestDecodeSessionBundleRejectsUnknownFields(t *testing.T) {
	document := []byte(`{
  "kind": "asc-web-session",
  "version": 1,
  "appleId": "user@example.com",
  "cookies": [{
    "url": "https://appstoreconnect.apple.com/",
    "name": "myacinfo",
    "value": "token",
    "expire": "2099-01-01T00:00:00Z"
  }]
}`)

	if _, err := DecodeSessionBundle(document); err == nil {
		t.Fatal("DecodeSessionBundle() error = nil, want an unknown-field failure")
	} else if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeSessionBundle() error = %v, want unknown-field context", err)
	}
}

func TestImportSessionBundleRejectsInvalidCookieSyntax(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Value = "token;injected"

	if err := bundle.Validate(); !errors.Is(err, ErrSessionCookieInvalid) {
		t.Fatalf("Validate() error = %v, want ErrSessionCookieInvalid", err)
	}
	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionCookieInvalid) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionCookieInvalid", err)
	}
	if err := bundle.Validate(); err != nil && strings.Contains(err.Error(), "token;injected") {
		t.Fatalf("validation error leaked a cookie value: %v", err)
	}
	if _, ok, err := LoadCachedSession("user@example.com"); err != nil || ok {
		t.Fatalf("LoadCachedSession() = (%v, %v), want no cached session after a refused import", ok, err)
	}
}

func TestImportSessionBundleRejectsCookieDomainTheJarCannotStore(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Domain = "evil.example"

	if err := bundle.Validate(); !errors.Is(err, ErrSessionCookieNotStorable) {
		t.Fatalf("Validate() error = %v, want ErrSessionCookieNotStorable", err)
	}
	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionCookieNotStorable) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionCookieNotStorable", err)
	}
	if _, ok, err := LoadCachedSession("user@example.com"); err != nil || ok {
		t.Fatalf("LoadCachedSession() = (%v, %v), want no cached session after a refused import", ok, err)
	}
}

func TestImportSessionBundleRejectsPublicSuffixCookieDomain(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Domain = "com"

	if err := bundle.Validate(); !errors.Is(err, ErrSessionCookieNotStorable) {
		t.Fatalf("Validate() error = %v, want ErrSessionCookieNotStorable", err)
	}
	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionCookieNotStorable) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionCookieNotStorable", err)
	}
	if _, ok, err := LoadCachedSession("user@example.com"); err != nil || ok {
		t.Fatalf("LoadCachedSession() = (%v, %v), want no cached session after a refused import", ok, err)
	}
}

func TestImportSessionBundleRejectsCookieDomainBroaderThanOrigin(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Domain = "apple.com"

	if err := bundle.Validate(); !errors.Is(err, ErrSessionCookieNotStorable) {
		t.Fatalf("Validate() error = %v, want ErrSessionCookieNotStorable", err)
	}
}

func TestImportSessionBundleAcceptsOriginHostCookieDomain(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Domain = "appstoreconnect.apple.com"

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil for the origin host", err)
	}
	if _, err := ImportSessionBundle(bundle); err != nil {
		t.Fatalf("ImportSessionBundle() error = %v", err)
	}
}

func TestImportSessionBundleTreatsExplicitZeroExpiryAsExpired(t *testing.T) {
	withFileSessionCache(t)
	zero := time.Time{}
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Expires = &zero

	if _, err := ImportSessionBundle(bundle); !errors.Is(err, ErrSessionBundleUnusable) {
		t.Fatalf("ImportSessionBundle() error = %v, want ErrSessionBundleUnusable", err)
	}
	if _, ok, err := LoadCachedSession("user@example.com"); err != nil || ok {
		t.Fatalf("LoadCachedSession() = (%v, %v), want no cached session after a refused import", ok, err)
	}
}

func TestImportSessionBundleFailsWhenLastSessionPointerCannotBeUpdated(t *testing.T) {
	withFileSessionCache(t)
	lastPath, err := webSessionLastFilePath()
	if err != nil {
		t.Fatalf("webSessionLastFilePath() error = %v", err)
	}
	if err := os.MkdirAll(lastPath, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", lastPath, err)
	}

	bundle := validTestBundle(time.Now().Add(time.Hour))
	if _, err := ImportSessionBundle(bundle); err == nil {
		t.Fatal("ImportSessionBundle() error = nil, want a last-session pointer failure")
	}
	key := webSessionCacheKey(bundle.AppleID)
	if _, ok, err := readSessionFromFile(key); err != nil {
		t.Fatalf("readSessionFromFile() error = %v", err)
	} else if ok {
		t.Fatal("failed import left a new session cache entry behind")
	}
}

func TestImportSessionBundleRestoresExistingSessionWhenLastSessionPointerCannotBeUpdated(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	old := persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-token", Path: "/"}},
		},
	}
	if err := writeSessionToFile(key, old); err != nil {
		t.Fatalf("writeSessionToFile() error = %v", err)
	}
	lastPath, err := webSessionLastFilePath()
	if err != nil {
		t.Fatalf("webSessionLastFilePath() error = %v", err)
	}
	if err := os.Remove(lastPath); err != nil {
		t.Fatalf("Remove(%q) error = %v", lastPath, err)
	}
	if err := os.MkdirAll(lastPath, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", lastPath, err)
	}

	if _, err := ImportSessionBundle(bundle); err == nil {
		t.Fatal("ImportSessionBundle() error = nil, want a last-session pointer failure")
	}
	restored, ok, err := readSessionFromFile(key)
	if err != nil {
		t.Fatalf("readSessionFromFile() error = %v", err)
	}
	if !ok {
		t.Fatal("failed import removed the previous session cache entry")
	}
	if got := restored.Cookies["https://appstoreconnect.apple.com/"][0].Value; got != "old-token" {
		t.Fatalf("restored cookie value = %q, want old-token", got)
	}
}

func TestImportSessionBundleOverwritesMalformedKeychainStore(t *testing.T) {
	kr := withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "keychain")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "unused-file-cache"))
	if err := kr.Set(keyring.Item{Key: webSessionStoreItem, Data: []byte("{")}); err != nil {
		t.Fatalf("seed malformed keychain store: %v", err)
	}

	bundle := validTestBundle(time.Now().Add(time.Hour))
	if _, err := ImportSessionBundleWithOptions(bundle, true); err != nil {
		t.Fatalf("ImportSessionBundle() error = %v, want overwrite of a malformed keychain store", err)
	}
	loaded, ok, err := LoadCachedSession("user@example.com")
	if err != nil || !ok || loaded == nil {
		t.Fatalf("LoadCachedSession() = (%v, %v, %v), want the imported session", loaded, ok, err)
	}
}

func TestImportSessionBundleOverwriteRemovesDefaultKeychainFallback(t *testing.T) {
	withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	if err := writeSessionToKeychain(key, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToKeychain() error = %v", err)
	}

	if _, err := ImportSessionBundleWithOptions(bundle, true); err != nil {
		t.Fatalf("ImportSessionBundleWithOptions() error = %v", err)
	}
	if _, ok, err := readSessionFromKeychain(key); err != nil {
		t.Fatalf("readSessionFromKeychain() error = %v", err)
	} else if ok {
		t.Fatal("overwrite left the stale keychain fallback entry behind")
	}
	if _, ok, err := readSessionFromFile(key); err != nil {
		t.Fatalf("readSessionFromFile() error = %v", err)
	} else if !ok {
		t.Fatal("overwrite did not persist the imported file-backed session")
	}
}

func TestImportSessionBundleConvertsPositiveMaxAgeToAbsoluteExpiry(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies[0].Expires = nil
	bundle.Cookies[0].MaxAge = 60

	before := time.Now().UTC()
	summary, err := ImportSessionBundle(bundle)
	if err != nil {
		t.Fatalf("ImportSessionBundle() error = %v", err)
	}
	after := time.Now().UTC()
	if summary.CookieCount != 1 || summary.SkippedExpired != 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	key := webSessionCacheKey("user@example.com")
	sess, ok, err := readSessionFromFile(key)
	if err != nil || !ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want the imported session", ok, err)
	}
	got := sess.Cookies["https://appstoreconnect.apple.com/"]
	if len(got) != 1 {
		t.Fatalf("imported cookies = %#v, want 1 cookie", sess.Cookies)
	}
	if got[0].MaxAge != 0 {
		t.Fatalf("MaxAge = %d, want 0 after converting to an absolute expiry", got[0].MaxAge)
	}
	if got[0].Expires.IsZero() {
		t.Fatal("Expires is zero, want an absolute deadline derived from MaxAge")
	}
	wantEarliest := before.Add(60 * time.Second)
	wantLatest := after.Add(60 * time.Second)
	if got[0].Expires.Before(wantEarliest) || got[0].Expires.After(wantLatest) {
		t.Fatalf("Expires = %v, want between %v and %v", got[0].Expires, wantEarliest, wantLatest)
	}
}

func TestImportSessionBundleDoesNotMergeDifferentAppleIDs(t *testing.T) {
	withFileSessionCache(t)
	firstExpires := time.Now().Add(time.Hour)
	persistTestSession(
		t, "first@example.com",
		&http.Cookie{Name: "myacinfo", Value: "first-token", Path: "/", Expires: firstExpires},
	)

	bundle := validTestBundle(time.Now().Add(2 * time.Hour))
	bundle.AppleID = "second@example.com"
	bundle.Cookies[0].Name = "myacinfo"
	bundle.Cookies[0].Value = "second-token"
	previousFetcher := sessionInfoFetcher
	sessionInfoFetcher = func(context.Context, *http.Client) (*sessionInfo, error) {
		out := &sessionInfo{}
		out.User.EmailAddress = "second@example.com"
		return out, nil
	}
	t.Cleanup(func() { sessionInfoFetcher = previousFetcher })

	if _, err := ImportSessionBundle(bundle); err != nil {
		t.Fatalf("ImportSessionBundle() error = %v", err)
	}

	first, ok, err := LoadCachedSession("first@example.com")
	if err != nil || !ok || first == nil {
		t.Fatalf("LoadCachedSession(first) = (%v, %v, %v), want the original session", first, ok, err)
	}
	target, _ := url.Parse("https://appstoreconnect.apple.com/")
	firstValues := map[string]string{}
	for _, cookie := range first.Client.Jar.Cookies(target) {
		firstValues[cookie.Name] = cookie.Value
	}
	if firstValues["myacinfo"] != "first-token" {
		t.Fatalf("first account cookies = %#v, want the original value", firstValues)
	}

	second, ok, err := LoadCachedSession("second@example.com")
	if err != nil || !ok || second == nil {
		t.Fatalf("LoadCachedSession(second) = (%v, %v, %v), want the imported session", second, ok, err)
	}

	last, ok, err := LoadLastCachedSession()
	if err != nil || !ok || last == nil {
		t.Fatalf("LoadLastCachedSession() = (%v, %v, %v), want the imported session", last, ok, err)
	}
	if last.UserEmail != "second@example.com" {
		t.Fatalf("last session UserEmail = %q, want second@example.com", last.UserEmail)
	}
}

func TestImportSessionBundlePersistsCookiesRefreshedDuringValidation(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	target, err := url.Parse("https://appstoreconnect.apple.com/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	validator := func(_ context.Context, client *http.Client) (string, error) {
		if client == nil || client.Jar == nil {
			return "", errors.New("session info validator received no cookie jar")
		}
		// Apple rotates the session cookie and adds a new one while answering
		// the validation request.
		client.Jar.SetCookies(target, []*http.Cookie{
			{Name: "myacinfo", Value: "rotated-token"},
			{Name: "dqsid", Value: "issued-token"},
		})
		return bundle.AppleID, nil
	}

	if _, err := importSessionBundleWithValidator(context.Background(), bundle, false, validator); err != nil {
		t.Fatalf("importSessionBundleWithValidator() error = %v", err)
	}

	sess, ok, err := readSessionFromFile(webSessionCacheKey(bundle.AppleID))
	if err != nil || !ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want the imported session", ok, err)
	}
	values := map[string]pCookie{}
	for _, cookie := range sess.Cookies["https://appstoreconnect.apple.com/"] {
		values[cookie.Name] = cookie
	}
	if values["myacinfo"].Value != "rotated-token" {
		t.Fatalf("cached myacinfo = %q, want the value Apple returned during validation", values["myacinfo"].Value)
	}
	if values["myacinfo"].Expires.IsZero() {
		t.Fatal("cached myacinfo lost the bundle expiry while folding in the refreshed value")
	}
	if values["dqsid"].Value != "issued-token" {
		t.Fatalf("cached dqsid = %q, want the cookie Apple issued during validation", values["dqsid"].Value)
	}
}

func TestImportSessionBundleDropsCookiesDeletedDuringValidation(t *testing.T) {
	withFileSessionCache(t)
	bundle := validTestBundle(time.Now().Add(time.Hour))
	bundle.Cookies = append(bundle.Cookies, SessionBundleCookie{
		URL:     "https://appstoreconnect.apple.com/",
		Name:    "itctx",
		Value:   "context-token",
		Path:    "/",
		Expires: bundle.Cookies[0].Expires,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "myacinfo=; Max-Age=0; Path=/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"user":{"emailAddress":"user@example.com"}}`)
	}))
	t.Cleanup(server.Close)
	appleOrigin, err := url.Parse("https://appstoreconnect.apple.com/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	validator := func(ctx context.Context, client *http.Client) (string, error) {
		info, err := getSessionInfoAt(ctx, client, server.URL)
		if err != nil {
			return "", err
		}
		// The test server stands in for Apple's endpoint, so replay its actual
		// Set-Cookie header at the canonical imported origin.
		response := &http.Response{Header: http.Header{
			"Set-Cookie": {"myacinfo=; Max-Age=0; Path=/"},
		}}
		client.Jar.SetCookies(appleOrigin, response.Cookies())
		return info.User.EmailAddress, nil
	}

	if _, err := importSessionBundleWithValidator(context.Background(), bundle, false, validator); err != nil {
		t.Fatalf("importSessionBundleWithValidator() error = %v", err)
	}
	sess, ok, err := readSessionFromFile(webSessionCacheKey(bundle.AppleID))
	if err != nil || !ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want the imported session", ok, err)
	}
	cookies := sess.Cookies["https://appstoreconnect.apple.com/"]
	values := map[string]string{}
	for _, cookie := range cookies {
		values[cookie.Name] = cookie.Value
	}
	if _, deleted := values["myacinfo"]; deleted {
		t.Fatalf("cached cookies retained the cookie deleted by validation: %#v", values)
	}
	if values["itctx"] != "context-token" {
		t.Fatalf("cached cookies lost the unaffected cookie: %#v", values)
	}
}

func TestImportSessionBundleOverwriteRemovesFileFallbackOnKeychainBackend(t *testing.T) {
	withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "keychain")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	if err := writeSessionToFile(key, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToFile() error = %v", err)
	}

	if _, err := ImportSessionBundleWithOptions(bundle, true); err != nil {
		t.Fatalf("ImportSessionBundleWithOptions() error = %v", err)
	}
	if _, ok, err := readSessionFromKeychain(key); err != nil {
		t.Fatalf("readSessionFromKeychain() error = %v", err)
	} else if !ok {
		t.Fatal("keychain overwrite did not persist the imported session")
	}
	if _, ok, err := readSessionFromFile(key); err != nil {
		t.Fatalf("readSessionFromFile() error = %v", err)
	} else if ok {
		t.Fatal("overwrite left the stale file fallback credential behind")
	}
	if _, ok, err := readLastKeyFromFile(); err != nil {
		t.Fatalf("readLastKeyFromFile() error = %v", err)
	} else if ok {
		t.Fatal("overwrite left the stale file last-session pointer behind")
	}
}

func TestImportSessionBundleLeavesFileCacheIntactWhenKeychainCleanupFails(t *testing.T) {
	withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	if err := writeSessionToFile(key, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToFile() error = %v", err)
	}

	// A refused keychain unlock is not an unavailable keyring, so the mirrored
	// cleanup fails for a reason the import must report.
	previousOpen := sessionKeyringOpen
	sessionKeyringOpen = func() (keyring.Keyring, error) {
		return nil, errors.New("keychain unlock refused")
	}
	t.Cleanup(func() { sessionKeyringOpen = previousOpen })

	if _, err := ImportSessionBundleWithOptions(bundle, true); err == nil {
		t.Fatal("ImportSessionBundleWithOptions() error = nil, want the mirrored keychain cleanup failure")
	}

	sess, ok, err := readSessionFromFile(key)
	if err != nil || !ok {
		t.Fatalf("readSessionFromFile() = (%v, %v), want the untouched cached session", ok, err)
	}
	cookies := sess.Cookies["https://appstoreconnect.apple.com/"]
	if len(cookies) != 1 || cookies[0].Value != "old-token" {
		t.Fatalf("cached cookies = %#v, want the import to report failure without replacing them", cookies)
	}
}

func TestImportSessionBundleRestoresFileMirrorAfterKeychainPersistenceFails(t *testing.T) {
	withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "keychain")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	if err := writeSessionToFile(key, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToFile() error = %v", err)
	}
	lastPath, err := webSessionLastFilePath()
	if err != nil {
		t.Fatalf("webSessionLastFilePath() error = %v", err)
	}
	lastRaw := []byte(`{"key":"` + key + `","version":1}` + "\n")
	if err := os.WriteFile(lastPath, lastRaw, 0o640); err != nil {
		t.Fatalf("write last-session pointer: %v", err)
	}
	sessionPath, err := webSessionFilePath(key)
	if err != nil {
		t.Fatalf("webSessionFilePath() error = %v", err)
	}
	previousSessionRaw, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read previous session cache: %v", err)
	}

	previousOpen := sessionKeyringOpen
	sessionKeyringOpen = func() (keyring.Keyring, error) {
		return nil, errors.New("keychain unlock refused")
	}
	t.Cleanup(func() { sessionKeyringOpen = previousOpen })

	if _, err := ImportSessionBundleWithOptions(bundle, true); err == nil {
		t.Fatal("ImportSessionBundleWithOptions() error = nil, want the keychain persistence failure")
	}

	gotSessionRaw, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read restored session cache: %v", err)
	}
	if string(gotSessionRaw) != string(previousSessionRaw) {
		t.Fatalf("restored session cache changed: got %q, want %q", gotSessionRaw, previousSessionRaw)
	}
	gotLastRaw, err := os.ReadFile(lastPath)
	if err != nil {
		t.Fatalf("read restored last-session pointer: %v", err)
	}
	if string(gotLastRaw) != string(lastRaw) {
		t.Fatalf("restored last-session pointer changed: got %q, want %q", gotLastRaw, lastRaw)
	}
}

func TestImportSessionBundleRestoresKeychainMirrorAfterFilePersistenceFails(t *testing.T) {
	testKeyring := withArraySessionKeyring(t)
	withSessionInfoStub(t)
	t.Setenv(webSessionCacheEnabledEnv, "1")
	t.Setenv(webSessionBackendEnv, "")
	t.Setenv(webSessionCacheDirEnv, filepath.Join(t.TempDir(), "web-cache"))

	bundle := validTestBundle(time.Now().Add(time.Hour))
	key := webSessionCacheKey(bundle.AppleID)
	if err := writeSessionToFile(key, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-file-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToFile() error = %v", err)
	}
	lastPath, err := webSessionLastFilePath()
	if err != nil {
		t.Fatalf("webSessionLastFilePath() error = %v", err)
	}
	lastRaw := []byte(`{"key":"` + key + `","version":1}` + "\n")
	if err := os.WriteFile(lastPath, lastRaw, 0o640); err != nil {
		t.Fatalf("write last-session pointer: %v", err)
	}
	sessionPath, err := webSessionFilePath(key)
	if err != nil {
		t.Fatalf("webSessionFilePath() error = %v", err)
	}
	previousSessionRaw, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read previous session cache: %v", err)
	}

	keychainSession := persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-time.Hour),
		UserEmail: bundle.AppleID,
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "old-keychain-token", Path: "/"}},
		},
	}
	if err := writeSessionToKeychain(key, keychainSession); err != nil {
		t.Fatalf("writeSessionToKeychain() error = %v", err)
	}
	otherKey := webSessionCacheKey("other@example.com")
	if err := writeSessionToKeychain(otherKey, persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: time.Now().UTC().Add(-2 * time.Hour),
		UserEmail: "other@example.com",
		Cookies: map[string][]pCookie{
			"https://appstoreconnect.apple.com/": {{Name: "myacinfo", Value: "other-token", Path: "/"}},
		},
	}); err != nil {
		t.Fatalf("writeSessionToKeychain(other) error = %v", err)
	}
	keychainItem, err := testKeyring.Get(webSessionStoreItem)
	if err != nil {
		t.Fatalf("read previous keychain store: %v", err)
	}
	previousKeychainRaw := append([]byte(nil), keychainItem.Data...)

	previousWrite := sessionFileWrite
	sessionFileWrite = func(path string, data []byte, perm os.FileMode) error {
		if strings.HasSuffix(path, ".tmp") && strings.Contains(filepath.Base(path), "session-") {
			return errors.New("file replacement refused")
		}
		return previousWrite(path, data, perm)
	}
	t.Cleanup(func() { sessionFileWrite = previousWrite })

	if _, err := ImportSessionBundleWithOptions(bundle, true); err == nil {
		t.Fatal("ImportSessionBundleWithOptions() error = nil, want the file persistence failure")
	}

	gotSessionRaw, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read restored session cache: %v", err)
	}
	if string(gotSessionRaw) != string(previousSessionRaw) {
		t.Fatalf("restored session cache changed: got %q, want %q", gotSessionRaw, previousSessionRaw)
	}
	gotLastRaw, err := os.ReadFile(lastPath)
	if err != nil {
		t.Fatalf("read restored last-session pointer: %v", err)
	}
	if string(gotLastRaw) != string(lastRaw) {
		t.Fatalf("restored last-session pointer changed: got %q, want %q", gotLastRaw, lastRaw)
	}
	restored, ok, err := readSessionFromKeychain(key)
	if err != nil || !ok {
		t.Fatalf("readSessionFromKeychain() = (%v, %v), want the restored mirror", ok, err)
	}
	if got := restored.Cookies["https://appstoreconnect.apple.com/"][0].Value; got != "old-keychain-token" {
		t.Fatalf("restored keychain cookie = %q, want old-keychain-token", got)
	}
	other, ok, err := readSessionFromKeychain(otherKey)
	if err != nil || !ok {
		t.Fatalf("readSessionFromKeychain(other) = (%v, %v), want unrelated state preserved", ok, err)
	}
	if got := other.Cookies["https://appstoreconnect.apple.com/"][0].Value; got != "other-token" {
		t.Fatalf("restored unrelated keychain cookie = %q, want other-token", got)
	}
	gotKeychainItem, err := testKeyring.Get(webSessionStoreItem)
	if err != nil {
		t.Fatalf("read restored keychain store: %v", err)
	}
	if string(gotKeychainItem.Data) != string(previousKeychainRaw) {
		t.Fatalf("restored keychain store changed: got %q, want %q", gotKeychainItem.Data, previousKeychainRaw)
	}
}
