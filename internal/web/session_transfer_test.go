package web

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withFileSessionCache(t *testing.T) {
	t.Helper()
	withArraySessionKeyring(t)
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
