package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// SessionBundleKind identifies an exported web-session document.
	SessionBundleKind = "asc-web-session"

	// SessionBundleVersion is the schema version written by the current
	// exporter. Importing a different version is refused instead of guessed.
	SessionBundleVersion = 1

	// MaxSessionBundleSize bounds how many bytes an imported bundle may hold.
	MaxSessionBundleSize = 1 << 20
)

var (
	// ErrSessionCacheDisabled reports that web-session caching is turned off,
	// so a session can neither be read from nor written to the cache.
	ErrSessionCacheDisabled = errors.New("web session cache is disabled")

	// ErrSessionBundleUnusable reports that a bundle carries no unexpired
	// cookie for a supported Apple origin.
	ErrSessionBundleUnusable = errors.New("web session bundle has no unexpired cookies")
)

// SessionBundle is the portable representation of a cached Apple web session.
// It is written by `asc web auth export` and read by `asc web auth import` so
// an already-authenticated session can move to another machine or to CI
// without repeating two-factor verification.
//
// The document holds live session credentials. Treat an exported file exactly
// like a password.
type SessionBundle struct {
	Kind       string                `json:"kind"`
	Version    int                   `json:"version"`
	ExportedAt time.Time             `json:"exportedAt"`
	AppleID    string                `json:"appleId"`
	ExpiresAt  *time.Time            `json:"expiresAt,omitempty"`
	Cookies    []SessionBundleCookie `json:"cookies"`
}

// SessionBundleCookie is one cookie in an exported session bundle. URL is the
// canonical Apple origin the cookie belongs to.
type SessionBundleCookie struct {
	URL      string     `json:"url"`
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Path     string     `json:"path,omitempty"`
	Domain   string     `json:"domain,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	MaxAge   int        `json:"maxAge,omitempty"`
	Secure   bool       `json:"secure,omitempty"`
	HTTPOnly bool       `json:"httpOnly,omitempty"`
	SameSite int        `json:"sameSite,omitempty"`
}

// SessionImportSummary reports what an import stored in the session cache.
type SessionImportSummary struct {
	AppleID        string
	CookieCount    int
	SkippedExpired int
	ExpiresAt      *time.Time
}

// SupportedSessionBundleOrigins lists the Apple origins a bundle may carry
// cookies for. It matches the origins the session cache itself persists.
func SupportedSessionBundleOrigins() []string {
	urls := sessionCookieURLs()
	origins := make([]string, 0, len(urls))
	for _, u := range urls {
		origins = append(origins, u.String())
	}
	return origins
}

// canonicalSessionCookieURL maps an origin to the exact cache key used for it,
// so imports cannot inject cookies for hosts the session cache never serves.
func canonicalSessionCookieURL(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	for _, candidate := range sessionCookieURLs() {
		if strings.EqualFold(parsed.Scheme, candidate.Scheme) && strings.EqualFold(parsed.Host, candidate.Host) {
			return candidate.String(), true
		}
	}
	return "", false
}

func cookieExpiry(expires *time.Time) time.Time {
	if expires == nil {
		return time.Time{}
	}
	return *expires
}

func earliestBundleExpiry(cookies []SessionBundleCookie) *time.Time {
	var earliest time.Time
	for _, cookie := range cookies {
		expires := cookieExpiry(cookie.Expires)
		if expires.IsZero() {
			continue
		}
		if earliest.IsZero() || expires.Before(earliest) {
			earliest = expires
		}
	}
	if earliest.IsZero() {
		return nil
	}
	utc := earliest.UTC()
	return &utc
}

// ExportSessionBundle reads a cached web session and returns it as a portable
// bundle. An empty username exports the last cached session. It reports
// ok=false when no session is cached.
func ExportSessionBundle(username string) (*SessionBundle, bool, error) {
	selection := resolveBackendSelection()
	if selection.backend == sessionBackendOff {
		return nil, false, ErrSessionCacheDisabled
	}

	username = strings.TrimSpace(username)
	var (
		sess persistedSession
		ok   bool
		err  error
	)
	if username == "" {
		sess, ok, err = readLastSessionBySelection(selection)
	} else {
		sess, ok, err = readSessionBySelection(selection, webSessionCacheKey(username))
	}
	if err != nil || !ok {
		return nil, false, err
	}

	appleID := strings.TrimSpace(sess.UserEmail)
	if appleID == "" {
		appleID = username
	}
	if appleID == "" {
		return nil, false, errors.New("cached web session does not record an Apple Account email; run \"asc web auth login\" again")
	}

	now := time.Now().UTC()
	bundle := &SessionBundle{
		Kind:       SessionBundleKind,
		Version:    SessionBundleVersion,
		ExportedAt: now.Truncate(time.Second),
		AppleID:    appleID,
		Cookies:    exportBundleCookies(sess, now),
	}
	if len(bundle.Cookies) == 0 {
		return nil, false, ErrSessionBundleUnusable
	}
	bundle.ExpiresAt = earliestBundleExpiry(bundle.Cookies)
	return bundle, true, nil
}

// exportBundleCookies flattens the cached cookie map into a deterministically
// ordered list. Cached sessions only ever hold the canonical Apple origins, so
// any other origin is left out rather than exported into a document the
// importer would reject.
func exportBundleCookies(sess persistedSession, now time.Time) []SessionBundleCookie {
	cookies := make([]SessionBundleCookie, 0, len(sess.Cookies))
	for origin, list := range sess.Cookies {
		canonical, ok := canonicalSessionCookieURL(origin)
		if !ok {
			continue
		}
		for _, cookie := range list {
			if strings.TrimSpace(cookie.Name) == "" || isExpiredCookie(cookie, now) {
				continue
			}
			exported := SessionBundleCookie{
				URL:      canonical,
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     cookie.Path,
				Domain:   cookie.Domain,
				MaxAge:   cookie.MaxAge,
				Secure:   cookie.Secure,
				HTTPOnly: cookie.HttpOnly,
				SameSite: cookie.SameSite,
			}
			if !cookie.Expires.IsZero() {
				expires := cookie.Expires.UTC()
				exported.Expires = &expires
			}
			cookies = append(cookies, exported)
		}
	}
	sort.Slice(cookies, func(i, j int) bool {
		if cookies[i].URL != cookies[j].URL {
			return cookies[i].URL < cookies[j].URL
		}
		return cookies[i].Name < cookies[j].Name
	})
	return cookies
}

// DecodeSessionBundle parses and validates a bundle document.
func DecodeSessionBundle(data []byte) (*SessionBundle, error) {
	if len(data) == 0 {
		return nil, errors.New("web session bundle is empty")
	}
	var bundle SessionBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("decode web session bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return &bundle, nil
}

// Validate checks the document shape without inspecting cookie expiry.
func (b *SessionBundle) Validate() error {
	if b == nil {
		return errors.New("web session bundle is empty")
	}
	if strings.TrimSpace(b.Kind) != SessionBundleKind {
		return fmt.Errorf("web session bundle kind %q is not %q", b.Kind, SessionBundleKind)
	}
	if b.Version != SessionBundleVersion {
		return fmt.Errorf("web session bundle version %d is not supported (expected %d)", b.Version, SessionBundleVersion)
	}
	if strings.TrimSpace(b.AppleID) == "" {
		return errors.New("web session bundle is missing appleId")
	}
	if len(b.Cookies) == 0 {
		return errors.New("web session bundle contains no cookies")
	}
	for index, cookie := range b.Cookies {
		if strings.TrimSpace(cookie.Name) == "" {
			return fmt.Errorf("web session bundle cookie %d is missing name", index)
		}
		if _, ok := canonicalSessionCookieURL(cookie.URL); !ok {
			return fmt.Errorf(
				"web session bundle cookie %q has unsupported url %q (supported origins: %s)",
				cookie.Name,
				cookie.URL,
				strings.Join(SupportedSessionBundleOrigins(), ", "),
			)
		}
	}
	return nil
}

// normalize converts a validated bundle into the cache representation, leaving
// out cookies that already expired.
func (b *SessionBundle) normalize(now time.Time) (persistedSession, SessionImportSummary, error) {
	if err := b.Validate(); err != nil {
		return persistedSession{}, SessionImportSummary{}, err
	}

	appleID := strings.TrimSpace(b.AppleID)
	out := persistedSession{
		Version:   webSessionCacheVersion,
		UpdatedAt: now,
		UserEmail: appleID,
		Cookies:   map[string][]pCookie{},
	}
	summary := SessionImportSummary{AppleID: appleID}
	kept := make([]SessionBundleCookie, 0, len(b.Cookies))
	for _, cookie := range b.Cookies {
		canonical, ok := canonicalSessionCookieURL(cookie.URL)
		if !ok {
			continue
		}
		persisted := pCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookieExpiry(cookie.Expires),
			MaxAge:   cookie.MaxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
			SameSite: cookie.SameSite,
		}
		if isExpiredCookie(persisted, now) {
			summary.SkippedExpired++
			continue
		}
		out.Cookies[canonical] = append(out.Cookies[canonical], persisted)
		kept = append(kept, cookie)
	}
	if len(kept) == 0 {
		return persistedSession{}, SessionImportSummary{}, ErrSessionBundleUnusable
	}
	summary.CookieCount = len(kept)
	summary.ExpiresAt = earliestBundleExpiry(kept)
	return out, summary, nil
}

// ImportSessionBundle stores a bundle in the same cache `asc web auth login`
// writes, so later `asc web` commands resume it. The imported session also
// becomes the last cached session.
func ImportSessionBundle(bundle *SessionBundle) (SessionImportSummary, error) {
	if bundle == nil {
		return SessionImportSummary{}, errors.New("web session bundle is empty")
	}

	sess, summary, err := bundle.normalize(time.Now().UTC())
	if err != nil {
		return SessionImportSummary{}, err
	}

	selection := resolveBackendSelection()
	if selection.backend == sessionBackendOff {
		return SessionImportSummary{}, ErrSessionCacheDisabled
	}
	if err := persistSessionBySelection(selection, webSessionCacheKey(summary.AppleID), sess); err != nil {
		return SessionImportSummary{}, err
	}
	return summary, nil
}
