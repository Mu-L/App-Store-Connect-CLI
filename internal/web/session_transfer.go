package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
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

	// ErrSessionCookieNotStorable reports that a cookie names a supported
	// origin but a Domain the session jar will not store for that origin.
	ErrSessionCookieNotStorable = errors.New("web session bundle cookie cannot be stored for its origin")

	// ErrSessionCookieInvalid reports that a cookie name, value, path, or
	// domain is not a valid HTTP cookie field.
	ErrSessionCookieInvalid = errors.New("web session bundle cookie is invalid")

	// ErrSessionBundleValidationFailed reports that Apple did not accept the
	// imported session or that its authenticated identity could not be proved.
	ErrSessionBundleValidationFailed = errors.New("web session bundle could not be validated")
)

type sessionInfoValidator func(context.Context, *http.Client) (string, error)

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

// cookieStorableForOrigin reports whether the session cookie jar will keep
// this cookie for the canonical Apple origin. A matching URL is not enough:
// cookiejar.SetCookies drops Domain values that do not belong to that host.
func cookieStorableForOrigin(origin string, cookie SessionBundleCookie) bool {
	if strings.TrimSpace(cookie.Name) == "" {
		return false
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil {
		return false
	}
	path := strings.TrimSpace(cookie.Path)
	if path == "" {
		path = "/"
	}
	u.Path = path
	jar.SetCookies(u, []*http.Cookie{{
		Name:    cookie.Name,
		Value:   "1",
		Path:    cookie.Path,
		Domain:  cookie.Domain,
		Secure:  cookie.Secure,
		Expires: time.Now().Add(time.Hour),
	}})
	for _, got := range jar.Cookies(u) {
		if got.Name == cookie.Name && got.Value == "1" {
			return true
		}
	}
	return false
}

// cookieDomainMatchesOrigin requires an empty Domain (host-only) or a Domain
// equal to the origin host. Broader values such as apple.com or the public
// suffix com would otherwise be accepted by cookiejar.New(nil) and sent to
// other hosts the web client later contacts.
func cookieDomainMatchesOrigin(origin, domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed == nil {
		return false
	}
	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), ".")
	domain = strings.TrimPrefix(strings.ToLower(domain), ".")
	return domain != "" && domain == host
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
				Secure:   cookie.Secure,
				HTTPOnly: cookie.HttpOnly,
				SameSite: cookie.SameSite,
			}
			expires, maxAge := absoluteCookieDeadline(cookie.Expires, cookie.MaxAge, now)
			exported.MaxAge = maxAge
			if !expires.IsZero() {
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode web session bundle: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode web session bundle: multiple JSON values")
		}
		return nil, fmt.Errorf("decode web session bundle: trailing data: %w", err)
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
		canonical, ok := canonicalSessionCookieURL(cookie.URL)
		if !ok {
			return fmt.Errorf(
				"web session bundle cookie %q has unsupported url %q (supported origins: %s)",
				cookie.Name,
				cookie.URL,
				strings.Join(SupportedSessionBundleOrigins(), ", "),
			)
		}
		if !cookieDomainMatchesOrigin(canonical, cookie.Domain) {
			return fmt.Errorf(
				"%w: cookie %q has domain %q that is not host-only for %q",
				ErrSessionCookieNotStorable,
				cookie.Name,
				cookie.Domain,
				canonical,
			)
		}
		if !cookieStorableForOrigin(canonical, cookie) {
			return fmt.Errorf(
				"%w: cookie %q has domain %q that the session jar cannot store for %q",
				ErrSessionCookieNotStorable,
				cookie.Name,
				cookie.Domain,
				canonical,
			)
		}
		if err := sessionBundleCookieSyntaxValid(cookie); err != nil {
			return err
		}
	}
	return nil
}

func sessionBundleCookieSyntaxValid(cookie SessionBundleCookie) error {
	parsed := http.Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Path:     cookie.Path,
		Domain:   cookie.Domain,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HTTPOnly,
		SameSite: http.SameSite(cookie.SameSite),
	}
	if cookie.Expires != nil {
		parsed.Expires = *cookie.Expires
	}
	if err := parsed.Valid(); err != nil {
		return fmt.Errorf("%w: cookie %q has an invalid name, value, path, or domain", ErrSessionCookieInvalid, cookie.Name)
	}
	return nil
}

// absoluteCookieDeadline converts a positive MaxAge into an absolute expiry
// so later cache loads cannot resurrect the cookie by applying the same
// relative lifetime again.
func absoluteCookieDeadline(expires time.Time, maxAge int, now time.Time) (time.Time, int) {
	if maxAge > 0 {
		return now.Add(time.Duration(maxAge) * time.Second).UTC(), 0
	}
	if expires.IsZero() {
		return time.Time{}, maxAge
	}
	return expires.UTC(), maxAge
}

// importedCookieDeadline converts positive MaxAge to an absolute expiry and
// treats an explicit zero timestamp as already expired so it cannot be stored
// as a session cookie.
func importedCookieDeadline(expires *time.Time, maxAge int, now time.Time) (time.Time, int, bool) {
	if maxAge > 0 {
		return now.Add(time.Duration(maxAge) * time.Second).UTC(), 0, false
	}
	if maxAge < 0 {
		return time.Time{}, maxAge, true
	}
	if expires == nil {
		return time.Time{}, 0, false
	}
	utc := expires.UTC()
	if utc.IsZero() || utc.Before(now) {
		return utc, 0, true
	}
	return utc, 0, false
}

type cookieJarMutation struct {
	origin      string
	requestPath string
	cookie      http.Cookie
	recordedAt  time.Time
}

// recordingCookieJar keeps the normal cookie-jar behavior while retaining the
// original Set-Cookie mutations observed during validation. cookiejar.Cookies
// intentionally exposes only name and value, so rebuilding a persisted session
// from a root Cookies call loses path, expiry, lifetime, and security
// attributes (and cannot distinguish a path-scoped cookie from a deletion).
type recordingCookieJar struct {
	jar       http.CookieJar
	mu        sync.Mutex
	mutations []cookieJarMutation
}

func (j *recordingCookieJar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || j.jar == nil {
		return nil
	}
	return j.jar.Cookies(u)
}

func (j *recordingCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || j.jar == nil {
		return
	}
	origin := ""
	requestPath := "/"
	if u != nil {
		origin, _ = canonicalSessionCookieURL(u.String())
		requestPath = u.Path
		if requestPath == "" {
			requestPath = "/"
		}
	}
	if origin != "" {
		recordedAt := time.Now().UTC()
		mutations := make([]cookieJarMutation, 0, len(cookies))
		for _, cookie := range cookies {
			if cookie == nil {
				continue
			}
			mutations = append(mutations, cookieJarMutation{
				origin:      origin,
				requestPath: requestPath,
				cookie:      *cookie,
				recordedAt:  recordedAt,
			})
		}
		if len(mutations) > 0 {
			j.mu.Lock()
			j.mutations = append(j.mutations, mutations...)
			j.mu.Unlock()
		}
	}
	j.jar.SetCookies(u, cookies)
}

func (j *recordingCookieJar) cookieMutations() []cookieJarMutation {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	mutations := append([]cookieJarMutation(nil), j.mutations...)
	j.mu.Unlock()
	return mutations
}

func isCookieDeletionAt(cookie http.Cookie, at time.Time) bool {
	if cookie.MaxAge < 0 {
		return true
	}
	// RFC 6265 gives Max-Age precedence over Expires. A positive lifetime
	// remains usable even when a legacy Expires attribute is already past.
	if cookie.MaxAge > 0 {
		return false
	}
	return !cookie.Expires.IsZero() && !cookie.Expires.After(at)
}

func effectiveCookiePath(path, requestPath string) string {
	if path != "" && path[0] == '/' {
		return path
	}
	if requestPath == "" || requestPath[0] != '/' {
		return "/"
	}
	index := strings.LastIndex(requestPath, "/")
	if index <= 0 {
		return "/"
	}
	return requestPath[:index]
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
		expires, maxAge, expired := importedCookieDeadline(cookie.Expires, cookie.MaxAge, now)
		persisted := pCookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  expires,
			MaxAge:   maxAge,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
			SameSite: cookie.SameSite,
		}
		if expired || isExpiredCookie(persisted, now) {
			summary.SkippedExpired++
			continue
		}
		normalizedCookie := cookie
		normalizedCookie.MaxAge = maxAge
		if !expires.IsZero() {
			expiresCopy := expires
			normalizedCookie.Expires = &expiresCopy
		} else {
			normalizedCookie.Expires = nil
		}
		out.Cookies[canonical] = append(out.Cookies[canonical], persisted)
		kept = append(kept, normalizedCookie)
	}
	if len(kept) == 0 {
		return persistedSession{}, SessionImportSummary{}, ErrSessionBundleUnusable
	}
	summary.CookieCount = len(kept)
	summary.ExpiresAt = earliestBundleExpiry(kept)
	return out, summary, nil
}

// ImportSessionBundle stores a bundle in the same cache `asc web auth login`
// writes, so later `asc web` commands resume it. Import performs local bundle
// validation only; use `asc web auth status` when live Apple validation is
// needed. The imported session also becomes the last cached session.
func ImportSessionBundle(bundle *SessionBundle) (SessionImportSummary, error) {
	return importSessionBundleLocally(bundle, false)
}

// ImportSessionBundleWithOptions imports a bundle and optionally permits
// replacing an existing cache entry. The overwrite bit is also used to scope
// recovery from a malformed keychain aggregate to the explicit replacement
// path; ordinary login and refresh writes must not erase other accounts. The
// import itself performs local validation only; it does not contact Apple.
func ImportSessionBundleWithOptions(bundle *SessionBundle, overwrite bool) (SessionImportSummary, error) {
	return importSessionBundleLocally(bundle, overwrite)
}

// ImportSessionBundleWithContext retains the context-aware API for callers
// compiled against the original transfer surface. Import is local-only, so
// ctx is intentionally ignored; callers that need live validation should run
// the status or resume workflow separately.
func ImportSessionBundleWithContext(_ context.Context, bundle *SessionBundle, overwrite bool) (SessionImportSummary, error) {
	return importSessionBundleLocally(bundle, overwrite)
}

func importSessionBundleLocally(bundle *SessionBundle, overwrite bool) (SessionImportSummary, error) {
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
	if err := persistImportedSessionBySelection(selection, webSessionCacheKey(summary.AppleID), sess, overwrite); err != nil {
		return SessionImportSummary{}, err
	}
	return summary, nil
}

func importSessionBundleWithValidator(ctx context.Context, bundle *SessionBundle, overwrite bool, validator sessionInfoValidator) (SessionImportSummary, error) {
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
	validated, err := validateImportedSession(ctx, sess, validator)
	if err != nil {
		return SessionImportSummary{}, err
	}
	summary, err = summarizeValidatedSession(validated, summary, time.Now().UTC())
	if err != nil {
		return SessionImportSummary{}, err
	}
	if err := persistImportedSessionBySelection(selection, webSessionCacheKey(summary.AppleID), validated, overwrite); err != nil {
		return SessionImportSummary{}, err
	}
	return summary, nil
}

func summarizeValidatedSession(session persistedSession, summary SessionImportSummary, now time.Time) (SessionImportSummary, error) {
	validated, cookieCount := discardExpiredPersistedCookies(session, now)
	if cookieCount == 0 {
		return SessionImportSummary{}, fmt.Errorf("%w: Apple revoked every cookie in the bundle", ErrSessionBundleValidationFailed)
	}

	var earliest time.Time
	for _, list := range validated.Cookies {
		for _, cookie := range list {
			if cookie.Expires.IsZero() {
				continue
			}
			if earliest.IsZero() || cookie.Expires.Before(earliest) {
				earliest = cookie.Expires
			}
		}
	}
	summary.CookieCount = cookieCount
	if earliest.IsZero() {
		summary.ExpiresAt = nil
	} else {
		expires := earliest.UTC()
		summary.ExpiresAt = &expires
	}
	return summary, nil
}

// validateImportedSession proves the bundle against Apple before anything is
// cached and returns the session to persist. Apple can rotate or add session
// cookies while answering that request, so the validated jar, not the
// pre-validation bundle, is what the cache must keep.
func validateImportedSession(ctx context.Context, sess persistedSession, validator sessionInfoValidator) (persistedSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if validator == nil {
		validator = validateSessionInfo
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return persistedSession{}, fmt.Errorf("%w: failed to create cookie jar: %w", ErrSessionBundleValidationFailed, err)
	}
	if hydrateCookieJar(jar, sess) == 0 {
		return persistedSession{}, fmt.Errorf("%w: session bundle has no usable cookies", ErrSessionBundleValidationFailed)
	}

	trackedJar := &recordingCookieJar{jar: jar}
	appleID, err := validator(ctx, newWebHTTPClient(trackedJar))
	if err != nil {
		return persistedSession{}, fmt.Errorf("%w: %w", ErrSessionBundleValidationFailed, err)
	}
	if !strings.EqualFold(strings.TrimSpace(appleID), strings.TrimSpace(sess.UserEmail)) {
		return persistedSession{}, fmt.Errorf("%w: authenticated Apple ID does not match bundle Apple ID", ErrSessionBundleValidationFailed)
	}
	validated := mergeRefreshedSessionCookies(sess, trackedJar)
	validated, cookieCount := discardExpiredPersistedCookies(validated, time.Now().UTC())
	if cookieCount == 0 {
		return persistedSession{}, fmt.Errorf("%w: Apple revoked every cookie in the bundle", ErrSessionBundleValidationFailed)
	}
	return validated, nil
}

// mergeRefreshedSessionCookies folds the cookies Apple rotated or issued during
// validation back into the session about to be cached by replaying the original
// Set-Cookie mutations. Replaying the mutations retains all cookie attributes;
// a root-level cookiejar.Cookies call would expose only names and values and
// would lose path, expiry, lifetime, and security attributes.
func mergeRefreshedSessionCookies(sess persistedSession, jar http.CookieJar) persistedSession {
	merged := persistedSession{
		Version:   sess.Version,
		UpdatedAt: sess.UpdatedAt,
		UserEmail: sess.UserEmail,
		Cookies:   make(map[string][]pCookie, len(sess.Cookies)),
	}
	for origin, list := range sess.Cookies {
		merged.Cookies[origin] = append([]pCookie(nil), list...)
	}
	if recorder, ok := jar.(*recordingCookieJar); ok {
		now := time.Now().UTC()
		for _, mutation := range recorder.cookieMutations() {
			applyCookieJarMutation(&merged, mutation, now)
		}
	}
	return merged
}

func applyCookieJarMutation(session *persistedSession, mutation cookieJarMutation, now time.Time) {
	if session == nil || mutation.origin == "" || mutation.cookie.Name == "" {
		return
	}

	path := effectiveCookiePath(mutation.cookie.Path, mutation.requestPath)
	list := session.Cookies[mutation.origin]
	if isCookieDeletionAt(mutation.cookie, mutation.recordedAt) {
		kept := list[:0]
		for _, cookie := range list {
			if !persistedCookieMatchesIdentity(cookie, mutation.cookie.Name, path, mutation.cookie.Domain) {
				kept = append(kept, cookie)
			}
		}
		if len(kept) == 0 {
			delete(session.Cookies, mutation.origin)
		} else {
			session.Cookies[mutation.origin] = kept
		}
		return
	}

	recordedAt := mutation.recordedAt
	if recordedAt.IsZero() {
		recordedAt = now
	}
	expires, maxAge := absoluteCookieDeadline(mutation.cookie.Expires, mutation.cookie.MaxAge, recordedAt)
	updated := pCookie{
		Name:     mutation.cookie.Name,
		Value:    mutation.cookie.Value,
		Path:     path,
		Domain:   mutation.cookie.Domain,
		Expires:  expires,
		MaxAge:   maxAge,
		Secure:   mutation.cookie.Secure,
		HttpOnly: mutation.cookie.HttpOnly,
		SameSite: int(mutation.cookie.SameSite),
	}
	if isExpiredCookie(updated, now) {
		kept := list[:0]
		for _, cookie := range list {
			if !persistedCookieMatchesIdentity(cookie, updated.Name, updated.Path, updated.Domain) {
				kept = append(kept, cookie)
			}
		}
		if len(kept) == 0 {
			delete(session.Cookies, mutation.origin)
		} else {
			session.Cookies[mutation.origin] = kept
		}
		return
	}

	for index := range list {
		if !persistedCookieMatchesIdentity(list[index], updated.Name, updated.Path, updated.Domain) {
			continue
		}
		// A Set-Cookie without an expiry turns a persistent cookie into a
		// session cookie in net/http. Preserve the bundle deadline for the
		// compatibility path used by older validators, while every attribute
		// supplied by the mutation still replaces the previous value.
		if updated.Expires.IsZero() && updated.MaxAge == 0 && !list[index].Expires.IsZero() {
			updated.Expires = list[index].Expires
		}
		list[index] = updated
		session.Cookies[mutation.origin] = list
		return
	}
	session.Cookies[mutation.origin] = append(list, updated)
}

func persistedCookieMatchesIdentity(cookie pCookie, name, path, domain string) bool {
	// cookiejar.Cookies omits Path, so sessions written by the regular login
	// path commonly carry an empty path even though the jar's effective path is
	// "/". Treat that representation as the root path when matching a later
	// Set-Cookie mutation.
	effectivePath := effectiveCookiePath(cookie.Path, "/")
	return cookie.Name == name && effectivePath == path && cookieDomainsEqual(cookie.Domain, domain)
}

func cookieDomainsEqual(left, right string) bool {
	return strings.EqualFold(strings.TrimPrefix(left, "."), strings.TrimPrefix(right, "."))
}

func discardExpiredPersistedCookies(session persistedSession, now time.Time) (persistedSession, int) {
	for origin, list := range session.Cookies {
		kept := list[:0]
		for _, cookie := range list {
			if cookie.MaxAge > 0 {
				cookie.Expires, cookie.MaxAge = absoluteCookieDeadline(cookie.Expires, cookie.MaxAge, now)
			}
			if cookie.Name == "" || isExpiredCookie(cookie, now) {
				continue
			}
			kept = append(kept, cookie)
		}
		if len(kept) == 0 {
			delete(session.Cookies, origin)
			continue
		}
		session.Cookies[origin] = kept
	}

	cookieCount := 0
	for _, list := range session.Cookies {
		cookieCount += len(list)
	}
	return session, cookieCount
}

func validateSessionInfo(ctx context.Context, client *http.Client) (string, error) {
	info, err := sessionInfoFetcher(ctx, client)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", errors.New("session info response is empty")
	}
	return strings.TrimSpace(info.User.EmailAddress), nil
}
