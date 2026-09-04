package signing

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/infoplist"
	"howett.net/plist"
)

// signingResignClaimUnauthorizedError marks an existing entitlement claim the
// replacement profile does not authorize, so the caller can aggregate every
// blocked claim into one actionable refusal.
type signingResignClaimUnauthorizedError struct{ key string }

func (err signingResignClaimUnauthorizedError) Error() string {
	return "existing entitlement " + err.key + " is not authorized by the replacement profile"
}

// signingResignUnauthorizedClaim records one blocked claim together with the
// profile value that refused it, for remediation reporting.
type signingResignUnauthorizedClaim struct {
	Key      string
	Existing any
	Profile  any
}

// signingResignUnauthorizedClaimsError lists every blocked claim with its
// offending value and a per-claim manual remediation. Re-signing across teams
// stays fail-closed; this only makes the refusal actionable.
func signingResignUnauthorizedClaimsError(claims []signingResignUnauthorizedClaim) error {
	descriptions := make([]string, 0, len(claims))
	for _, claim := range claims {
		remediation := "authorize this exact value in the replacement profile, or drop the claim from the app, then re-run"
		if suggestion, ok := signingResignClaimRebaseSuggestion(claim.Existing, claim.Profile); ok {
			remediation = "edit the claim to " + suggestion + ", or drop it from the app, then re-run"
		}
		descriptions = append(descriptions, fmt.Sprintf(
			"%s=%s (%s)",
			claim.Key,
			signingResignFormatClaimValue(claim.Existing),
			remediation,
		))
	}
	return &signingResignPublicDetailError{
		message: "existing entitlements are not authorized by the replacement profile: " + strings.Join(descriptions, "; "),
	}
}

// signingResignProfileRequiredEntitlementKeyOrder lists distribution claims a
// replacement profile injects for its class. They are derived from the
// profile when the existing signature has no claim, because distribution
// requires them.
var signingResignProfileRequiredEntitlementKeyOrder = []string{"beta-reports-active"}

// signingResignClaimRebaseSuggestion derives the concrete value a wildcard
// profile authorization would accept for an existing claim, for diagnostics
// only: the suffix after the claim's first prefix segment is re-anchored to
// the profile's wildcard prefix. No value is ever rewritten automatically.
func signingResignClaimRebaseSuggestion(existing, profileValue any) (string, bool) {
	prefix, ok := signingResignWildcardPrefix(profileValue)
	if !ok {
		return "", false
	}
	rebase := func(value string) (string, bool) {
		separator := strings.IndexRune(value, '.')
		if separator <= 0 || separator == len(value)-1 {
			return "", false
		}
		return prefix + value[separator+1:], true
	}
	switch typed := existing.(type) {
	case string:
		rebased, ok := rebase(typed)
		if !ok {
			return "", false
		}
		return fmt.Sprintf("%q", rebased), true
	default:
		list, isList := signingResignEntitlementList(existing)
		if !isList || len(list) == 0 {
			return "", false
		}
		rebasedValues := make([]string, 0, len(list))
		for _, item := range list {
			text, isString := item.(string)
			if !isString {
				return "", false
			}
			rebased, ok := rebase(text)
			if !ok {
				return "", false
			}
			rebasedValues = append(rebasedValues, fmt.Sprintf("%q", rebased))
		}
		return "[" + strings.Join(rebasedValues, ", ") + "]", true
	}
}

// signingResignWildcardPrefix extracts the single terminal-wildcard prefix,
// including its trailing separator, from a profile authorization value.
func signingResignWildcardPrefix(profileValue any) (string, bool) {
	candidates := []any{profileValue}
	if list, isList := signingResignEntitlementList(profileValue); isList {
		candidates = list
	}
	prefix := ""
	for _, candidate := range candidates {
		text, isString := candidate.(string)
		if !isString || !strings.HasSuffix(text, "*") {
			continue
		}
		trimmed := strings.TrimSuffix(text, "*")
		if trimmed == "" || strings.ContainsRune(trimmed, '*') {
			return "", false
		}
		if prefix != "" && prefix != trimmed {
			// Multiple distinct wildcard prefixes make a single suggestion
			// ambiguous; fall back to the generic remediation.
			return "", false
		}
		prefix = trimmed
	}
	return prefix, prefix != ""
}

func signingResignFormatClaimValue(value any) string {
	switch typed := value.(type) {
	case string:
		return fmt.Sprintf("%q", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	default:
		list, isList := signingResignEntitlementList(value)
		if !isList {
			return fmt.Sprintf("%v", value)
		}
		items := make([]string, 0, len(list))
		for _, item := range list {
			if text, isString := item.(string); isString {
				items = append(items, fmt.Sprintf("%q", text))
				continue
			}
			items = append(items, fmt.Sprintf("%v", item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
}

const (
	signingResignClaimDetailMaxBytes  = 512
	signingResignPublicDetailMaxBytes = 8192
)

func signingResignSafeClaimName(key string) string {
	if signingResignSafeClaimIdentifier(key) {
		return key
	}
	return signingResignQuoteBounded(key, 128)
}

func signingResignSafeClaimIdentifier(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, character := range key {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) || unicode.In(character, unicode.Bidi_Control) {
			return false
		}
	}
	return true
}

func signingResignQuoteBounded(value string, limit int) string {
	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}
	quoted := strconv.Quote(value)
	if limit > 0 && len(quoted) > limit {
		quoted = quoted[:limit]
	}
	return quoted
}

var signingResignIdentityEntitlementKeys = map[string]struct{}{
	"application-identifier":                                 {},
	"com.apple.application-identifier":                       {},
	"com.apple.developer.team-identifier":                    {},
	"get-task-allow":                                         {},
	"keychain-access-groups":                                 {},
	"com.apple.developer.ubiquity-kvstore-identifier":        {},
	"com.apple.developer.parent-application-identifiers":     {},
	"com.apple.developer.associated-appclip-app-identifiers": {},
}

var signingResignIdentityEntitlementKeyOrder = []string{
	"application-identifier",
	"com.apple.application-identifier",
	"com.apple.developer.team-identifier",
	"get-task-allow",
	"keychain-access-groups",
	"com.apple.developer.ubiquity-kvstore-identifier",
	"com.apple.developer.parent-application-identifiers",
	"com.apple.developer.associated-appclip-app-identifiers",
}

func buildSigningResignEntitlements(existing, profile map[string]any) (map[string]any, error) {
	result, _, err := buildSigningResignEntitlementPlan(existing, profile, "", "", nil)
	return result, err
}

// buildSigningResignEntitlementsForProfile applies the replacement profile's
// class-controlled values while retaining the existing claim-preservation
// rules for capabilities.
func buildSigningResignEntitlementsForProfile(existing map[string]any, profile signingResignProfile) (map[string]any, error) {
	result, _, err := buildSigningResignEntitlementPlan(existing, profile.Entitlements, profile.Class, "", nil)
	return result, err
}

// resolveSigningResignProfileClassEntitlement identifies claims whose value
// is controlled by the replacement profile class rather than preserved as an
// arbitrary subset of the old signed document.
func resolveSigningResignProfileClassEntitlement(key, profileClass string, existingValue, profileValue any, present bool) (value any, handled bool, err error) {
	if key != "aps-environment" {
		return nil, false, nil
	}
	if !present {
		return nil, false, nil
	}
	existingText, ok := existingValue.(string)
	if !ok || strings.TrimSpace(existingText) != existingText || existingText != "development" && existingText != "production" {
		return nil, true, fmt.Errorf("existing entitlement %s is invalid", key)
	}
	text, ok := profileValue.(string)
	if !ok || strings.TrimSpace(text) != text {
		return nil, true, fmt.Errorf("replacement profile entitlement %s is invalid", key)
	}
	expected := ""
	switch profileClass {
	case signingResignProfileClassDevelopment:
		expected = "development"
	case signingResignProfileClassAdHoc, signingResignProfileClassAppStore:
		expected = "production"
	default:
		return nil, true, fmt.Errorf("replacement profile class is unsupported for entitlement %s", key)
	}
	if text != expected {
		return nil, true, fmt.Errorf("replacement profile entitlement %s does not match profile class", key)
	}
	return text, true, nil
}

// signingResignOptionalIdentityEntitlementKey reports whether an identity
// entitlement is optional for a signed target: it is granted only when the
// existing signature already claims it and the replacement profile authorizes
// that claim.
func signingResignOptionalIdentityEntitlementKey(key string) bool {
	switch key {
	case "com.apple.application-identifier",
		"keychain-access-groups",
		"com.apple.developer.ubiquity-kvstore-identifier",
		"com.apple.developer.parent-application-identifiers",
		"com.apple.developer.associated-appclip-app-identifiers":
		return true
	default:
		return false
	}
}

// signingResignPreserveExistingIdentityKeys lists capability-group claims
// whose signed value must stay the app's own concrete subset. The replacement
// profile value, wildcard or concrete, is a permission boundary; adopting it
// verbatim could widen keychain, ubiquity, or App Clip access.
var signingResignPreserveExistingIdentityKeys = map[string]struct{}{
	"keychain-access-groups":                                 {},
	"com.apple.developer.ubiquity-kvstore-identifier":        {},
	"com.apple.developer.parent-application-identifiers":     {},
	"com.apple.developer.associated-appclip-app-identifiers": {},
}

// validateSigningResignExistingEntitlements checks the identity claims from
// the input signature before any replacement profile or tree mutation is
// attempted. The alternate com.apple.application-identifier claim is
// optional, but when present it must agree with application-identifier.
func validateSigningResignExistingEntitlements(existing map[string]any, bundleID string) error {
	if existing == nil {
		return nil
	}
	if err := validateSigningResignBundleID(bundleID); err != nil {
		return fmt.Errorf("target bundle identifier is invalid: %w", err)
	}
	identifiers := make(map[string]string, 2)
	for _, key := range []string{"application-identifier", "com.apple.application-identifier"} {
		value, exists := existing[key]
		if !exists {
			continue
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) != text || strings.ContainsRune(text, '*') {
			return fmt.Errorf("existing entitlement %s is invalid", key)
		}
		prefix, err := signingResignApplicationIdentifierPrefix(text, bundleID)
		if err != nil {
			return fmt.Errorf("existing entitlement %s is invalid: %w", key, err)
		}
		identifiers[key] = prefix
	}
	if canonical, exists := identifiers["application-identifier"]; exists {
		if alternate, alternateExists := identifiers["com.apple.application-identifier"]; alternateExists && canonical != alternate {
			return fmt.Errorf("existing application identifiers are contradictory")
		}
	}
	teamValue, hasTeam := existing["com.apple.developer.team-identifier"]
	if hasTeam {
		team, ok := teamValue.(string)
		if !ok || strings.TrimSpace(team) != team || strings.ContainsRune(team, '*') || validateSigningResignTeamID(team) != nil {
			return fmt.Errorf("existing entitlement com.apple.developer.team-identifier is invalid")
		}
	}
	// A legacy signing identity can use an application-identifier prefix that
	// differs from com.apple.developer.team-identifier. Without a captured
	// code-signature TeamIdentifier, do not infer equality between them; the
	// replacement profile is independently checked before signing.
	return nil
}

func signingResignApplicationIdentifierPrefix(value, bundleID string) (string, error) {
	suffix := "." + bundleID
	if !strings.HasSuffix(value, suffix) {
		return "", fmt.Errorf("does not match target bundle identifier")
	}
	prefix := strings.TrimSuffix(value, suffix)
	if prefix == "" || strings.ContainsRune(prefix, '*') {
		return "", fmt.Errorf("does not contain a concrete team prefix")
	}
	if err := validateSigningResignTeamID(prefix); err != nil {
		return "", fmt.Errorf("team prefix is invalid")
	}
	return prefix, nil
}

func resolveSigningResignIdentityEntitlement(key string, existing, profile any) (any, error) {
	if !signingResignIdentityValueIsConcrete(existing) {
		return nil, fmt.Errorf("existing entitlement %s is not a concrete value", key)
	}
	_, preserveExisting := signingResignPreserveExistingIdentityKeys[key]
	if preserveExisting || signingResignEntitlementContainsWildcard(profile) {
		if !signingResignEntitlementValuePermits(profile, existing) {
			return nil, signingResignClaimUnauthorizedError{key: key}
		}
		// The profile value, whether a wildcard pattern or a broader concrete
		// set, is an authorization boundary rather than the claim to sign.
		// Keep the app's already-concrete claim after proving the replacement
		// profile authorizes it, so re-signing never widens an identity
		// capability.
		return existing, nil
	}
	return profile, nil
}

func signingResignEntitlementContainsWildcard(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.ContainsRune(typed, '*')
	case []string:
		for _, item := range typed {
			if signingResignEntitlementContainsWildcard(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if signingResignEntitlementContainsWildcard(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if signingResignEntitlementContainsWildcard(item) {
				return true
			}
		}
	}
	return false
}

func signingResignIdentityValueIsConcrete(value any) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != "" && !strings.ContainsRune(typed, '*')
	case []string:
		if len(typed) == 0 {
			return false
		}
		for _, item := range typed {
			if !signingResignIdentityValueIsConcrete(item) {
				return false
			}
		}
		return true
	case []any:
		if len(typed) == 0 {
			return false
		}
		for _, item := range typed {
			if !signingResignIdentityValueIsConcrete(item) {
				return false
			}
		}
		return true
	case bool:
		return true
	default:
		return false
	}
}

func signingResignEntitlementValuePermits(profileValue, signedValue any) bool {
	profileString, profileIsString := profileValue.(string)
	signedString, signedIsString := signedValue.(string)
	if profileIsString && signedIsString {
		if strings.HasSuffix(profileString, "*") {
			prefix := strings.TrimSuffix(profileString, "*")
			return strings.HasPrefix(signedString, prefix) && len(signedString) > len(prefix)
		}
		return signedString == profileString
	}
	profileList, profileIsList := signingResignEntitlementList(profileValue)
	signedList, signedIsList := signingResignEntitlementList(signedValue)
	if profileIsList && signedIsList {
		for _, signedItem := range signedList {
			permitted := false
			for _, profileItem := range profileList {
				if signingResignEntitlementValuePermits(profileItem, signedItem) {
					permitted = true
					break
				}
			}
			if !permitted {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(profileValue, signedValue)
}

func signingResignEntitlementList(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	case []string:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = item
		}
		return result, true
	default:
		return nil, false
	}
}

func marshalSigningResignEntitlements(entitlements map[string]any) ([]byte, error) {
	if len(entitlements) == 0 {
		return nil, nil
	}
	data, err := plist.MarshalIndent(entitlements, plist.XMLFormat, "\t")
	if err != nil {
		return nil, fmt.Errorf("encode signing entitlements: %w", err)
	}
	if len(data) > infoplist.MaxBytes {
		return nil, fmt.Errorf("signing entitlements exceed %d bytes", infoplist.MaxBytes)
	}
	if err := infoplist.ValidateStructure(data); err != nil {
		return nil, fmt.Errorf("validate signing entitlements: %w", err)
	}
	return data, nil
}
