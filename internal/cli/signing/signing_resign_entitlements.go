package signing

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/infoplist"
	"howett.net/plist"
)

var signingResignIdentityEntitlementKeys = map[string]struct{}{
	"application-identifier":                             {},
	"com.apple.application-identifier":                   {},
	"com.apple.developer.team-identifier":                {},
	"get-task-allow":                                     {},
	"keychain-access-groups":                             {},
	"com.apple.developer.ubiquity-kvstore-identifier":    {},
	"com.apple.developer.parent-application-identifiers": {},
}

var signingResignIdentityEntitlementKeyOrder = []string{
	"application-identifier",
	"com.apple.application-identifier",
	"com.apple.developer.team-identifier",
	"get-task-allow",
	"keychain-access-groups",
	"com.apple.developer.ubiquity-kvstore-identifier",
	"com.apple.developer.parent-application-identifiers",
}

func buildSigningResignEntitlements(existing, profile map[string]any) (map[string]any, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile entitlements are missing")
	}
	for _, key := range []string{"application-identifier", "com.apple.application-identifier"} {
		if value, exists := existing[key]; exists {
			text, ok := value.(string)
			if !ok || strings.TrimSpace(text) == "" || strings.ContainsRune(text, '*') {
				return nil, fmt.Errorf("existing entitlement %s is invalid", key)
			}
		}
	}
	if value, exists := existing["com.apple.developer.team-identifier"]; exists {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("existing entitlement %s is invalid", "com.apple.developer.team-identifier")
		}
	}
	if value, exists := existing["get-task-allow"]; exists {
		if _, ok := value.(bool); !ok {
			return nil, fmt.Errorf("existing entitlement get-task-allow is invalid")
		}
	}
	result := make(map[string]any, len(existing)+4)
	existingKeys := make([]string, 0, len(existing))
	for key := range existing {
		existingKeys = append(existingKeys, key)
	}
	sort.Strings(existingKeys)
	for _, key := range existingKeys {
		value := existing[key]
		if _, identityKey := signingResignIdentityEntitlementKeys[key]; identityKey {
			profileValue, exists := profile[key]
			if !exists {
				return nil, fmt.Errorf("existing entitlement %s is missing from the replacement profile", key)
			}
			resolved, err := resolveSigningResignIdentityEntitlement(key, value, profileValue)
			if err != nil {
				return nil, err
			}
			result[key] = resolved
			continue
		}
		profileValue, permitted := profile[key]
		if !permitted || !signingResignEntitlementValuePermits(profileValue, value) {
			return nil, fmt.Errorf("existing entitlement %s is not permitted by the replacement profile", key)
		}
		result[key] = value
	}
	for _, key := range signingResignIdentityEntitlementKeyOrder {
		if _, exists := existing[key]; exists {
			continue
		}
		if signingResignOptionalIdentityEntitlementKey(key) {
			// Optional identity capabilities are granted only when the
			// existing signature already claims them. The profile value,
			// wildcard or concrete, is an authorization boundary: signing an
			// unclaimed capability in would widen the app's access.
			continue
		}
		value, exists := profile[key]
		if !exists {
			return nil, fmt.Errorf("replacement profile entitlement %s is missing", key)
		}
		if signingResignEntitlementContainsWildcard(value) {
			return nil, fmt.Errorf("replacement profile entitlement %s is wildcard-only and has no concrete signed value", key)
		}
		result[key] = value
	}
	return result, nil
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
		"com.apple.developer.parent-application-identifiers":
		return true
	default:
		return false
	}
}

// signingResignPreserveExistingIdentityKeys lists capability-group claims
// whose signed value must stay the app's own concrete subset. The replacement
// profile value, wildcard or concrete, is a permission boundary; adopting it
// verbatim could widen keychain, ubiquity, or parent-application access.
var signingResignPreserveExistingIdentityKeys = map[string]struct{}{
	"keychain-access-groups":                             {},
	"com.apple.developer.ubiquity-kvstore-identifier":    {},
	"com.apple.developer.parent-application-identifiers": {},
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
			return nil, fmt.Errorf("existing entitlement %s is not permitted by the replacement profile", key)
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
