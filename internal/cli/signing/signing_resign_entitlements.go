package signing

import (
	"fmt"
	"reflect"
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
	for key, value := range existing {
		if _, identityKey := signingResignIdentityEntitlementKeys[key]; identityKey {
			profileValue, exists := profile[key]
			if !exists {
				return nil, fmt.Errorf("existing entitlement %s is missing from the replacement profile", key)
			}
			result[key] = profileValue
			continue
		}
		profileValue, permitted := profile[key]
		if !permitted || !signingResignEntitlementValuePermits(profileValue, value) {
			return nil, fmt.Errorf("existing entitlement %s is not permitted by the replacement profile", key)
		}
		result[key] = value
	}
	for key := range signingResignIdentityEntitlementKeys {
		value, exists := profile[key]
		if !exists {
			if key == "com.apple.application-identifier" ||
				key == "keychain-access-groups" ||
				key == "com.apple.developer.ubiquity-kvstore-identifier" ||
				key == "com.apple.developer.parent-application-identifiers" {
				continue
			}
			return nil, fmt.Errorf("replacement profile entitlement %s is missing", key)
		}
		result[key] = value
	}
	return result, nil
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
