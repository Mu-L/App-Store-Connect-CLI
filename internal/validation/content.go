package validation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Content lint rules flag localized metadata wording that App Store review
// commonly rejects: references to other platforms, leftover placeholder copy,
// promises of unreleased functionality, and test or demo framing.
//
// Every rule is offline (no network lookups) and advisory: matches are reported
// as warnings so they never block a submission on their own. Matching is
// word-boundary based rather than substring based, so "androids", "freedom",
// and "testament" never trigger a platform, placeholder, or test warning.

// otherPlatformPhrases lists competing platforms, stores, and device families.
// Only phrases that are unambiguous on their own belong here: bare "windows",
// "galaxy", "kindle", and "play" are ordinary product vocabulary, so they are
// matched only as part of a longer platform phrase.
var otherPlatformPhrases = []string{
	"android",
	"google",
	"google play",
	"play store",
	"blackberry",
	"windows phone",
	"windows mobile",
	"samsung galaxy",
	"galaxy store",
	"amazon appstore",
	"amazon app store",
	"kindle fire",
	"huawei",
	"appgallery",
	"symbian",
	"tizen",
}

// otherPlatformAllowlist covers service names an App Store listing may name
// legitimately. An allowlist hit suppresses any platform match it overlaps, so
// "Google Drive" stays silent while "Google Play" is still reported.
var otherPlatformAllowlist = []string{
	"google account",
	"google ads",
	"google analytics",
	"google api",
	"google apis",
	"google assistant",
	"google authenticator",
	"google books",
	"google calendar",
	"google chrome",
	"google classroom",
	"google cloud",
	"google contacts",
	"google docs",
	"google drive",
	"google earth",
	"google firebase",
	"google fit",
	"google fonts",
	"google forms",
	"google gemini",
	"google home",
	"google keep",
	"google lens",
	"google login",
	"google maps",
	"google meet",
	"google news",
	"google oauth",
	"google one",
	"google pay",
	"google photos",
	"google scholar",
	"google search console",
	"google sheets",
	"google sign in",
	"google sign-in",
	"google slides",
	"google tasks",
	"google translate",
	"google voice",
	"google wallet",
	"google workspace",
	"continue with google",
	"log in with google",
	"login with google",
	"sign in with google",
	"sign up with google",
}

// placeholderPhrases lists template copy that should never reach the store.
var placeholderPhrases = []string{
	"lorem ipsum",
	"placeholder",
	"placeholder text",
	"text here",
	"your text here",
	"description here",
	"enter description here",
	"insert description",
	"sample text",
	"dummy text",
}

// placeholderMarkers are matched case-sensitively on purpose. As placeholders
// these acronyms are always written in caps, while lowercase "todo" is ordinary
// vocabulary for to-do apps ("manage your todo list").
var placeholderMarkers = []string{
	"TODO",
	"TBD",
	"FIXME",
}

// futureFunctionalityPhrases lists promises of functionality that does not ship
// with the submitted binary. Phrases stay specific so ordinary product copy such
// as "your notes will be available offline" is not flagged.
var futureFunctionalityPhrases = []string{
	"coming soon",
	"coming very soon",
	"will be available soon",
	"will soon be available",
	"in the next release",
	"in the next update",
	"in a future release",
	"in a future update",
	"in a future version",
	"in future updates",
	"not yet available",
	"not available yet",
	"under development",
	"currently in development",
	"still in development",
	"stay tuned",
}

// testWordPhrases lists wording that presents the submission as a test, beta, or
// demo build. Bare "beta" is deliberately absent: it is legitimate in release
// notes and product names, so only qualified phrases are reported.
var testWordPhrases = []string{
	"beta test",
	"beta tests",
	"beta tester",
	"beta testers",
	"beta testing",
	"beta version",
	"beta build",
	"beta release",
	"just a test",
	"this is a test",
	"for testing purposes",
	"testing purposes",
	"testing only",
	"internal testing",
	"test version",
	"test build",
	"demo version",
	"demo build",
}

// contentRule describes one offline content-lint rule.
type contentRule struct {
	id          string
	patterns    []*regexp.Regexp
	allow       *regexp.Regexp
	message     string
	remediation string
}

var contentRules = []contentRule{
	{
		id:          "content.other_platforms",
		patterns:    []*regexp.Regexp{contentPhrasePattern(otherPlatformPhrases)},
		allow:       contentPhrasePattern(otherPlatformAllowlist),
		message:     "%s references another platform (%s)",
		remediation: "Remove references to other platforms and their stores; naming a cross-platform service such as \"Google Drive\" is fine",
	},
	{
		id:          "content.placeholder_text",
		patterns:    []*regexp.Regexp{contentPhrasePattern(placeholderPhrases), contentMarkerPattern(placeholderMarkers)},
		message:     "%s contains placeholder text (%s)",
		remediation: "Replace the placeholder copy with the final listing text",
	},
	{
		id:          "content.future_functionality",
		patterns:    []*regexp.Regexp{contentPhrasePattern(futureFunctionalityPhrases)},
		message:     "%s promises functionality that is not in this build (%s)",
		remediation: "Describe only what the submitted build already does; App Store review rejects metadata that advertises unreleased features",
	},
	{
		id:          "content.test_words",
		patterns:    []*regexp.Regexp{contentPhrasePattern(testWordPhrases)},
		message:     "%s describes the app as a test or demo build (%s)",
		remediation: "Remove test, beta, and demo framing from App Store metadata; keep that wording in TestFlight test information instead",
	},
}

// contentField is one localized metadata value to lint.
type contentField struct {
	field        string
	label        string
	value        string
	locale       string
	resourceType string
	resourceID   string
}

func contentChecks(versionLocs []VersionLocalization, appInfoLocs []AppInfoLocalization) []CheckResult {
	fields := make([]contentField, 0, len(versionLocs)*4+len(appInfoLocs)*2)

	for _, loc := range versionLocs {
		base := contentField{locale: loc.Locale, resourceType: "appStoreVersionLocalization", resourceID: loc.ID}
		fields = append(
			fields,
			contentFieldWith(base, "description", "description", loc.Description),
			contentFieldWith(base, "keywords", "keywords", loc.Keywords),
			contentFieldWith(base, "whatsNew", "what's new", loc.WhatsNew),
			contentFieldWith(base, "promotionalText", "promotional text", loc.PromotionalText),
		)
	}

	for _, loc := range appInfoLocs {
		base := contentField{locale: loc.Locale, resourceType: "appInfoLocalization", resourceID: loc.ID}
		fields = append(
			fields,
			contentFieldWith(base, "name", "name", loc.Name),
			contentFieldWith(base, "subtitle", "subtitle", loc.Subtitle),
		)
	}

	var checks []CheckResult
	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			continue
		}
		for _, rule := range contentRules {
			matches := rule.findMatches(field.value)
			if len(matches) == 0 {
				continue
			}
			checks = append(checks, CheckResult{
				ID:           rule.id,
				Severity:     SeverityWarning,
				Locale:       field.locale,
				Field:        field.field,
				ResourceType: field.resourceType,
				ResourceID:   field.resourceID,
				Message:      fmt.Sprintf(rule.message, field.label, quoteContentMatches(matches)),
				Remediation:  rule.remediation,
			})
		}
	}

	return checks
}

func contentFieldWith(base contentField, field string, label string, value string) contentField {
	base.field = field
	base.label = label
	base.value = value
	return base
}

// findMatches returns the distinct phrases the rule matched, in the order they
// appear, with allowlisted occurrences removed.
func (rule contentRule) findMatches(value string) []string {
	var allowed [][]int
	if rule.allow != nil {
		allowed = rule.allow.FindAllStringIndex(value, -1)
	}

	seen := make(map[string]struct{})
	matches := make([]string, 0, 2)
	for _, pattern := range rule.patterns {
		for _, loc := range pattern.FindAllStringIndex(value, -1) {
			if contentRangeAllowed(loc, allowed) {
				continue
			}
			phrase := strings.Join(strings.Fields(value[loc[0]:loc[1]]), " ")
			key := strings.ToLower(phrase)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, phrase)
		}
	}

	return matches
}

// contentRangeAllowed reports whether a match overlaps an allowlisted phrase.
func contentRangeAllowed(match []int, allowed [][]int) bool {
	for _, allow := range allowed {
		if match[0] < allow[1] && allow[0] < match[1] {
			return true
		}
	}
	return false
}

func quoteContentMatches(matches []string) string {
	quoted := make([]string, 0, len(matches))
	for _, match := range matches {
		quoted = append(quoted, fmt.Sprintf("%q", match))
	}
	return strings.Join(quoted, ", ")
}

// contentPhrasePattern builds a case-insensitive, word-boundary pattern for the
// given phrases. Words inside a phrase may be separated by any run of
// whitespace, and longer phrases are tried first so the most specific match is
// the one reported.
func contentPhrasePattern(phrases []string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b(?:` + contentAlternation(phrases) + `)\b`)
}

// contentMarkerPattern builds a case-sensitive, word-boundary pattern, used for
// acronym markers whose lowercase spelling is ordinary vocabulary.
func contentMarkerPattern(markers []string) *regexp.Regexp {
	return regexp.MustCompile(`\b(?:` + contentAlternation(markers) + `)\b`)
}

func contentAlternation(phrases []string) string {
	ordered := make([]string, len(phrases))
	copy(ordered, phrases)
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i]) > len(ordered[j])
	})

	parts := make([]string, 0, len(ordered))
	for _, phrase := range ordered {
		words := strings.Fields(phrase)
		escaped := make([]string, 0, len(words))
		for _, word := range words {
			escaped = append(escaped, regexp.QuoteMeta(word))
		}
		parts = append(parts, strings.Join(escaped, `[\s\p{Zs}]+`))
	}

	return strings.Join(parts, "|")
}
