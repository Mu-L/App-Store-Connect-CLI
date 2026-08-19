package snitch

import (
	"regexp"
	"strings"
)

const (
	redactionMarker           = "[REDACTED]"
	privateKeyRedactionMarker = "[REDACTED PRIVATE KEY]"
	redactionNotice           = "Note: sensitive values were redacted from the snitch report."

	sensitiveAssignmentName = `(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|signing[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?answer|asc[_-]?private[_-]?key(?:[_-]?b64)?|private[_-]?key(?:[_-]?b64)?|password|passwd|pwd|secret|token)`
	sensitivePrefixedName   = `_*(?:[a-z0-9]+[_-])*[a-z0-9]*` + sensitiveAssignmentName
	sensitiveFlagName       = `(?:oauth2-bearer|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|signing[_-]?secret|secret[_-]?access[_-]?key|demo[_-]?account[_-]?password|two[_-]?factor[_-]?code|proxy-tlspassword|tlspassword|password|passwd|pwd|pass|token)`
	credentialHeaderName    = `(?:authorization|cookie|set-cookie|scnt|x-apple-id-session-id|csrf|csrf_ts)`
	traceCredentialHeader   = `(?:cookie|set-cookie|scnt|x-apple-id-session-id|csrf|csrf_ts)`
	webAuthQueryCredential  = `(?:widgetkey|code|scnt)`
	singleLineQuotedValue   = `(?:"(?:\\.|[^"\\\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*')`
	escapedQuotedCharacter  = `\\(?:\r?\n|[^\r\n])`
	escapeAwareQuotedValue  = `(?:"(?:` + escapedQuotedCharacter + `|[^"\\])*"|\$?'(?:` + escapedQuotedCharacter + `|[^'\\])*')`
	unterminatedQuotedValue = `(?:"[^\r\n]*|\$?'[^\r\n]*)`
	shellUnquotedValue      = `(?:\\(?:\r?\n|[^\r\n])|[^\s])+`
	flagUnquotedValue       = `(?:\\[^\r\n]|-[^-\s\\]|[^-\s\\])(?:\\[^\r\n]|[^\s])*`
	credentialPairQuoted    = `(?:"(?:\\.|[^"\\\r\n])*:(?:\\.|[^"\\\r\n])+"|\$'(?:\\.|[^'\\\r\n])*:(?:\\.|[^'\\\r\n])+'|'(?:\\.|[^'\\\r\n])*:(?:\\.|[^'\\\r\n])+')`
	credentialPairOpen      = `(?:"[^\r\n]*:[^\r\n]+|\$?'[^\r\n]*:[^\r\n]+)`
	credentialPairUnquoted  = `(?:\\[^\r\n]|[^\s:])*:(?:\\[^\r\n]|[^\s])+`
	credentialPairValue     = `(?:` + credentialPairQuoted + `|` + credentialPairOpen + `|` + credentialPairUnquoted + `)`
	cookieDataQuoted        = `(?:"(?:\\.|[^"\\\r\n])*=(?:\\.|[^"\\\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*=(?:\\.|[^'\\\r\n])*')`
	cookieDataUnquoted      = `(?:\\(?:\r?\n|[^\r\n])|[^\s])*=(?:\\(?:\r?\n|[^\r\n])|[^\s])*`
	cookieDataValue         = `(?:` + cookieDataQuoted + `|` + cookieDataUnquoted + `)`
)

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var (
	secretMarkerPattern     = regexp.MustCompile(`(?i)(^|[ \t])-{1,2}secret(?:[ \t]|$|[ \t]*=[ \t]*(?:1|t|true)(?:[ \t]|$))`)
	secretValuePattern      = regexp.MustCompile(`(?i)(^|[ \t])(-{1,2}value(?:[ \t]+|[ \t]*=[ \t]*))(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + flagUnquotedValue + `)`)
	rawCookieJarPattern     = regexp.MustCompile(`(?i)"cookies"[ \t\r\n]*:[ \t\r\n]*\{`)
	escapedCookieJarPattern = regexp.MustCompile(`(?i)\\"cookies\\"[ \t\r\n]*:[ \t\r\n]*\{`)
)

var structuredCookieValueRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?i)("name"[ \t\r\n]*:[ \t\r\n]*"(?:\\.|[^"\\\r\n])*"[ \t\r\n]*,[ \t\r\n]*"value"[ \t\r\n]*:[ \t\r\n]*")(?:\\.|[^"\\\r\n])*(")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"name\\"[ \t\r\n]*:[ \t\r\n]*\\"(?:\\.|[^"\\\r\n])*?\\"[ \t\r\n]*,[ \t\r\n]*\\"value\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
}

// Redact complete single-line shell values first so an unmatched quote in an
// earlier log line cannot claim a later command's opening quote as its closer.
var singleLineQuotedRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}` + sensitiveFlagName + `\b[ \t]+)` + singleLineQuotedValue),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}(?:` + sensitiveFlagName + `|secret)\b[ \t]*=[ \t]*)` + singleLineQuotedValue),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[^-a-z0-9_])(` + sensitivePrefixedName + `\b[ \t]*[:=][ \t]*)` + singleLineQuotedValue),
		replacement: `${1}${2}` + redactionMarker,
	},
}

var sensitiveTextRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?s)-----BEGIN[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----.*?-----END[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----`),
		replacement: privateKeyRedactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?s)-----BEGIN[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----.*\z`),
		replacement: privateKeyRedactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:["']?` + sensitivePrefixedName + `["']?)[ \t]*:[ \t]*)[|>](?:[+-]?[1-9]?|[1-9][+-]?)[ \t]*(?:#[^\r\n]*)?(?:\r?\n(?:[ \t]+[^\r\n]*|[ \t]*$))+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:bearer|basic|token)[ \t]+(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;]+)`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*[a-z][a-z0-9_-]*[ \t]+[^\s=,]+[ \t]*=[^\r\n]+`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*[a-z][a-z0-9_-]*[ \t]+[^\r\n]+`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;]+)`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)("` + traceCredentialHeader + `[ \t]*:[ \t]*)(?:\\.|[^"\\\r\n])*(")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)('` + traceCredentialHeader + `[ \t]*:[ \t]*)(?:\\.|[^'\\\r\n])*(')`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:[<>][ \t]*)?` + traceCredentialHeader + `)[ \t]*:[ \t]*[^\r\n]+`),
		replacement: `${1}: ` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/?#\s@]+@`),
		replacement: `${1}` + redactionMarker + `@`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)([?&](?:x-amz-(?:credential|security-token|signature)|x-goog-(?:credential|signature)|signature|sig|` + webAuthQueryCredential + `|` + sensitiveAssignmentName + `)=)[^&#\s"'<>]+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:-u|--(?:proxy-)?user)\b[ \t]+)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + credentialPairValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:-u|--(?:proxy-)?user)\b[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + credentialPairValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-u)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + credentialPairValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:-b|--cookie)\b[ \t]+)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:-b|--cookie)\b[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-b)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}` + sensitiveFlagName + `\b[ \t]+)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}secret\b[ \t]+)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + flagUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}(?:` + sensitiveFlagName + `|secret)\b[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"(?:` + sensitivePrefixedName + `|` + credentialHeaderName + `)\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(["'](?:` + sensitivePrefixedName + `|` + credentialHeaderName + `)["'][ \t\r\n]*:[ \t\r\n]*)(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;}\]]+)`),
		replacement: `${1}"` + redactionMarker + `"`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[^-a-z0-9_])(` + sensitivePrefixedName + `\b[ \t]*[:=][ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|(?:(?:bearer|basic|token)[ \t]+)` + shellUnquotedValue + `|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bbearer[ \t]+[-A-Z0-9._~+/=]{8,}`),
		replacement: "Bearer " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		replacement: redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b`),
		replacement: redactionMarker,
	},
}

func redactSensitiveText(value string) (string, bool) {
	redacted, changed := redactSecretMarkedValues(value)
	if next, cookieChanged := redactStructuredCookieValues(redacted); cookieChanged {
		redacted = next
		changed = true
	}
	for _, rule := range singleLineQuotedRedactionRules {
		next := rule.pattern.ReplaceAllString(redacted, rule.replacement)
		if next != redacted {
			changed = true
			redacted = next
		}
	}
	for _, rule := range sensitiveTextRedactionRules {
		next := rule.pattern.ReplaceAllString(redacted, rule.replacement)
		if next != redacted {
			changed = true
			redacted = next
		}
	}
	return redacted, changed
}

func redactStructuredCookieValues(value string) (string, bool) {
	if !rawCookieJarPattern.MatchString(value) && !escapedCookieJarPattern.MatchString(value) {
		return value, false
	}

	redacted := value
	changed := false
	for _, rule := range structuredCookieValueRedactionRules {
		next := rule.pattern.ReplaceAllString(redacted, rule.replacement)
		if next != redacted {
			redacted = next
			changed = true
		}
	}
	return redacted, changed
}

func redactSecretMarkedValues(value string) (string, bool) {
	lines := strings.Split(value, "\n")
	changed := false
	for start := 0; start < len(lines); {
		end := start
		for end < len(lines)-1 && shellLineContinues(strings.TrimSuffix(lines[end], "\r")) {
			end++
		}

		marked := false
		for i := start; i <= end; i++ {
			if secretMarkerPattern.MatchString(strings.TrimSuffix(lines[i], "\r")) {
				marked = true
				break
			}
		}
		if marked {
			for i := start; i <= end; i++ {
				redacted := secretValuePattern.ReplaceAllString(lines[i], `${1}${2}`+redactionMarker)
				if redacted != lines[i] {
					lines[i] = redacted
					changed = true
				}
			}
		}

		start = end + 1
	}
	return strings.Join(lines, "\n"), changed
}

func shellLineContinues(line string) bool {
	backslashes := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func redactLogEntry(entry LogEntry) (LogEntry, bool) {
	changed := false
	redactField := func(field *string) {
		redacted, fieldChanged := redactSensitiveText(*field)
		*field = redacted
		changed = changed || fieldChanged
	}

	redactField(&entry.Description)
	redactField(&entry.Repro)
	redactField(&entry.Expected)
	redactField(&entry.Actual)
	redactField(&entry.Severity)
	redactField(&entry.ASCVersion)
	redactField(&entry.OS)
	var labelsChanged bool
	entry.Labels, labelsChanged = redactStringSlice(entry.Labels)
	changed = changed || labelsChanged

	return entry, changed
}

func redactStringSlice(values []string) ([]string, bool) {
	if len(values) == 0 {
		return values, false
	}

	redacted := make([]string, len(values))
	anyChanged := false
	for i, value := range values {
		redactedValue, valueChanged := redactSensitiveText(value)
		redacted[i] = redactedValue
		anyChanged = anyChanged || valueChanged
	}
	return redacted, anyChanged
}

func redactLogEntries(entries []LogEntry) ([]LogEntry, bool) {
	if len(entries) == 0 {
		return entries, false
	}

	redacted := make([]LogEntry, len(entries))
	changed := false
	for i, entry := range entries {
		var entryChanged bool
		redacted[i], entryChanged = redactLogEntry(entry)
		changed = changed || entryChanged
	}
	return redacted, changed
}
