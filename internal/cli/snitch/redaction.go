package snitch

import "regexp"

const (
	redactionMarker           = "[REDACTED]"
	privateKeyRedactionMarker = "[REDACTED PRIVATE KEY]"
	redactionNotice           = "Note: sensitive values were redacted from the snitch report."

	sensitiveAssignmentName = `(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|signing[_-]?secret|secret[_-]?access[_-]?key|asc[_-]?private[_-]?key(?:[_-]?b64)?|private[_-]?key|password|passwd|pwd|secret|token)`
	sensitiveFlagName       = `(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|signing[_-]?secret|secret[_-]?access[_-]?key|password|passwd|pwd|secret|token)`
	escapeAwareQuotedValue  = `(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')`
)

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var sensitiveTextRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?s)-----BEGIN[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----.*?-----END[ \t]+(?:[A-Z0-9]+[ \t]+)*PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----`),
		replacement: privateKeyRedactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*AWS4-HMAC-SHA256[ \t]+[^\r\n]+`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:` + escapeAwareQuotedValue + `|(?:(?:bearer|basic|token)[ \t]+)?[^\s,;]+)`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/?#\s@]+@`),
		replacement: `${1}` + redactionMarker + `@`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)([?&](?:x-amz-(?:credential|security-token|signature)|x-goog-(?:credential|signature)|signature|sig|` + sensitiveAssignmentName + `)=)[^&#\s"'<>]+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(--` + sensitiveFlagName + `\b[ \t]+)(?:` + escapeAwareQuotedValue + `|[^\s,;]+)`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(["']` + sensitiveAssignmentName + `["'][ \t]*:[ \t]*)(?:` + escapeAwareQuotedValue + `|[^\s,;}\]]+)`),
		replacement: `${1}"` + redactionMarker + `"`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\b_*(?:[a-z0-9]+_)*` + sensitiveAssignmentName + `\b[ \t]*[:=][ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|(?:(?:bearer|basic|token)[ \t]+)[^\s,;]+|` + escapeAwareQuotedValue + `|[^\s,;]+)`),
		replacement: `${1}` + redactionMarker,
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
	redacted := value
	changed := false
	for _, rule := range sensitiveTextRedactionRules {
		next := rule.pattern.ReplaceAllString(redacted, rule.replacement)
		if next != redacted {
			changed = true
			redacted = next
		}
	}
	return redacted, changed
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
