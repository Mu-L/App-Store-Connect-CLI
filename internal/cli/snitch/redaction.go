package snitch

import (
	"regexp"
	"strings"
)

const (
	redactionMarker           = "[REDACTED]"
	privateKeyRedactionMarker = "[REDACTED PRIVATE KEY]"
	redactionNotice           = "Note: sensitive values were redacted from the snitch report."

	sensitiveAssignmentName     = `(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|webhook|signing[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?answer|asc[_-]?private[_-]?key(?:[_-]?b64)?|private[_-]?key(?:[_-]?b64)?|password|passwd|pwd|secret|token)`
	sensitivePrefixedName       = `_*(?:[a-z0-9]+[_-])*[a-z0-9]*` + sensitiveAssignmentName
	sensitiveFlagName           = `(?:oauth2-bearer|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|webhook[_-]?header|slack[_-]?webhook|webhook|signing[_-]?secret|secret[_-]?access[_-]?key|demo[_-]?account[_-]?password|two[_-]?factor[_-]?code|proxy-tlspassword|tlspassword|password|passwd|pwd|pass|token)`
	credentialHeaderName        = `(?:proxy-authorization|authorization|cookie|set-cookie|scnt|x-apple-id-session-id|x-apple-widget-key|csrf|csrf_ts)`
	traceCredentialHeader       = `(?:cookie|set-cookie|scnt|x-apple-id-session-id|x-apple-widget-key|csrf|csrf_ts)`
	webAuthQueryCredential      = `(?:widgetkey|code|scnt)`
	webAuthStructuredCredential = `(?:authservicekey|servicekey)`
	structuredCredentialName    = `(?:` + sensitivePrefixedName + `|` + credentialHeaderName + `|` + webAuthStructuredCredential + `)`
	singleLineQuotedValue       = `(?:"(?:\\.|[^"\\\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*')`
	shellCommandSubstitution    = `(?:\x60(?:\\.|[^\x60\\\r\n])*\x60|\$\((?:\\.|[^)\\\r\n])*\))`
	fishCommandSubstitution     = `\((?:\\.|[^)\\\r\n])*\)`
	singleLineUnquotedFragment  = `(?:\\[^\r\n]|[^\s\\;&|<>()"'])+`
	singleLineShellWord         = `(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + singleLineUnquotedFragment + `)+`
	fishShellWord               = `(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + fishCommandSubstitution + `|` + singleLineUnquotedFragment + `)+`
	singleLineShellTerminator   = `(?:[ \t;&|<>()]|\r?\n|\z)`
	escapedQuotedCharacter      = `\\(?:\r?\n|[^\r\n])`
	escapeAwareQuotedValue      = `(?:"(?:` + escapedQuotedCharacter + `|[^"\\])*"|\$?'(?:''|` + escapedQuotedCharacter + `|[^'\\])*')`
	unterminatedQuotedValue     = `(?:"[^\r\n]*|\$?'[^\r\n]*)`
	shellUnquotedValue          = `(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()"'])+`
	flagUnquotedValue           = `(?:\\[^\r\n]|-[^-\s\\;&|<>()]|[^-\s\\;&|<>()])(?:\\[^\r\n]|[^\s;&|<>()])*`
	credentialPairQuoted        = `(?:"(?:` + escapedQuotedCharacter + `|[^"\\])*:(?:` + escapedQuotedCharacter + `|[^"\\])+"|\$?'(?:` + escapedQuotedCharacter + `|[^'\\])*:(?:` + escapedQuotedCharacter + `|[^'\\])+')`
	credentialPairOpen          = `(?:"[^\r\n]*:[^\r\n]+|\$?'[^\r\n]*:[^\r\n]+)`
	credentialPairUnquoted      = `(?:\\(?:\r?\n|[^\r\n])|[^\s:;&|<>()])*:(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])+`
	credentialPairValue         = `(?:` + credentialPairQuoted + `|` + credentialPairOpen + `|` + credentialPairUnquoted + `)`
	cookieDataQuoted            = `(?:"(?:\\.|[^"\\\r\n])*=(?:\\.|[^"\\\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*=(?:\\.|[^'\\\r\n])*')`
	cookieDataUnquoted          = `(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])*=(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])*`
	cookieDataValue             = `(?:` + cookieDataQuoted + `|` + cookieDataUnquoted + `)`
	curlCertOptionPrefix        = `(?:(?:(?-i:-E)|--cert)\b(?:[ \t]+|[ \t]*=[ \t]*)|(?-i:-E))`
	curlCertUnquotedPath        = `(?:\\(?:\r?\n|[^\r\n])|[^\s:'"])+`
	curlHeaderOptionPrefix      = `(?:(?:-H|--header|--proxy-header)\b(?:[ \t]+|[ \t]*=[ \t]*)|-H)`
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
	rawRequestHeaders       = regexp.MustCompile(`(?i)"requestHeaders"[ \t\r\n]*:[ \t\r\n]*\[`)
	escapedRequestHeaders   = regexp.MustCompile(`(?i)\\"requestHeaders\\"[ \t\r\n]*:[ \t\r\n]*\[`)
	rawStructuredValueStart = regexp.MustCompile(`(?i)"value"[ \t\r\n]*:[ \t\r\n]*"`)
	escapedValueStart       = regexp.MustCompile(`(?i)\\"value\\"[ \t\r\n]*:[ \t\r\n]*\\"`)
	rawCredentialObject     = regexp.MustCompile(`(?i)"` + structuredCredentialName + `"[ \t\r\n]*:[ \t\r\n]*\{`)
	escapedCredentialObject = regexp.MustCompile(`(?i)\\"` + structuredCredentialName + `\\"[ \t\r\n]*:[ \t\r\n]*\{`)
	booleanSecretMarker     = regexp.MustCompile(`(?i)(^|\s)(-{1,2}secret)([ \t]*=[ \t]*)(true|false|1)(` + singleLineShellTerminator + `)`)
	yamlCredentialScalar    = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?(?:["']?` + sensitivePrefixedName + `["']?)[ \t]*:[ \t]*)[|>](?:[+-]?[1-9]?|[1-9][+-]?)[ \t]*(?:#[^\r\n]*)?$`)
	yamlCredentialMapping   = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?(?:["']?` + sensitivePrefixedName + `["']?)[ \t]*:)[ \t]*(?:(?:[!&][^\s#]+)[ \t]*)*(?:#[^\r\n]*)?$`)
	yamlCredentialFlowStart = regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?(?:["']?` + sensitivePrefixedName + `["']?)[ \t]*:[ \t]*)([\[{])`)
	jsonQuotedScalarLine    = regexp.MustCompile(`^"(?:\\.|[^"\\])*"[ \t]*,?[ \t]*$`)
)

var structuredContainerValueRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?i)("value"[ \t\r\n]*:[ \t\r\n]*")(?:\\.|[^"\\\r\n])*(")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"value\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
}

// Redact complete single-line shell words first so adjacent quoted and
// unquoted fragments cannot leak, and an unmatched quote in an earlier log
// line cannot claim a later command's opening quote as its closer.
var singleLineShellWordRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?im)(^|[;&|][ \t]*)([ \t]*set[ \t]+(?:(?:--|-[a-z]+|--[a-z][a-z-]*)[ \t]+)*` + sensitivePrefixedName + `\b[ \t]+)` + fishShellWord + `(?:[ \t]+` + fishShellWord + `)*`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}` + sensitiveFlagName + `\b[ \t]+)` + singleLineShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}(?:` + sensitiveFlagName + `|secret)\b[ \t]*=[ \t]*)` + singleLineShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[^-a-z0-9_])(` + sensitivePrefixedName + `\b[ \t]*=[ \t]*)` + singleLineShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
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
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?` + sensitivePrefixedName + `[ \t]*:[ \t]*)(?:\[[^\]\r\n]*\]|\{[^}\r\n]*\})`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?["']` + sensitivePrefixedName + `["'][ \t]*:[ \t]*)(?:\[[ \t]*[^"'\]\r\n][^\]\r\n]*\]|\{[ \t]*[^"'}\r\n][^}\r\n]*\})`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:["']?` + sensitivePrefixedName + `["']?)[ \t]*:[ \t]*)(?:[^"'[{\s\r\n][^\r\n]*)(\r?)$`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(["']` + structuredCredentialName + `["'][ \t\r\n]*:[ \t\r\n]*\[)[ \t\r\n]*(?:"(?:\\.|[^"\\\r\n])*"(?:[ \t\r\n]*,[ \t\r\n]*"(?:\\.|[^"\\\r\n])*")*)[ \t\r\n]*(\])`),
		replacement: `${1}"` + redactionMarker + `"${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"` + structuredCredentialName + `\\"[ \t\r\n]*:[ \t\r\n]*\[)[ \t\r\n]*(?:\\"(?:\\.|[^"\\\r\n])*?\\"(?:[ \t\r\n]*,[ \t\r\n]*\\"(?:\\.|[^"\\\r\n])*?\\")*)[ \t\r\n]*(\])`),
		replacement: `${1}\"` + redactionMarker + `\"${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)("securitycode"[ \t\r\n]*:[ \t\r\n]*\{[ \t\r\n]*"code"[ \t\r\n]*:[ \t\r\n]*")(?:\\.|[^"\\\r\n])*(")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"securitycode\\"[ \t\r\n]*:[ \t\r\n]*\{[ \t\r\n]*\\"code\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)("authorization[ \t]*:[ \t]*)(?:` + escapedQuotedCharacter + `|[^"\\])*(")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)('authorization[ \t]*:[ \t]*)(?:` + escapedQuotedCharacter + `|[^'\\])*(')`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:bearer|basic|token)[ \t]+(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;"']+)`),
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
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;"']+)`),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)("` + traceCredentialHeader + `[ \t]*:[ \t]*)(?:` + escapedQuotedCharacter + `|[^"\\])*(")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)('` + traceCredentialHeader + `[ \t]*:[ \t]*)(?:` + escapedQuotedCharacter + `|[^'\\])*(')`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\b(` + credentialHeaderName + `)[ \t]*:\[[^\]\r\n]*\]`),
		replacement: `${1}:` + redactionMarker,
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
		pattern:     regexp.MustCompile(`(?i)(^|[\s"'=])[^/?#\s@:]+:[^/?#\s@]+@([a-z0-9.-]+:[^\s"'<>]+)`),
		replacement: `${1}` + redactionMarker + `@${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)([?&](?:x-amz-(?:credential|security-token|signature)|x-goog-(?:credential|signature)|signature|sig|` + webAuthQueryCredential + `|` + sensitiveAssignmentName + `)=)[^&#\s"'<>]+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlHeaderOptionPrefix + `)(` + credentialHeaderName + `)[ \t]*:[ \t]*(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])+`),
		replacement: `${1}${2}${3}:` + redactionMarker,
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
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(")((?:` + escapedQuotedCharacter + `|[^"\\:\r\n])+):(?:` + escapedQuotedCharacter + `|[^"\\])+(")`),
		replacement: `${1}${2}${3}${4}:` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(')((?:` + escapedQuotedCharacter + `|[^'\\:\r\n])+):(?:` + escapedQuotedCharacter + `|[^'\\])+(')`),
		replacement: `${1}${2}${3}${4}:` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(` + curlCertUnquotedPath + `):` + singleLineShellWord),
		replacement: `${1}${2}${3}:` + redactionMarker,
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
		pattern:     regexp.MustCompile(`(?i)(\\"` + structuredCredentialName + `\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")([ \t\r\n]*(?:[,}\]]|\z))`),
		replacement: `${1}` + redactionMarker + `${2}${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(["']` + structuredCredentialName + `["'][ \t\r\n]*:[ \t\r\n]*)(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;}\[\]]+)`),
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
	if next, headerChanged := redactStructuredUploadHeaderValues(redacted); headerChanged {
		redacted = next
		changed = true
	}
	if next, objectChanged := redactStructuredCredentialObjects(redacted); objectChanged {
		redacted = next
		changed = true
	}
	if next, yamlChanged := redactYAMLCredentialBlocks(redacted); yamlChanged {
		redacted = next
		changed = true
	}
	if next, yamlFlowChanged := redactYAMLFlowCredentials(redacted); yamlFlowChanged {
		redacted = next
		changed = true
	}
	redacted, booleanMarkerProtection := protectBooleanSecretMarkers(redacted)
	for _, rule := range singleLineShellWordRedactionRules {
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
	if booleanMarkerProtection != "" {
		redacted = strings.ReplaceAll(redacted, booleanMarkerProtection, "")
	}
	return redacted, changed
}

func redactYAMLCredentialBlocks(value string) (string, bool) {
	lines := strings.SplitAfter(value, "\n")
	changed := false
	for line := 0; line < len(lines); line++ {
		content, ending := splitLineEnding(lines[line])
		match := yamlCredentialScalar.FindStringSubmatch(content)
		separator := ""
		if match == nil {
			match = yamlCredentialMapping.FindStringSubmatch(content)
			separator = " "
		}
		if match == nil {
			continue
		}

		keyIndent := yamlKeyIndent(content)
		end := line + 1
		hasIndentedContent := false
		firstIndentedContent := ""
		for end < len(lines) {
			child, _ := splitLineEnding(lines[end])
			if strings.TrimSpace(child) == "" {
				end++
				continue
			}
			if leadingIndent(child) <= keyIndent {
				break
			}
			hasIndentedContent = true
			if firstIndentedContent == "" {
				firstIndentedContent = strings.TrimSpace(child)
			}
			end++
		}
		if !hasIndentedContent {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(content), `"`) && jsonQuotedScalarLine.MatchString(firstIndentedContent) {
			continue
		}

		lines[line] = match[1] + separator + redactionMarker + ending
		lines = append(lines[:line+1], lines[end:]...)
		changed = true
	}
	return strings.Join(lines, ""), changed
}

func redactYAMLFlowCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := yamlCredentialFlowStart.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		start := searchStart + match[0]
		prefixEnd := searchStart + match[3]
		open := searchStart + match[4]
		close := findYAMLFlowEnd(redacted, open)
		if close < 0 {
			close = len(redacted) - 1
		}
		if !strings.Contains(redacted[open:close+1], "\n") || flowStartsWithQuotedValue(redacted, open, close) {
			searchStart = open + 1
			continue
		}

		replacement := redacted[start:prefixEnd] + redactionMarker
		redacted = redacted[:start] + replacement + redacted[close+1:]
		changed = true
		searchStart = start + len(replacement)
	}
	return redacted, changed
}

func findYAMLFlowEnd(value string, open int) int {
	if open < 0 || open >= len(value) || (value[open] != '[' && value[open] != '{') {
		return -1
	}

	stack := []byte{value[open]}
	var quote byte
	for i := open + 1; i < len(value); i++ {
		if quote != 0 {
			if quote == '"' && value[i] == '\\' {
				i++
				continue
			}
			if quote == '\'' && value[i] == '\'' && i+1 < len(value) && value[i+1] == '\'' {
				i++
				continue
			}
			if value[i] == quote {
				quote = 0
			}
			continue
		}

		switch value[i] {
		case '"', '\'':
			quote = value[i]
		case '[', '{':
			stack = append(stack, value[i])
		case ']':
			if stack[len(stack)-1] == '[' {
				stack = stack[:len(stack)-1]
			}
		case '}':
			if stack[len(stack)-1] == '{' {
				stack = stack[:len(stack)-1]
			}
		}
		if len(stack) == 0 {
			return i
		}
	}
	return -1
}

func flowStartsWithQuotedValue(value string, open, close int) bool {
	for i := open + 1; i < close; i++ {
		if value[i] == ' ' || value[i] == '\t' || value[i] == '\r' || value[i] == '\n' {
			continue
		}
		return value[i] == '"'
	}
	return false
}

func splitLineEnding(line string) (string, string) {
	if strings.HasSuffix(line, "\r\n") {
		return strings.TrimSuffix(line, "\r\n"), "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return strings.TrimSuffix(line, "\n"), "\n"
	}
	return line, ""
}

func leadingIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func yamlKeyIndent(line string) int {
	indent := leadingIndent(line)
	if indent >= len(line) || line[indent] != '-' {
		return indent
	}

	key := indent + 1
	if key >= len(line) || (line[key] != ' ' && line[key] != '\t') {
		return indent
	}
	for key < len(line) && (line[key] == ' ' || line[key] == '\t') {
		key++
	}
	return key
}

func protectBooleanSecretMarkers(value string) (string, string) {
	if !booleanSecretMarker.MatchString(value) {
		return value, ""
	}

	protection := "\x00"
	for strings.Contains(value, protection) {
		protection += "\x00"
	}
	protected := booleanSecretMarker.ReplaceAllString(value, `${1}${2}`+protection+`${3}${4}${5}`)
	return protected, protection
}

func redactStructuredCredentialObjects(value string) (string, bool) {
	type objectPattern struct {
		pattern       *regexp.Regexp
		escapedQuotes bool
		quote         string
	}

	patterns := []objectPattern{
		{pattern: rawCredentialObject, quote: `"`},
		{pattern: escapedCredentialObject, escapedQuotes: true, quote: `\"`},
	}
	redacted := value
	changed := false
	for _, candidate := range patterns {
		searchStart := 0
		for searchStart < len(redacted) {
			match := candidate.pattern.FindStringIndex(redacted[searchStart:])
			if match == nil {
				break
			}

			open := searchStart + match[1] - 1
			close := findJSONObjectEnd(redacted, open, candidate.escapedQuotes)

			replacement := candidate.quote + redactionMarker + candidate.quote
			redacted = redacted[:open] + replacement + redacted[close+1:]
			changed = true
			searchStart = open + len(replacement)
		}
	}
	return redacted, changed
}

func findJSONObjectEnd(value string, open int, escapedQuotes bool) int {
	return findJSONContainerEnd(value, open, escapedQuotes)
}

func findJSONContainerEnd(value string, open int, escapedQuotes bool) int {
	if open < 0 || open >= len(value) || (value[open] != '{' && value[open] != '[') {
		return len(value) - 1
	}

	stack := []byte{value[open]}
	inString := false
	for i := open + 1; i < len(value); i++ {
		if value[i] == '"' && isJSONStringDelimiter(value, i, escapedQuotes) {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		switch value[i] {
		case '{', '[':
			stack = append(stack, value[i])
		case '}':
			if stack[len(stack)-1] == '{' {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				return i
			}
		case ']':
			if stack[len(stack)-1] == '[' {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				return i
			}
		}
	}
	return len(value) - 1
}

func isJSONStringDelimiter(value string, quote int, escapedQuotes bool) bool {
	backslashes := 0
	for i := quote - 1; i >= 0 && value[i] == '\\'; i-- {
		backslashes++
	}
	if escapedQuotes {
		return backslashes%4 == 1
	}
	return backslashes%2 == 0
}

func redactStructuredCookieValues(value string) (string, bool) {
	if !rawCookieJarPattern.MatchString(value) && !escapedCookieJarPattern.MatchString(value) {
		return value, false
	}

	type cookieObjectPattern struct {
		pattern       *regexp.Regexp
		escapedQuotes bool
	}
	patterns := []cookieObjectPattern{
		{pattern: rawCookieJarPattern},
		{pattern: escapedCookieJarPattern, escapedQuotes: true},
	}
	redacted := value
	changed := false
	for _, candidate := range patterns {
		searchStart := 0
		for searchStart < len(redacted) {
			match := candidate.pattern.FindStringIndex(redacted[searchStart:])
			if match == nil {
				break
			}

			open := searchStart + match[1] - 1
			close := findJSONObjectEnd(redacted, open, candidate.escapedQuotes)
			object := redacted[open : close+1]
			redactedObject := object
			for _, rule := range structuredContainerValueRedactionRules {
				redactedObject = rule.pattern.ReplaceAllString(redactedObject, rule.replacement)
			}
			if next, truncatedChanged := redactTruncatedStructuredValues(redactedObject, candidate.escapedQuotes); truncatedChanged {
				redactedObject = next
			}
			if redactedObject != object {
				redacted = redacted[:open] + redactedObject + redacted[close+1:]
				changed = true
			}
			searchStart = open + len(redactedObject)
		}
	}
	return redacted, changed
}

// Upload-operation request-header values are capabilities regardless of their
// names, matching asc.RedactUploadOperations while preserving useful metadata.
func redactStructuredUploadHeaderValues(value string) (string, bool) {
	type headerContainerPattern struct {
		pattern       *regexp.Regexp
		escapedQuotes bool
	}
	patterns := []headerContainerPattern{
		{pattern: rawRequestHeaders},
		{pattern: escapedRequestHeaders, escapedQuotes: true},
	}

	redacted := value
	changed := false
	for _, candidate := range patterns {
		searchStart := 0
		for searchStart < len(redacted) {
			match := candidate.pattern.FindStringIndex(redacted[searchStart:])
			if match == nil {
				break
			}

			open := searchStart + match[1] - 1
			close := findJSONContainerEnd(redacted, open, candidate.escapedQuotes)
			container := redacted[open : close+1]
			redactedContainer := container
			for _, rule := range structuredContainerValueRedactionRules {
				redactedContainer = rule.pattern.ReplaceAllString(redactedContainer, rule.replacement)
			}
			if next, truncatedChanged := redactTruncatedStructuredValues(redactedContainer, candidate.escapedQuotes); truncatedChanged {
				redactedContainer = next
			}
			if redactedContainer != container {
				redacted = redacted[:open] + redactedContainer + redacted[close+1:]
				changed = true
			}
			searchStart = open + len(redactedContainer)
		}
	}
	return redacted, changed
}

func redactTruncatedStructuredValues(value string, escapedQuotes bool) (string, bool) {
	pattern := rawStructuredValueStart
	if escapedQuotes {
		pattern = escapedValueStart
	}

	searchStart := 0
	for searchStart < len(value) {
		match := pattern.FindStringIndex(value[searchStart:])
		if match == nil {
			return value, false
		}

		openQuote := searchStart + match[1] - 1
		for quote := openQuote + 1; quote < len(value); quote++ {
			if value[quote] == '"' && isJSONStringDelimiter(value, quote, escapedQuotes) {
				searchStart = quote + 1
				break
			}
			if quote == len(value)-1 {
				return value[:openQuote+1] + redactionMarker, true
			}
		}
		if openQuote == len(value)-1 {
			return value + redactionMarker, true
		}
	}
	return value, false
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
