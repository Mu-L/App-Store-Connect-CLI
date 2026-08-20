package snitch

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	redactionMarker           = "[REDACTED]"
	privateKeyRedactionMarker = "[REDACTED PRIVATE KEY]"
	oversizedFieldMarker      = "[REDACTED: oversized report field omitted]"
	redactionNotice           = "Note: sensitive values were redacted from the snitch report."
	maxRedactionFieldBytes    = 64 * 1024

	sensitiveAssignmentName     = `(?:_auth|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|client[_-]?key[_-]?data|app[_-]?secret|webhook[_-]?secret|webhook|signing[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?answer|secret[_-]?key(?:[_-]?base)?|asc[_-]?private[_-]?key(?:[_-]?b64)?|private[_-]?key(?:[_-]?b64)?|password|passphrase|passwd|pwd|secret|token)`
	sensitivePrefixedName       = `_*(?:[a-z0-9]+[_-])*[a-z0-9]*` + sensitiveAssignmentName
	tomlQuotedSensitiveKey      = `(?:"` + sensitivePrefixedName + `"|'` + sensitivePrefixedName + `')`
	valueBearingFlagPrefix      = `(?:n(?:[a-np-z0-9][a-z0-9]*|o[a-z0-9]+)?|[a-mo-z0-9][a-z0-9]*)`
	sensitiveFlagName           = `(?:(?:` + valueBearingFlagPrefix + `[_-])+` + sensitiveAssignmentName + `|oauth2-bearer|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|app[_-]?secret|webhook[_-]?secret|webhook[_-]?header|slack[_-]?webhook|webhook|signing[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?answer|secret[_-]?key(?:[_-]?base)?|demo[_-]?account[_-]?password|two[_-]?factor[_-]?code|proxy-tlspassword|tlspassword|password|passphrase|passwd|pwd|pass|token)`
	sensitiveOrSecretFlagName   = `(?:` + sensitiveFlagName + `|secret)`
	powerShellVariableScope     = `(?:(?:env|global|local|private|script|using):)`
	powerShellSensitiveVariable = `(?:\$(?:(?:` + powerShellVariableScope + `)?` + sensitivePrefixedName + `\b|\{(?:` + powerShellVariableScope + `)?` + sensitivePrefixedName + `\}))`
	sensitiveShellFlagToken     = `(?:-{1,2}` + sensitiveFlagName + `\b|"-{1,2}` + sensitiveFlagName + `\b"|'-{1,2}` + sensitiveFlagName + `\b'|-{1,2}"` + sensitiveFlagName + `\b"|-{1,2}'` + sensitiveFlagName + `\b')`
	sensitiveOrSecretShellToken = `(?:-{1,2}` + sensitiveOrSecretFlagName + `\b|"-{1,2}` + sensitiveOrSecretFlagName + `\b"|'-{1,2}` + sensitiveOrSecretFlagName + `\b'|-{1,2}"` + sensitiveOrSecretFlagName + `\b"|-{1,2}'` + sensitiveOrSecretFlagName + `\b')`
	credentialHeaderName        = `(?:proxy-authorization|authorization|cookie|set-cookie|scnt|x-apple-id-session-id|x-apple-widget-key|csrf|csrf_ts)`
	cgiCredentialHeaderName     = `(?:proxy_authorization|authorization|cookie|set_cookie|scnt|x_apple_id_session_id|x_apple_widget_key|csrf|csrf_ts)`
	traceCredentialHeader       = `(?:cookie|set-cookie|scnt|x-apple-id-session-id|x-apple-widget-key|csrf|csrf_ts)`
	webAuthQueryCredential      = `(?:widgetkey|code|scnt)`
	queryCredentialName         = `(?:x-amz-(?:credential|security-token|signature)|x-goog-(?:credential|signature)|signature|sig|` + webAuthQueryCredential + `|` + sensitiveAssignmentName + `)`
	webAuthStructuredCredential = `(?:authservicekey|servicekey)`
	wellKnownSecretDataName     = `(?:tls\.key|\.dockerconfigjson)`
	structuredCredentialName    = `(?:` + sensitivePrefixedName + `|` + credentialHeaderName + `|` + webAuthStructuredCredential + `|` + wellKnownSecretDataName + `)`
	yamlCredentialName          = `(?:` + sensitivePrefixedName + `|` + wellKnownSecretDataName + `)`
	yamlNodeTag                 = `(?:!<[^>\r\n]+>|![^\s#]+)`
	powerShellEscapedCharacter  = `\x60(?:\r?\n|[^\r\n])`
	singleLineQuotedValue       = `(?:"(?:\\.|` + powerShellEscapedCharacter + `|[^"\\\x60\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*')`
	shellCommandSubstitution    = `(?:\x60(?:\\.|[^\x60\\\r\n])*\x60|\$\((?:\\.|[^)\\\r\n])*\))`
	fishCommandSubstitution     = `\((?:\\.|[^)\\\r\n])*\)`
	cmdEscapedCharacter         = `\^(?:\r?\n|[^\r\n])`
	singleLineUnquotedFragment  = `(?:\\[^\r\n]|[^\s\\;&|<>()"'\x60^])+`
	singleLineShellWord         = `(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + powerShellEscapedCharacter + `|` + cmdEscapedCharacter + `|` + singleLineUnquotedFragment + `)+`
	kubectlShellWord            = `(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + powerShellEscapedCharacter + `|` + cmdEscapedCharacter + `|\\\r?\n[ \t]*|` + singleLineUnquotedFragment + `)+`
	fishShellWord               = `(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + fishCommandSubstitution + `|` + powerShellEscapedCharacter + `|` + cmdEscapedCharacter + `|` + singleLineUnquotedFragment + `)+`
	singleLineShellTerminator   = `(?:[ \t;&|<>()]|\r?\n|\z)`
	escapedQuotedCharacter      = `\\(?:\r?\n|[^\r\n])`
	escapeAwareQuotedValue      = `(?:"(?:` + escapedQuotedCharacter + `|` + powerShellEscapedCharacter + `|[^"\\\x60])*"|\$?'(?:''|` + escapedQuotedCharacter + `|[^'\\])*')`
	unterminatedQuotedValue     = `(?s:".*|\$?'.*)`
	shellUnquotedValue          = `(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()"'])+`
	structuredUnquotedValue     = `(?:\\(?:\r?\n|[^\r\n])|[^\s,;&|<>()"'{}\[\]])+`
	flagUnquotedValue           = `(?:\\[^\r\n]|-[^-\s\\;&|<>()]|[^-\s\\;&|<>()])(?:\\[^\r\n]|[^\s;&|<>()])*`
	credentialPairQuoted        = `(?:"(?:` + escapedQuotedCharacter + `|[^"\\])*:(?:` + escapedQuotedCharacter + `|[^"\\])+"|\$?'(?:` + escapedQuotedCharacter + `|[^'\\])*:(?:` + escapedQuotedCharacter + `|[^'\\])+')`
	credentialPairOpen          = `(?:"[^\r\n]*:[^\r\n]+|\$?'[^\r\n]*:[^\r\n]+)`
	credentialPairShellWord     = `(?:` + singleLineQuotedValue + `|\\(?:\r?\n|[^\r\n])|[^\s:;&|<>()"'])+:(?:` + singleLineQuotedValue + `|` + shellCommandSubstitution + `|` + fishCommandSubstitution + `|` + shellUnquotedValue + `)+`
	credentialPairUnquoted      = `(?:\\(?:\r?\n|[^\r\n])|[^\s:;&|<>()])*:(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])+`
	credentialPairValue         = `(?:` + credentialPairQuoted + `|` + credentialPairShellWord + `|` + credentialPairOpen + `|` + credentialPairUnquoted + `)`
	cookieDataQuoted            = `(?:"(?:\\.|[^"\\\r\n])*=(?:\\.|[^"\\\r\n])*"|\$?'(?:\\.|[^'\\\r\n])*=(?:\\.|[^'\\\r\n])*')`
	cookieDataUnquoted          = `(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])+=(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])*`
	cookieDataValue             = `(?:` + cookieDataQuoted + `|` + cookieDataUnquoted + `)`
	curlCertOptionPrefix        = `(?:(?:(?-i:-E)|--(?:proxy-)?cert)\b(?:[ \t]+|[ \t]*=[ \t]*)|(?-i:-E))`
	curlCertUnquotedPath        = `(?:\\(?:\r?\n|[^\r\n])|[^\s:'"])+`
	curlCertShellPath           = `(?:` + singleLineQuotedValue + `|` + curlCertUnquotedPath + `)+`
	curlHeaderOptionPrefix      = `(?:(?:-H|--header|--proxy-header)\b(?:[ \t]+|[ \t]*=[ \t]*)|-H)`
	curlFormDataOptionPrefix    = `(?:(?-i:-F)(?:[ \t]+|[ \t]*=[ \t]*)?|--(?:data-urlencode|data|form-string|form)\b(?:[ \t]+|[ \t]*=[ \t]*))`
	curlConfigSeparator         = `(?:[ \t]*[=:][ \t]*|[ \t]+)`
	shellCommandPathSeparator   = `(?:[ \t]+(?:\\\r?\n[ \t]*)*|(?:\\\r?\n)+[ \t]+(?:\\\r?\n[ \t]*)*)`
	foldedHeaderContinuation    = `(?:\r?\n[ \t]+[^\r\n]*)*`
	passwordFileField           = `(?:\\[:\\]|[^:\\\r\n])+`
	passwordFileHostField       = `(?:\\[:\\]|[^#:\\\r\n])(?:\\[:\\]|[^:\\\r\n])*`
)

const (
	powerShellSecureStringSwitch    = `(?:(?:-AsPlainText|-Force)(?:[ \t]+|[ \t]*:[ \t]*\$?(?:true|false)[ \t]+))`
	uppercaseSessionEnvironmentName = `(?:[A-Z0-9]+_)+SESSION`
)

type redactionRule struct {
	pattern     *regexp.Regexp
	replacement string
}

type yamlAnchorLocation struct {
	line      int
	anchorEnd int
}

var (
	secretMarkerPattern                = regexp.MustCompile(`(?i)(^|[ \t])-{1,2}secret(?:` + singleLineShellTerminator + `|[ \t]*=[ \t]*(?:1|t|true)(?:` + singleLineShellTerminator + `))`)
	secretValuePattern                 = regexp.MustCompile(`(?i)(^|[ \t])(-{1,2}value(?:[ \t]+|[ \t]*=[ \t]*))(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + flagUnquotedValue + `)`)
	kubectlFromLiteralValue            = regexp.MustCompile(`(?i)(--from-literal(?:[ \t]+|[ \t]*=[ \t]*))(?:\[REDACTED(?: PRIVATE KEY)?\]|` + kubectlShellWord + `)`)
	rawCookieJarPattern                = regexp.MustCompile(`(?i)"cookies"[ \t\r\n]*:[ \t\r\n]*(?:\{|\[)`)
	escapedCookieJarPattern            = regexp.MustCompile(`(?i)\\"cookies\\"[ \t\r\n]*:[ \t\r\n]*(?:\{|\[)`)
	rawRegistryAuthsPattern            = regexp.MustCompile(`(?i)"auths"[ \t\r\n]*:[ \t\r\n]*\{`)
	escapedRegistryAuthsPattern        = regexp.MustCompile(`(?i)\\"auths\\"[ \t\r\n]*:[ \t\r\n]*\{`)
	rawRequestHeaders                  = regexp.MustCompile(`(?i)"requestHeaders"[ \t\r\n]*:[ \t\r\n]*\[`)
	escapedRequestHeaders              = regexp.MustCompile(`(?i)\\"requestHeaders\\"[ \t\r\n]*:[ \t\r\n]*\[`)
	rawStructuredValueStart            = regexp.MustCompile(`(?i)"value"[ \t\r\n]*:[ \t\r\n]*"`)
	escapedValueStart                  = regexp.MustCompile(`(?i)\\"value\\"[ \t\r\n]*:[ \t\r\n]*\\"`)
	rawCredentialObject                = regexp.MustCompile(`(?i)"` + structuredCredentialName + `"[ \t\r\n]*:[ \t\r\n]*\{`)
	escapedCredentialObject            = regexp.MustCompile(`(?i)\\"` + structuredCredentialName + `\\"[ \t\r\n]*:[ \t\r\n]*\{`)
	rawCredentialArray                 = regexp.MustCompile(`(?i)"` + structuredCredentialName + `"[ \t\r\n]*:[ \t\r\n]*\[`)
	escapedCredentialArray             = regexp.MustCompile(`(?i)\\"` + structuredCredentialName + `\\"[ \t\r\n]*:[ \t\r\n]*\[`)
	credentialHeaderNamePattern        = regexp.MustCompile(`(?i)^` + credentialHeaderName + `$`)
	sensitiveAssignmentHeaderName      = regexp.MustCompile(`(?i)^` + sensitivePrefixedName + `$`)
	queryCredentialNamePattern         = regexp.MustCompile(`(?i)^` + queryCredentialName + `$`)
	queryParameterName                 = regexp.MustCompile(`[?&]([^=&#\s"'<>]+)=`)
	curlHeaderOptionStart              = regexp.MustCompile(`(?i)(^|\s)(` + curlHeaderOptionPrefix + `)`)
	completeShellWord                  = regexp.MustCompile(`^(` + fishShellWord + `)(` + singleLineShellTerminator + `)`)
	netrcEntryStart                    = regexp.MustCompile(`(?im)(?:^|[\r\n])[ \t]*(?:machine[ \t]+[^\s#]+|default)(?:[ \t\r\n]|\z)`)
	netrcPasswordValue                 = regexp.MustCompile(`(?i)(^|[ \t\r\n])(password[ \t]+)` + singleLineShellWord + `(` + singleLineShellTerminator + `)`)
	booleanSecretMarker                = regexp.MustCompile(`(?i)(^|\s)(-{1,2}secret)([ \t]*=[ \t]*)(true|false|1|0|t|f)(` + singleLineShellTerminator + `)`)
	yamlCredentialScalar               = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?(?:["']?` + yamlCredentialName + `["']?)[ \t]*:[ \t]*)(?:(?:[!&][^\s#]+)[ \t]*)*[|>](?:[+-]?[1-9]?|[1-9][+-]?)[ \t]*(?:#[^\r\n]*)?$`)
	yamlCredentialMapping              = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?(?:["']?` + yamlCredentialName + `["']?)[ \t]*:)[ \t]*(?:(?:[!&][^\s#]+)[ \t]*)*(?:#[^\r\n]*)?$`)
	yamlCredentialPlainScalar          = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?(?:["']?` + yamlCredentialName + `["']?)[ \t]*:[ \t]*)[^"'[\{\s\r\n][^\r\n]*$`)
	yamlCredentialFlowStart            = regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?(?:["']?` + yamlCredentialName + `["']?)[ \t]*:[ \t]*)([\[{])`)
	yamlExplicitCredentialKey          = regexp.MustCompile(`(?i)^[ \t]*(?:-[ \t]+)?\?[ \t]+(?:` + yamlNodeTag + `[ \t]+)*(?:["']?` + yamlCredentialName + `["']?)[ \t]*(?:#[^\r\n]*)?$`)
	yamlCredentialAlias                = regexp.MustCompile(`(?im)^[ \t]*(?:-[ \t]+)?(?:["']?` + yamlCredentialName + `["']?)[ \t]*:[ \t]*\*([a-z0-9_-]+)[ \t]*(?:#[^\r\n]*)?$`)
	yamlValueAlias                     = regexp.MustCompile(`\*([a-zA-Z0-9_-]+)\b`)
	yamlAnchor                         = regexp.MustCompile(`&([a-zA-Z0-9_-]+)\b`)
	yamlSensitiveNameAnchor            = regexp.MustCompile(`(?im)&([a-zA-Z0-9_-]+)[ \t]+(?:(?:` + yamlNodeTag + `)[ \t]+)*(?:["']?` + yamlCredentialName + `["']?)[ \t]*(?:#[^\r\n]*)?$`)
	yamlAliasMappingKey                = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?)(\*([a-zA-Z0-9_-]+))([ \t]*:)`)
	yamlExplicitAliasKey               = regexp.MustCompile(`(?i)^([ \t]*(?:-[ \t]+)?\?[ \t]+)(\*([a-zA-Z0-9_-]+))([ \t]*(?:#[^\r\n]*)?)$`)
	jsonQuotedScalarLine               = regexp.MustCompile(`^"(?:\\.|[^"\\])*"[ \t]*,?[ \t]*$`)
	jsonCredentialName                 = regexp.MustCompile(`(?i)^(?:` + structuredCredentialName + `)$`)
	yamlCredentialNamePattern          = regexp.MustCompile(`(?i)^(?:` + yamlCredentialName + `)$`)
	tomlCredentialName                 = regexp.MustCompile(`(?i)^(?:` + sensitivePrefixedName + `)$`)
	tomlMultilineCredentialStart       = regexp.MustCompile(`(?i)(?:^|[^-a-z0-9_])(?:` + sensitivePrefixedName + `\b|` + tomlQuotedSensitiveKey + `)[ \t]*=[ \t]*(?:"""|''')`)
	sensitiveCommandSubstitutionStart  = regexp.MustCompile(`(?i)(?:^|\s)(?:` + sensitiveShellFlagToken + `(?:[ \t]+|[ \t]*=[ \t]*)|` + sensitivePrefixedName + `\b[ \t]*[:=][ \t]*)(\$\(|\(|\x60)`)
	powerShellHereStringCredential     = regexp.MustCompile(`(?i)(?:^|\s)(?:` + sensitiveShellFlagToken + `(?:` + shellCommandPathSeparator + `|[ \t]*=[ \t]*)|` + powerShellSensitiveVariable + `[ \t]*=[ \t]*)(@["']\r?\n)`)
	powerShellCollectionCredential     = regexp.MustCompile(`(?i)(?:^|\s)` + powerShellSensitiveVariable + `[ \t]*=[ \t]*(@[({])`)
	commandPromptQuotedSetAssignment   = regexp.MustCompile(`(?im)(?:^|[ \t;&|])set[ \t]+"` + sensitivePrefixedName + `\b[ \t]*=[ \t]*`)
	commandPromptUnquotedSetAssignment = regexp.MustCompile(`(?im)(?:^|[ \t;&|()])set[ \t]+` + sensitivePrefixedName + `\b[ \t]*=[ \t]*`)
	bareEnvironmentDumpCredential      = regexp.MustCompile(`(?im)^([ \t]*(?:export[ \t]+)?(?:` + sensitivePrefixedName + `|(?-i:` + uppercaseSessionEnvironmentName + `))\b[ \t]*=[ \t]*)([^\s"'\\;&|<>()]+(?:[ \t]+[^\s"'\\;&|<>()]+)+)([ \t]*\r?)$`)
	shellAssignmentWord                = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	curlConfigCertificateEntry         = regexp.MustCompile(`(?im)^([ \t]*(?:cert|proxy-cert)` + curlConfigSeparator + `)`)
	xmlCredentialElementStart          = regexp.MustCompile(`(?i)<(?:[a-z_][a-z0-9_.-]*:)?` + sensitivePrefixedName + `(?:[ \t\r\n/>])`)
	xmlElementStart                    = regexp.MustCompile(`<[a-zA-Z_:][a-zA-Z0-9_.:-]*(?:[ \t\r\n/>])`)
	xmlAttribute                       = regexp.MustCompile(`(?s)(?:^|[ \t\r\n])([a-zA-Z_:][a-zA-Z0-9_.:-]*)[ \t\r\n]*=[ \t\r\n]*(?:"([^"]*)"|'([^']*)')`)
	authorizationHeaderValueStart      = regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*`)
	standaloneBearerCandidate          = regexp.MustCompile(`(?i)\bbearer[ \t]+([-a-z0-9._~+/=]+)`)
	xcodeCloudEnvVarSetCommand         = regexp.MustCompile(`(?i)(?:\basc\b|"asc"|'asc')` + shellCommandPathSeparator + `web` + shellCommandPathSeparator + `xcode-cloud` + shellCommandPathSeparator + `env-vars` + shellCommandPathSeparator + `(?:shared` + shellCommandPathSeparator + `)?set\b`)
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

var registryAuthValueRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?i)("auth"[ \t\r\n]*:[ \t\r\n]*")(?:\\.|[^"\\\r\n])*(")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\\"auth\\"[ \t\r\n]*:[ \t\r\n]*\\")(?:\\.|[^"\\\r\n])*?(\\")`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
}

// Redact complete single-line shell words first so adjacent quoted and
// unquoted fragments cannot leak, and an unmatched quote in an earlier log
// line cannot claim a later command's opening quote as its closer.
var singleLineShellWordRedactionRules = []redactionRule{
	{
		pattern:     regexp.MustCompile(`(?m)(^|[ \t;&|])(` + uppercaseSessionEnvironmentName + `[ \t]*=[ \t]*)` + singleLineShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?im)(^|[ \t;&|])(` + powerShellSensitiveVariable + `[ \t]*=[ \t]*)(?:&[ \t]+)?(?:[a-z0-9_.-]+\\)?ConvertTo-SecureString[ \t]+(?:` + powerShellSecureStringSwitch + `)*(?:-String(?:[ \t]+|[ \t]*:[ \t]*))?` + fishShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?im)(^|[;&|][ \t]*)([ \t]*set[ \t]+(?:(?:--|-[a-z]+|--[a-z][a-z-]*)[ \t]+)*` + sensitivePrefixedName + `\b[ \t]+)` + fishShellWord + `(?:[ \t]+` + fishShellWord + `)*`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + sensitiveShellFlagToken + shellCommandPathSeparator + `)` + fishShellWord + `(` + singleLineShellTerminator + `)`),
		replacement: `${1}${2}` + redactionMarker + `${3}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + sensitiveOrSecretShellToken + `[ \t]*=[ \t]*)` + fishShellWord + `(` + singleLineShellTerminator + `)`),
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
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:redirect_)?http_` + cgiCredentialHeaderName + `\b[ \t]*=[ \t]*)[^\r\n]*(\r?)$`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?m)^(` + passwordFileHostField + `:(?:[0-9]+|\*):` + passwordFileField + `:` + passwordFileField + `:)` + passwordFileField + `(\r?)$`),
		replacement: `${1}` + redactionMarker + `${2}`,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?` + yamlCredentialName + `[ \t]*:[ \t]*)(?:\[[^\]\r\n]*\]|\{[^}\r\n]*\})`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:-[ \t]+)?["']` + yamlCredentialName + `["'][ \t]*:[ \t]*)(?:\[[ \t]*[^"'\]\r\n][^\]\r\n]*\]|\{[ \t]*[^"'}\r\n][^}\r\n]*\})`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:["']?` + yamlCredentialName + `["']?)[ \t]*:[ \t]*)(?:[^"'[{\s\r\n][^\r\n]*)(\r?)$`),
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
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*(?:bearer|basic|token)[ \t]+(?:` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;"']+)` + foldedHeaderContinuation),
		replacement: "Authorization: " + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)\bauthorization[ \t]*[:=][ \t]*[a-z][a-z0-9_-]*[ \t]+[^\s=,]+[ \t]*=[^\r\n]+` + foldedHeaderContinuation),
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
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:(?:[<>][ \t]*)?` + traceCredentialHeader + `|[<>][ \t]*` + sensitivePrefixedName + `))[ \t]*:[ \t]*[^\r\n]+` + foldedHeaderContinuation),
		replacement: `${1}: ` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[\s"'(<>{}\[\],;])((?:cookie|set-cookie)[ \t]*:[ \t]*)(?:` + cookieDataQuoted + `|` + cookieDataUnquoted + `)(?:[ \t]*;[ \t]*` + cookieDataUnquoted + `)*` + foldedHeaderContinuation),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[\s"'(<>{}\[\],;])((?:` + traceCredentialHeader + `)[ \t]*:[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s,;"'()<>{}\[\]]+)` + foldedHeaderContinuation),
		replacement: `${1}${2}` + redactionMarker,
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
		pattern:     regexp.MustCompile(`(?i)\b(https://hooks\.slack(?:-gov)?\.com/services/)[^?#\s"'()<>{}\[\],;]+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)([?&]` + queryCredentialName + `=)[^&#\s"'<>]+`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlHeaderOptionPrefix + `)(` + credentialHeaderName + `)[ \t]*:[ \t]*(?:\\(?:\r?\n|[^\r\n])|[^\s;&|<>()])+`),
		replacement: `${1}${2}${3}:` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:user|proxy-user)` + curlConfigSeparator + `)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + credentialPairValue + `)`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*(?:oauth2-bearer|pass|proxy-tlspassword|tlspassword)` + curlConfigSeparator + `)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|[^\s#]+)`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^([ \t]*cookie` + curlConfigSeparator + `)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)^((?:#HttpOnly_)?[^#\t\r\n][^\t\r\n]*\t(?:TRUE|FALSE)\t[^\t\r\n]*\t(?:TRUE|FALSE)\t[0-9]+\t[^\t\r\n]+\t)(?:\[REDACTED(?: PRIVATE KEY)?\]|[^\t\r\n]+)`),
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
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(")((?:` + escapedQuotedCharacter + `|[^"\\:\r\n])+):(?:` + escapedQuotedCharacter + `|[^"\\])+(")`),
		replacement: `${1}${2}${3}${4}:` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(')((?:` + escapedQuotedCharacter + `|[^'\\:\r\n])+):(?:` + escapedQuotedCharacter + `|[^'\\])+(')`),
		replacement: `${1}${2}${3}${4}:` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlCertOptionPrefix + `)(` + curlCertShellPath + `):` + singleLineShellWord),
		replacement: `${1}${2}${3}:` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:(?-i:-b)|--cookie)\b[ \t]+)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?:(?-i:-b)|--cookie)\b[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)((?-i:-b))(?:\[REDACTED(?: PRIVATE KEY)?\]|` + cookieDataValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlFormDataOptionPrefix + `)(")((?:\\.|[^"\\])*?` + sensitivePrefixedName + `\b[ \t]*=[ \t]*)(?:\\.|[^"\\])*(")`),
		replacement: `${1}${2}${3}${4}` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + curlFormDataOptionPrefix + `)(')([^']*?` + sensitivePrefixedName + `\b[ \t]*=[ \t]*)[^']*(')`),
		replacement: `${1}${2}${3}${4}` + redactionMarker + `${5}`,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + sensitiveShellFlagToken + shellCommandPathSeparator + `)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(-{1,2}secret\b` + shellCommandPathSeparator + `)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + flagUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|\s)(` + sensitiveOrSecretShellToken + `[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
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
		pattern:     regexp.MustCompile(`(?i)(^|[^-a-z0-9_])(` + tomlQuotedSensitiveKey + `[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?i)(^|[^-a-z0-9_])(` + sensitivePrefixedName + `\b[ \t]*=[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|(?:(?:bearer|basic|token)[ \t]+)` + shellUnquotedValue + `|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + shellUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`(?im)(^[ \t]*|[\[{(,;][ \t]*)(` + sensitivePrefixedName + `\b[ \t]*:[ \t]*)(?:\[REDACTED(?: PRIVATE KEY)?\]|(?:(?:bearer|basic|token)[ \t]+)` + structuredUnquotedValue + `|` + escapeAwareQuotedValue + `|` + unterminatedQuotedValue + `|` + structuredUnquotedValue + `)`),
		replacement: `${1}${2}` + redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		replacement: redactionMarker,
	},
	{
		pattern:     regexp.MustCompile(`\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}|xoxp-[A-Za-z0-9-]{20,}|xapp-[0-9]+-[A-Za-z0-9]{10,}(?:-[A-Za-z0-9]{6,})+|npm_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20,})\b`),
		replacement: redactionMarker,
	},
}

func redactSensitiveText(value string) (string, bool) {
	redacted, changed := boundRedactionInput(value)
	if next, kubernetesChanged := redactKubernetesSecretData(redacted); kubernetesChanged {
		redacted = next
		changed = true
	}
	if next, powerShellChanged := redactPowerShellHereStringCredentials(redacted); powerShellChanged {
		redacted = next
		changed = true
	}
	if next, powerShellChanged := redactPowerShellCollectionCredentials(redacted); powerShellChanged {
		redacted = next
		changed = true
	}
	if next, commandPromptChanged := redactCommandPromptSetAssignments(redacted); commandPromptChanged {
		redacted = next
		changed = true
	}
	if next, curlConfigChanged := redactCurlConfigCertificatePasswords(redacted); curlConfigChanged {
		redacted = next
		changed = true
	}
	if next, secretChanged := redactSecretMarkedValues(redacted); secretChanged {
		redacted = next
		changed = true
	}
	if next, kubectlChanged := redactKubectlSecretLiterals(redacted); kubectlChanged {
		redacted = next
		changed = true
	}
	if next, netrcChanged := redactNetrcPasswords(redacted); netrcChanged {
		redacted = next
		changed = true
	}
	if next, queryChanged := redactEncodedQueryCredentialValues(redacted); queryChanged {
		redacted = next
		changed = true
	}
	if next, headerChanged := redactCompoundCurlHeaderWords(redacted); headerChanged {
		redacted = next
		changed = true
	}
	if next, plistChanged := redactPlistCredentialValues(redacted); plistChanged {
		redacted = next
		changed = true
	}
	if next, xmlChanged := redactXMLCredentialElements(redacted); xmlChanged {
		redacted = next
		changed = true
	}
	if next, xmlChanged := redactXMLCredentialAttributes(redacted); xmlChanged {
		redacted = next
		changed = true
	}
	redacted, yamlKeyRestorations := normalizeYAMLEscapedCredentialKeys(redacted)
	redacted, yamlAliasKeyRestorations := normalizeYAMLAliasCredentialKeys(redacted)
	if next, tomlValueChanged := redactTOMLCredentialValues(redacted); tomlValueChanged {
		redacted = next
		changed = true
	}
	if next, tomlChanged := redactTOMLMultilineCredentials(redacted); tomlChanged {
		redacted = next
		changed = true
	}
	if next, jsonKeyChanged := redactJSONEscapedCredentialValues(redacted); jsonKeyChanged {
		redacted = next
		changed = true
	}
	if next, jsonContextChanged := redactContextualJSONCredentialValues(redacted); jsonContextChanged {
		redacted = next
		changed = true
	}
	if next, cookieChanged := redactStructuredCookieValues(redacted); cookieChanged {
		redacted = next
		changed = true
	}
	if next, registryChanged := redactRegistryConfigurationAuthValues(redacted); registryChanged {
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
	if next, yamlAliasChanged := redactYAMLCredentialAliases(redacted); yamlAliasChanged {
		redacted = next
		changed = true
	}
	if next, yamlExplicitChanged := redactYAMLExplicitCredentialMappings(redacted); yamlExplicitChanged {
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
	if next, substitutionChanged := redactSensitiveCommandSubstitutions(redacted); substitutionChanged {
		redacted = next
		changed = true
	}
	if next, environmentChanged := redactBareEnvironmentDumpCredentials(redacted); environmentChanged {
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
	if next, authorizationChanged := redactHighConfidenceAuthorizationCredentials(redacted); authorizationChanged {
		redacted = next
		changed = true
	}
	if next, bearerChanged := redactStandaloneBearerCredentials(redacted); bearerChanged {
		redacted = next
		changed = true
	}
	if booleanMarkerProtection != "" {
		redacted = strings.ReplaceAll(redacted, booleanMarkerProtection, "")
	}
	for placeholder, original := range yamlKeyRestorations {
		redacted = strings.ReplaceAll(redacted, placeholder, original)
	}
	for placeholder, original := range yamlAliasKeyRestorations {
		redacted = strings.ReplaceAll(redacted, placeholder, original)
	}
	return redacted, changed
}

func redactKubernetesSecretData(value string) (string, bool) {
	redacted, changed := redactKubernetesSecretYAMLData(value)
	maxEscapeDepth := maxJSONEscapeDepthForLength(len(redacted))
	for escapeDepth := 0; escapeDepth <= maxEscapeDepth; escapeDepth++ {
		if next, jsonChanged := redactKubernetesSecretJSONData(redacted, escapeDepth); jsonChanged {
			redacted = next
			changed = true
		}
	}
	return redacted, changed
}

func redactKubernetesSecretYAMLData(value string) (string, bool) {
	value, flowChanged := redactKubernetesSecretYAMLFlowData(value)
	lines := strings.SplitAfter(value, "\n")
	secretIndent := -1
	containerIndent := -1
	blockIndent := -1
	secretActive := false
	scalarAnchors := make(map[string]string)
	anchorLocations := make(map[string]yamlAnchorLocation)
	changed := flowChanged

	resetSecret := func() {
		secretIndent = -1
		containerIndent = -1
		blockIndent = -1
		secretActive = false
	}
	resetDocument := func() {
		resetSecret()
		clear(scalarAnchors)
		clear(anchorLocations)
	}

	for line := 0; line < len(lines); line++ {
		content, ending := splitLineEnding(lines[line])
		trimmed := strings.TrimSpace(content)
		if trimmed == "---" || trimmed == "..." {
			resetDocument()
			continue
		}

		indent := leadingIndent(content)
		if blockIndent >= 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if indent > blockIndent {
				lines[line] = content[:indent] + redactionMarker + ending
				changed = true
				continue
			}
			blockIndent = -1
		}

		if flowStart := yamlFlowMapStart(content); flowStart >= 0 {
			close := findYAMLFlowEnd(content, flowStart)
			if close >= flowStart {
				flow, flowChanged := redactKubernetesSecretYAMLFlowObject(content[flowStart : close+1])
				if flowChanged {
					lines[line] = content[:flowStart] + flow + content[close+1:] + ending
					changed = true
					continue
				}
			}
		}

		if containerIndent >= 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if indent > containerIndent {
				if _, valueStart, ok := parseYAMLMappingLine(content); ok {
					if next, scalarChanged, blockScalar := redactKubernetesYAMLScalar(content, valueStart); scalarChanged {
						if alias := kubernetesYAMLScalar(content[valueStart:]); strings.HasPrefix(alias, "*") {
							location, exists := anchorLocations[strings.TrimPrefix(alias, "*")]
							if exists {
								redactKubernetesYAMLAnchorDefinition(lines, location)
							}
						}
						lines[line] = next + ending
						changed = true
						if blockScalar {
							blockIndent = indent
						} else if redactKubernetesYAMLScalarContinuations(lines, line, content, valueStart) {
							changed = true
						}
					}
				} else if isYAMLSequenceItemAtIndent(content, indent) {
					lines[line] = content[:indent] + "- " + redactionMarker + ending
					changed = true
				}
				continue
			}
			containerIndent = -1
		}

		key, valueStart, ok := parseYAMLMappingLine(content)
		if !ok {
			continue
		}
		value := strings.TrimSpace(content[valueStart:])
		keyIndent := yamlKeyIndent(content)
		if secretActive && keyIndent < secretIndent {
			resetSecret()
		}
		rawValue := content[valueStart:]
		if anchor := yamlAnchor.FindStringSubmatchIndex(rawValue); len(anchor) == 4 {
			anchorName := rawValue[anchor[2]:anchor[3]]
			anchorLocations[anchorName] = yamlAnchorLocation{
				line:      line,
				anchorEnd: valueStart + anchor[1],
			}
			if scalar := kubernetesYAMLScalar(value); scalar != "" && scalar != value {
				scalarAnchors[anchorName] = scalar
			}
		}
		if !secretActive && (strings.EqualFold(key, "data") || strings.EqualFold(key, "stringData")) && yamlSecretKindFollows(lines, line+1, keyIndent, scalarAnchors) {
			secretIndent = keyIndent
			secretActive = true
		}
		if strings.EqualFold(key, "kind") {
			kind := kubernetesYAMLScalar(value)
			if strings.HasPrefix(kind, "*") {
				kind = scalarAnchors[strings.TrimPrefix(kind, "*")]
			}
			if strings.EqualFold(kind, "Secret") {
				secretIndent = keyIndent
				secretActive = true
				containerIndent = -1
				blockIndent = -1
			} else if secretActive && keyIndent <= secretIndent {
				resetSecret()
			}
			continue
		}
		if !secretActive || keyIndent != secretIndent || !strings.EqualFold(key, "data") && !strings.EqualFold(key, "stringData") {
			continue
		}

		_, propertyOffset := trimYAMLNodeProperties(content[valueStart:])
		flowValueStart := valueStart + propertyOffset
		if flowValueStart < len(content) && content[flowValueStart] == '{' {
			close := findYAMLFlowEnd(content, flowValueStart)
			if close >= flowValueStart {
				originalFlow := content[flowValueStart : close+1]
				redactKubernetesYAMLAnchorAliases(lines, originalFlow, anchorLocations)
				flow, nestedFlowChanged := redactKubernetesSecretFlowMap(originalFlow)
				if nestedFlowChanged {
					lines[line] = content[:flowValueStart] + flow + content[close+1:] + ending
					changed = true
				}
				continue
			}

			remaining := strings.Join(lines[line:], "")
			close = findYAMLFlowEnd(remaining, flowValueStart)
			if close >= flowValueStart {
				originalFlow := remaining[flowValueStart : close+1]
				redactKubernetesYAMLAnchorAliases(lines, originalFlow, anchorLocations)
				flow, nestedFlowChanged := redactKubernetesSecretFlowMap(originalFlow)
				if nestedFlowChanged {
					updated := remaining[:flowValueStart] + flow + remaining[close+1:]
					lines = append(lines[:line], strings.SplitAfter(updated, "\n")...)
					changed = true
				}
				continue
			}

			lines[line] = content[:flowValueStart] + redactionMarker + ending
			blockIndent = keyIndent
			changed = true
			continue
		}
		if remainder, _ := trimYAMLNodeProperties(value); value != "" && (strings.TrimSpace(remainder) == "" || strings.HasPrefix(strings.TrimSpace(remainder), "#")) {
			containerIndent = keyIndent
			continue
		}
		if value != "" && !strings.HasPrefix(value, "#") {
			if value == redactionMarker || value == privateKeyRedactionMarker {
				continue
			}
			if alias := kubernetesYAMLScalar(value); strings.HasPrefix(alias, "*") {
				if location, exists := anchorLocations[strings.TrimPrefix(alias, "*")]; exists {
					redactKubernetesYAMLAnchorDefinition(lines, location)
				}
			}
			lines[line] = content[:valueStart] + redactionMarker + ending
			changed = true
			continue
		}
		containerIndent = keyIndent
	}
	return strings.Join(lines, ""), changed
}

func redactKubernetesYAMLAnchorAliases(lines []string, value string, locations map[string]yamlAnchorLocation) {
	for _, alias := range yamlValueAlias.FindAllStringSubmatch(value, -1) {
		if location, exists := locations[alias[1]]; exists {
			redactKubernetesYAMLAnchorDefinition(lines, location)
		}
	}
}

func redactKubernetesYAMLAnchorDefinition(lines []string, location yamlAnchorLocation) {
	if location.line < 0 || location.line >= len(lines) {
		return
	}
	content, ending := splitLineEnding(lines[location.line])
	cursor := location.anchorEnd
	for cursor < len(content) && (content[cursor] == ' ' || content[cursor] == '\t') {
		cursor++
	}
	if cursor >= len(content) || content[cursor] == '#' {
		prefix := content[:cursor]
		if prefix != "" && prefix[len(prefix)-1] != ' ' && prefix[len(prefix)-1] != '\t' {
			prefix += " "
		}
		lines[location.line] = prefix + redactionMarker + ending
		indent := leadingIndent(content)
		for line := location.line + 1; line < len(lines); line++ {
			nextContent, _ := splitLineEnding(lines[line])
			trimmed := strings.TrimSpace(nextContent)
			if trimmed != "" && leadingIndent(nextContent) <= indent {
				break
			}
			if trimmed != "" {
				lines[line] = ""
			}
		}
		return
	}
	if strings.HasPrefix(content[cursor:], redactionMarker) {
		return
	}
	redactKubernetesYAMLScalarContinuations(lines, location.line, content, cursor)
	lines[location.line] = content[:cursor] + redactionMarker + ending
}

func redactKubernetesYAMLScalarContinuations(lines []string, line int, content string, valueStart int) bool {
	value, _ := trimYAMLNodeProperties(content[valueStart:])
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
		return false
	}

	indent := leadingIndent(content)
	quote := byte(0)
	if value[0] == '\'' || value[0] == '"' {
		quote = value[0]
		if yamlQuotedScalarCloses(value[1:], quote) {
			return false
		}
	}

	changed := false
	for nextLine := line + 1; nextLine < len(lines); nextLine++ {
		nextContent, _ := splitLineEnding(lines[nextLine])
		trimmed := strings.TrimSpace(nextContent)
		if quote == 0 && trimmed != "" && leadingIndent(nextContent) <= indent {
			break
		}
		if quote != 0 && yamlQuotedScalarCloses(nextContent, quote) {
			lines[nextLine] = ""
			return true
		}
		if trimmed != "" {
			lines[nextLine] = ""
			changed = true
		}
	}
	return changed
}

func yamlQuotedScalarCloses(value string, quote byte) bool {
	for index := 0; index < len(value); index++ {
		if quote == '"' && value[index] == '\\' {
			index++
			continue
		}
		if value[index] != quote {
			continue
		}
		if quote == '\'' && index+1 < len(value) && value[index+1] == '\'' {
			index++
			continue
		}
		return true
	}
	return false
}

func parseYAMLMappingLine(content string) (string, int, bool) {
	cursor := leadingIndent(content)
	if cursor >= len(content) || content[cursor] == '#' {
		return "", 0, false
	}
	if content[cursor] == '-' {
		if cursor+1 >= len(content) || (content[cursor+1] != ' ' && content[cursor+1] != '\t') {
			return "", 0, false
		}
		cursor++
		for cursor < len(content) && (content[cursor] == ' ' || content[cursor] == '\t') {
			cursor++
		}
	}
	keyStart := cursor
	var quote byte
	for cursor < len(content) {
		switch content[cursor] {
		case '\'', '"':
			switch quote {
			case 0:
				quote = content[cursor]
			case content[cursor]:
				quote = 0
			}
		case ':':
			if quote == 0 {
				key := strings.TrimSpace(content[keyStart:cursor])
				key = strings.Trim(key, "\"'")
				if key == "" {
					return "", 0, false
				}
				valueStart := cursor + 1
				for valueStart < len(content) && (content[valueStart] == ' ' || content[valueStart] == '\t') {
					valueStart++
				}
				return key, valueStart, true
			}
		}
		cursor++
	}
	return "", 0, false
}

func kubernetesYAMLScalar(value string) string {
	value = strings.TrimSpace(value)
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	value, _ = trimYAMLNodeProperties(value)
	return strings.Trim(value, "\"'")
}

func trimYAMLNodeProperties(value string) (string, int) {
	offset := len(value) - len(strings.TrimLeft(value, " \t\r\n"))
	for offset < len(value) && (value[offset] == '!' || value[offset] == '&') {
		remaining := value[offset:]
		if strings.HasPrefix(remaining, "!<") {
			end := strings.IndexByte(remaining, '>')
			if end < 0 {
				break
			}
			offset += end + 1
		} else {
			end := strings.IndexAny(remaining, " \t\r\n")
			if end < 0 {
				return "", len(value)
			}
			offset += end
		}
		for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t' || value[offset] == '\r' || value[offset] == '\n') {
			offset++
		}
	}
	return value[offset:], offset
}

func redactKubernetesSecretYAMLFlowData(value string) (string, bool) {
	lower := strings.ToLower(value)
	if !strings.Contains(lower, "kind") || !strings.Contains(lower, "secret") ||
		!strings.Contains(lower, "data") && !strings.Contains(lower, "stringdata") {
		return value, false
	}
	redacted := value
	changed := false
	for lineStart := 0; lineStart < len(redacted); {
		lineEnd := len(redacted)
		if relativeEnd := strings.IndexByte(redacted[lineStart:], '\n'); relativeEnd >= 0 {
			lineEnd = lineStart + relativeEnd
		}
		relative := yamlFlowMapStart(redacted[lineStart:lineEnd])
		if relative < 0 {
			if lineEnd == len(redacted) {
				break
			}
			lineStart = lineEnd + 1
			continue
		}
		open := lineStart + relative
		close := findYAMLFlowEnd(redacted, open)
		if close < open {
			break
		}
		flow, flowChanged := redactKubernetesSecretYAMLFlowObject(redacted[open : close+1])
		if flowChanged {
			redacted = redacted[:open] + flow + redacted[close+1:]
			changed = true
			close = open + len(flow) - 1
		}
		nextLine := strings.IndexByte(redacted[close+1:], '\n')
		if nextLine < 0 {
			break
		}
		lineStart = close + 1 + nextLine + 1
	}
	return redacted, changed
}

func yamlSecretKindFollows(lines []string, start, secretIndent int, scalarAnchors map[string]string) bool {
	for line := start; line < len(lines); line++ {
		content, _ := splitLineEnding(lines[line])
		trimmed := strings.TrimSpace(content)
		if trimmed == "---" || trimmed == "..." {
			return false
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := leadingIndent(content)
		if indent < secretIndent || indent == secretIndent && indent < len(content) && content[indent] == '-' {
			return false
		}
		key, valueStart, ok := parseYAMLMappingLine(content)
		if !ok {
			continue
		}
		keyIndent := yamlKeyIndent(content)
		if keyIndent < secretIndent {
			return false
		}
		if keyIndent != secretIndent {
			continue
		}
		if strings.EqualFold(key, "kind") {
			kind := kubernetesYAMLScalar(content[valueStart:])
			if strings.HasPrefix(kind, "*") {
				kind = scalarAnchors[strings.TrimPrefix(kind, "*")]
			}
			return strings.EqualFold(kind, "Secret")
		}
	}
	return false
}

func yamlFlowMapStart(content string) int {
	start := leadingIndent(content)
	sequenceItem := false
	if start < len(content) && content[start] == '-' {
		if start+1 >= len(content) || (content[start+1] != ' ' && content[start+1] != '\t') {
			return -1
		}
		sequenceItem = true
		start++
		for start < len(content) && (content[start] == ' ' || content[start] == '\t') {
			start++
		}
	}
	if !sequenceItem && leadingIndent(content) != 0 {
		return -1
	}
	if start < len(content) && content[start] == '{' {
		return start
	}
	return -1
}

func redactKubernetesSecretYAMLFlowObject(flow string) (string, bool) {
	if len(flow) < 2 || flow[0] != '{' || flow[len(flow)-1] != '}' {
		return flow, false
	}
	type property struct {
		key             string
		valueStart      int
		trimmedValueEnd int
	}
	var properties []property
	for cursor := 1; cursor < len(flow)-1; {
		cursor = skipYAMLFlowSpaceAndComments(flow, cursor, len(flow)-1)
		if cursor >= len(flow)-1 {
			break
		}
		colon := findKubernetesFlowColon(flow, cursor)
		if colon < 0 {
			return flow, false
		}
		key := strings.TrimSpace(flow[cursor:colon])
		key = strings.Trim(key, "\"'")
		valueStart := colon + 1
		for valueStart < len(flow)-1 && (flow[valueStart] == ' ' || flow[valueStart] == '\t' || flow[valueStart] == '\r' || flow[valueStart] == '\n') {
			valueStart++
		}
		valueEnd := findKubernetesFlowValueEnd(flow, valueStart)
		if valueEnd < valueStart {
			return flow, false
		}
		trimmedEnd := valueEnd
		for trimmedEnd > valueStart && (flow[trimmedEnd-1] == ' ' || flow[trimmedEnd-1] == '\t' || flow[trimmedEnd-1] == '\r' || flow[trimmedEnd-1] == '\n') {
			trimmedEnd--
		}
		properties = append(properties, property{key: key, valueStart: valueStart, trimmedValueEnd: trimmedEnd})
		cursor = valueEnd
	}
	secret := false
	for _, property := range properties {
		if strings.EqualFold(property.key, "kind") && strings.EqualFold(kubernetesYAMLScalar(flow[property.valueStart:property.trimmedValueEnd]), "Secret") {
			secret = true
			break
		}
	}
	if !secret {
		return flow, false
	}
	type replacement struct {
		start, end int
		value      string
	}
	var replacements []replacement
	for _, property := range properties {
		if !strings.EqualFold(property.key, "data") && !strings.EqualFold(property.key, "stringData") || property.valueStart >= property.trimmedValueEnd {
			continue
		}
		if flow[property.valueStart] == '{' {
			child, childChanged := redactKubernetesSecretFlowMap(flow[property.valueStart:property.trimmedValueEnd])
			if childChanged {
				replacements = append(replacements, replacement{start: property.valueStart, end: property.trimmedValueEnd, value: child})
			}
			continue
		}
		if flow[property.valueStart:property.trimmedValueEnd] != redactionMarker {
			replacements = append(replacements, replacement{start: property.valueStart, end: property.trimmedValueEnd, value: redactionMarker})
		}
	}
	if len(replacements) == 0 {
		return flow, false
	}
	redacted := flow
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		redacted = redacted[:replacement.start] + replacement.value + redacted[replacement.end:]
	}
	return redacted, true
}

func skipYAMLFlowSpaceAndComments(value string, start, limit int) int {
	for start < limit {
		for start < limit && (value[start] == ' ' || value[start] == '\t' || value[start] == '\r' || value[start] == '\n' || value[start] == ',') {
			start++
		}
		if start >= limit || value[start] != '#' {
			return start
		}
		for start < limit && value[start] != '\r' && value[start] != '\n' {
			start++
		}
	}
	return start
}

func redactKubernetesYAMLScalar(content string, valueStart int) (string, bool, bool) {
	if valueStart >= len(content) {
		return content, false, false
	}
	value := strings.TrimSpace(content[valueStart:])
	if value == "" || strings.HasPrefix(value, "#") || value == redactionMarker {
		return content, false, false
	}
	blockScalar := strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">")
	return content[:valueStart] + redactionMarker, true, blockScalar
}

func redactKubernetesSecretFlowMap(flow string) (string, bool) {
	if len(flow) < 2 || flow[0] != '{' || flow[len(flow)-1] != '}' {
		return flow, false
	}
	type span struct{ start, end int }
	var replacements []span
	for cursor := 1; cursor < len(flow)-1; {
		for cursor < len(flow)-1 && (flow[cursor] == ' ' || flow[cursor] == '\t' || flow[cursor] == '\r' || flow[cursor] == '\n' || flow[cursor] == ',') {
			cursor++
		}
		if cursor >= len(flow)-1 {
			break
		}
		colon := findKubernetesFlowColon(flow, cursor)
		if colon < 0 {
			break
		}
		valueStart := colon + 1
		for valueStart < len(flow)-1 && (flow[valueStart] == ' ' || flow[valueStart] == '\t' || flow[valueStart] == '\r' || flow[valueStart] == '\n') {
			valueStart++
		}
		valueEnd := findKubernetesFlowValueEnd(flow, valueStart)
		if valueEnd < valueStart {
			break
		}
		trimmedEnd := valueEnd
		for trimmedEnd > valueStart && (flow[trimmedEnd-1] == ' ' || flow[trimmedEnd-1] == '\t' || flow[trimmedEnd-1] == '\r' || flow[trimmedEnd-1] == '\n') {
			trimmedEnd--
		}
		if trimmedEnd <= valueStart || flow[valueStart:trimmedEnd] == redactionMarker {
			cursor = valueEnd
			continue
		}
		replacementStart, replacementEnd := valueStart, trimmedEnd
		if trimmedEnd-valueStart >= 2 && (flow[valueStart] == '\'' || flow[valueStart] == '"') && flow[trimmedEnd-1] == flow[valueStart] {
			if flow[valueStart+1:trimmedEnd-1] == redactionMarker {
				cursor = valueEnd
				continue
			}
			replacementStart++
			replacementEnd--
		}
		replacements = append(replacements, span{start: replacementStart, end: replacementEnd})
		cursor = valueEnd
	}
	if len(replacements) == 0 {
		return flow, false
	}
	redacted := flow
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		redacted = redacted[:replacement.start] + redactionMarker + redacted[replacement.end:]
	}
	return redacted, true
}

func findKubernetesFlowColon(value string, start int) int {
	depth := 0
	var quote byte
	for index := start; index < len(value); index++ {
		if quote != 0 {
			if quote == '"' && value[index] == '\\' {
				index++
				continue
			}
			if quote == '\'' && value[index] == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				index++
				continue
			}
			if value[index] == quote {
				quote = 0
			}
			continue
		}
		switch value[index] {
		case '"', '\'':
			quote = value[index]
		case '[', '{':
			depth++
		case ']', '}':
			if depth == 0 {
				return -1
			}
			depth--
		case ':':
			if depth == 0 {
				return index
			}
		}
	}
	return -1
}

func findKubernetesFlowValueEnd(value string, start int) int {
	depth := 0
	var quote byte
	for index := start; index < len(value); index++ {
		if quote != 0 {
			if quote == '"' && value[index] == '\\' {
				index++
				continue
			}
			if quote == '\'' && value[index] == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				index++
				continue
			}
			if value[index] == quote {
				quote = 0
			}
			continue
		}
		switch value[index] {
		case '"', '\'':
			quote = value[index]
		case '[', '{':
			depth++
		case ']', '}':
			if depth == 0 {
				return index
			}
			depth--
		case ',':
			if depth == 0 {
				return index
			}
		}
	}
	return len(value) - 1
}

type kubernetesJSONProperty struct {
	key        string
	valueStart int
	valueEnd   int
}

func redactKubernetesSecretJSONData(value string, escapeDepth int) (string, bool) {
	if !containsJSONKeyAtDepth(value, "kind", escapeDepth) ||
		!containsJSONKeyAtDepth(value, "data", escapeDepth) && !containsJSONKeyAtDepth(value, "stringData", escapeDepth) {
		return value, false
	}
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		open := nextJSONObjectStart(redacted, searchStart, escapeDepth)
		if open < 0 {
			break
		}
		close := findJSONContainerEndAtDepth(redacted, open, escapeDepth)
		if close < open {
			break
		}
		object := redacted[open : close+1]
		redactedObject, objectChanged := redactKubernetesSecretJSONObject(object, escapeDepth)
		if objectChanged {
			redacted = redacted[:open] + redactedObject + redacted[close+1:]
			changed = true
		}
		searchStart = open + 1
	}
	return redacted, changed
}

func containsJSONKeyAtDepth(value, key string, escapeDepth int) bool {
	delimiter := jsonQuoteDelimiter(escapeDepth)
	for searchStart := 0; searchStart < len(value); {
		relative := strings.Index(value[searchStart:], delimiter)
		if relative < 0 {
			return false
		}
		open := searchStart + relative
		quote := open + len(delimiter) - 1
		if !isJSONStringDelimiterAtDepth(value, quote, escapeDepth) {
			searchStart = open + len(delimiter)
			continue
		}
		close := findJSONStringEndAtDepth(value, open, escapeDepth)
		if close < 0 {
			return false
		}
		cursor := close + 1
		for cursor < len(value) && (value[cursor] == ' ' || value[cursor] == '\t' || value[cursor] == '\r' || value[cursor] == '\n') {
			cursor++
		}
		decoded, valid := decodeJSONCredentialKey(value[open:close+1], escapeDepth)
		if valid && cursor < len(value) && value[cursor] == ':' && strings.EqualFold(decoded, key) {
			return true
		}
		searchStart = close + 1
	}
	return false
}

func nextJSONObjectStart(value string, start, escapeDepth int) int {
	inString := false
	for index := start; index < len(value); index++ {
		if value[index] == '"' && isJSONStringDelimiterAtDepth(value, index, escapeDepth) {
			inString = !inString
			continue
		}
		if !inString && value[index] == '{' {
			return index
		}
	}
	return -1
}

func redactKubernetesSecretJSONObject(object string, escapeDepth int) (string, bool) {
	properties := parseKubernetesJSONObject(object, escapeDepth)
	if len(properties) == 0 {
		return object, false
	}
	isSecret := false
	for _, property := range properties {
		if !strings.EqualFold(property.key, "kind") || property.valueStart >= len(object) || !strings.HasPrefix(object[property.valueStart:], jsonQuoteDelimiter(escapeDepth)) {
			continue
		}
		kind, valid := decodeJSONCredentialKey(object[property.valueStart:property.valueEnd], escapeDepth)
		if valid && strings.EqualFold(kind, "Secret") {
			isSecret = true
			break
		}
	}
	if !isSecret {
		return object, false
	}

	type replacement struct{ start, end int }
	var replacements []replacement
	quotedMarker := jsonQuoteDelimiter(escapeDepth) + redactionMarker + jsonQuoteDelimiter(escapeDepth)
	for _, property := range properties {
		if !strings.EqualFold(property.key, "data") && !strings.EqualFold(property.key, "stringData") || property.valueStart >= len(object) || object[property.valueStart] != '{' {
			continue
		}
		container := object[property.valueStart:property.valueEnd]
		containerProperties := parseKubernetesJSONObject(container, escapeDepth)
		for _, child := range containerProperties {
			if child.valueStart >= len(container) || container[child.valueStart:child.valueEnd] == quotedMarker {
				continue
			}
			replacements = append(replacements, replacement{
				start: property.valueStart + child.valueStart,
				end:   property.valueStart + child.valueEnd,
			})
		}
	}
	if len(replacements) == 0 {
		return object, false
	}
	redacted := object
	for index := len(replacements) - 1; index >= 0; index-- {
		span := replacements[index]
		redacted = redacted[:span.start] + quotedMarker + redacted[span.end:]
	}
	return redacted, true
}

func parseKubernetesJSONObject(object string, escapeDepth int) []kubernetesJSONProperty {
	if len(object) < 2 || object[0] != '{' {
		return nil
	}
	objectEnd := len(object)
	if object[len(object)-1] == '}' {
		objectEnd--
	}
	var properties []kubernetesJSONProperty
	for cursor := 1; cursor < objectEnd; {
		for cursor < objectEnd && (object[cursor] == ' ' || object[cursor] == '\t' || object[cursor] == '\r' || object[cursor] == '\n' || object[cursor] == ',') {
			cursor++
		}
		delimiter := jsonQuoteDelimiter(escapeDepth)
		if cursor >= objectEnd || !strings.HasPrefix(object[cursor:], delimiter) || !isJSONStringDelimiterAtDepth(object, cursor+len(delimiter)-1, escapeDepth) {
			return properties
		}
		keyEnd := findJSONStringEndAtDepth(object, cursor, escapeDepth)
		if keyEnd < 0 {
			return properties
		}
		key, valid := decodeJSONCredentialKey(object[cursor:keyEnd+1], escapeDepth)
		if !valid {
			return properties
		}
		valueStart := keyEnd + 1
		for valueStart < len(object) && (object[valueStart] == ' ' || object[valueStart] == '\t' || object[valueStart] == '\r' || object[valueStart] == '\n') {
			valueStart++
		}
		if valueStart >= len(object) || object[valueStart] != ':' {
			return properties
		}
		valueStart++
		for valueStart < len(object) && (object[valueStart] == ' ' || object[valueStart] == '\t' || object[valueStart] == '\r' || object[valueStart] == '\n') {
			valueStart++
		}
		valueEnd := jsonKubernetesPropertyValueEnd(object, valueStart, escapeDepth)
		if valueEnd <= valueStart {
			return properties
		}
		properties = append(properties, kubernetesJSONProperty{key: key, valueStart: valueStart, valueEnd: valueEnd})
		cursor = valueEnd
	}
	return properties
}

func jsonKubernetesPropertyValueEnd(object string, start, escapeDepth int) int {
	end, _ := jsonCredentialValueReplacement(object, start, escapeDepth)
	return end
}

func redactBareEnvironmentDumpCredentials(value string) (string, bool) {
	matches := bareEnvironmentDumpCredential.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value, false
	}

	var redacted strings.Builder
	redacted.Grow(len(value))
	last := 0
	changed := false
	for _, match := range matches {
		valueStart, valueEnd := match[4], match[5]
		words := strings.Fields(value[valueStart:valueEnd])
		// A leading assignment followed by asc is a shell command invocation,
		// not an environment dump. The shell-word pass below redacts only the
		// assignment value and preserves that useful command context.
		if len(words) > 1 && (words[1] == "asc" || shellAssignmentWord.MatchString(words[1])) {
			continue
		}

		redacted.WriteString(value[last:valueStart])
		redacted.WriteString(redactionMarker)
		last = valueEnd
		changed = true
	}
	if !changed {
		return value, false
	}
	redacted.WriteString(value[last:])
	return redacted.String(), true
}

// boundRedactionInput limits parser work before any redaction pass runs. It
// omits an oversized field in full so a multiline credential that crosses the
// byte boundary cannot leave part of its value in a report.
func boundRedactionInput(value string) (string, bool) {
	if len(value) <= maxRedactionFieldBytes {
		return value, false
	}
	return oversizedFieldMarker, true
}

func redactPowerShellHereStringCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := powerShellHereStringCredential.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		open := searchStart + match[2]
		contentStart := searchStart + match[3]
		quote := redacted[open+1]
		end := findPowerShellHereStringEnd(redacted, contentStart, quote)
		if end < 0 {
			end = len(redacted)
		}
		redacted = redacted[:open] + redactionMarker + redacted[end:]
		changed = true
		searchStart = open + len(redactionMarker)
	}
	return redacted, changed
}

func findPowerShellHereStringEnd(value string, contentStart int, quote byte) int {
	for lineStart := contentStart; lineStart < len(value); {
		marker := lineStart
		for marker < len(value) && (value[marker] == ' ' || value[marker] == '\t') {
			marker++
		}
		if marker+1 < len(value) && value[marker] == quote && value[marker+1] == '@' &&
			(marker+2 == len(value) || strings.ContainsRune(" \t\r\n;&|)", rune(value[marker+2]))) {
			return marker + 2
		}
		lineBreak := strings.IndexByte(value[lineStart:], '\n')
		if lineBreak < 0 {
			break
		}
		lineStart += lineBreak + 1
	}
	return -1
}

func redactPowerShellCollectionCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := powerShellCollectionCredential.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		open := searchStart + match[2]
		end := findPowerShellCollectionEnd(redacted, open)
		if end < 0 {
			end = len(redacted)
		}
		redacted = redacted[:open] + redactionMarker + redacted[end:]
		changed = true
		searchStart = open + len(redactionMarker)
	}
	return redacted, changed
}

func findPowerShellCollectionEnd(value string, open int) int {
	if open < 0 || open+1 >= len(value) || value[open] != '@' ||
		(value[open+1] != '(' && value[open+1] != '{') {
		return -1
	}

	stack := []byte{value[open+1]}
	var quote byte
	for index := open + 2; index < len(value); index++ {
		if quote != 0 {
			if quote == '"' && value[index] == '`' {
				index++
				continue
			}
			if value[index] != quote {
				continue
			}
			if quote == '\'' && index+1 < len(value) && value[index+1] == '\'' {
				index++
				continue
			}
			quote = 0
			continue
		}
		if value[index] == '`' {
			index++
			continue
		}

		switch value[index] {
		case '\'', '"':
			quote = value[index]
		case '(', '{', '[':
			stack = append(stack, value[index])
		case ')', '}', ']':
			if !powerShellDelimitersMatch(stack[len(stack)-1], value[index]) {
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return index + 1
			}
		}
	}
	return -1
}

func powerShellDelimitersMatch(open, close byte) bool {
	return open == '(' && close == ')' || open == '{' && close == '}' || open == '[' && close == ']'
}

func redactCommandPromptSetAssignments(value string) (string, bool) {
	redacted, changed := redactCommandPromptSetAssignmentValues(value, commandPromptQuotedSetAssignment, findCommandPromptQuotedSetValueEnd)
	if next, unquotedChanged := redactCommandPromptSetAssignmentValues(redacted, commandPromptUnquotedSetAssignment, findCommandPromptUnquotedSetValueEnd); unquotedChanged {
		redacted = next
		changed = true
	}
	return redacted, changed
}

func redactCommandPromptSetAssignmentValues(value string, pattern *regexp.Regexp, findValueEnd func(string, int) int) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := pattern.FindStringIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		valueStart := searchStart + match[1]
		valueEnd := findValueEnd(redacted, valueStart)
		currentValue := redacted[valueStart:valueEnd]
		if currentValue == "" || currentValue == redactionMarker || currentValue == privateKeyRedactionMarker {
			searchStart = valueEnd + 1
			continue
		}
		redacted = redacted[:valueStart] + redactionMarker + redacted[valueEnd:]
		changed = true
		searchStart = valueStart + len(redactionMarker)
	}
	return redacted, changed
}

func findCommandPromptQuotedSetValueEnd(value string, start int) int {
	for index := start; index < len(value); index++ {
		switch value[index] {
		case '^':
			if index+2 < len(value) && value[index+1] == '\r' && value[index+2] == '\n' {
				index += 2
			} else if index+1 < len(value) {
				index++
			}
		case '"', '\r', '\n':
			return index
		}
	}
	return len(value)
}

func findCommandPromptUnquotedSetValueEnd(value string, start int) int {
	inQuotes := false
	for index := start; index < len(value); index++ {
		switch value[index] {
		case '^':
			if index+2 < len(value) && value[index+1] == '\r' && value[index+2] == '\n' {
				index += 2
			} else if index+1 < len(value) {
				index++
			}
		case '"':
			inQuotes = !inQuotes
		case '&', '|', '<', '>', '(', ')', '\r', '\n':
			if !inQuotes {
				for index > start && (value[index-1] == ' ' || value[index-1] == '\t') {
					index--
				}
				return index
			}
		}
	}
	return len(value)
}

func redactCurlConfigCertificatePasswords(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := curlConfigCertificateEntry.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		valueStart := searchStart + match[1]
		lineEnd := valueStart + strings.IndexAny(redacted[valueStart:], "\r\n")
		if lineEnd < valueStart {
			lineEnd = len(redacted)
		}
		contentStart, contentEnd := curlConfigValueBounds(redacted, valueStart, lineEnd)
		separator := curlCertificatePasswordSeparator(redacted[contentStart:contentEnd])
		if separator < 0 {
			searchStart = lineEnd + 1
			continue
		}

		passwordStart := contentStart + separator + 1
		if passwordStart == contentEnd || redacted[passwordStart:contentEnd] == redactionMarker {
			searchStart = lineEnd + 1
			continue
		}
		redacted = redacted[:passwordStart] + redactionMarker + redacted[contentEnd:]
		changed = true
		searchStart = passwordStart + len(redactionMarker)
	}
	return redacted, changed
}

func curlConfigValueBounds(value string, start, lineEnd int) (int, int) {
	if start >= lineEnd || (value[start] != '"' && value[start] != '\'') {
		end := start
		for end < lineEnd && value[end] != ' ' && value[end] != '\t' {
			end++
		}
		return start, end
	}

	quote := value[start]
	for index := start + 1; index < lineEnd; index++ {
		if value[index] == '\\' && index+1 < lineEnd {
			index++
			continue
		}
		if value[index] == quote {
			return start + 1, index
		}
	}
	return start + 1, lineEnd
}

func curlCertificatePasswordSeparator(value string) int {
	searchStart := 0
	if len(value) >= 3 && isASCIIAlpha(value[0]) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		searchStart = 3
	}
	for index := searchStart; index < len(value); index++ {
		if value[index] == '\\' && index+1 < len(value) {
			index++
			continue
		}
		if value[index] == ':' {
			return index
		}
	}
	return -1
}

func isASCIIAlpha(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

func redactNetrcPasswords(value string) (string, bool) {
	redacted := value
	entries := netrcEntryStart.FindAllStringIndex(redacted, -1)
	changed := false
	for index := len(entries) - 1; index >= 0; index-- {
		start := entries[index][0]
		end := len(redacted)
		if index+1 < len(entries) {
			end = entries[index+1][0]
		}
		entry := redacted[start:end]
		next := netrcPasswordValue.ReplaceAllString(entry, `${1}${2}`+redactionMarker+`${3}`)
		if next == entry {
			continue
		}
		redacted = redacted[:start] + next + redacted[end:]
		changed = true
	}
	return redacted, changed
}

func redactEncodedQueryCredentialValues(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := queryParameterName.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		nameStart := searchStart + match[2]
		nameEnd := searchStart + match[3]
		valueStart := searchStart + match[1]
		searchStart = valueStart
		encodedName := redacted[nameStart:nameEnd]
		if !strings.Contains(encodedName, "%") {
			continue
		}
		decodedName, err := url.QueryUnescape(encodedName)
		if err != nil || !queryCredentialNamePattern.MatchString(decodedName) {
			continue
		}

		valueEnd := valueStart
		for valueEnd < len(redacted) && !isQueryValueTerminator(redacted[valueEnd]) {
			valueEnd++
		}
		if valueEnd == valueStart || redacted[valueStart:valueEnd] == redactionMarker {
			continue
		}

		redacted = redacted[:valueStart] + redactionMarker + redacted[valueEnd:]
		changed = true
		searchStart = valueStart + len(redactionMarker)
	}
	return redacted, changed
}

func isQueryValueTerminator(character byte) bool {
	switch character {
	case '&', '#', ' ', '\t', '\r', '\n', '\f', '\v', '"', '\'', '<', '>':
		return true
	default:
		return false
	}
}

func redactCompoundCurlHeaderWords(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		option := curlHeaderOptionStart.FindStringSubmatchIndex(redacted[searchStart:])
		if option == nil {
			break
		}

		valueStart := searchStart + option[1]
		wordMatch := completeShellWord.FindStringSubmatchIndex(redacted[valueStart:])
		if wordMatch == nil {
			searchStart = valueStart
			continue
		}
		wordEnd := valueStart + wordMatch[3]
		word := redacted[valueStart:wordEnd]
		headerName, valid := decodeShellHeaderName(word)
		assignmentHeader := valid && sensitiveAssignmentHeaderName.MatchString(headerName)
		if !valid || (!credentialHeaderNamePattern.MatchString(headerName) && !assignmentHeader) {
			searchStart = wordEnd
			continue
		}
		if !assignmentHeader && !isCompoundQuotedShellWord(word) {
			searchStart = wordEnd
			continue
		}

		replacement := `"` + headerName + `: ` + redactionMarker + `"`
		if word == replacement {
			searchStart = wordEnd
			continue
		}
		redacted = redacted[:valueStart] + replacement + redacted[wordEnd:]
		changed = true
		searchStart = valueStart + len(replacement)
	}
	return redacted, changed
}

func isCompoundQuotedShellWord(word string) bool {
	if word == "" || !strings.ContainsAny(word, `"'`) {
		return false
	}
	if word[0] != '\'' && word[0] != '"' {
		return true
	}

	quote := word[0]
	for index := 1; index < len(word); index++ {
		if quote == '"' && (word[index] == '\\' || word[index] == '`') {
			index++
			continue
		}
		if word[index] == quote {
			return index != len(word)-1
		}
	}
	return false
}

func decodeShellHeaderName(word string) (string, bool) {
	var decoded strings.Builder
	var quote byte
	for index := 0; index < len(word); index++ {
		character := word[index]
		if quote != 0 {
			if character == quote {
				quote = 0
				continue
			}
			if quote != '"' || (character != '\\' && character != '`') {
				if character == ':' {
					return decoded.String(), decoded.Len() > 0
				}
				decoded.WriteByte(character)
				continue
			}
		} else {
			switch character {
			case '\'', '"':
				quote = character
				continue
			case ':':
				return decoded.String(), decoded.Len() > 0
			case '$', '(', ')':
				return "", false
			case '\\', '`', '^':
			default:
				decoded.WriteByte(character)
				continue
			}
		}

		index++
		if index >= len(word) {
			return "", false
		}
		if word[index] == '\r' && index+1 < len(word) && word[index+1] == '\n' {
			index++
			continue
		}
		if word[index] != '\n' {
			decoded.WriteByte(word[index])
		}
	}
	return "", false
}

func redactPlistCredentialValues(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		relativeKey := strings.Index(redacted[searchStart:], "<key")
		if relativeKey < 0 {
			break
		}
		keyStart := searchStart + relativeKey
		contentStart, contentEnd, elementEnd, valid := findPlistCredentialValue(redacted, keyStart)
		if !valid || contentStart == contentEnd || redacted[contentStart:contentEnd] == redactionMarker {
			searchStart = keyStart + len("<key")
			continue
		}

		redacted = redacted[:contentStart] + redactionMarker + redacted[contentEnd:]
		changed = true
		searchStart = elementEnd - (contentEnd - contentStart) + len(redactionMarker)
	}
	return redacted, changed
}

func redactXMLCredentialElements(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := xmlCredentialElementStart.FindStringIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		elementStart := searchStart + match[0]
		decoder := xml.NewDecoder(strings.NewReader(redacted[elementStart:]))
		first, err := decoder.Token()
		element, validElement := first.(xml.StartElement)
		if err != nil || !validElement || !tomlCredentialName.MatchString(element.Name.Local) {
			searchStart = elementStart + 1
			continue
		}

		contentStart := elementStart + int(decoder.InputOffset())
		_, contentEnd, elementEnd, valid := findPlistElementEnd(decoder, elementStart, contentStart)
		if !valid {
			searchStart = elementStart + 1
			continue
		}
		if next, attributeChanged, delta := redactXMLElementValueAttribute(redacted, elementStart, contentStart, element); attributeChanged {
			redacted = next
			contentStart += delta
			contentEnd += delta
			elementEnd += delta
			changed = true
		}
		if contentStart == contentEnd || redacted[contentStart:contentEnd] == redactionMarker {
			searchStart = elementEnd
			continue
		}

		redacted = redacted[:contentStart] + redactionMarker + redacted[contentEnd:]
		changed = true
		searchStart = elementEnd - (contentEnd - contentStart) + len(redactionMarker)
	}
	return redacted, changed
}

func redactXMLElementValueAttribute(value string, elementStart, elementEnd int, element xml.StartElement) (string, bool, int) {
	attributeMatches := xmlAttribute.FindAllStringSubmatchIndex(value[elementStart:elementEnd], -1)
	if len(attributeMatches) != len(element.Attr) {
		return value, false, 0
	}
	for index, attribute := range element.Attr {
		if !strings.EqualFold(attribute.Name.Local, "value") {
			continue
		}
		attributeMatch := attributeMatches[index]
		valueStart, valueEnd := attributeMatch[4], attributeMatch[5]
		if valueStart < 0 {
			valueStart, valueEnd = attributeMatch[6], attributeMatch[7]
		}
		if valueStart < 0 || valueEnd < valueStart {
			return value, false, 0
		}
		valueStart += elementStart
		valueEnd += elementStart
		if value[valueStart:valueEnd] == "" || value[valueStart:valueEnd] == redactionMarker {
			return value, false, 0
		}
		return value[:valueStart] + redactionMarker + value[valueEnd:], true, len(redactionMarker) - (valueEnd - valueStart)
	}
	return value, false, 0
}

func redactXMLCredentialAttributes(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := xmlElementStart.FindStringIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		elementStart := searchStart + match[0]
		decoder := xml.NewDecoder(strings.NewReader(redacted[elementStart:]))
		first, err := decoder.Token()
		element, validElement := first.(xml.StartElement)
		if err != nil || !validElement {
			searchStart = elementStart + 1
			continue
		}

		elementEnd := elementStart + int(decoder.InputOffset())
		attributeMatches := xmlAttribute.FindAllStringSubmatchIndex(redacted[elementStart:elementEnd], -1)
		if len(attributeMatches) != len(element.Attr) {
			searchStart = elementEnd
			continue
		}

		sensitiveKey := false
		valueAttribute := -1
		for index, attribute := range element.Attr {
			switch strings.ToLower(attribute.Name.Local) {
			case "key", "name":
				if tomlCredentialName.MatchString(attribute.Value) {
					sensitiveKey = true
				}
			case "value":
				valueAttribute = index
			}
		}
		if !sensitiveKey || valueAttribute < 0 {
			searchStart = elementEnd
			continue
		}

		attributeMatch := attributeMatches[valueAttribute]
		valueStart, valueEnd := attributeMatch[4], attributeMatch[5]
		if valueStart < 0 {
			valueStart, valueEnd = attributeMatch[6], attributeMatch[7]
		}
		valueStart += elementStart
		valueEnd += elementStart
		if redacted[valueStart:valueEnd] == redactionMarker {
			searchStart = elementEnd
			continue
		}

		redacted = redacted[:valueStart] + redactionMarker + redacted[valueEnd:]
		changed = true
		searchStart = elementEnd - (valueEnd - valueStart) + len(redactionMarker)
	}
	return redacted, changed
}

func redactHighConfidenceAuthorizationCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := authorizationHeaderValueStart.FindStringIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		headerStart := searchStart + match[0]
		valueStart := searchStart + match[1]
		lineEnd := valueStart
		for lineEnd < len(redacted) && redacted[lineEnd] != '\r' && redacted[lineEnd] != '\n' {
			lineEnd++
		}
		line := redacted[valueStart:lineEnd]
		if strings.HasPrefix(line, redactionMarker) {
			searchStart = lineEnd
			continue
		}
		firstEnd := strings.IndexAny(line, " \t")
		if firstEnd < 0 {
			firstEnd = len(line)
		}
		scheme := line[:firstEnd]
		credential := scheme
		credentialEnd := firstEnd
		nextStart := firstEnd
		for nextStart < len(line) && (line[nextStart] == ' ' || line[nextStart] == '\t') {
			nextStart++
		}
		if nextStart < len(line) {
			nextEnd := nextStart
			for nextEnd < len(line) && line[nextEnd] != ' ' && line[nextEnd] != '\t' {
				nextEnd++
			}
			credential = line[nextStart:nextEnd]
			credentialEnd = nextEnd
		}

		if !isCredentialSpecificAuthorizationScheme(scheme) && !looksLikeAuthorizationCredential(credential) {
			searchStart = lineEnd
			continue
		}

		redacted = redacted[:headerStart] + "Authorization: " + redactionMarker + redacted[valueStart+credentialEnd:]
		changed = true
		searchStart = headerStart + len("Authorization: ") + len(redactionMarker)
	}
	return redacted, changed
}

func isCredentialSpecificAuthorizationScheme(value string) bool {
	switch strings.ToLower(value) {
	case "apikey", "api-key":
		return true
	default:
		return false
	}
}

func looksLikeAuthorizationCredential(value string) bool {
	if len(value) < 8 || value == redactionMarker {
		return false
	}
	return strings.ContainsAny(value, "0123456789._~+/=-")
}

func redactStandaloneBearerCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := standaloneBearerCandidate.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		tokenStart := searchStart + match[2]
		tokenEnd := searchStart + match[3]
		token := redacted[tokenStart:tokenEnd]
		if len(token) < 8 || !strings.ContainsAny(token, "0123456789") || isBenignBearerProtocol(token) {
			searchStart = tokenEnd
			continue
		}

		redacted = redacted[:tokenStart] + redactionMarker + redacted[tokenEnd:]
		changed = true
		searchStart = tokenStart + len(redactionMarker)
	}
	return redacted, changed
}

func isBenignBearerProtocol(value string) bool {
	lower := strings.ToLower(value)
	switch lower {
	case "oauth2", "oauth2.0", "http2", "http2.0", "rfc6750":
		return true
	}
	if !strings.HasPrefix(lower, "oauth2.") {
		return false
	}
	suffix := strings.TrimPrefix(lower, "oauth2.")
	if suffix == "0-beta" {
		return true
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return false
		}
	}
	return suffix != ""
}

func findPlistCredentialValue(value string, keyStart int) (int, int, int, bool) {
	decoder := xml.NewDecoder(strings.NewReader(value[keyStart:]))
	first, err := decoder.Token()
	keyElement, validKeyElement := first.(xml.StartElement)
	if err != nil || !validKeyElement || keyElement.Name.Local != "key" {
		return 0, 0, 0, false
	}

	var keyText strings.Builder
	for {
		token, tokenErr := decoder.Token()
		if tokenErr != nil {
			return 0, 0, 0, false
		}
		switch typed := token.(type) {
		case xml.CharData:
			keyText.Write(typed)
		case xml.Comment, xml.ProcInst, xml.Directive:
		case xml.EndElement:
			if typed.Name != keyElement.Name {
				return 0, 0, 0, false
			}
			if !tomlCredentialName.MatchString(strings.TrimSpace(keyText.String())) {
				return 0, 0, 0, false
			}
			goto findValue
		default:
			return 0, 0, 0, false
		}
	}

findValue:
	for {
		token, tokenErr := decoder.Token()
		if tokenErr != nil {
			return 0, 0, 0, false
		}
		switch typed := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(typed)) != "" {
				return 0, 0, 0, false
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		case xml.StartElement:
			contentStart := keyStart + int(decoder.InputOffset())
			return findPlistElementEnd(decoder, keyStart, contentStart)
		default:
			return 0, 0, 0, false
		}
	}
}

func findPlistElementEnd(decoder *xml.Decoder, offsetBase, contentStart int) (int, int, int, bool) {
	for depth := 1; depth > 0; {
		tokenStart := offsetBase + int(decoder.InputOffset())
		token, tokenErr := decoder.Token()
		if tokenErr != nil {
			if isTruncatedXML(tokenErr) {
				contentEnd := offsetBase + int(decoder.InputOffset())
				return contentStart, contentEnd, contentEnd, true
			}
			return 0, 0, 0, false
		}
		switch token.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				return contentStart, tokenStart, offsetBase + int(decoder.InputOffset()), true
			}
		}
	}
	return 0, 0, 0, false
}

func isTruncatedXML(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var syntaxError *xml.SyntaxError
	return errors.As(err, &syntaxError) && strings.EqualFold(syntaxError.Msg, "unexpected EOF")
}

func redactTOMLCredentialValues(value string) (string, bool) {
	redacted := value
	changed := false
	tableSensitive := false
	for lineStart := 0; lineStart < len(redacted); {
		if sensitive, header := parseTOMLTableHeader(redacted, lineStart); header {
			tableSensitive = sensitive
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}

		keyStart := lineStart
		for keyStart < len(redacted) && (redacted[keyStart] == ' ' || redacted[keyStart] == '\t') {
			keyStart++
		}
		keyEnd, sensitiveKey, validKey := parseTOMLKeyPath(redacted, keyStart)
		sensitiveKey = sensitiveKey || tableSensitive
		if !validKey {
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}

		equals := keyEnd
		for equals < len(redacted) && (redacted[equals] == ' ' || redacted[equals] == '\t') {
			equals++
		}
		if equals >= len(redacted) || redacted[equals] != '=' || !sensitiveKey {
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}

		valueStart := equals + 1
		for valueStart < len(redacted) && (redacted[valueStart] == ' ' || redacted[valueStart] == '\t') {
			valueStart++
		}
		if valueStart >= len(redacted) || redacted[valueStart] == '\r' || redacted[valueStart] == '\n' {
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}
		compositeValue := redacted[valueStart] == '{' || redacted[valueStart] == '['
		structuredKey := strings.ContainsAny(redacted[keyStart:keyEnd], `.\`)
		if !compositeValue && !structuredKey && !tableSensitive {
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}
		valueEnd := findTOMLValueEnd(redacted, valueStart)
		if valueEnd <= valueStart {
			lineStart = nextTOMLLineStart(redacted, lineStart)
			continue
		}
		if redacted[valueStart:valueEnd] != redactionMarker {
			redacted = redacted[:valueStart] + redactionMarker + redacted[valueEnd:]
			changed = true
		}
		lineStart = nextTOMLLineStart(redacted, valueStart+len(redactionMarker))
	}
	return redacted, changed
}

func parseTOMLTableHeader(value string, lineStart int) (bool, bool) {
	if lineStart < 0 || lineStart >= len(value) {
		return false, false
	}
	lineEnd := lineStart + strings.IndexByte(value[lineStart:], '\n')
	if lineEnd < lineStart {
		lineEnd = len(value)
	}
	start := lineStart
	for start < lineEnd && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	arrayTable := strings.HasPrefix(value[start:lineEnd], "[[")
	if !arrayTable && (start >= lineEnd || value[start] != '[') {
		return false, false
	}
	keyStart := start + 1
	if arrayTable {
		keyStart++
	}
	keyEnd, sensitive, valid := parseTOMLKeyPath(value, keyStart)
	if !valid {
		return false, false
	}
	close := "]"
	if arrayTable {
		close = "]]"
	}
	rest := strings.TrimSpace(value[keyEnd:lineEnd])
	if !strings.HasPrefix(rest, close) {
		return false, false
	}
	if trailing := strings.TrimSpace(rest[len(close):]); trailing != "" && !strings.HasPrefix(trailing, "#") {
		return false, false
	}
	return sensitive, true
}

func parseTOMLKeyPath(value string, start int) (int, bool, bool) {
	component, componentEnd, valid := parseTOMLKey(value, start)
	if !valid {
		return start, false, false
	}
	sensitive := tomlCredentialName.MatchString(component)
	for {
		dot := componentEnd
		for dot < len(value) && (value[dot] == ' ' || value[dot] == '\t') {
			dot++
		}
		if dot >= len(value) || value[dot] != '.' {
			return componentEnd, sensitive, true
		}

		next := dot + 1
		for next < len(value) && (value[next] == ' ' || value[next] == '\t') {
			next++
		}
		component, componentEnd, valid = parseTOMLKey(value, next)
		if !valid {
			return start, false, false
		}
		sensitive = sensitive || tomlCredentialName.MatchString(component)
	}
}

func parseTOMLKey(value string, start int) (string, int, bool) {
	if start < 0 || start >= len(value) {
		return "", start, false
	}
	switch value[start] {
	case '"':
		end := findTOMLQuotedStringEnd(value, start, '"')
		if end <= start {
			return "", start, false
		}
		key, err := strconv.Unquote(value[start:end])
		return key, end, err == nil
	case '\'':
		end := findTOMLQuotedStringEnd(value, start, '\'')
		if end <= start+1 || end > len(value) || value[end-1] != '\'' {
			return "", start, false
		}
		return value[start+1 : end-1], end, true
	default:
		end := start
		for end < len(value) && isTOMLBareKeyCharacter(value[end]) {
			end++
		}
		if end == start {
			return "", start, false
		}
		return value[start:end], end, true
	}
}

func isTOMLBareKeyCharacter(character byte) bool {
	return character == '_' || character == '-' || character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func nextTOMLLineStart(value string, start int) int {
	if start < 0 || start >= len(value) {
		return len(value)
	}
	newline := strings.IndexByte(value[start:], '\n')
	if newline < 0 {
		return len(value)
	}
	return start + newline + 1
}

func findTOMLValueEnd(value string, start int) int {
	if strings.HasPrefix(value[start:], `"""`) || strings.HasPrefix(value[start:], `'''`) {
		end := findTOMLMultilineStringEnd(value, start)
		if end < 0 {
			return len(value)
		}
		return end + 1
	}
	switch value[start] {
	case '"', '\'':
		return findTOMLQuotedStringEnd(value, start, value[start])
	case '{', '[':
		return findTOMLCompositeEnd(value, start)
	default:
		end := start
		for end < len(value) && value[end] != '#' && value[end] != '\r' && value[end] != '\n' {
			end++
		}
		for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
			end--
		}
		return end
	}
}

func findTOMLQuotedStringEnd(value string, start int, quote byte) int {
	for index := start + 1; index < len(value); index++ {
		if value[index] == '\r' || value[index] == '\n' {
			return index
		}
		if quote == '"' && value[index] == '\\' {
			index++
			continue
		}
		if value[index] == quote {
			return index + 1
		}
	}
	return len(value)
}

func findTOMLCompositeEnd(value string, start int) int {
	stack := make([]byte, 0, 4)
	stringDelimiter := ""
	for index := start; index < len(value); {
		if stringDelimiter != "" {
			if stringDelimiter[0] == '"' && value[index] == '\\' {
				index += 2
				continue
			}
			if strings.HasPrefix(value[index:], stringDelimiter) {
				index += len(stringDelimiter)
				stringDelimiter = ""
				continue
			}
			index++
			continue
		}

		if value[index] == '#' {
			for index < len(value) && value[index] != '\n' {
				index++
			}
			continue
		}
		if strings.HasPrefix(value[index:], `"""`) || strings.HasPrefix(value[index:], `'''`) {
			stringDelimiter = value[index : index+3]
			index += 3
			continue
		}
		switch value[index] {
		case '"', '\'':
			stringDelimiter = value[index : index+1]
			index++
		case '{', '[':
			stack = append(stack, value[index])
			index++
		case '}':
			if len(stack) > 0 && stack[len(stack)-1] == '{' {
				stack = stack[:len(stack)-1]
			}
			index++
			if len(stack) == 0 {
				return index
			}
		case ']':
			if len(stack) > 0 && stack[len(stack)-1] == '[' {
				stack = stack[:len(stack)-1]
			}
			index++
			if len(stack) == 0 {
				return index
			}
		default:
			index++
		}
	}
	return len(value)
}

func redactTOMLMultilineCredentials(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := tomlMultilineCredentialStart.FindStringIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		open := searchStart + match[1] - 3
		close := findTOMLMultilineStringEnd(redacted, open)
		if close < 0 {
			close = len(redacted) - 1
		}
		redacted = redacted[:open] + redactionMarker + redacted[close+1:]
		changed = true
		searchStart = open + len(redactionMarker)
	}
	return redacted, changed
}

func findTOMLMultilineStringEnd(value string, open int) int {
	if open < 0 || open+3 > len(value) {
		return -1
	}
	delimiter := value[open : open+3]
	if delimiter != `"""` && delimiter != `'''` {
		return -1
	}

	for index := open + 3; index+3 <= len(value); index++ {
		if delimiter == `"""` && value[index] == '\\' {
			index++
			continue
		}
		if value[index:index+3] == delimiter {
			return index + 2
		}
	}
	return -1
}

func redactJSONEscapedCredentialValues(value string) (string, bool) {
	redacted := value
	changed := false
	maxEscapeDepth := maxJSONEscapeDepthForLength(len(value))
	for escapeDepth := 0; escapeDepth <= maxEscapeDepth; escapeDepth++ {
		if next, layerChanged := redactJSONCredentialValues(redacted, escapeDepth); layerChanged {
			redacted = next
			changed = true
		}
	}
	return redacted, changed
}

func maxJSONEscapeDepthForLength(length int) int {
	maxDepth := 0
	for length > 1 {
		maxDepth++
		length >>= 1
	}
	return maxDepth
}

func redactJSONCredentialValues(value string, escapeDepth int) (string, bool) {
	return redactJSONValuesMatchingName(value, escapeDepth, jsonCredentialName.MatchString, false, false)
}

func redactJSONValuesMatchingName(value string, escapeDepth int, nameMatches func(string) bool, includePlainKeys, preserveUnterminatedValues bool) (string, bool) {
	redacted := value
	changed := false
	quoteDelimiter := jsonQuoteDelimiter(escapeDepth)
	for searchStart := 0; searchStart < len(redacted); {
		relativeOpen := strings.Index(redacted[searchStart:], quoteDelimiter)
		if relativeOpen < 0 {
			break
		}
		open := searchStart + relativeOpen
		quote := open + len(quoteDelimiter) - 1
		if !isJSONStringDelimiterAtDepth(redacted, quote, escapeDepth) {
			searchStart = open + len(quoteDelimiter)
			continue
		}
		close := findJSONStringEndAtDepth(redacted, open, escapeDepth)
		if close < 0 {
			break
		}

		encodedKey := redacted[open : close+1]
		if !includePlainKeys && escapeDepth == 0 && !strings.Contains(encodedKey, `\`) {
			searchStart = close + 1
			continue
		}
		decodedKey, valid := decodeJSONCredentialKey(encodedKey, escapeDepth)
		if !valid || !nameMatches(decodedKey) {
			searchStart = close + 1
			continue
		}

		colon := close + 1
		for colon < len(redacted) && strings.ContainsRune(" \t\r\n", rune(redacted[colon])) {
			colon++
		}
		if colon >= len(redacted) || redacted[colon] != ':' {
			searchStart = close + 1
			continue
		}
		valueStart := colon + 1
		for valueStart < len(redacted) && strings.ContainsRune(" \t\r\n", rune(redacted[valueStart])) {
			valueStart++
		}
		valueEnd, replacement := jsonCredentialValueReplacement(redacted, valueStart, escapeDepth)
		if preserveUnterminatedValues && strings.HasPrefix(redacted[valueStart:], quoteDelimiter) && findJSONStringEndAtDepth(redacted, valueStart, escapeDepth) < 0 {
			valueEnd = len(redacted)
			replacement = quoteDelimiter + redactionMarker
		}
		if valueEnd <= valueStart {
			searchStart = close + 1
			continue
		}
		if redacted[valueStart:valueEnd] == replacement {
			searchStart = valueEnd
			continue
		}

		redacted = redacted[:valueStart] + replacement + redacted[valueEnd:]
		changed = true
		searchStart = valueStart + len(replacement)
	}
	return redacted, changed
}

type contextualJSONContainerRule struct {
	name      string
	openers   string
	valueName string
}

var contextualJSONContainerRules = []contextualJSONContainerRule{
	{name: "cookies", openers: "[{", valueName: "value"},
	{name: "auths", openers: "{", valueName: "auth"},
	{name: "requestHeaders", openers: "[", valueName: "value"},
}

func redactContextualJSONCredentialValues(value string) (string, bool) {
	redacted := value
	changed := false
	maxEscapeDepth := maxJSONEscapeDepthForLength(len(value))
	for escapeDepth := 0; escapeDepth <= maxEscapeDepth; escapeDepth++ {
		for _, rule := range contextualJSONContainerRules {
			if next, layerChanged := redactJSONValuesInNamedContainer(redacted, escapeDepth, rule); layerChanged {
				redacted = next
				changed = true
			}
		}
	}
	return redacted, changed
}

func redactJSONValuesInNamedContainer(value string, escapeDepth int, rule contextualJSONContainerRule) (string, bool) {
	redacted := value
	changed := false
	quoteDelimiter := jsonQuoteDelimiter(escapeDepth)
	for searchStart := 0; searchStart < len(redacted); {
		relativeOpen := strings.Index(redacted[searchStart:], quoteDelimiter)
		if relativeOpen < 0 {
			break
		}
		keyOpen := searchStart + relativeOpen
		quote := keyOpen + len(quoteDelimiter) - 1
		if !isJSONStringDelimiterAtDepth(redacted, quote, escapeDepth) {
			searchStart = keyOpen + len(quoteDelimiter)
			continue
		}
		keyClose := findJSONStringEndAtDepth(redacted, keyOpen, escapeDepth)
		if keyClose < 0 {
			break
		}

		decodedKey, valid := decodeJSONCredentialKey(redacted[keyOpen:keyClose+1], escapeDepth)
		if !valid || !strings.EqualFold(decodedKey, rule.name) {
			searchStart = keyClose + 1
			continue
		}

		colon := keyClose + 1
		for colon < len(redacted) && strings.ContainsRune(" \t\r\n", rune(redacted[colon])) {
			colon++
		}
		if colon >= len(redacted) || redacted[colon] != ':' {
			searchStart = keyClose + 1
			continue
		}
		containerOpen := colon + 1
		for containerOpen < len(redacted) && strings.ContainsRune(" \t\r\n", rune(redacted[containerOpen])) {
			containerOpen++
		}
		if containerOpen >= len(redacted) || !strings.ContainsRune(rule.openers, rune(redacted[containerOpen])) {
			searchStart = keyClose + 1
			continue
		}

		containerClose := findJSONContainerEndAtDepth(redacted, containerOpen, escapeDepth)
		container := redacted[containerOpen : containerClose+1]
		redactedContainer, containerChanged := redactJSONValuesMatchingName(container, escapeDepth, func(name string) bool {
			return strings.EqualFold(name, rule.valueName)
		}, true, true)
		if containerChanged {
			redacted = redacted[:containerOpen] + redactedContainer + redacted[containerClose+1:]
			changed = true
		}
		searchStart = containerOpen + len(redactedContainer)
	}
	return redacted, changed
}

func decodeJSONCredentialKey(encodedKey string, escapeDepth int) (string, bool) {
	for layer := 0; layer < escapeDepth; layer++ {
		var rawKey string
		if json.Unmarshal([]byte(`"`+encodedKey+`"`), &rawKey) != nil {
			return "", false
		}
		encodedKey = rawKey
	}

	var decodedKey string
	if json.Unmarshal([]byte(encodedKey), &decodedKey) != nil {
		return "", false
	}
	return decodedKey, true
}

func findJSONStringEndAtDepth(value string, open, escapeDepth int) int {
	delimiter := jsonQuoteDelimiter(escapeDepth)
	if open < 0 || open+len(delimiter) > len(value) || value[open:open+len(delimiter)] != delimiter {
		return -1
	}
	if !isJSONStringDelimiterAtDepth(value, open+len(delimiter)-1, escapeDepth) {
		return -1
	}
	for quote := open + len(delimiter); quote < len(value); quote++ {
		if value[quote] == '"' && isJSONStringDelimiterAtDepth(value, quote, escapeDepth) {
			return quote
		}
	}
	return -1
}

func jsonCredentialValueReplacement(value string, start, escapeDepth int) (int, string) {
	if start < 0 || start >= len(value) {
		return -1, ""
	}
	delimiter := jsonQuoteDelimiter(escapeDepth)
	if strings.HasPrefix(value[start:], delimiter) && isJSONStringDelimiterAtDepth(value, start+len(delimiter)-1, escapeDepth) {
		close := findJSONStringEndAtDepth(value, start, escapeDepth)
		if close < 0 {
			return len(value), delimiter + redactionMarker + delimiter
		}
		return close + 1, delimiter + redactionMarker + delimiter
	}
	switch value[start] {
	case '{':
		return findJSONContainerEndAtDepth(value, start, escapeDepth) + 1, delimiter + redactionMarker + delimiter
	case '[':
		return findJSONContainerEndAtDepth(value, start, escapeDepth) + 1, `[` + delimiter + redactionMarker + delimiter + `]`
	default:
		end := start
		for end < len(value) && !strings.ContainsRune(",}]\r\n", rune(value[end])) {
			end++
		}
		return end, delimiter + redactionMarker + delimiter
	}
}

func jsonQuoteDelimiter(escapeDepth int) string {
	return strings.Repeat(`\`, 1<<escapeDepth-1) + `"`
}

func normalizeYAMLEscapedCredentialKeys(value string) (string, map[string]string) {
	lines := strings.SplitAfter(value, "\n")
	restorations := make(map[string]string)
	placeholderIndex := 0
	for line := range lines {
		content, ending := splitLineEnding(lines[line])
		keyStart, explicitKey := yamlQuotedKeyStart(content)
		if keyStart < 0 || keyStart >= len(content) || content[keyStart] != '"' {
			continue
		}
		keyEnd := findTOMLQuotedStringEnd(content, keyStart, '"')
		if keyEnd <= keyStart || keyEnd > len(content) {
			continue
		}
		encodedKey := content[keyStart:keyEnd]
		if !strings.Contains(encodedKey, `\`) {
			continue
		}
		decodedKey, err := strconv.Unquote(encodedKey)
		if err != nil || !yamlCredentialNamePattern.MatchString(decodedKey) || !isYAMLMappingKeySuffix(content[keyEnd:], explicitKey) {
			continue
		}

		placeholder := ""
		for placeholder == "" || strings.Contains(value, placeholder) {
			placeholder = `"_snitch_redaction_` + strconv.Itoa(placeholderIndex) + `_password"`
			placeholderIndex++
		}
		restorations[placeholder] = encodedKey
		lines[line] = content[:keyStart] + placeholder + content[keyEnd:] + ending
	}
	return strings.Join(lines, ""), restorations
}

func normalizeYAMLAliasCredentialKeys(value string) (string, map[string]string) {
	sensitiveAliases := make(map[string]struct{})
	for _, match := range yamlSensitiveNameAnchor.FindAllStringSubmatch(value, -1) {
		sensitiveAliases[match[1]] = struct{}{}
	}
	if len(sensitiveAliases) == 0 {
		return value, nil
	}

	lines := strings.SplitAfter(value, "\n")
	restorations := make(map[string]string)
	placeholderIndex := 0
	patterns := []*regexp.Regexp{yamlAliasMappingKey, yamlExplicitAliasKey}
	for line := range lines {
		content, ending := splitLineEnding(lines[line])
		for _, pattern := range patterns {
			match := pattern.FindStringSubmatchIndex(content)
			if match == nil {
				continue
			}
			if _, sensitive := sensitiveAliases[content[match[6]:match[7]]]; !sensitive {
				continue
			}

			placeholder := ""
			for placeholder == "" || strings.Contains(value, placeholder) {
				placeholder = `_snitch_redaction_` + strconv.Itoa(placeholderIndex) + `_password`
				placeholderIndex++
			}
			original := content[match[4]:match[5]]
			restorations[placeholder] = original
			lines[line] = content[:match[4]] + placeholder + content[match[5]:] + ending
			break
		}
	}
	return strings.Join(lines, ""), restorations
}

func yamlQuotedKeyStart(content string) (int, bool) {
	cursor := 0
	for cursor < len(content) && (content[cursor] == ' ' || content[cursor] == '\t') {
		cursor++
	}
	if cursor < len(content) && content[cursor] == '-' {
		cursor++
		if cursor >= len(content) || (content[cursor] != ' ' && content[cursor] != '\t') {
			return -1, false
		}
		for cursor < len(content) && (content[cursor] == ' ' || content[cursor] == '\t') {
			cursor++
		}
	}
	if cursor < len(content) && content[cursor] == '?' {
		cursor++
		if cursor >= len(content) || (content[cursor] != ' ' && content[cursor] != '\t') {
			return -1, false
		}
		for cursor < len(content) && (content[cursor] == ' ' || content[cursor] == '\t') {
			cursor++
		}
		return cursor, true
	}
	return cursor, false
}

func isYAMLMappingKeySuffix(suffix string, explicitKey bool) bool {
	suffix = strings.TrimSpace(suffix)
	if explicitKey {
		return suffix == "" || strings.HasPrefix(suffix, "#")
	}
	return strings.HasPrefix(suffix, ":")
}

func redactYAMLCredentialAliases(value string) (string, bool) {
	aliases := make(map[string]struct{})
	for _, match := range yamlCredentialAlias.FindAllStringSubmatch(value, -1) {
		aliases[match[1]] = struct{}{}
	}
	if len(aliases) == 0 {
		return value, false
	}

	lines := strings.SplitAfter(value, "\n")
	changed := false
	for line := 0; line < len(lines); line++ {
		content, ending := splitLineEnding(lines[line])
		for _, match := range yamlAnchor.FindAllStringSubmatchIndex(content, -1) {
			if _, sensitive := aliases[content[match[2]:match[3]]]; !sensitive {
				continue
			}

			prefix := content[:match[0]]
			valueIndent, isValue := yamlAnchorValueIndent(prefix)
			if !isValue {
				continue
			}

			inlineValue := strings.TrimSpace(content[match[1]:])
			hasInlineValue := inlineValue != "" && !strings.HasPrefix(inlineValue, "#")
			end := line + 1
			hasIndentedContent := false
			for end < len(lines) {
				child, _ := splitLineEnding(lines[end])
				if strings.TrimSpace(child) == "" {
					end++
					continue
				}
				if leadingIndent(child) <= valueIndent {
					break
				}
				hasIndentedContent = true
				end++
			}
			if !hasInlineValue && !hasIndentedContent {
				continue
			}
			if inlineValue == redactionMarker && !hasIndentedContent {
				continue
			}

			lines[line] = content[:match[1]] + " " + redactionMarker + ending
			lines = append(lines[:line+1], lines[end:]...)
			changed = true
			break
		}
	}
	return strings.Join(lines, ""), changed
}

func yamlAnchorValueIndent(prefix string) (int, bool) {
	if colon := strings.LastIndexByte(prefix, ':'); colon >= 0 && strings.TrimSpace(prefix[colon+1:]) == "" {
		return yamlKeyIndent(prefix), true
	}
	if strings.TrimSpace(prefix) == "-" {
		return leadingIndent(prefix), true
	}
	return 0, false
}

func redactYAMLExplicitCredentialMappings(value string) (string, bool) {
	lines := strings.SplitAfter(value, "\n")
	changed := false
	for line := 0; line < len(lines)-1; line++ {
		key, _ := splitLineEnding(lines[line])
		if !yamlExplicitCredentialKey.MatchString(key) {
			continue
		}

		keyIndent := yamlKeyIndent(key)
		valueLine := line + 1
		for valueLine < len(lines) {
			candidate, _ := splitLineEnding(lines[valueLine])
			trimmed := strings.TrimSpace(candidate)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				break
			}
			valueLine++
		}
		if valueLine >= len(lines) {
			continue
		}
		valueContent, ending := splitLineEnding(lines[valueLine])
		if leadingIndent(valueContent) != keyIndent {
			continue
		}
		indicator := valueContent[keyIndent:]
		if indicator == "" || indicator[0] != ':' || (len(indicator) > 1 && indicator[1] != ' ' && indicator[1] != '\t' && indicator[1] != '#') {
			continue
		}

		inlineValue := strings.TrimSpace(indicator[1:])
		hasInlineValue := inlineValue != "" && !strings.HasPrefix(inlineValue, "#")
		end := valueLine + 1
		hasIndentedContent := false
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
			end++
		}
		if !hasInlineValue && !hasIndentedContent {
			continue
		}
		if inlineValue == redactionMarker && !hasIndentedContent {
			continue
		}

		lines[valueLine] = valueContent[:keyIndent] + ": " + redactionMarker + ending
		lines = append(lines[:valueLine+1], lines[end:]...)
		changed = true
		line = valueLine
	}
	return strings.Join(lines, ""), changed
}

func redactYAMLCredentialBlocks(value string) (string, bool) {
	lines := strings.SplitAfter(value, "\n")
	changed := false
	for line := 0; line < len(lines); line++ {
		content, ending := splitLineEnding(lines[line])
		match := yamlCredentialScalar.FindStringSubmatch(content)
		blockScalar := match != nil
		plainScalar := false
		separator := ""
		if match == nil {
			match = yamlCredentialMapping.FindStringSubmatch(content)
			separator = " "
		}
		if match == nil {
			match = yamlCredentialPlainScalar.FindStringSubmatch(content)
			plainScalar = match != nil
			separator = ""
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
			trimmedChild := strings.TrimSpace(child)
			if trimmedChild == "" || !blockScalar && !plainScalar && strings.HasPrefix(trimmedChild, "#") {
				end++
				continue
			}
			childIndent := leadingIndent(child)
			indentlessSequence := !blockScalar && !plainScalar && isYAMLSequenceItemAtIndent(child, keyIndent)
			if childIndent < keyIndent || childIndent == keyIndent && !indentlessSequence {
				break
			}
			hasIndentedContent = true
			if firstIndentedContent == "" {
				firstIndentedContent = trimmedChild
			}
			end++
		}
		if !hasIndentedContent {
			continue
		}
		if !blockScalar && !plainScalar && strings.HasPrefix(strings.TrimSpace(content), `"`) && jsonQuotedScalarLine.MatchString(firstIndentedContent) {
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
		if redacted[open:close+1] == redactionMarker {
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

func isYAMLSequenceItemAtIndent(line string, indent int) bool {
	if indent < 0 || leadingIndent(line) != indent || indent >= len(line) || line[indent] != '-' {
		return false
	}
	return indent+1 == len(line) || line[indent+1] == ' ' || line[indent+1] == '\t'
}

func protectBooleanSecretMarkers(value string) (string, string) {
	if !booleanSecretMarker.MatchString(value) {
		return value, ""
	}

	protection := "\x00"
	for strings.Contains(value, protection) {
		protection += "\x00"
	}
	protected, changed := transformXcodeCloudEnvVarSetCommands(value, func(command string) (string, bool) {
		next := booleanSecretMarker.ReplaceAllString(command, `${1}${2}`+protection+`${3}${4}${5}`)
		return next, next != command
	})
	if !changed {
		return value, ""
	}
	return protected, protection
}

func redactStructuredCredentialObjects(value string) (string, bool) {
	type objectPattern struct {
		pattern       *regexp.Regexp
		escapedQuotes bool
		replacement   string
		array         bool
	}

	patterns := []objectPattern{
		{pattern: rawCredentialObject, replacement: `"` + redactionMarker + `"`},
		{pattern: escapedCredentialObject, escapedQuotes: true, replacement: `\"` + redactionMarker + `\"`},
		{pattern: rawCredentialArray, replacement: `["` + redactionMarker + `"]`, array: true},
		{pattern: escapedCredentialArray, escapedQuotes: true, replacement: `[\"` + redactionMarker + `\"]`, array: true},
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
			if redacted[open] == '[' && (strings.HasPrefix(redacted[open:], redactionMarker) || strings.HasPrefix(redacted[open:], candidate.replacement)) {
				searchStart = open + 1
				continue
			}
			close := findJSONObjectEnd(redacted, open, candidate.escapedQuotes)
			if candidate.array && !looksLikeJSONCredentialArray(redacted, open, close, candidate.escapedQuotes) {
				searchStart = open + 1
				continue
			}

			redacted = redacted[:open] + candidate.replacement + redacted[close+1:]
			changed = true
			searchStart = open + len(candidate.replacement)
		}
	}
	return redacted, changed
}

func looksLikeJSONCredentialArray(value string, open, close int, escapedQuotes bool) bool {
	for index := open + 1; index <= close && index < len(value); index++ {
		switch value[index] {
		case ' ', '\t', '\r', '\n':
			continue
		case '"', '{', '[', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		case '\\':
			return escapedQuotes && index+1 < len(value) && value[index+1] == '"'
		default:
			remaining := value[index : close+1]
			return strings.HasPrefix(remaining, "true") || strings.HasPrefix(remaining, "false") || strings.HasPrefix(remaining, "null")
		}
	}
	return false
}

func findJSONObjectEnd(value string, open int, escapedQuotes bool) int {
	return findJSONContainerEnd(value, open, escapedQuotes)
}

func findJSONContainerEnd(value string, open int, escapedQuotes bool) int {
	escapeDepth := 0
	if escapedQuotes {
		escapeDepth = 1
	}
	return findJSONContainerEndAtDepth(value, open, escapeDepth)
}

func findJSONContainerEndAtDepth(value string, open, escapeDepth int) int {
	if open < 0 || open >= len(value) || (value[open] != '{' && value[open] != '[') {
		return len(value) - 1
	}

	stack := []byte{value[open]}
	inString := false
	for i := open + 1; i < len(value); i++ {
		if value[i] == '"' && isJSONStringDelimiterAtDepth(value, i, escapeDepth) {
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
	escapeDepth := 0
	if escapedQuotes {
		escapeDepth = 1
	}
	return isJSONStringDelimiterAtDepth(value, quote, escapeDepth)
}

func isJSONStringDelimiterAtDepth(value string, quote, escapeDepth int) bool {
	backslashes := 0
	for i := quote - 1; i >= 0 && value[i] == '\\'; i-- {
		backslashes++
	}
	period := 1 << (escapeDepth + 1)
	want := 1<<escapeDepth - 1
	return backslashes%period == want
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

// Registry configuration auth values are base64-encoded username/password
// pairs. Scope the generic "auth" key to the auths container so unrelated
// diagnostic fields with that name remain useful.
func redactRegistryConfigurationAuthValues(value string) (string, bool) {
	type authsContainerPattern struct {
		pattern       *regexp.Regexp
		escapedQuotes bool
	}
	patterns := []authsContainerPattern{
		{pattern: rawRegistryAuthsPattern},
		{pattern: escapedRegistryAuthsPattern, escapedQuotes: true},
	}

	redacted := value
	changed := false
	for _, candidate := range patterns {
		for searchStart := 0; searchStart < len(redacted); {
			match := candidate.pattern.FindStringIndex(redacted[searchStart:])
			if match == nil {
				break
			}

			open := searchStart + match[1] - 1
			close := findJSONObjectEnd(redacted, open, candidate.escapedQuotes)
			container := redacted[open : close+1]
			redactedContainer := container
			for _, rule := range registryAuthValueRedactionRules {
				redactedContainer = rule.pattern.ReplaceAllString(redactedContainer, rule.replacement)
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
	return transformXcodeCloudEnvVarSetCommands(value, func(command string) (string, bool) {
		if secretMarkerPattern.MatchString(command) {
			redacted := secretValuePattern.ReplaceAllString(command, `${1}${2}`+redactionMarker)
			if redacted != command {
				return redacted, true
			}
		}
		return command, false
	})
}

func redactKubectlSecretLiterals(value string) (string, bool) {
	result := value
	changed := false
	for start := 0; start < len(result); {
		end := findShellCommandEnd(result, start)
		command := result[start:end]
		redacted := command
		if isKubectlCreateSecretCommand(command) {
			redacted = kubectlFromLiteralValue.ReplaceAllString(command, `${1}`+redactionMarker)
		}
		if redacted != command {
			result = result[:start] + redacted + result[end:]
			changed = true
		}

		separator := start + len(redacted)
		if separator >= len(result) {
			break
		}
		start = separator + 1
		if result[separator] == '\r' && start < len(result) && result[start] == '\n' {
			start++
		}
	}
	return result, changed
}

func isKubectlCreateSecretCommand(command string) bool {
	normalized := strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(command)
	words := strings.Fields(normalized)
	if len(words) < 3 {
		return false
	}

	kubectlIndex := -1
	for index, word := range words {
		word = strings.Trim(word, `"'`)
		if separator := strings.LastIndexAny(word, `/\\`); separator >= 0 {
			word = word[separator+1:]
		}
		if strings.EqualFold(word, "kubectl") {
			kubectlIndex = index
			break
		}
	}
	if kubectlIndex < 0 || !isKubectlCommandPrefix(words[:kubectlIndex]) {
		return false
	}

	for index := kubectlIndex + 1; index+1 < len(words); index++ {
		if strings.EqualFold(strings.Trim(words[index], `"'`), "create") &&
			strings.EqualFold(strings.Trim(words[index+1], `"'`), "secret") {
			return true
		}
	}
	return false
}

func isKubectlCommandPrefix(words []string) bool {
	if len(words) == 0 {
		return true
	}

	first := strings.ToLower(strings.Trim(words[0], `"'`))
	if separator := strings.LastIndexAny(first, `/\\`); separator >= 0 {
		first = first[separator+1:]
	}
	if first == "sudo" || first == "doas" || first == "command" || first == "env" {
		return true
	}

	for _, word := range words {
		if !strings.Contains(word, "=") {
			return false
		}
	}
	return true
}

func transformXcodeCloudEnvVarSetCommands(value string, transform func(string) (string, bool)) (string, bool) {
	result := value
	changed := false
	for searchStart := 0; searchStart < len(result); {
		match := xcodeCloudEnvVarSetCommand.FindStringIndex(result[searchStart:])
		if match == nil {
			break
		}

		start := searchStart + match[0]
		end := findShellCommandEnd(result, searchStart+match[1])
		command := result[start:end]
		next, commandChanged := transform(command)
		if commandChanged {
			result = result[:start] + next + result[end:]
			changed = true
		}
		searchStart = start + len(next)
	}
	return result, changed
}

func findShellCommandEnd(value string, start int) int {
	var quote byte
	parenDepth := 0
	for i := start; i < len(value); i++ {
		if quote == '\'' {
			if value[i] == '\'' {
				quote = 0
			}
			continue
		}
		if value[i] == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if value[i] == quote {
				quote = 0
			}
			continue
		}

		switch value[i] {
		case '\'', '"', '`':
			quote = value[i]
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '\r':
			if parenDepth == 0 && i+1 < len(value) && value[i+1] == '\n' {
				return i
			}
		case '\n', ';', '&', '|':
			if parenDepth == 0 {
				return i
			}
		}
	}
	return len(value)
}

func redactSensitiveCommandSubstitutions(value string) (string, bool) {
	redacted := value
	changed := false
	for searchStart := 0; searchStart < len(redacted); {
		match := sensitiveCommandSubstitutionStart.FindStringSubmatchIndex(redacted[searchStart:])
		if match == nil {
			break
		}

		open := searchStart + match[2]
		close := findShellCommandSubstitutionEnd(redacted, open)
		if close < 0 {
			close = len(redacted) - 1
		}
		redacted = redacted[:open] + redactionMarker + redacted[close+1:]
		changed = true
		searchStart = open + len(redactionMarker)
	}
	return redacted, changed
}

func findShellCommandSubstitutionEnd(value string, open int) int {
	if open < 0 || open >= len(value) {
		return -1
	}
	if value[open] == '`' {
		for index := open + 1; index < len(value); index++ {
			if value[index] == '\\' {
				index++
				continue
			}
			if value[index] == '`' {
				return index
			}
		}
		return -1
	}
	contentStart := open + 1
	if value[open] == '$' && open+1 < len(value) && value[open+1] == '(' {
		contentStart++
	} else if value[open] != '(' {
		return -1
	}

	depth := 1
	resumeQuotes := []byte{0}
	var quote byte
	for i := contentStart; i < len(value); i++ {
		if quote == '\'' {
			if value[i] == '\'' {
				quote = 0
			}
			continue
		}
		if value[i] == '\\' {
			i++
			continue
		}
		if value[i] == '$' && i+1 < len(value) && value[i+1] == '(' {
			resumeQuotes = append(resumeQuotes, quote)
			quote = 0
			depth++
			i++
			continue
		}
		if quote != 0 {
			if value[i] == quote {
				quote = 0
			}
			continue
		}

		switch value[i] {
		case '\'', '"', '`':
			quote = value[i]
		case '(':
			resumeQuotes = append(resumeQuotes, 0)
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
			quote = resumeQuotes[len(resumeQuotes)-1]
			resumeQuotes = resumeQuotes[:len(resumeQuotes)-1]
		}
	}
	return -1
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
