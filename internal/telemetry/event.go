package telemetry

import (
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

type Event struct {
	EventID          string           `json:"event_id"`
	SchemaVersion    uint8            `json:"schema_version"`
	ASCVersion       string           `json:"asc_version"`
	OS               string           `json:"os"`
	Arch             string           `json:"arch"`
	CommandPath      string           `json:"command_path"`
	CommandFamily    string           `json:"command_family"`
	DurationMS       uint32           `json:"duration_ms"`
	DurationBucket   string           `json:"duration_bucket"`
	ExitCode         int              `json:"exit_code"`
	Success          bool             `json:"success"`
	RuntimeContext   RuntimeContext   `json:"runtime_context"`
	InvocationSource InvocationSource `json:"invocation_source"`
	InstallID        *string          `json:"install_id"`
	SessionID        string           `json:"session_id"`
	InvocationShape  InvocationShape  `json:"invocation_shape"`
	ErrorKind        *ErrorKind       `json:"error_kind"`
	FailureStage     *FailureStage    `json:"failure_stage"`
	FailureParameter *string          `json:"failure_parameter"`
	DiagnosticCode   *string          `json:"diagnostic_code,omitempty"`
	OutcomeKind      OutcomeKind      `json:"outcome_kind,omitempty"`
	HTTPStatus       *int             `json:"http_status,omitempty"`
}

type OutcomeKind string

const (
	OutcomeSuccess          OutcomeKind = "success"
	OutcomeExpectedNegative OutcomeKind = "expected_negative"
	OutcomeUsageError       OutcomeKind = "usage_error"
	OutcomeAuthError        OutcomeKind = "auth_error"
	OutcomeNotFound         OutcomeKind = "not_found"
	OutcomeConflict         OutcomeKind = "conflict"
	OutcomeAPIClientError   OutcomeKind = "api_client_error"
	OutcomeAPIServerError   OutcomeKind = "api_server_error"
	OutcomeTransportError   OutcomeKind = "transport_error"
	OutcomeCancelled        OutcomeKind = "cancelled"
	OutcomeInternalError    OutcomeKind = "internal_error"
)

type InvocationShape string

const (
	InvocationShapeLeaf           InvocationShape = "leaf"
	InvocationShapeBareGroup      InvocationShape = "bare_group"
	InvocationShapeGroupWithFlags InvocationShape = "group_with_flags"
	InvocationShapeUnknownChild   InvocationShape = "unknown_child"
)

type ErrorKind string

const (
	ErrorKindUnknownFlag     ErrorKind = "unknown_flag"
	ErrorKindMissingRequired ErrorKind = "missing_required"
	ErrorKindInvalidValue    ErrorKind = "invalid_value"
	ErrorKindBareGroup       ErrorKind = "bare_group"
	ErrorKindAPIConflict     ErrorKind = "api_conflict"
	ErrorKindAPI5xx          ErrorKind = "api_5xx"
	ErrorKindOther           ErrorKind = "other"
)

type FailureStage string

const (
	FailureStageParse      FailureStage = "parse"
	FailureStageValidation FailureStage = "validation"
	FailureStageRequest    FailureStage = "request"
	FailureStageExecution  FailureStage = "execution"
)

type EventContext struct {
	InvocationShape  InvocationShape
	ErrorKind        ErrorKind
	FailureStage     FailureStage
	FailureParameter string
	// DiagnosticCode is populated from structured CLI errors and is sanitized
	// against the shared low-cardinality taxonomy before it reaches the wire.
	DiagnosticCode   string
	OutcomeKind      OutcomeKind
	HTTPStatus       int
	PublicStorefront bool
}

// processSessionID groups events from one CLI process without linking separate
// invocations of the executable.
var processSessionID = uuid.NewString()

func BuildEvent(commandName, version string, duration time.Duration, exitCode int) (Event, bool) {
	return BuildEventWithContext(commandName, version, duration, exitCode, EventContext{
		InvocationShape: InvocationShapeLeaf,
	})
}

func BuildEventWithContext(
	commandName, version string,
	duration time.Duration,
	exitCode int,
	eventContext EventContext,
) (Event, bool) {
	commandPath := sanitizeCommandName(commandName)
	if commandPath == "" {
		return Event{}, false
	}
	if shouldSkipCommand(commandPath) {
		return Event{}, false
	}

	runtimeContext := DetectRuntimeContext()
	invocationSource := DetectInvocationSource()
	var installID *string
	if shouldAttachInstallID(runtimeContext) {
		id, err := ensureInstallID(0)
		if err == nil && id != "" {
			installID = &id
		}
	}

	eventContext = normalizeEventContext(eventContext, exitCode)

	return Event{
		EventID:          uuid.NewString(),
		SchemaVersion:    4,
		ASCVersion:       strings.TrimSpace(version),
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		CommandPath:      commandPath,
		CommandFamily:    commandFamily(commandPath),
		DurationMS:       durationMillis(duration),
		DurationBucket:   durationBucket(duration),
		ExitCode:         exitCode,
		Success:          exitCode == 0,
		RuntimeContext:   runtimeContext,
		InvocationSource: invocationSource,
		InstallID:        installID,
		SessionID:        processSessionID,
		InvocationShape:  eventContext.InvocationShape,
		ErrorKind:        optionalErrorKind(eventContext.ErrorKind),
		FailureStage:     optionalFailureStage(eventContext.FailureStage),
		FailureParameter: optionalFailureParameter(eventContext.FailureParameter, exitCode),
		DiagnosticCode:   optionalDiagnosticCode(eventContext.DiagnosticCode, exitCode),
		OutcomeKind:      eventContext.OutcomeKind,
		HTTPStatus:       optionalHTTPStatus(eventContext.HTTPStatus),
	}, true
}

func normalizeEventContext(eventContext EventContext, exitCode int) EventContext {
	switch eventContext.InvocationShape {
	case InvocationShapeLeaf, InvocationShapeBareGroup, InvocationShapeGroupWithFlags, InvocationShapeUnknownChild:
	default:
		eventContext.InvocationShape = InvocationShapeLeaf
	}

	eventContext.HTTPStatus = sanitizeHTTPStatus(eventContext.HTTPStatus)

	if exitCode == 0 {
		eventContext.ErrorKind = ""
		eventContext.FailureStage = ""
		eventContext.FailureParameter = ""
		eventContext.DiagnosticCode = ""
		eventContext.OutcomeKind = OutcomeSuccess
		eventContext.HTTPStatus = 0
		return eventContext
	}
	if eventContext.ErrorKind == "" {
		eventContext.ErrorKind = ErrorKindOther
	}
	switch eventContext.ErrorKind {
	case ErrorKindUnknownFlag:
		eventContext.FailureStage = FailureStageParse
	case ErrorKindMissingRequired, ErrorKindInvalidValue, ErrorKindBareGroup:
		eventContext.FailureStage = FailureStageValidation
	case ErrorKindAPIConflict, ErrorKindAPI5xx:
		eventContext.FailureStage = FailureStageRequest
	case ErrorKindOther:
		switch eventContext.FailureStage {
		case FailureStageParse, FailureStageValidation, FailureStageRequest, FailureStageExecution:
		default:
			eventContext.FailureStage = FailureStageExecution
		}
	default:
		eventContext.ErrorKind = ErrorKindOther
		eventContext.FailureStage = FailureStageExecution
	}
	eventContext.OutcomeKind = normalizeOutcomeKind(eventContext, exitCode)
	return eventContext
}

func normalizeOutcomeKind(eventContext EventContext, exitCode int) OutcomeKind {
	status := eventContext.HTTPStatus
	switch {
	case eventContext.PublicStorefront && (status == 401 || status == 403):
		return OutcomeAPIClientError
	case status == 401 || status == 403:
		return OutcomeAuthError
	case status == 404:
		return OutcomeNotFound
	case status == 409:
		return OutcomeConflict
	case status >= 400 && status < 500:
		return OutcomeAPIClientError
	case status >= 500:
		return OutcomeAPIServerError
	}
	switch eventContext.ErrorKind {
	case ErrorKindAPIConflict:
		return OutcomeConflict
	case ErrorKindAPI5xx:
		return OutcomeAPIServerError
	}

	switch eventContext.OutcomeKind {
	case OutcomeExpectedNegative:
		if eventContext.FailureStage == FailureStageValidation {
			return OutcomeExpectedNegative
		}
	case OutcomeUsageError:
		if exitCode == 2 && (eventContext.FailureStage == FailureStageParse || eventContext.FailureStage == FailureStageValidation) {
			return OutcomeUsageError
		}
	case OutcomeAuthError, OutcomeNotFound, OutcomeConflict, OutcomeAPIClientError, OutcomeAPIServerError, OutcomeCancelled, OutcomeInternalError:
		return eventContext.OutcomeKind
	case OutcomeTransportError:
		if eventContext.FailureStage == FailureStageRequest {
			return OutcomeTransportError
		}
	}

	if exitCode == 2 && (eventContext.FailureStage == FailureStageParse || eventContext.FailureStage == FailureStageValidation) {
		return OutcomeUsageError
	}
	if eventContext.FailureStage == FailureStageRequest {
		return OutcomeTransportError
	}
	return OutcomeInternalError
}

func optionalErrorKind(kind ErrorKind) *ErrorKind {
	if kind == "" {
		return nil
	}
	return &kind
}

func optionalFailureStage(stage FailureStage) *FailureStage {
	if stage == "" {
		return nil
	}
	return &stage
}

func optionalFailureParameter(parameter string, exitCode int) *string {
	if exitCode == 0 {
		return nil
	}
	parameter = sanitizeFailureParameter(parameter)
	if parameter == "" {
		return nil
	}
	return &parameter
}

func optionalHTTPStatus(status int) *int {
	status = sanitizeHTTPStatus(status)
	if status == 0 {
		return nil
	}
	return &status
}

func optionalDiagnosticCode(code string, exitCode int) *string {
	if exitCode == 0 {
		return nil
	}
	code = strings.TrimSpace(code)
	if !shared.IsKnownDiagnosticCode(shared.DiagnosticCode(code)) {
		return nil
	}
	return &code
}

func sanitizeHTTPStatus(status int) int {
	if status < 400 || status > 599 {
		return 0
	}
	return status
}

// MarshalJSON keeps queued schema-v3 records wire-compatible while ensuring
// nullable schema-v4 fields are present even when their value is null.
func (event Event) MarshalJSON() ([]byte, error) {
	type eventAlias Event
	if event.SchemaVersion != 4 {
		return json.Marshal(eventAlias(event))
	}
	return json.Marshal(struct {
		eventAlias
		HTTPStatus     *int    `json:"http_status"`
		DiagnosticCode *string `json:"diagnostic_code"`
	}{
		eventAlias:     eventAlias(event),
		HTTPStatus:     event.HTTPStatus,
		DiagnosticCode: event.DiagnosticCode,
	})
}

func sanitizeFailureParameter(parameter string) string {
	parameter = strings.TrimSpace(parameter)
	if parameter == "" {
		return ""
	}
	name := strings.SplitN(parameter, "=", 2)[0]
	name = strings.TrimLeft(name, "-")
	if name == "" || len(name) > 64 {
		return ""
	}
	if name[0] < 'a' || name[0] > 'z' || isUUIDLike(name) {
		return ""
	}
	if !isKnownFailureParameter(name) {
		return ""
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		if r == '-' && i > 0 {
			continue
		}
		return ""
	}
	return "--" + name
}

func isKnownFailureParameter(name string) bool {
	_, ok := knownFailureParameters[name]
	return ok
}

// Keep this list deliberately small: failure_parameter is a telemetry
// dimension, so only public flags and compatibility aliases that help diagnose
// common agent failures belong here.
var knownFailureParameters = map[string]struct{}{
	"all":                               {},
	"active":                            {},
	"achievement-id":                    {},
	"activity-id":                       {},
	"after-earned-description":          {},
	"agreement-text":                    {},
	"app":                               {},
	"app-id":                            {},
	"app-store-version-id":              {},
	"availability-id":                   {},
	"base-price":                        {},
	"base-territory":                    {},
	"batch-id":                          {},
	"before-earned-description":         {},
	"build":                             {},
	"build-id":                          {},
	"bundle-id":                         {},
	"code":                              {},
	"confirm":                           {},
	"copy-metadata-from":                {},
	"copyright":                         {},
	"cursor":                            {},
	"custom-code":                       {},
	"custom-code-id":                    {},
	"custom-app-name":                   {},
	"customer-eligibilities":            {},
	"challenge-id":                      {},
	"description":                       {},
	"dry-run":                           {},
	"duration":                          {},
	"email":                             {},
	"end-date":                          {},
	"enabled":                           {},
	"eligibility-last-subscribed-min":   {},
	"eligibility-paid-months":           {},
	"expression":                        {},
	"export-xcodebuild-flag":            {},
	"fallback-url":                      {},
	"file":                              {},
	"formatter":                         {},
	"game-center-group-id":              {},
	"granularity":                       {},
	"group-id":                          {},
	"group":                             {},
	"id":                                {},
	"ids":                               {},
	"iap-id":                            {},
	"image-id":                          {},
	"input":                             {},
	"ipa":                               {},
	"issuer-id":                         {},
	"key-id":                            {},
	"key-type":                          {},
	"leaderboard-id":                    {},
	"leaderboard-set-id":                {},
	"limit":                             {},
	"local":                             {},
	"locale":                            {},
	"localization-id":                   {},
	"min-players":                       {},
	"keywords":                          {},
	"next":                              {},
	"name":                              {},
	"older-than":                        {},
	"number-of-periods":                 {},
	"offer-code":                        {},
	"offer-code-id":                     {},
	"offer-eligibility":                 {},
	"offer-id":                          {},
	"offer-mode":                        {},
	"one-time-code-id":                  {},
	"org":                               {},
	"os-version-filter":                 {},
	"output":                            {},
	"output-dir":                        {},
	"paginate":                          {},
	"path":                              {},
	"period-count":                      {},
	"percentage":                        {},
	"platform":                          {},
	"pkg":                               {},
	"private-key":                       {},
	"price":                             {},
	"price-id":                          {},
	"price-point-id":                    {},
	"prices":                            {},
	"profile":                           {},
	"product-id":                        {},
	"product-type":                      {},
	"promoted-purchase-id":              {},
	"priority":                          {},
	"public-link-limit":                 {},
	"quantity":                          {},
	"queue-id":                          {},
	"reference-name":                    {},
	"ref-name":                          {},
	"review-id":                         {},
	"rule-id":                           {},
	"rule-language-version":             {},
	"rule-set-id":                       {},
	"scoped-player-id":                  {},
	"score":                             {},
	"screenshot-id":                     {},
	"schedule-id":                       {},
	"set-id":                            {},
	"skip-validation":                   {},
	"sort":                              {},
	"state":                             {},
	"start-date":                        {},
	"submission":                        {},
	"subscription-id":                   {},
	"submission-id":                     {},
	"submission-type":                   {},
	"team-id":                           {},
	"term":                              {},
	"territories":                       {},
	"territory":                         {},
	"tester":                            {},
	"tester-id":                         {},
	"test-notes":                        {},
	"treatment-id":                      {},
	"type":                              {},
	"upload":                            {},
	"uploaded":                          {},
	"uses-non-exempt-encryption":        {},
	"uses-third-party-content":          {},
	"version":                           {},
	"version-id":                        {},
	"vendor-id":                         {},
	"visible-for-all-users":             {},
	"visible-in-app-store":              {},
	"app-clip-id":                       {},
	"archived":                          {},
	"asset-pack-identifier":             {},
	"asset-type":                        {},
	"background-asset-id":               {},
	"build-bundle-id":                   {},
	"clip-id":                           {},
	"custom-page-id":                    {},
	"custom-page-version-id":            {},
	"deep-link":                         {},
	"default-language":                  {},
	"delta-id":                          {},
	"device-type":                       {},
	"domain":                            {},
	"domain-id":                         {},
	"event-id":                          {},
	"experience-id":                     {},
	"experiment-id":                     {},
	"header-image-id":                   {},
	"invocation-id":                     {},
	"is-powered-by":                     {},
	"language":                          {},
	"link":                              {},
	"package-id":                        {},
	"promotional-text":                  {},
	"public-key":                        {},
	"title":                             {},
	"upload-file-id":                    {},
	"url":                               {},
	"variant-id":                        {},
	"bucket":                            {},
	"bundle-dir":                        {},
	"endpoint":                          {},
	"framed-dir":                        {},
	"ios-app-on-mac":                    {},
	"item-id":                           {},
	"item-type":                         {},
	"patch-file":                        {},
	"plan":                              {},
	"prefix":                            {},
	"product-ids":                       {},
	"region":                            {},
	"response":                          {},
	"review-detail":                     {},
	"value":                             {},
	"xcode-version":                     {},
	"activated":                         {},
	"all-apps":                          {},
	"app-description":                   {},
	"archive-path":                      {},
	"available-on-french-store":         {},
	"bundle":                            {},
	"capability":                        {},
	"certificate":                       {},
	"certificate-type":                  {},
	"contains-proprietary-cryptography": {},
	"contains-third-party-cryptography": {},
	"csr":                               {},
	"csr-out":                           {},
	"declaration":                       {},
	"device":                            {},
	"devices-file":                      {},
	"first-name":                        {},
	"identifier":                        {},
	"key-out":                           {},
	"last-name":                         {},
	"max-mutations":                     {},
	"minimum-validity-days":             {},
	"profile-type":                      {},
	"roles":                             {},
	"state-dir":                         {},
	"udid":                              {},
	"available":                         {},
	"available-in-new-territories":      {},
	"catalog-url":                       {},
	"pass-type-id":                      {},
	"price-point":                       {},
	"release-date":                      {},
	"schedule":                          {},
	"search-detail-id":                  {},
	"secret":                            {},
	"status":                            {},
	"submitted":                         {},
	"territory-availability":            {},
	"webhook-id":                        {},
	"workflow-id":                       {},
	"whats-new":                         {},
	"xcodebuild-flag":                   {},
}

func isUUIDLike(name string) bool {
	if len(name) != 36 {
		return false
	}
	for i, r := range name {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}

func sanitizeCommandName(commandName string) string {
	commandName = strings.ToLower(strings.Join(strings.Fields(commandName), " "))
	if commandName == "" {
		return ""
	}
	if commandName == "asc" || strings.HasPrefix(commandName, "asc ") {
		return commandName
	}
	return "asc " + commandName
}

func shouldSkipCommand(commandPath string) bool {
	switch commandPath {
	case "", "asc", "asc completion", "asc version", "asc telemetry", "asc telemetry status", "asc telemetry enable", "asc telemetry disable", "asc telemetry reset-id":
		return true
	default:
		return false
	}
}

func commandFamily(commandPath string) string {
	parts := strings.Fields(commandPath)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func durationMillis(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	ms := d.Milliseconds()
	if ms > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}

func durationBucket(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	switch {
	case ms < 100:
		return "lt_100ms"
	case ms < 500:
		return "100ms_500ms"
	case ms < 1000:
		return "500ms_1s"
	case ms < 5000:
		return "1s_5s"
	case ms < 30000:
		return "5s_30s"
	default:
		return "gte_30s"
	}
}

func RedactedSummary(ev Event) map[string]string {
	installID := ""
	if ev.InstallID != nil {
		installID = *ev.InstallID
	}
	return map[string]string{
		"command_path":      ev.CommandPath,
		"command_family":    ev.CommandFamily,
		"runtime_context":   string(ev.RuntimeContext),
		"invocation_source": string(ev.InvocationSource),
		"duration_ms":       strconv.FormatUint(uint64(ev.DurationMS), 10),
		"install_id":        installID,
	}
}
