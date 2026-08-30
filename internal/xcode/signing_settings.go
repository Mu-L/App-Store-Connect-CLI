package xcode

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

const (
	signingPlanSchemaVersion = 1
	signingSettingsMaxBytes  = 1 << 20
	signingPlanMaxBytes      = 8 << 20

	signingPlanCommand = "asc xcode signing plan"
)

var (
	signingTeamIDPattern    = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	signingBundleIDPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	signingReferencePattern = regexp.MustCompile(`\$\(([^):]+)(?::([^)]*))?\)|\$\{([^}:]+)(?::([^}]*))?\}`)
)

// signingInputError marks deterministic manifest or artifact-shape failures
// that the CLI can report as usage errors. Filesystem, parser, and staging
// failures intentionally remain ordinary runtime errors.
type signingInputError struct {
	err error
}

func (e signingInputError) Error() string {
	return e.err.Error()
}

func (e signingInputError) Unwrap() error {
	return e.err
}

func newSigningInputError(err error) error {
	if err == nil {
		return nil
	}
	return signingInputError{err: err}
}

type signingArtifactAliasError struct {
	err error
}

func (e signingArtifactAliasError) Error() string {
	return e.err.Error()
}

func (e signingArtifactAliasError) Unwrap() error {
	return e.err
}

func newSigningArtifactAliasError(err error) error {
	if err == nil {
		return nil
	}
	return signingArtifactAliasError{err: err}
}

const signingUnauthorizedExternalXCConfigMessage = "unauthorized external xcconfig cannot be safely inventoried without --allow-external-xcconfig"

// signingUnauthorizedExternalXCConfigError marks an external xcconfig that
// was discovered but not authorized for reading. Its contents are unknown, so
// the planner cannot safely publish even a blocked artifact. Keep the cause
// available for internal classification while exposing only stable text.
type signingUnauthorizedExternalXCConfigError struct {
	err error
}

func (e signingUnauthorizedExternalXCConfigError) Error() string {
	return signingUnauthorizedExternalXCConfigMessage
}

func (e signingUnauthorizedExternalXCConfigError) Unwrap() error {
	return e.err
}

func newSigningUnauthorizedExternalXCConfigError(err error) error {
	return signingUnauthorizedExternalXCConfigError{err: err}
}

// signingConditionalEntitlementError marks a conditional entitlement value
// whose reference graph could not be inventoried safely. Such a value cannot
// be represented by a blocked plan because an artifact path may be hidden
// behind the unresolved expression.
type signingConditionalEntitlementError struct {
	err error
}

func (e signingConditionalEntitlementError) Error() string {
	return "conditional CODE_SIGN_ENTITLEMENTS cannot be safely inventoried"
}

func (e signingConditionalEntitlementError) Unwrap() error {
	return e.err
}

func newSigningConditionalEntitlementError(err error) error {
	return signingConditionalEntitlementError{err: err}
}

// NewSigningInputError adapts a deterministic signing-input failure for a
// command boundary. It is primarily useful to keep adapters and tests aligned
// with the same usage classification as the built-in manifest validator.
func NewSigningInputError(err error) error {
	return newSigningInputError(err)
}

// IsSigningInputError reports whether err is a deterministic signing-manifest
// or signing-artifact validation failure suitable for usage classification.
func IsSigningInputError(err error) bool {
	var inputErr signingInputError
	return errors.As(err, &inputErr)
}

// SigningPlanOptions controls generation of a deterministic local Xcode
// signing-settings plan. Paths are operator-selected; no remote input is
// consulted by this workflow.
type SigningPlanOptions struct {
	ProjectPath           string
	SettingsFilePath      string
	StateDir              string
	PlanPath              string
	ReceiptPath           string
	AllowExternalXCConfig bool
}

// SigningApplyOptions controls application of a previously generated plan.
type SigningApplyOptions struct {
	PlanPath              string
	AllowExternalXCConfig bool
}

// SigningPlan is the stable JSON artifact consumed by signing apply. Fields
// are intentionally additive: the plan records enough provenance to reject a
// stale or redirected apply before touching the project.
type SigningPlan struct {
	SchemaVersion         int                    `json:"schemaVersion"`
	Command               string                 `json:"command"`
	GeneratedAt           string                 `json:"generatedAt"`
	PlanHash              string                 `json:"planHash"`
	Ready                 bool                   `json:"ready"`
	ProjectPath           string                 `json:"projectPath"`
	SettingsFilePath      string                 `json:"settingsFilePath"`
	PlanPath              string                 `json:"planPath"`
	ReceiptPath           string                 `json:"receiptPath"`
	AllowExternalXCConfig bool                   `json:"allowExternalXCConfig"`
	Desired               []SigningPlanTarget    `json:"desired"`
	Files                 []SigningPlanFile      `json:"files"`
	Changes               []SigningSettingChange `json:"changes"`
	Blockers              []string               `json:"blockers"`
	Warnings              []string               `json:"warnings"`
}

// SigningPlanTarget describes the requested target/configuration scope.
type SigningPlanTarget struct {
	Target         string                     `json:"target"`
	Configurations []SigningPlanConfiguration `json:"configurations"`
}

// SigningPlanConfiguration describes normalized desired signing settings.
// A null value means remove a direct assignment where the setting supports
// removal.
type SigningPlanConfiguration struct {
	Name     string               `json:"name"`
	Settings []SigningPlanSetting `json:"settings"`
}

// SigningPlanSetting is one normalized desired build setting.
type SigningPlanSetting struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// SigningPlanFile records a source file digest bound into the plan.
type SigningPlanFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

// SigningSettingChange records one concrete setting operation.
type SigningSettingChange struct {
	Target        string  `json:"target"`
	Configuration string  `json:"configuration"`
	Setting       string  `json:"setting"`
	Operation     string  `json:"operation"`
	Resolution    string  `json:"resolution"`
	OldValue      *string `json:"oldValue"`
	NewValue      *string `json:"newValue"`
	Path          string  `json:"path"`
	Source        string  `json:"source"`
}

// SigningFileChange binds each written file to its before and after digest in
// the apply receipt without including any signing asset bytes.
type SigningFileChange struct {
	Path         string `json:"path"`
	Source       string `json:"source"`
	BeforeSHA256 string `json:"beforeSha256"`
	AfterSHA256  string `json:"afterSha256"`
}

// SigningApplyResult is written as the receipt after a successful apply.
type SigningApplyResult struct {
	SchemaVersion int                    `json:"schemaVersion"`
	AppliedAt     string                 `json:"appliedAt"`
	Completed     bool                   `json:"completed"`
	PlanHash      string                 `json:"planHash"`
	PlanPath      string                 `json:"planPath"`
	ReceiptPath   string                 `json:"receiptPath"`
	ChangedFiles  []string               `json:"changedFiles"`
	Files         []SigningFileChange    `json:"files"`
	Changes       []SigningSettingChange `json:"changes"`
}

type signingSettingsManifest struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Targets       []signingManifestTarget `json:"targets"`
}

type signingXCConfigAccessError struct {
	path     string
	err      error
	external bool
}

func (e *signingXCConfigAccessError) Error() string {
	if e.external {
		return fmt.Sprintf("external xcconfig %s requires --allow-external-xcconfig: %v", e.path, e.err)
	}
	return fmt.Sprintf("xcconfig %s cannot be read: %v", e.path, e.err)
}

func (e *signingXCConfigAccessError) Unwrap() error {
	return e.err
}

type signingManifestTarget struct {
	Name           string                         `json:"name"`
	Configurations []signingManifestConfiguration `json:"configurations"`
}

type signingManifestConfiguration struct {
	Name     string                     `json:"name"`
	Settings map[string]json.RawMessage `json:"settings"`
}

type signingDesiredSetting struct {
	key   string
	value *string
}

type signingRequest struct {
	target        string
	configuration string
	settings      []signingDesiredSetting
}

type signingCandidate struct {
	configuration *versionConfiguration
	setting       string
	desired       *string
	old           *string
	mode          string
	paths         []string
	resolution    string
	noOp          bool
}

type signingPlanOperation struct {
	SigningSettingChange
	configuration *versionConfiguration
}

type signingPlanBuild struct {
	plan           *SigningPlan
	project        *structuredVersionProject
	operations     []signingPlanOperation
	fileIdentities map[string]string
}

// BuildSigningPlan resolves the requested settings and returns a plan without
// mutating any project, xcconfig, or artifact file.
func BuildSigningPlan(opts SigningPlanOptions) (*SigningPlan, error) {
	built, err := buildSigningPlan(opts)
	if err != nil {
		return nil, err
	}
	return built.plan, nil
}

func buildSigningPlan(opts SigningPlanOptions) (*signingPlanBuild, error) {
	if strings.TrimSpace(opts.ProjectPath) == "" {
		return nil, fmt.Errorf("--project is required")
	}
	settingsPath, err := canonicalSigningPath(opts.SettingsFilePath, "settings file")
	if err != nil {
		return nil, err
	}
	settings, err := readSigningSettingsManifest(settingsPath)
	if err != nil {
		return nil, err
	}

	project, err := openSigningStructuredVersionProject(opts.ProjectPath)
	if err != nil {
		return nil, err
	}
	if err := validateSigningProjectFile(project); err != nil {
		return nil, err
	}

	stateDir := opts.StateDir
	if strings.TrimSpace(stateDir) == "" {
		stateDir = filepath.Join(".asc", "xcode", "signing")
	}
	stateDir, err = canonicalSigningPath(stateDir, "state directory")
	if err != nil {
		return nil, err
	}
	planPath := opts.PlanPath
	if strings.TrimSpace(planPath) == "" {
		planPath = filepath.Join(stateDir, "plan.json")
	}
	planPath, err = canonicalSigningPath(planPath, "plan file")
	if err != nil {
		return nil, err
	}
	receiptPath := opts.ReceiptPath
	if strings.TrimSpace(receiptPath) == "" {
		receiptPath = filepath.Join(stateDir, "receipt.json")
	}
	receiptPath, err = canonicalSigningPath(receiptPath, "receipt file")
	if err != nil {
		return nil, err
	}
	if err := validateSigningArtifactPaths(planPath, receiptPath, project.pbxprojPath, settingsPath); err != nil {
		return nil, newSigningInputError(err)
	}

	requests, desired, err := normalizeSigningRequests(settings)
	if err != nil {
		return nil, newSigningInputError(err)
	}
	selectedIDs := make(map[string]bool, len(requests))
	requestedSettings := make(map[string]map[string]bool, len(requests))
	requestedValues := make(map[string]map[string]*string, len(requests))
	for _, request := range requests {
		configuration, configurationErr := signingConfigurationFor(project, request.target, request.configuration)
		if configurationErr == nil {
			selectedIDs[configuration.id] = true
			if requestedSettings[configuration.id] == nil {
				requestedSettings[configuration.id] = make(map[string]bool)
			}
			if requestedValues[configuration.id] == nil {
				requestedValues[configuration.id] = make(map[string]*string)
			}
			for _, setting := range request.settings {
				requestedSettings[configuration.id][setting.key] = true
				requestedValues[configuration.id][setting.key] = cloneSigningString(setting.value)
			}
		}
	}
	plan := &SigningPlan{
		SchemaVersion:         signingPlanSchemaVersion,
		Command:               signingPlanCommand,
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		Ready:                 true,
		ProjectPath:           project.projectPath,
		SettingsFilePath:      settingsPath,
		PlanPath:              planPath,
		ReceiptPath:           receiptPath,
		AllowExternalXCConfig: opts.AllowExternalXCConfig,
		Desired:               desired,
		Blockers:              []string{},
		Warnings:              []string{},
	}
	var inputBlockers []string
	for _, request := range requests {
		configuration, configurationErr := signingConfigurationFor(project, request.target, request.configuration)
		if configurationErr != nil {
			continue
		}
		for _, setting := range request.settings {
			if setting.key != "CODE_SIGN_ENTITLEMENTS" || setting.value == nil {
				continue
			}
			if err := validateSigningEntitlementsPath(project, *setting.value); err != nil {
				inputBlockers = append(inputBlockers, signingSettingBlocker(configuration, setting.key, fmt.Errorf("validate path %q: %w", *setting.value, err)))
			}
		}
	}

	fileConsumers, configFiles, fileIdentities, uncertainConsumers, protectedConfigPaths, blockedExternalPaths, lexicalConfigPaths, unauthorizedExternal, err := project.signingXCConfigConsumers(selectedIDs, opts.AllowExternalXCConfig)
	hasUnauthorizedExternal := func(paths []string) bool {
		return !opts.AllowExternalXCConfig && unauthorizedExternal && len(paths) > 0
	}
	if err != nil {
		if len(blockedExternalPaths) > 0 {
			inputPaths, externalEntitlementPaths, inputPathBlockers, inputErr := signingProjectInputPaths(project, settingsPath, configFiles, fileIdentities, requests, opts.AllowExternalXCConfig, lexicalConfigPaths)
			if inputErr != nil {
				return nil, inputErr
			}
			protectedConfigPaths = appendUniqueSigningPaths(protectedConfigPaths, externalEntitlementPaths...)
			if aliasErr := validateSigningArtifactAliases(planPath, receiptPath, inputPaths, protectedConfigPaths); aliasErr != nil {
				return nil, aliasErr
			}
			// An unauthorized external xcconfig is not merely an uncertain
			// consumer. Its unread contents may define an entitlement input, so
			// the artifact alias set cannot be complete without reading it. Do
			// not serialize a blocked plan: even a distinct plan path could later
			// be changed to collide with an undiscovered input. Lexical alias
			// failures above remain the more precise, no-read diagnostic.
			if hasUnauthorizedExternal(blockedExternalPaths) {
				return nil, newSigningUnauthorizedExternalXCConfigError(err)
			}
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("selected xcconfig collection failed: %v", err))
			plan.Blockers = append(plan.Blockers, inputPathBlockers...)
			for _, path := range blockedExternalPaths {
				plan.Blockers = append(plan.Blockers, signingXCConfigCollectionBlocker(project, path, opts.AllowExternalXCConfig))
			}
			plan.Ready = false
			plan.PlanHash = signingPlanHash(plan)
			return &signingPlanBuild{plan: plan, project: project}, nil
		}
		return nil, err
	}
	inputPaths, externalEntitlementPaths, inputPathBlockers, err := signingProjectInputPaths(project, settingsPath, configFiles, fileIdentities, requests, opts.AllowExternalXCConfig, lexicalConfigPaths)
	if err != nil {
		return nil, err
	}
	protectedConfigPaths = appendUniqueSigningPaths(protectedConfigPaths, externalEntitlementPaths...)
	if err := validateSigningArtifactAliases(
		planPath,
		receiptPath,
		inputPaths,
		protectedConfigPaths,
	); err != nil {
		return nil, err
	}
	if hasUnauthorizedExternal(blockedExternalPaths) {
		// Unselected configurations deliberately do not make collection errors
		// the primary return value. They are still fatal here: without reading
		// an unauthorized source, its contents cannot be inventoried and a
		// blocked plan is unsafe to publish.
		return nil, newSigningUnauthorizedExternalXCConfigError(nil)
	}
	inputBlockers = append(inputBlockers, inputPathBlockers...)
	if len(inputBlockers) > 0 {
		plan.Blockers = append(plan.Blockers, inputBlockers...)
		plan.Ready = false
		plan.PlanHash = signingPlanHash(plan)
		return &signingPlanBuild{plan: plan, project: project}, nil
	}
	for _, path := range externalEntitlementPaths {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("external CODE_SIGN_ENTITLEMENTS input %s cannot be read or authorized by this signing workflow", path))
	}
	for _, path := range blockedExternalPaths {
		plan.Blockers = append(plan.Blockers, signingXCConfigCollectionBlocker(project, path, opts.AllowExternalXCConfig))
	}
	if len(blockedExternalPaths) > 0 || len(externalEntitlementPaths) > 0 {
		plan.Ready = false
		plan.PlanHash = signingPlanHash(plan)
		return &signingPlanBuild{plan: plan, project: project}, nil
	}

	var candidates []signingCandidate
	for _, request := range requests {
		configuration, err := signingConfigurationFor(project, request.target, request.configuration)
		if err != nil {
			plan.Blockers = append(plan.Blockers, err.Error())
			continue
		}
		for _, setting := range request.settings {
			candidate, blocker, warning := inspectSigningCandidate(
				project,
				configuration,
				setting,
				configFiles,
				fileConsumers,
				fileIdentities,
				requestedSettings,
				requestedValues,
				uncertainConsumers,
				opts.AllowExternalXCConfig,
				lexicalConfigPaths,
			)
			if warning != "" {
				plan.Warnings = append(plan.Warnings, warning)
			}
			if blocker != "" {
				plan.Blockers = append(plan.Blockers, blocker)
				continue
			}
			if candidate.mode != "" {
				candidates = append(candidates, candidate)
			}
		}
	}

	// A shared xcconfig can only be changed once. If selected configurations
	// require different values, narrow each operation to its target instead of
	// rewriting a value that would affect another configuration.
	resolveSigningSharedCandidates(candidates, fileIdentities)
	resolver := newSigningSettingResolver(project, configFiles, opts.AllowExternalXCConfig, lexicalConfigPaths)
	operations := make([]signingPlanOperation, 0, len(candidates))
	for index := range candidates {
		candidate := &candidates[index]
		if candidate.mode == "" || candidate.noOp {
			continue
		}
		if candidate.mode == "xcconfig" {
			var validationErr error
			for _, path := range candidate.paths {
				if err := validateSigningXCConfigWrite(resolver, path, candidate.setting, candidate.desired); err != nil {
					validationErr = err
					break
				}
			}
			if validationErr != nil {
				plan.Blockers = append(plan.Blockers, signingSettingBlocker(candidate.configuration, candidate.setting, validationErr))
				continue
			}
			for _, path := range candidate.paths {
				operations = append(operations, signingPlanOperation{
					SigningSettingChange: signingChange(candidate, path, "xcconfig"),
					configuration:        candidate.configuration,
				})
			}
			continue
		}
		operations = append(operations, signingPlanOperation{
			SigningSettingChange: signingChange(candidate, project.pbxprojPath, "pbxproj"),
			configuration:        candidate.configuration,
		})
	}
	sortSigningPlanOperations(operations)
	plan.Changes = make([]SigningSettingChange, 0, len(operations))
	for _, operation := range operations {
		plan.Changes = append(plan.Changes, operation.SigningSettingChange)
	}

	files := map[string]SigningPlanFile{}
	addFile := func(path, source string) {
		key := signingXCConfigOperationKey(path, fileIdentities)
		if _, exists := files[key]; exists {
			return
		}
		digest, digestErr := signingFileDigest(path)
		if digestErr != nil {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("digest %s: %v", path, digestErr))
			return
		}
		files[key] = SigningPlanFile{Path: path, SHA256: digest, Source: source}
	}
	addFile(project.pbxprojPath, "pbxproj")
	addFile(settingsPath, "settings")
	for _, operation := range operations {
		if operation.Source == "xcconfig" {
			addFile(operation.Path, "xcconfig")
		}
	}
	// Bind every successfully collected xcconfig consumer graph, not only the
	// files this plan rewrites or the selected configuration resolves through.
	// Consumer analysis uses unselected graphs to decide whether a source is
	// shared and safe to rewrite, so changing any consulted input must stale the
	// plan before commit.
	resolutionInputs := make([]string, 0)
	for _, paths := range configFiles {
		resolutionInputs = append(resolutionInputs, paths...)
	}
	sort.Strings(resolutionInputs)
	for _, path := range resolutionInputs {
		addFile(path, "xcconfig")
	}
	for _, file := range files {
		plan.Files = append(plan.Files, file)
	}
	sort.Slice(plan.Files, func(left, right int) bool { return plan.Files[left].Path < plan.Files[right].Path })
	sort.Strings(plan.Blockers)
	sort.Strings(plan.Warnings)
	plan.Ready = len(plan.Blockers) == 0
	plan.PlanHash = signingPlanHash(plan)

	return &signingPlanBuild{plan: plan, project: project, operations: operations, fileIdentities: fileIdentities}, nil
}

func canonicalSigningPath(path, label string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s path is empty", label)
	}
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("%s path contains NUL", label)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	return filepath.Clean(absolute), nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
		return err
	}
	return nil
}

func scanJSONValueForDuplicateKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValueForDuplicateKeys(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}

	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	expectedClosing := json.Delim('}')
	if delimiter == '[' {
		expectedClosing = ']'
	}
	if closing != expectedClosing {
		return fmt.Errorf("unexpected JSON delimiter %q", closing)
	}
	return nil
}

func readSigningSettingsManifest(path string) (*signingSettingsManifest, error) {
	data, err := readSigningRegularFile(path, signingSettingsMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read settings file %s: %w", path, err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, newSigningInputError(fmt.Errorf("decode settings file %s: %w", path, err))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest signingSettingsManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, newSigningInputError(fmt.Errorf("decode settings file %s: %w", path, err))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, newSigningInputError(fmt.Errorf("decode settings file %s: multiple JSON values", path))
		}
		return nil, newSigningInputError(fmt.Errorf("decode settings file %s: %w", path, err))
	}
	if manifest.SchemaVersion != signingPlanSchemaVersion {
		return nil, newSigningInputError(fmt.Errorf("settings file schemaVersion must be %d", signingPlanSchemaVersion))
	}
	if len(manifest.Targets) == 0 {
		return nil, newSigningInputError(fmt.Errorf("settings file targets must not be empty"))
	}
	return &manifest, nil
}

func normalizeSigningRequests(manifest *signingSettingsManifest) ([]signingRequest, []SigningPlanTarget, error) {
	requests := make([]signingRequest, 0)
	desired := make([]SigningPlanTarget, 0, len(manifest.Targets))
	seenTargets := make(map[string]bool)
	for _, target := range manifest.Targets {
		name := strings.TrimSpace(target.Name)
		if err := validateSigningName(name, "target"); err != nil {
			return nil, nil, err
		}
		if seenTargets[name] {
			return nil, nil, fmt.Errorf("settings file contains duplicate target %q", name)
		}
		seenTargets[name] = true
		if len(target.Configurations) == 0 {
			return nil, nil, fmt.Errorf("target %q configurations must not be empty", name)
		}
		seenConfigurations := make(map[string]bool)
		planTarget := SigningPlanTarget{Target: name}
		for _, configuration := range target.Configurations {
			configurationName := strings.TrimSpace(configuration.Name)
			if err := validateSigningName(configurationName, "configuration"); err != nil {
				return nil, nil, fmt.Errorf("target %q: %w", name, err)
			}
			if seenConfigurations[configurationName] {
				return nil, nil, fmt.Errorf("target %q contains duplicate configuration %q", name, configurationName)
			}
			seenConfigurations[configurationName] = true
			if len(configuration.Settings) == 0 {
				return nil, nil, fmt.Errorf("target %q configuration %q settings must not be empty", name, configurationName)
			}
			settings, err := normalizeSigningSettings(configuration.Settings)
			if err != nil {
				return nil, nil, fmt.Errorf("target %q configuration %q: %w", name, configurationName, err)
			}
			request := signingRequest{target: name, configuration: configurationName, settings: settings}
			requests = append(requests, request)
			planConfiguration := SigningPlanConfiguration{Name: configurationName}
			for _, setting := range settings {
				planConfiguration.Settings = append(planConfiguration.Settings, SigningPlanSetting{Key: setting.key, Value: cloneSigningString(setting.value)})
			}
			planTarget.Configurations = append(planTarget.Configurations, planConfiguration)
		}
		desired = append(desired, planTarget)
	}
	sort.Slice(desired, func(left, right int) bool { return desired[left].Target < desired[right].Target })
	for index := range desired {
		sort.Slice(desired[index].Configurations, func(left, right int) bool {
			return desired[index].Configurations[left].Name < desired[index].Configurations[right].Name
		})
	}
	return requests, desired, nil
}

func normalizeSigningSettings(raw map[string]json.RawMessage) ([]signingDesiredSetting, error) {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	settings := make([]signingDesiredSetting, 0, len(keys))
	for _, key := range keys {
		if !allowedSigningSetting(key) {
			return nil, fmt.Errorf("unsupported signing setting %q", key)
		}
		value, err := normalizeSigningValue(key, raw[key])
		if err != nil {
			return nil, err
		}
		settings = append(settings, signingDesiredSetting{key: key, value: value})
	}
	return settings, nil
}

func normalizeSigningValue(key string, raw json.RawMessage) (*string, error) {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		if !signingSettingAllowsRemoval(key) {
			return nil, fmt.Errorf("%s does not support null removal", key)
		}
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return nil, fmt.Errorf("%s must be a string or null", key)
	}
	if err := validateSigningStaticValue(key, value); err != nil {
		return nil, err
	}
	value = strings.TrimSpace(value)
	if value == "" && (key == "CODE_SIGN_STYLE" || key == "DEVELOPMENT_TEAM" || key == "PRODUCT_BUNDLE_IDENTIFIER") {
		return nil, fmt.Errorf("%s must not be empty", key)
	}
	switch key {
	case "CODE_SIGN_STYLE":
		switch strings.ToLower(value) {
		case "automatic":
			value = "Automatic"
		case "manual":
			value = "Manual"
		default:
			return nil, fmt.Errorf("CODE_SIGN_STYLE must be automatic or manual")
		}
	case "DEVELOPMENT_TEAM":
		value = strings.ToUpper(value)
		if !signingTeamIDPattern.MatchString(value) {
			return nil, fmt.Errorf("DEVELOPMENT_TEAM must be a 10-character alphanumeric team ID")
		}
	case "PROVISIONING_PROFILE":
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil {
			return nil, fmt.Errorf("PROVISIONING_PROFILE must be a UUID")
		}
		value = parsed.String()
	case "PRODUCT_BUNDLE_IDENTIFIER":
		if !signingBundleIDPattern.MatchString(value) {
			return nil, fmt.Errorf("PRODUCT_BUNDLE_IDENTIFIER must be a reverse-DNS bundle identifier")
		}
	case "CODE_SIGN_ENTITLEMENTS":
		if err := validateSigningRelativePath(value); err != nil {
			return nil, fmt.Errorf("CODE_SIGN_ENTITLEMENTS: %w", err)
		}
	}
	return stringPtr(value), nil
}

func validateSigningStaticValue(key, value string) error {
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s must not contain NUL", key)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s must not contain a newline", key)
	}
	if strings.Contains(value, "//") || strings.Contains(value, "/*") || strings.Contains(value, "*/") {
		return fmt.Errorf("%s must not contain comment syntax", key)
	}
	if strings.Contains(value, "$(") || strings.Contains(value, "${") {
		return fmt.Errorf("%s must be a static value without build-setting references", key)
	}
	return nil
}

func validateSigningRelativePath(value string) error {
	if value == "" {
		return fmt.Errorf("path must not be empty")
	}
	if pathpkg.IsAbs(value) || strings.HasPrefix(value, "~") || strings.Contains(value, "\\") || isWindowsDrivePath(value) {
		return fmt.Errorf("path must be relative and use POSIX separators")
	}
	clean := pathpkg.Clean(value)
	if clean == "." || clean != value {
		return fmt.Errorf("path must not contain traversal or redundant components")
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." || component == "" {
			return fmt.Errorf("path must stay within the project")
		}
	}
	return nil
}

func isWindowsDrivePath(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':'
}

func validateSigningName(value, label string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	if strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s must not contain control characters", label)
	}
	return nil
}

func allowedSigningSetting(key string) bool {
	switch key {
	case "CODE_SIGN_STYLE", "DEVELOPMENT_TEAM", "CODE_SIGN_IDENTITY", "PROVISIONING_PROFILE_SPECIFIER", "PROVISIONING_PROFILE", "CODE_SIGN_ENTITLEMENTS", "PRODUCT_BUNDLE_IDENTIFIER":
		return true
	default:
		return false
	}
}

func signingSettingAllowsRemoval(key string) bool {
	switch key {
	case "CODE_SIGN_IDENTITY", "PROVISIONING_PROFILE_SPECIFIER", "PROVISIONING_PROFILE", "CODE_SIGN_ENTITLEMENTS":
		return true
	default:
		return false
	}
}

func signingConfigurationFor(project *structuredVersionProject, target, configuration string) (*versionConfiguration, error) {
	targetMatches := 0
	for _, candidate := range project.project.Proj.Targets {
		if candidate.Name == target {
			targetMatches++
		}
	}
	if targetMatches > 1 {
		return nil, fmt.Errorf("project contains multiple targets named %q", target)
	}
	var match *versionConfiguration
	for _, candidate := range project.configurations {
		if !candidate.projectLevel && candidate.target == target && candidate.name == configuration {
			if match != nil {
				return nil, fmt.Errorf("target %q contains multiple configurations named %q", target, configuration)
			}
			match = candidate
		}
	}
	if match != nil {
		return match, nil
	}
	return nil, fmt.Errorf("configuration %q not found for target %q", configuration, target)
}

func inspectSigningCandidate(
	project *structuredVersionProject,
	configuration *versionConfiguration,
	setting signingDesiredSetting,
	configFiles map[string][]string,
	fileConsumers map[string]map[string]bool,
	fileIdentities map[string]string,
	requestedSettings map[string]map[string]bool,
	requestedValues map[string]map[string]*string,
	uncertainConsumers bool,
	allowExternal bool,
	lexicalConfigPaths map[string][]string,
) (signingCandidate, string, string) {
	candidate := signingCandidate{configuration: configuration, setting: setting.key, desired: cloneSigningString(setting.value)}
	if !signingConfigurationSourcesAuthorized(project, configuration, configFiles) {
		return candidate, signingSettingBlocker(configuration, setting.key, errors.New("configuration inherits from an xcconfig that was not authorized or could not be read")), ""
	}
	resolver := newSigningSettingResolver(project, configFiles, allowExternal, lexicalConfigPaths)
	if setting.key == "CODE_SIGN_ENTITLEMENTS" && setting.value != nil {
		if err := validateSigningEntitlementsPath(project, *setting.value); err != nil {
			return candidate, signingSettingBlocker(configuration, setting.key, fmt.Errorf("validate path %q: %w", *setting.value, err)), ""
		}
	}
	keys := matchingBuildSettingKeys(configuration.buildSettings, setting.key)
	if len(keys) > 0 {
		old, _, err := resolver.resolveSetting(configuration, setting.key)
		if err != nil {
			return candidate, signingSettingBlocker(configuration, setting.key, err), ""
		}
		candidate.old = stringPtr(old)
		candidate.resolution = "direct"
		if signingValuesEqual(setting.value, candidate.old) {
			if signingDirectValueDependsOnRequestedChange(configuration, setting.key, requestedValues[configuration.id], resolver) {
				// The requested effective value currently happens to match the
				// resolved direct assignment, but that assignment references a
				// setting changed by this same plan. Materialize the requested
				// value so the dependent edit cannot silently change this setting.
				candidate.mode = "pbxproj"
				return candidate, "", ""
			}
			// A direct assignment that still defers to $(inherited) keeps a live
			// dependency on the xcconfig supplying that value. Retain it as a
			// no-op consumer so shared-file resolution can see the disagreement
			// when a sibling configuration wants a different value in the same
			// file; otherwise rewriting that file would silently change this
			// configuration's effective value.
			if setting.value != nil && signingDirectValueInherits(configuration, setting.key) {
				assignmentFiles, assignmentErr := xcconfigFilesDefiningWithReader(configFiles[configuration.id], setting.key, resolver.readXCConfig)
				if assignmentErr != nil {
					return candidate, signingSettingBlocker(configuration, setting.key, assignmentErr), ""
				}
				if len(assignmentFiles) > 0 {
					depends, dependencyErr := signingXCConfigValueDependsOnRequestedChange(
						configuration,
						setting.key,
						assignmentFiles,
						requestedValues[configuration.id],
						resolver,
					)
					if dependencyErr != nil {
						return candidate, signingSettingBlocker(configuration, setting.key, dependencyErr), ""
					}
					if depends {
						// The direct assignment inherits a lower xcconfig value
						// that depends on another requested change. Preserve this
						// configuration's current effective value explicitly.
						candidate.mode = "pbxproj"
						return candidate, "", ""
					}
					candidate.mode = "xcconfig"
					candidate.paths = append(candidate.paths, assignmentFiles...)
					candidate.noOp = true
				}
			}
			return candidate, "", ""
		}
		candidate.mode = "pbxproj"
		return candidate, "", ""
	}

	assignmentFiles, err := xcconfigFilesDefiningWithReader(configFiles[configuration.id], setting.key, resolver.readXCConfig)
	if err != nil {
		return candidate, signingSettingBlocker(configuration, setting.key, err), ""
	}
	old, _, resolveErr := resolver.resolveSetting(configuration, setting.key)
	if resolveErr == nil {
		candidate.old = stringPtr(old)
		if len(assignmentFiles) > 0 {
			candidate.resolution = "xcconfig"
		} else {
			candidate.resolution = "inherited"
		}
	} else if !errors.Is(resolveErr, errVersionSettingNotFound) {
		return candidate, signingSettingBlocker(configuration, setting.key, resolveErr), ""
	} else {
		candidate.resolution = "missing"
	}
	if signingValuesEqual(setting.value, candidate.old) {
		if len(assignmentFiles) > 0 && setting.value != nil {
			depends, dependencyErr := signingXCConfigValueDependsOnRequestedChange(
				configuration,
				setting.key,
				assignmentFiles,
				requestedValues[configuration.id],
				resolver,
			)
			if dependencyErr != nil {
				return candidate, signingSettingBlocker(configuration, setting.key, dependencyErr), ""
			}
			if depends {
				// The requested effective value currently happens to match the
				// resolved xcconfig value, but that assignment references a
				// setting changed by this same plan. Materialize the requested
				// value so the dependent edit cannot silently change this setting.
				candidate.mode = "pbxproj"
				return candidate, "", ""
			}
			candidate.mode = "xcconfig"
			candidate.paths = append(candidate.paths, assignmentFiles...)
			candidate.noOp = true
		}
		if len(assignmentFiles) == 0 && setting.value != nil {
			depends, dependencyErr := signingRawSettingDependsOnRequestedChange(
				configuration,
				setting.key,
				requestedValues[configuration.id],
				resolver,
			)
			if dependencyErr != nil {
				return candidate, signingSettingBlocker(configuration, setting.key, dependencyErr), ""
			}
			if depends {
				// The matching value is supplied by a project-level fallback or
				// another inherited layer. Materialize it before a dependent
				// requested setting can change that fallback's effective value.
				candidate.mode = "pbxproj"
				return candidate, "", ""
			}
		}
		return candidate, "", ""
	}

	if setting.value == nil {
		return candidate, fmt.Sprintf("target %q configuration %q cannot remove inherited %s; only a direct project assignment can be removed", configuration.target, configuration.name, setting.key), ""
	}
	if len(assignmentFiles) > 0 {
		if uncertainConsumers {
			candidate.mode = "pbxproj"
			return candidate, "", "xcconfig consumer scope is uncertain; using a target-level override for " + setting.key
		}
		if !consumersAuthorizeSetting(assignmentFiles, fileConsumers, fileIdentities, requestedSettings, setting.key) {
			candidate.mode = "pbxproj"
			return candidate, "", "shared xcconfig is consumed by a configuration that did not request " + setting.key + "; using a target-level override"
		}
		warning := ""
		for _, path := range assignmentFiles {
			if err := project.checkXCConfigWritable(path, allowExternal); err != nil {
				return candidate, fmt.Sprintf("target %q configuration %q cannot update %s in xcconfig %s: %v", configuration.target, configuration.name, setting.key, path, err), ""
			}
			if err := validateSigningXCConfigPath(project, path, allowExternal); err != nil {
				return candidate, fmt.Sprintf("target %q configuration %q cannot update xcconfig %s: %v", configuration.target, configuration.name, path, err), ""
			}
			if allowExternal && !signingPathContained(project, path) {
				if warning == "" {
					warning = fmt.Sprintf("external xcconfig %s is authorized for %s", path, setting.key)
				}
			}
		}
		candidate.mode = "xcconfig"
		candidate.paths = append(candidate.paths, assignmentFiles...)
		return candidate, "", warning
	}

	// Project-level inheritance is deliberately shadowed at the selected
	// target/configuration. This avoids widening a change to other targets.
	candidate.mode = "pbxproj"
	return candidate, "", ""
}

// signingDirectValueInherits reports whether a direct project assignment for
// setting still defers to a lower-level value through $(inherited). Such a
// configuration keeps depending on the xcconfig that supplies the inherited
// value even when its resolved value already matches the requested one.
func signingDirectValueInherits(configuration *versionConfiguration, setting string) bool {
	for _, key := range matchingBuildSettingKeys(configuration.buildSettings, setting) {
		switch value := configuration.buildSettings[key].(type) {
		case string:
			if signingValueInherits(value) {
				return true
			}
		case []any:
			for _, element := range value {
				if text, ok := element.(string); ok && signingValueInherits(text) {
					return true
				}
			}
		}
	}
	return false
}

// signingDirectValueDependsOnRequestedChange reports whether a direct
// assignment references another setting whose requested value changes from
// the value currently resolved in this configuration. A matching no-op must
// be materialized in that case; otherwise a later dependent edit can change
// the effective value of the supposedly untouched setting.
func signingDirectValueDependsOnRequestedChange(
	configuration *versionConfiguration,
	setting string,
	settingValues map[string]*string,
	resolver *signingSettingResolver,
) bool {
	if configuration == nil || resolver == nil || len(settingValues) == 0 {
		return false
	}
	for _, key := range matchingBuildSettingKeys(configuration.buildSettings, setting) {
		value, ok := configuration.buildSettings[key].(string)
		if !ok {
			continue
		}
		if signingValueDependsOnRequestedChange(
			configuration,
			setting,
			value,
			settingValues,
			resolver,
			map[string]bool{setting: true},
			0,
			"direct",
		) {
			return true
		}
	}
	return false
}

type signingRawSettingValue struct {
	value  string
	source string
}

// signingValueDependsOnRequestedChange walks the complete build-setting
// reference graph rooted at value. A no-op is unsafe when any transitive
// reference reaches a requested setting whose effective value will change.
// Resolution or graph-inspection failures conservatively report a dependency
// so an uncertain no-op is materialized instead of silently changing later.
func signingValueDependsOnRequestedChange(
	configuration *versionConfiguration,
	setting string,
	value string,
	settingValues map[string]*string,
	resolver *signingSettingResolver,
	stack map[string]bool,
	depth int,
	source string,
) bool {
	for _, match := range signingReferencePattern.FindAllStringSubmatch(value, -1) {
		name := match[1]
		if name == "" {
			name = match[3]
		}
		if name == "" {
			continue
		}
		if name == "inherited" {
			if depth == 0 {
				continue
			}
			values, err := signingRawInheritedSettingValues(configuration, setting, source, resolver)
			if err != nil {
				return true
			}
			for _, lowerValue := range values {
				if signingValueDependsOnRequestedChange(
					configuration,
					setting,
					lowerValue.value,
					settingValues,
					resolver,
					stack,
					depth+1,
					lowerValue.source,
				) {
					return true
				}
			}
			continue
		}
		if stack[name] {
			return true
		}
		nextStack := make(map[string]bool, len(stack)+1)
		for key, present := range stack {
			nextStack[key] = present
		}
		nextStack[name] = true
		desired, requested := settingValues[name]
		if requested {
			current, _, err := resolver.resolveSetting(configuration, name)
			if err != nil || !signingValuesEqual(stringPtr(current), desired) {
				return true
			}
		}
		values, err := signingRawSettingValues(configuration, name, resolver)
		if err != nil {
			return true
		}
		for _, referencedValue := range values {
			if signingValueDependsOnRequestedChange(
				configuration,
				name,
				referencedValue.value,
				settingValues,
				resolver,
				nextStack,
				depth+1,
				referencedValue.source,
			) {
				return true
			}
		}
	}
	return false
}

func signingRawSettingValues(
	configuration *versionConfiguration,
	setting string,
	resolver *signingSettingResolver,
) ([]signingRawSettingValue, error) {
	if configuration == nil || resolver == nil {
		return nil, fmt.Errorf("cannot inspect %s dependencies without a resolver", setting)
	}
	if keys := matchingBuildSettingKeys(configuration.buildSettings, setting); len(keys) > 0 {
		values := make([]signingRawSettingValue, 0, len(keys))
		for _, key := range keys {
			value, ok := configuration.buildSettings[key].(string)
			if !ok {
				return nil, fmt.Errorf("%s has a non-string build setting value", key)
			}
			values = append(values, signingRawSettingValue{value: value, source: "direct"})
		}
		return values, nil
	}

	paths := resolver.configFiles[configuration.id]
	if len(paths) > 0 {
		values, err := signingRawXCConfigSettingValues(configuration, setting, resolver)
		if err != nil {
			return nil, err
		}
		if len(values) > 0 {
			return values, nil
		}
	}

	if !configuration.projectLevel {
		return signingRawSettingValues(resolver.project.projectConfiguration(configuration.name), setting, resolver)
	}
	return nil, nil
}

func signingRawInheritedSettingValues(
	configuration *versionConfiguration,
	setting, source string,
	resolver *signingSettingResolver,
) ([]signingRawSettingValue, error) {
	if source == "xcconfig" {
		if configuration == nil || configuration.projectLevel {
			return nil, nil
		}
		return signingRawSettingValues(resolver.project.projectConfiguration(configuration.name), setting, resolver)
	}
	if configuration == nil {
		return nil, fmt.Errorf("cannot inspect %s inherited dependency without a configuration", setting)
	}
	if configuration.baseReferenceID != "" {
		values, err := signingRawXCConfigSettingValues(configuration, setting, resolver)
		if err != nil {
			return nil, err
		}
		if len(values) > 0 {
			return values, nil
		}
	}
	if !configuration.projectLevel {
		return signingRawSettingValues(resolver.project.projectConfiguration(configuration.name), setting, resolver)
	}
	return nil, nil
}

func signingRawXCConfigSettingValues(
	configuration *versionConfiguration,
	setting string,
	resolver *signingSettingResolver,
) ([]signingRawSettingValue, error) {
	paths := resolver.configFiles[configuration.id]
	if len(paths) == 0 {
		return nil, nil
	}
	defining, err := xcconfigFilesDefiningWithReader(paths, setting, resolver.readXCConfig)
	if err != nil {
		return nil, err
	}
	values := make([]signingRawSettingValue, 0, len(defining))
	for _, path := range defining {
		data, err := resolver.readXCConfig(path)
		if err != nil {
			return nil, err
		}
		document, err := parseXCConfig(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, assignment := range document.assignments {
			if assignment.baseKey == setting {
				values = append(values, signingRawSettingValue{value: assignment.value, source: "xcconfig"})
			}
		}
	}
	return values, nil
}

func signingRawSettingDependsOnRequestedChange(
	configuration *versionConfiguration,
	setting string,
	settingValues map[string]*string,
	resolver *signingSettingResolver,
) (bool, error) {
	if configuration == nil || resolver == nil || len(settingValues) == 0 {
		return false, nil
	}
	values, err := signingRawSettingValues(configuration, setting, resolver)
	if err != nil {
		return false, err
	}
	for _, raw := range values {
		if signingValueDependsOnRequestedChange(
			configuration,
			setting,
			raw.value,
			settingValues,
			resolver,
			map[string]bool{setting: true},
			0,
			raw.source,
		) {
			return true, nil
		}
	}
	return false, nil
}

// signingXCConfigValueDependsOnRequestedChange reports whether an assignment
// that currently supplies a matching no-op value references another setting
// whose requested value changes. Rewriting that other assignment would change
// the effective value of this setting unless the no-op is materialized at the
// target level.
func signingXCConfigValueDependsOnRequestedChange(
	configuration *versionConfiguration,
	setting string,
	paths []string,
	settingValues map[string]*string,
	resolver *signingSettingResolver,
) (bool, error) {
	if configuration == nil || resolver == nil || len(paths) == 0 || len(settingValues) == 0 {
		return false, nil
	}
	for _, path := range paths {
		data, err := resolver.readXCConfig(path)
		if err != nil {
			return false, fmt.Errorf("read xcconfig %s while checking %s dependencies: %w", path, setting, err)
		}
		document, err := parseXCConfig(data)
		if err != nil {
			return false, fmt.Errorf("parse %s while checking %s dependencies: %w", path, setting, err)
		}
		for _, assignment := range document.assignments {
			if assignment.baseKey != setting {
				continue
			}
			if signingValueDependsOnRequestedChange(
				configuration,
				setting,
				assignment.value,
				settingValues,
				resolver,
				map[string]bool{setting: true},
				0,
				"xcconfig",
			) {
				return true, nil
			}
		}
	}
	return false, nil
}

func signingValueInherits(value string) bool {
	return strings.Contains(value, "$(inherited)") || strings.Contains(value, "${inherited}")
}

func signingConfigurationSourcesAuthorized(
	project *structuredVersionProject,
	configuration *versionConfiguration,
	configFiles map[string][]string,
) bool {
	for current := configuration; current != nil; {
		if current.baseReferenceID != "" {
			if _, ok := configFiles[current.id]; !ok {
				return false
			}
		}
		if current.projectLevel {
			break
		}
		current = project.projectConfiguration(current.name)
	}
	return true
}

// signingSettingResolver is the signing workflow's authorization-aware
// counterpart to structuredVersionProject.resolveSetting. Its xcconfig reads
// are limited to paths successfully collected for this plan; this keeps a
// later setting-resolution pass from reopening an unselected or redirected
// external include through the generic resolver.
type signingSettingResolver struct {
	project     *structuredVersionProject
	configFiles map[string][]string
	// lexicalConfigPaths retains every path the collector observed for each
	// configuration, including a directly missing optional include. It is used
	// only to authorize the later no-follow existence check; reads still
	// require membership in authorizedPath (the successfully collected files).
	lexicalConfigPaths map[string][]string
	authorizedPath     map[string]bool
	allowExternal      bool
}

func newSigningSettingResolver(project *structuredVersionProject, configFiles map[string][]string, allowExternal bool, lexicalConfigPaths map[string][]string) *signingSettingResolver {
	resolver := &signingSettingResolver{
		project:            project,
		configFiles:        configFiles,
		lexicalConfigPaths: lexicalConfigPaths,
		authorizedPath:     make(map[string]bool),
		allowExternal:      allowExternal,
	}
	for _, paths := range configFiles {
		for _, path := range paths {
			resolver.authorizedPath[signingLexicalPathKey(path)] = true
		}
	}
	return resolver
}

func (resolver *signingSettingResolver) readXCConfig(path string) ([]byte, error) {
	absolute := normalizeSigningLexicalPath(path)
	if !resolver.authorizedPath[signingLexicalPathKey(absolute)] {
		return nil, fmt.Errorf("xcconfig %s was not collected for this signing plan", absolute)
	}
	if err := resolver.authorizeXCConfigPath(absolute); err != nil {
		return nil, err
	}
	return signingXCConfigReadFileFn(absolute, signingPlanMaxBytes)
}

func (resolver *signingSettingResolver) statXCConfigFor(configuration *versionConfiguration, path string) (os.FileInfo, error) {
	absolute := normalizeSigningLexicalPath(path)
	key := signingLexicalPathKey(absolute)
	if !resolver.configurationCollectedPath(configuration, key) {
		known := false
		if configuration != nil {
			for _, observed := range resolver.lexicalConfigPaths[configuration.id] {
				if signingLexicalPathKey(observed) == key {
					known = true
					break
				}
			}
		}
		if !known {
			return nil, fmt.Errorf("xcconfig %s was not collected for this signing plan", absolute)
		}
		if err := resolver.authorizeXCConfigPath(absolute); err != nil {
			return nil, err
		}
		info, err := signingXCConfigStatFileFn(absolute)
		if err != nil {
			return nil, err
		}
		if info != nil {
			return nil, fmt.Errorf("xcconfig %s appeared after configuration collection", absolute)
		}
		return nil, os.ErrNotExist
	}
	if err := resolver.authorizeXCConfigPath(absolute); err != nil {
		return nil, err
	}
	return signingXCConfigStatFileFn(absolute)
}

func (resolver *signingSettingResolver) readXCConfigFor(configuration *versionConfiguration, path string) ([]byte, error) {
	absolute := normalizeSigningLexicalPath(path)
	if !resolver.configurationCollectedPath(configuration, signingLexicalPathKey(absolute)) {
		return nil, fmt.Errorf("xcconfig %s was not collected for this configuration", absolute)
	}
	return resolver.readXCConfig(absolute)
}

func (resolver *signingSettingResolver) configurationCollectedPath(configuration *versionConfiguration, key string) bool {
	if configuration == nil {
		return false
	}
	for _, collected := range resolver.configFiles[configuration.id] {
		if signingLexicalPathKey(collected) == key {
			return true
		}
	}
	return false
}

func (resolver *signingSettingResolver) authorizeXCConfigPath(path string) error {
	if !resolver.allowExternal && !signingPathLexicallyContained(resolver.project, path) {
		return fmt.Errorf("external xcconfig %s requires --allow-external-xcconfig", path)
	}
	return validateSigningXCConfigPath(resolver.project, path, resolver.allowExternal)
}

func (resolver *signingSettingResolver) resolveSetting(configuration *versionConfiguration, setting string) (string, string, error) {
	value, ok, err := directBuildSetting(configuration.buildSettings, setting)
	if err != nil {
		return "", "", err
	}
	if ok {
		return resolver.expandDirectSetting(configuration, setting, value, map[string]bool{setting: true})
	}
	if configuration.baseReferenceID != "" {
		path, err := resolver.project.fileReferencePath(configuration.baseReferenceID)
		if err != nil {
			return "", "", err
		}
		resolved, err := resolver.resolveConfigurationXCConfig(configuration, path, setting)
		if err != nil {
			return "", "", err
		}
		if resolved.found {
			value, _, err := resolver.expandSettingReferences(configuration, resolved.value, map[string]bool{setting: true})
			return value, resolved.path, err
		}
	}
	if !configuration.projectLevel {
		if projectConfiguration := resolver.project.projectConfiguration(configuration.name); projectConfiguration != nil {
			return resolver.resolveSetting(projectConfiguration, setting)
		}
	}
	return "", "", fmt.Errorf("%s: %w", setting, errVersionSettingNotFound)
}

func (resolver *signingSettingResolver) expandDirectSetting(
	configuration *versionConfiguration,
	setting, value string,
	stack map[string]bool,
) (string, string, error) {
	if strings.Contains(value, "$(inherited)") || strings.Contains(value, "${inherited}") {
		inherited, _, err := resolver.resolveLowerSetting(configuration, setting)
		if err != nil {
			return "", "", fmt.Errorf("resolve inherited %s: %w", setting, err)
		}
		value = strings.ReplaceAll(value, "$(inherited)", inherited)
		value = strings.ReplaceAll(value, "${inherited}", inherited)
	}
	return resolver.expandSettingReferences(configuration, value, stack)
}

func (resolver *signingSettingResolver) resolveLowerSetting(configuration *versionConfiguration, setting string) (string, string, error) {
	if configuration.baseReferenceID != "" {
		path, err := resolver.project.fileReferencePath(configuration.baseReferenceID)
		if err != nil {
			return "", "", err
		}
		resolved, err := resolver.resolveConfigurationXCConfig(configuration, path, setting)
		if err != nil {
			return "", "", err
		}
		if resolved.found {
			value, _, err := resolver.expandSettingReferences(configuration, resolved.value, map[string]bool{setting: true})
			return value, resolved.path, err
		}
	}
	if !configuration.projectLevel {
		if fallback := resolver.project.projectConfiguration(configuration.name); fallback != nil {
			return resolver.resolveSetting(fallback, setting)
		}
	}
	return "", "", fmt.Errorf("%s: %w", setting, errVersionSettingNotFound)
}

func (resolver *signingSettingResolver) resolveSettingReference(configuration *versionConfiguration, setting string, stack map[string]bool) (string, string, error) {
	value, ok, err := directBuildSetting(configuration.buildSettings, setting)
	if err != nil {
		return "", "", err
	}
	if ok {
		return resolver.expandDirectSetting(configuration, setting, value, stack)
	}
	if configuration.baseReferenceID != "" {
		path, err := resolver.project.fileReferencePath(configuration.baseReferenceID)
		if err != nil {
			return "", "", err
		}
		resolved, err := resolver.resolveConfigurationXCConfig(configuration, path, setting)
		if err != nil {
			return "", "", err
		}
		if resolved.found {
			value, _, err := resolver.expandSettingReferences(configuration, resolved.value, stack)
			return value, resolved.path, err
		}
	}
	if !configuration.projectLevel {
		if fallback := resolver.project.projectConfiguration(configuration.name); fallback != nil {
			return resolver.resolveSettingReference(fallback, setting, stack)
		}
	}
	return "", "", fmt.Errorf("setting not found")
}

func (resolver *signingSettingResolver) resolveConfigurationXCConfig(
	configuration *versionConfiguration,
	path, setting string,
) (xcconfigResolvedValue, error) {
	base := xcconfigResolvedValue{}
	if !configuration.projectLevel {
		if fallback := resolver.project.projectConfiguration(configuration.name); fallback != nil {
			value, source, err := resolver.resolveSetting(fallback, setting)
			if err == nil {
				base = xcconfigResolvedValue{value: value, path: source, found: true}
			} else if !errors.Is(err, errVersionSettingNotFound) {
				// A direct '=' assignment in the target xcconfig overrides the
				// project-level value and does not depend on it. Probe with and
				// without a private sentinel so only ?=/+=/inherited resolution
				// paths retain a fallback error as a blocker.
				if resolver.xcconfigDependsOnFallback(configuration, path, setting) {
					return xcconfigResolvedValue{}, fmt.Errorf("resolve project-level fallback for %s: %w", setting, err)
				}
			}
		}
	}
	stat := func(includePath string) (os.FileInfo, error) {
		return resolver.statXCConfigFor(configuration, includePath)
	}
	read := func(includePath string) ([]byte, error) {
		return resolver.readXCConfigFor(configuration, includePath)
	}
	return resolveXCConfigSettingWithBaseReader(
		path,
		setting,
		base,
		read,
		stat,
	)
}

// xcconfigDependsOnFallback distinguishes a target xcconfig that semantically
// consumes its project-level base from one that replaces it with a direct
// assignment. The probe is read-only and uses the same authorization-aware
// callbacks as normal resolution. A sentinel is intentionally private: it is
// only compared inside this helper and is never surfaced in a plan or error.
func (resolver *signingSettingResolver) xcconfigDependsOnFallback(configuration *versionConfiguration, path, setting string) bool {
	stat := func(includePath string) (os.FileInfo, error) {
		return resolver.statXCConfigFor(configuration, includePath)
	}
	read := func(includePath string) ([]byte, error) {
		return resolver.readXCConfigFor(configuration, includePath)
	}
	withoutBase, withoutErr := resolveXCConfigSettingWithBaseReader(
		path,
		setting,
		xcconfigResolvedValue{},
		read,
		stat,
	)
	const sentinel = "__asc_signing_project_fallback_sentinel__"
	withBase, withErr := resolveXCConfigSettingWithBaseReader(
		path,
		setting,
		xcconfigResolvedValue{value: sentinel, path: resolver.project.pbxprojPath, found: true, exact: true},
		read,
		stat,
	)
	if withoutErr != nil || withErr != nil {
		// If one probe succeeds and the other does not, the base changes the
		// result. When both fail, the target's own error is returned by the
		// normal resolution below and the fallback error is not needed.
		return (withoutErr == nil) != (withErr == nil)
	}
	return withoutBase.value != withBase.value ||
		withoutBase.found != withBase.found ||
		withoutBase.exact != withBase.exact ||
		withoutBase.missingInherited != withBase.missingInherited
}

func (resolver *signingSettingResolver) expandSettingReferences(configuration *versionConfiguration, value string, stack map[string]bool) (string, string, error) {
	resolved := value
	for iteration := 0; iteration < 32; iteration++ {
		match := signingReferencePattern.FindStringSubmatchIndex(resolved)
		if match == nil {
			if strings.Contains(resolved, "$(") || strings.Contains(resolved, "${") {
				return "", "", fmt.Errorf("incomplete build-setting reference")
			}
			return strings.TrimSpace(resolved), resolver.project.pbxprojPath, nil
		}
		name := ""
		if match[2] >= 0 {
			name = resolved[match[2]:match[3]]
		} else {
			name = resolved[match[6]:match[7]]
		}
		if match[4] >= 0 || match[8] >= 0 {
			return "", "", fmt.Errorf("build-setting reference modifier for %s is unsupported", name)
		}
		if stack[name] {
			return "", "", fmt.Errorf("build-setting reference cycle at %s", name)
		}
		nextStack := make(map[string]bool, len(stack)+1)
		for key, set := range stack {
			nextStack[key] = set
		}
		nextStack[name] = true
		replacement, _, err := resolver.resolveSettingReference(configuration, name, nextStack)
		if err != nil {
			return "", "", fmt.Errorf("unresolved build-setting reference %s", name)
		}
		resolved = resolved[:match[0]] + replacement + resolved[match[1]:]
	}
	return "", "", fmt.Errorf("too many nested build-setting references")
}

// validateSigningEntitlementsPath binds a non-null CODE_SIGN_ENTITLEMENTS
// value to the selected project root. It requires an existing regular file
// and rejects symlinked parent or final components before a plan is ready.
func validateSigningEntitlementsPath(project *structuredVersionProject, path string) error {
	root, err := rootfs.New(project.rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func resolveSigningSharedCandidates(candidates []signingCandidate, fileIdentities map[string]string) {
	desiredByFile := make(map[string]string)
	conflictByFile := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate.mode != "xcconfig" || candidate.desired == nil {
			continue
		}
		for _, path := range candidate.paths {
			key := signingXCConfigOperationKey(path, fileIdentities) + "\x00" + candidate.setting
			value := *candidate.desired
			if previous, exists := desiredByFile[key]; exists && previous != value {
				conflictByFile[key] = true
				continue
			}
			desiredByFile[key] = value
		}
	}
	for index := range candidates {
		if candidates[index].mode != "xcconfig" {
			continue
		}
		for _, path := range candidates[index].paths {
			if conflictByFile[signingXCConfigOperationKey(path, fileIdentities)+"\x00"+candidates[index].setting] {
				candidates[index].mode = "pbxproj"
				candidates[index].paths = nil
				break
			}
		}
	}
}

// signingXCConfigOperationKey groups authorized xcconfig paths by the
// filesystem identity captured during collection. This is important on
// case-insensitive macOS volumes, where two operator spellings can name the
// same file even though their lexical paths differ. Missing or uncollected
// paths retain the platform lexical key; prepared signing operations only
// accept paths that were successfully collected and identity-bound.
func signingXCConfigOperationKey(path string, fileIdentities map[string]string) string {
	pathKey := signingLexicalPathKey(path)
	if identity, ok := fileIdentities[pathKey]; ok && identity != "" {
		return "identity:" + identity
	}
	return "path:" + pathKey
}

func signingSettingBlocker(configuration *versionConfiguration, setting string, err error) string {
	return fmt.Sprintf("target %q configuration %q cannot resolve %s: %v", configuration.target, configuration.name, setting, err)
}

func validateSigningXCConfigWrite(resolver *signingSettingResolver, path, setting string, desired *string) error {
	if desired == nil {
		return nil
	}
	if xcconfigValueHasLineContinuation(*desired) {
		return fmt.Errorf("desired value has a trailing backslash that would continue the xcconfig assignment")
	}
	data, err := resolver.readXCConfig(path)
	if err != nil {
		return err
	}
	document, err := parseXCConfig(data)
	if err != nil {
		return err
	}
	for _, assignment := range document.assignments {
		if assignment.baseKey != setting || assignment.quote == "" {
			continue
		}
		if strings.Contains(*desired, assignment.quote) {
			return fmt.Errorf("desired value contains the quote delimiter used by the xcconfig assignment")
		}
	}
	return nil
}

func signingValuesEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func signingChange(candidate *signingCandidate, path, source string) SigningSettingChange {
	operation := "set"
	if candidate.desired == nil {
		operation = "remove"
	}
	return SigningSettingChange{
		Target:        candidate.configuration.target,
		Configuration: candidate.configuration.name,
		Setting:       candidate.setting,
		Operation:     operation,
		OldValue:      cloneSigningString(candidate.old),
		NewValue:      cloneSigningString(candidate.desired),
		Path:          path,
		Source:        source,
		Resolution:    candidate.resolution,
	}
}

func signingPathContained(project *structuredVersionProject, path string) bool {
	root, err := rootfs.New(project.rootDir)
	if err != nil {
		return false
	}
	defer root.Close()
	return root.AllowingInternalSymlinks().CheckContained(path) == nil
}

// normalizeSigningLexicalPath returns the absolute, cleaned spelling used for
// lexical path decisions. It intentionally does not resolve symlinks: lexical
// protection must also cover a path that does not exist yet.
func normalizeSigningLexicalPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(absolute)
}

// signingLexicalPathKey applies the host filesystem's equality semantics to a
// normalized path. Windows paths are case-insensitive even when the protected
// or artifact path is still missing, so SameFile cannot be relied on there.
func signingLexicalPathKey(path string) string {
	path = normalizeSigningLexicalPath(path)
	if runtimeGOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func signingLexicalPathEqual(left, right string) bool {
	return signingLexicalPathKey(left) == signingLexicalPathKey(right)
}

// signingArtifactLexicalPathEqual applies filesystem case semantics only at
// the artifact-alias boundary. General signing path keys retain their
// platform-independent spelling rules; this helper additionally protects
// missing paths on case-insensitive Darwin volumes where SameFile cannot
// inspect an inode yet. Unknown volume metadata is treated conservatively as
// case-insensitive so an uncertain alias cannot reach an artifact write.
func signingArtifactLexicalPathEqual(left, right string) bool {
	left = normalizeSigningLexicalPath(left)
	right = normalizeSigningLexicalPath(right)
	if signingLexicalPathEqual(left, right) {
		return true
	}
	if runtimeGOOS != "darwin" || !strings.EqualFold(left, right) {
		return false
	}
	caseInsensitive, known := signingCaseInsensitiveVolumeFor(left)
	return !known || caseInsensitive
}

func signingPathLexicallyContained(project *structuredVersionProject, path string) bool {
	root := signingLexicalPathKey(project.rootDir)
	absolute := signingLexicalPathKey(path)
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func signingXCConfigCollectionBlocker(project *structuredVersionProject, path string, allowExternal bool) string {
	if !signingPathLexicallyContained(project, path) {
		if !allowExternal {
			return fmt.Sprintf("xcconfig %s is external and could not be read without --allow-external-xcconfig", path)
		}
		return fmt.Sprintf("xcconfig %s is external and could not be safely collected", path)
	}
	return fmt.Sprintf("xcconfig %s could not be safely collected; signing scope is uncertain", path)
}

func appendUniqueSigningPaths(paths []string, additions ...string) []string {
	for _, path := range additions {
		path = normalizeSigningLexicalPath(path)
		if path == "" {
			continue
		}
		found := false
		for _, existing := range paths {
			if signingLexicalPathEqual(existing, path) {
				found = true
				break
			}
		}
		if !found {
			paths = append(paths, path)
		}
	}
	return paths
}

func sortSigningPlanOperations(operations []signingPlanOperation) {
	sort.Slice(operations, func(left, right int) bool {
		first, second := operations[left], operations[right]
		if first.Path != second.Path {
			return first.Path < second.Path
		}
		if first.Target != second.Target {
			return first.Target < second.Target
		}
		if first.Configuration != second.Configuration {
			return first.Configuration < second.Configuration
		}
		return first.Setting < second.Setting
	})
}

func validateSigningProjectFile(project *structuredVersionProject) error {
	root, err := rootfs.New(project.rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.AllowingInternalSymlinks().CheckContained(project.pbxprojPath); err != nil {
		return fmt.Errorf("refusing to use Xcode project file %s: %w", project.pbxprojPath, err)
	}
	return nil
}

func validateSigningArtifactPaths(planPath, receiptPath, projectPath, settingsPath string) error {
	if signingArtifactLexicalPathEqual(planPath, receiptPath) {
		return fmt.Errorf("plan and receipt paths must be different")
	}
	for _, candidate := range []struct {
		label string
		path  string
	}{{"plan", planPath}, {"receipt", receiptPath}} {
		if signingArtifactLexicalPathEqual(candidate.path, projectPath) {
			return fmt.Errorf("%s path must not replace the Xcode project file", candidate.label)
		}
		if signingArtifactLexicalPathEqual(candidate.path, settingsPath) {
			return fmt.Errorf("%s path must not replace the settings file", candidate.label)
		}
	}
	return nil
}

// validateSigningArtifactAliases rejects an existing plan or receipt that
// resolves to any source consumed while building the plan. Lexical path
// comparisons do not catch hard-link aliases, while rooted no-follow identity
// checks plus os.SameFile identify existing aliases without mutating the
// filesystem; symlink aliases are rejected by the rooted opener.
func validateSigningArtifactAliases(planPath, receiptPath string, inputPaths, protectedPaths []string) error {
	normalize := func(path string) string {
		return normalizeSigningLexicalPath(path)
	}
	type artifact struct {
		label string
		path  string
	}
	artifacts := []artifact{
		{label: "plan", path: normalize(planPath)},
		{label: "receipt", path: normalize(receiptPath)},
	}
	for _, artifact := range artifacts {
		for _, protectedPath := range protectedPaths {
			if signingArtifactLexicalPathEqual(artifact.path, protectedPath) {
				return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("%s path aliases protected project input %s", artifact.label, artifact.path)))
			}
		}
	}
	if signingArtifactLexicalPathEqual(artifacts[0].path, artifacts[1].path) {
		return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("plan and receipt paths must not alias the same file")))
	}
	artifactInfos := make(map[string]os.FileInfo, len(artifacts))
	for _, artifact := range artifacts {
		info, err := signingArtifactPathInfoFn(artifact.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("inspect %s artifact path %s: %w", artifact.label, artifact.path, err)))
		}
		artifactInfos[artifact.label] = info
	}
	if planInfo, planOK := artifactInfos["plan"]; planOK {
		if receiptInfo, receiptOK := artifactInfos["receipt"]; receiptOK && os.SameFile(planInfo, receiptInfo) {
			return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("plan and receipt paths must not alias the same file")))
		}
	}

	seenInputs := make([]string, 0, len(inputPaths))
	for _, inputPath := range inputPaths {
		if strings.TrimSpace(inputPath) == "" {
			continue
		}
		inputPath = normalize(inputPath)
		duplicate := false
		for _, seenInput := range seenInputs {
			if signingArtifactLexicalPathEqual(seenInput, inputPath) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seenInputs = append(seenInputs, inputPath)
		for _, artifact := range artifacts {
			if signingArtifactLexicalPathEqual(inputPath, artifact.path) {
				return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("%s path aliases project input %s", artifact.label, inputPath)))
			}
		}
		inputInfo, err := signingArtifactPathInfoFn(inputPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect project input %s: %w", inputPath, err)
		}
		for _, artifact := range artifacts {
			artifactInfo, ok := artifactInfos[artifact.label]
			if ok && os.SameFile(artifactInfo, inputInfo) {
				return newSigningInputError(newSigningArtifactAliasError(fmt.Errorf("%s path aliases project input %s", artifact.label, inputPath)))
			}
		}
	}
	return nil
}

func signingProjectInputPaths(
	project *structuredVersionProject,
	settingsPath string,
	configFiles map[string][]string,
	fileIdentities map[string]string,
	requests []signingRequest,
	allowExternal bool,
	lexicalConfigPaths map[string][]string,
) ([]string, []string, []string, error) {
	// Paths that failed collection or authorization are intentionally not added
	// to the readable input set. The caller protects their lexical paths
	// separately, so alias validation never stats an unauthorized or missing
	// path.
	externalEntitlementPaths := make([]string, 0)
	inputBlockers := make([]string, 0)
	paths := []string{project.pbxprojPath, settingsPath}
	selectedIDs := make(map[string]bool, len(requests))
	for _, request := range requests {
		configuration, err := signingConfigurationFor(project, request.target, request.configuration)
		if err == nil {
			selectedIDs[configuration.id] = true
		}
	}
	selectedXCConfigSources := make(map[string]bool)
	for _, configuration := range project.configurations {
		if !selectedIDs[configuration.id] {
			continue
		}
		for current := configuration; current != nil; {
			for _, filePath := range configFiles[current.id] {
				selectedXCConfigSources[signingXCConfigOperationKey(filePath, fileIdentities)] = true
			}
			if current.projectLevel {
				break
			}
			current = project.projectConfiguration(current.name)
		}
	}
	appendEntitlements := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		// Raw project/xcconfig scans can encounter the expression that the
		// authorization-aware resolver already expanded. Do not turn that
		// expression into a synthetic filesystem path; a selected unresolved
		// expression is still reported by the resolver above.
		if strings.Contains(value, "$(") || strings.Contains(value, "${") {
			return nil
		}
		if validateSigningRelativePath(value) == nil {
			paths = append(paths, filepath.Join(project.rootDir, filepath.FromSlash(value)))
			return nil
		}
		if filepath.IsAbs(value) {
			absolute := filepath.Clean(value)
			if !signingPathLexicallyContained(project, absolute) {
				externalEntitlementPaths = appendUniqueSigningPaths(externalEntitlementPaths, absolute)
				return nil
			}
			paths = append(paths, absolute)
			return nil
		}
		return fmt.Errorf("CODE_SIGN_ENTITLEMENTS path %q is invalid and cannot be protected", value)
	}
	appendLexicalEntitlementCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "$(") || strings.Contains(value, "${") {
			return
		}
		candidate := value
		if !filepath.IsAbs(candidate) && !pathpkg.IsAbs(candidate) && !isWindowsDrivePath(candidate) {
			candidate = filepath.Join(project.rootDir, filepath.FromSlash(candidate))
		}
		externalEntitlementPaths = appendUniqueSigningPaths(externalEntitlementPaths, filepath.Clean(candidate))
	}
	isConditionalEntitlementKey := func(key string) bool {
		return key != "CODE_SIGN_ENTITLEMENTS" && xcconfigBaseKey(key) == "CODE_SIGN_ENTITLEMENTS"
	}
	for _, files := range configFiles {
		paths = append(paths, files...)
	}
	for _, request := range requests {
		for _, setting := range request.settings {
			if setting.key == "CODE_SIGN_ENTITLEMENTS" && setting.value != nil {
				if err := appendEntitlements(*setting.value); err != nil {
					return nil, externalEntitlementPaths, inputBlockers, err
				}
			}
		}
	}
	resolver := newSigningSettingResolver(project, configFiles, allowExternal, lexicalConfigPaths)
	appendResolvedEntitlements := func(configuration *versionConfiguration, value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if strings.Contains(value, "$(") || strings.Contains(value, "${") {
			if configuration == nil {
				return fmt.Errorf("CODE_SIGN_ENTITLEMENTS reference cannot be resolved without a configuration")
			}
			// Use the same source-aware expansion as direct build settings. In
			// particular, $(inherited) must resolve against the lower project or
			// xcconfig layer rather than being treated as an ordinary setting
			// reference. This keeps raw PBX and xcconfig scans aligned with the
			// effective resolver and prevents an inherited entitlement path from
			// disappearing from the protected-input inventory.
			expanded, _, err := resolver.expandDirectSetting(configuration, "CODE_SIGN_ENTITLEMENTS", value, map[string]bool{"CODE_SIGN_ENTITLEMENTS": true})
			if err != nil {
				return err
			}
			value = expanded
		}
		return appendEntitlements(value)
	}
	for _, configuration := range project.configurations {
		selected := selectedIDs[configuration.id]
		authorized := signingConfigurationSourcesAuthorized(project, configuration, configFiles)
		if authorized {
			value, _, err := resolver.resolveSetting(configuration, "CODE_SIGN_ENTITLEMENTS")
			if err == nil {
				if err := appendResolvedEntitlements(configuration, value); err != nil {
					if selected {
						return nil, externalEntitlementPaths, inputBlockers, err
					}
					inputBlockers = append(inputBlockers, fmt.Sprintf("target %q configuration %q has an unresolved CODE_SIGN_ENTITLEMENTS input: %v", configuration.target, configuration.name, err))
				}
			} else if !errors.Is(err, errVersionSettingNotFound) {
				resolutionErr := fmt.Errorf("resolve CODE_SIGN_ENTITLEMENTS for target %q configuration %q: %w", configuration.target, configuration.name, err)
				if selected {
					return nil, externalEntitlementPaths, inputBlockers, resolutionErr
				}
				inputBlockers = append(inputBlockers, resolutionErr.Error())
			}
		}
		for _, key := range matchingBuildSettingKeys(configuration.buildSettings, "CODE_SIGN_ENTITLEMENTS") {
			value, ok := configuration.buildSettings[key].(string)
			if ok {
				if !authorized && !selected && (strings.Contains(value, "$(") || strings.Contains(value, "${")) {
					if isConditionalEntitlementKey(key) {
						return nil, externalEntitlementPaths, inputBlockers, newSigningConditionalEntitlementError(nil)
					}
					inputBlockers = append(inputBlockers, fmt.Sprintf("target %q configuration %q has unresolved CODE_SIGN_ENTITLEMENTS reference; signing scope is uncertain", configuration.target, configuration.name))
					continue
				}
				if err := appendResolvedEntitlements(configuration, value); err != nil {
					if isConditionalEntitlementKey(key) {
						return nil, externalEntitlementPaths, inputBlockers, newSigningConditionalEntitlementError(err)
					}
					if selected {
						return nil, externalEntitlementPaths, inputBlockers, err
					}
					inputBlockers = append(inputBlockers, fmt.Sprintf("target %q configuration %q has an unresolved CODE_SIGN_ENTITLEMENTS input: %v", configuration.target, configuration.name, err))
				}
			}
		}
	}
	knownConfigurationIDs := make(map[string]bool, len(project.configurations))
	for _, configuration := range project.configurations {
		knownConfigurationIDs[configuration.id] = true
		files, ok := configFiles[configuration.id]
		if !ok {
			continue
		}
		selected := selectedIDs[configuration.id]
		for _, filePath := range files {
			// These paths came from the successful collector, but keep the
			// membership and authorization checks on this later read as well.
			// This prevents a future caller from turning configFiles into an
			// ambient path list that bypasses the signing resolver's rooted,
			// no-follow policy.
			data, err := resolver.readXCConfig(filePath)
			if err != nil {
				return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("read xcconfig %s: %w", filePath, err)
			}
			document, err := parseXCConfig(data)
			if err != nil {
				return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("parse xcconfig %s: %w", filePath, err)
			}
			for _, assignment := range document.assignments {
				selectedSource := selectedXCConfigSources[signingXCConfigOperationKey(filePath, fileIdentities)]
				if assignment.continued && allowedSigningSetting(assignment.baseKey) &&
					(assignment.baseKey == "CODE_SIGN_ENTITLEMENTS" || selectedSource) {
					return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("xcconfig %s uses a line continuation for signing setting %s", filePath, assignment.baseKey)
				}
				if assignment.baseKey == "CODE_SIGN_ENTITLEMENTS" {
					if err := appendResolvedEntitlements(configuration, assignment.value); err != nil {
						appendLexicalEntitlementCandidate(assignment.value)
						if isConditionalEntitlementKey(assignment.key) {
							return nil, externalEntitlementPaths, inputBlockers, newSigningConditionalEntitlementError(err)
						}
						if selected {
							return nil, externalEntitlementPaths, inputBlockers, err
						}
						inputBlockers = append(inputBlockers, fmt.Sprintf("target %q configuration %q has an invalid CODE_SIGN_ENTITLEMENTS input: %v", configuration.target, configuration.name, err))
					}
				}
			}
		}
	}
	// configFiles is normally keyed only by configurations parsed from the
	// project. Keep this boundary fail-closed for injected or future collector
	// results as well: an unassociated source cannot be safely classified as an
	// unselected consumer, so it must remain readable and representable rather
	// than being silently omitted from the protected-input inventory.
	for configurationID, files := range configFiles {
		if knownConfigurationIDs[configurationID] {
			continue
		}
		for _, filePath := range files {
			data, err := resolver.readXCConfig(filePath)
			if err != nil {
				return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("read xcconfig %s: %w", filePath, err)
			}
			document, err := parseXCConfig(data)
			if err != nil {
				return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("parse xcconfig %s: %w", filePath, err)
			}
			for _, assignment := range document.assignments {
				if assignment.continued && allowedSigningSetting(assignment.baseKey) {
					return nil, externalEntitlementPaths, inputBlockers, fmt.Errorf("xcconfig %s uses a line continuation for signing setting %s", filePath, assignment.baseKey)
				}
				if assignment.baseKey != "CODE_SIGN_ENTITLEMENTS" {
					continue
				}
				if strings.Contains(assignment.value, "$(") || strings.Contains(assignment.value, "${") {
					if isConditionalEntitlementKey(assignment.key) {
						return nil, externalEntitlementPaths, inputBlockers, newSigningConditionalEntitlementError(nil)
					}
				}
				if err := appendEntitlements(assignment.value); err != nil {
					return nil, externalEntitlementPaths, inputBlockers, err
				}
			}
		}
	}
	return paths, externalEntitlementPaths, inputBlockers, nil
}

func validateSigningXCConfigPath(project *structuredVersionProject, path string, allowExternal bool) error {
	root, err := rootfs.New(project.rootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.AllowingInternalSymlinks().CheckContained(path); err == nil {
		return nil
	} else if !allowExternal {
		return err
	}
	externalRoot, err := rootfs.New(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer externalRoot.Close()
	return externalRoot.CheckContained(filepath.Base(path))
}

func signingFileDigest(path string) (string, error) {
	data, err := readSigningRegularFile(path, signingPlanMaxBytes)
	if err != nil {
		return "", err
	}
	return signingFileDigestBytes(data), nil
}

func signingFileDigestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func readSigningRegularFile(path string, limit int64) ([]byte, error) {
	absolute, err := canonicalSigningPath(path, "file")
	if err != nil {
		return nil, err
	}
	root, err := rootfs.New(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFileLimited(filepath.Base(absolute), limit)
}

// signingXCConfigReadFileFn keeps configuration reads behind the same rooted
// reader while allowing tests to prove that authorization rejects a path
// before any read is attempted. Production always uses readSigningRegularFile.
var signingXCConfigReadFileFn = readSigningRegularFile

// signingXCConfigStatFileFn keeps later authorization-aware existence checks
// behind the same rooted reader while allowing tests to prove that an
// unauthorized path is rejected before stat/open is attempted.
var signingXCConfigStatFileFn = signingRegularFileInfo

// signingRegularFileInfo obtains metadata through the same rooted no-follow
// path policy used for signing reads. Callers must establish authorization
// before invoking it for any path that came from project configuration.
func signingRegularFileInfo(path string) (os.FileInfo, error) {
	absolute, err := canonicalSigningPath(path, "file")
	if err != nil {
		return nil, err
	}
	root, err := rootfs.New(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := root.CheckCreateNewFile(filepath.Base(absolute)); err == nil {
		return nil, os.ErrNotExist
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	file, err := root.OpenFile(filepath.Base(absolute))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

// signingArtifactPathInfoFn is kept narrow so tests can inject a path
// inspection failure at the alias-validation boundary. Production alias
// checks always use signingRegularFileInfo's rooted, no-follow implementation.
var signingArtifactPathInfoFn = signingRegularFileInfo

func signingPlanHash(plan *SigningPlan) string {
	copyPlan := *plan
	copyPlan.GeneratedAt = ""
	copyPlan.PlanHash = ""
	encoded, err := json.Marshal(copyPlan)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// WriteSigningPlanArtifact atomically writes a plan artifact. Existing plans
// are replaced only when overwrite is explicitly requested.
func WriteSigningPlanArtifact(plan *SigningPlan, overwrite bool) error {
	if plan == nil {
		return fmt.Errorf("signing plan is nil")
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signing plan: %w", err)
	}
	data = append(data, '\n')
	absolute, err := canonicalSigningPath(plan.PlanPath, "plan file")
	if err != nil {
		return err
	}
	root, err := rootfs.New(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(absolute)
	if overwrite {
		if err := root.WriteFile(name, data, 0o600); err != nil {
			return fmt.Errorf("write signing plan %s: %w", absolute, err)
		}
		return nil
	}
	if err := root.CreateNewFile(name, data, 0o600); err != nil {
		return fmt.Errorf("write signing plan %s: %w; use --overwrite to replace it", absolute, err)
	}
	return nil
}

// ApplySigningPlan verifies and applies a plan, then writes its receipt. No
// project write occurs until the plan hash and all source digests match a
// freshly resolved plan. Project files and the complete receipt are committed
// as one transaction so a receipt failure cannot leave signing settings
// partially applied.
func ApplySigningPlan(opts SigningApplyOptions) (*SigningApplyResult, error) {
	planPath, err := canonicalSigningPath(opts.PlanPath, "plan file")
	if err != nil {
		return nil, err
	}
	plan, err := readSigningPlanArtifact(planPath)
	if err != nil {
		return nil, err
	}
	if plan.PlanPath != planPath {
		return nil, fmt.Errorf("plan path does not match artifact location: %s", plan.PlanPath)
	}
	if plan.AllowExternalXCConfig != opts.AllowExternalXCConfig {
		return nil, fmt.Errorf("--allow-external-xcconfig does not match the plan")
	}
	if !plan.Ready {
		return nil, fmt.Errorf("plan is blocked: %s", strings.Join(plan.Blockers, "; "))
	}
	if plan.PlanHash == "" || plan.PlanHash != signingPlanHash(plan) {
		return nil, fmt.Errorf("plan hash is invalid")
	}

	built, err := buildSigningPlan(SigningPlanOptions{
		ProjectPath:           plan.ProjectPath,
		SettingsFilePath:      plan.SettingsFilePath,
		PlanPath:              plan.PlanPath,
		ReceiptPath:           plan.ReceiptPath,
		AllowExternalXCConfig: plan.AllowExternalXCConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("re-resolve signing plan: %w", err)
	}
	if !built.plan.Ready || built.plan.PlanHash != plan.PlanHash {
		return nil, fmt.Errorf("signing plan is stale; regenerate it before applying")
	}
	if err := preflightSigningReceipt(plan.ReceiptPath); err != nil {
		return nil, err
	}
	prepared, err := prepareSigningOperations(built)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
	}()
	if beforeSigningCommitForTest != nil {
		beforeSigningCommitForTest()
	}
	if err := verifySigningPlanSources(plan, prepared.writes); err != nil {
		return nil, fmt.Errorf("verify signing plan sources: %w", err)
	}
	fileChanges, err := signingReceiptFileChanges(plan, prepared.writes, prepared.changedFiles)
	if err != nil {
		return nil, fmt.Errorf("prepare signing receipt: %w", err)
	}
	result := &SigningApplyResult{
		SchemaVersion: signingPlanSchemaVersion,
		AppliedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Completed:     true,
		PlanHash:      plan.PlanHash,
		PlanPath:      plan.PlanPath,
		ReceiptPath:   plan.ReceiptPath,
		ChangedFiles:  prepared.changedFiles,
		Files:         fileChanges,
		Changes:       append([]SigningSettingChange(nil), plan.Changes...),
	}
	receiptWrite, err := prepareSigningReceiptWrite(result)
	if err != nil {
		return nil, fmt.Errorf("prepare signing receipt: %w", err)
	}
	prepared.writes = append(prepared.writes, receiptWrite)
	if err := commitVersionWritesWithCreateCheck(prepared.writes, func(committed []preparedVersionWrite) error {
		return verifySigningPlanSourcesBeforeReceipt(plan, committed)
	}); err != nil {
		return nil, fmt.Errorf("apply signing settings transaction: %w", err)
	}
	return result, nil
}

var beforeSigningCommitForTest func()

// verifySigningPlanSources closes the gap between re-resolution and staged
// publication. Every staged original must still match the digest captured in
// the plan, and every source must still match the bytes used to prepare the
// update before a receipt is even encoded.
func verifySigningPlanSources(plan *SigningPlan, writes []preparedVersionWrite) error {
	if plan == nil {
		return fmt.Errorf("signing plan is nil")
	}
	expected := make(map[string]SigningPlanFile, len(plan.Files))
	for _, file := range plan.Files {
		expected[signingLexicalPathKey(file.Path)] = file
	}
	staged := make(map[string]preparedVersionWrite, len(writes))
	for _, write := range writes {
		if write.createOnly {
			continue
		}
		file, ok := expected[signingLexicalPathKey(write.path)]
		if !ok {
			return fmt.Errorf("signing plan is stale; staged source %s is not recorded in plan", write.path)
		}
		if signingFileDigestBytes(write.original) != file.SHA256 {
			return fmt.Errorf("signing plan is stale; staged source %s differs from plan", write.path)
		}
		staged[signingLexicalPathKey(write.path)] = write
	}
	for _, file := range plan.Files {
		if write, ok := staged[signingLexicalPathKey(file.Path)]; ok {
			current, _, err := readRegularVersionFile(&write)
			if err != nil {
				return fmt.Errorf("signing plan is stale; read source %s: %w", file.Path, err)
			}
			if !bytes.Equal(current, write.original) || signingFileDigestBytes(current) != file.SHA256 {
				return fmt.Errorf("signing plan is stale; source %s changed after preparation", file.Path)
			}
			continue
		}
		current, err := readSigningRegularFile(file.Path, signingPlanMaxBytes)
		if err != nil {
			return fmt.Errorf("signing plan is stale; read source %s: %w", file.Path, err)
		}
		if signingFileDigestBytes(current) != file.SHA256 {
			return fmt.Errorf("signing plan is stale; source %s differs from plan", file.Path)
		}
	}
	return nil
}

// verifySigningPlanSourcesBeforeReceipt rechecks every planned source after
// ordinary project writes have completed and immediately before the receipt is
// published. Changed files are expected to contain this transaction's staged
// bytes; untouched files must still match their plan digest. A concurrent save
// in this final window therefore fails the transaction and is handled by the
// ordinary rollback path instead of receiving a misleading successful receipt.
func verifySigningPlanSourcesBeforeReceipt(plan *SigningPlan, committed []preparedVersionWrite) error {
	if plan == nil {
		return fmt.Errorf("signing plan is nil")
	}
	committedByPath := make(map[string]preparedVersionWrite, len(committed))
	for _, write := range committed {
		if !write.createOnly {
			committedByPath[signingLexicalPathKey(write.path)] = write
		}
	}
	for _, file := range plan.Files {
		if write, ok := committedByPath[signingLexicalPathKey(file.Path)]; ok {
			current, _, err := readRegularVersionFile(&write)
			if err != nil {
				return fmt.Errorf("read written source %s: %w", file.Path, err)
			}
			if !bytes.Equal(current, write.updated) || signingFileDigestBytes(current) != signingFileDigestBytes(write.updated) {
				return fmt.Errorf("written source %s changed before receipt", file.Path)
			}
			continue
		}
		current, err := readSigningRegularFile(file.Path, signingPlanMaxBytes)
		if err != nil {
			return fmt.Errorf("read source %s: %w", file.Path, err)
		}
		if signingFileDigestBytes(current) != file.SHA256 {
			return fmt.Errorf("source %s differs from plan before receipt", file.Path)
		}
	}
	return nil
}

func signingReceiptFileChanges(plan *SigningPlan, writes []preparedVersionWrite, changedFiles []string) ([]SigningFileChange, error) {
	before := make(map[string]SigningPlanFile, len(plan.Files))
	for _, file := range plan.Files {
		before[signingLexicalPathKey(file.Path)] = file
	}
	updated := make(map[string][]byte, len(writes))
	for _, write := range writes {
		if write.createOnly || bytes.Equal(write.original, write.updated) {
			continue
		}
		updated[signingLexicalPathKey(write.path)] = write.updated
	}
	changes := make([]SigningFileChange, 0, len(changedFiles))
	for _, path := range changedFiles {
		file, ok := before[signingLexicalPathKey(path)]
		if !ok {
			return nil, fmt.Errorf("changed file %s was not present in the plan", path)
		}
		data, ok := updated[signingLexicalPathKey(path)]
		if !ok {
			return nil, fmt.Errorf("changed file %s was not prepared for the transaction", path)
		}
		changes = append(changes, SigningFileChange{
			Path:         path,
			Source:       file.Source,
			BeforeSHA256: file.SHA256,
			AfterSHA256:  signingFileDigestBytes(data),
		})
	}
	return changes, nil
}

func readSigningPlanArtifact(path string) (*SigningPlan, error) {
	data, err := readSigningRegularFile(path, signingPlanMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read signing plan %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan SigningPlan
	if err := decoder.Decode(&plan); err != nil {
		return nil, newSigningInputError(fmt.Errorf("decode signing plan %s: %w", path, err))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, newSigningInputError(fmt.Errorf("decode signing plan %s: multiple JSON values", path))
		}
		return nil, newSigningInputError(fmt.Errorf("decode signing plan %s: %w", path, err))
	}
	if plan.SchemaVersion != signingPlanSchemaVersion {
		return nil, newSigningInputError(fmt.Errorf("plan schemaVersion must be %d", signingPlanSchemaVersion))
	}
	if plan.Command != signingPlanCommand {
		return nil, newSigningInputError(fmt.Errorf("plan command is not %q", signingPlanCommand))
	}
	return &plan, nil
}

func preflightSigningReceipt(path string) error {
	absolute, err := canonicalSigningPath(path, "receipt file")
	if err != nil {
		return err
	}
	root, err := rootfs.New(filepath.Dir(absolute))
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.CheckCreateNewFile(filepath.Base(absolute)); err != nil {
		return fmt.Errorf("preflight receipt %s: %w", absolute, err)
	}
	return nil
}

func encodeSigningReceipt(result *SigningApplyResult) ([]byte, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func prepareSigningReceiptWrite(result *SigningApplyResult) (preparedVersionWrite, error) {
	data, err := encodeSigningReceipt(result)
	if err != nil {
		return preparedVersionWrite{}, err
	}
	absolute, err := canonicalSigningPath(result.ReceiptPath, "receipt file")
	if err != nil {
		return preparedVersionWrite{}, err
	}
	root, err := rootfs.New(filepath.Dir(absolute))
	if err != nil {
		return preparedVersionWrite{}, err
	}
	name := filepath.Base(absolute)
	if err := root.CheckCreateNewFile(name); err != nil {
		_ = root.Close()
		return preparedVersionWrite{}, err
	}
	return preparedVersionWrite{
		path:       absolute,
		updated:    data,
		mode:       0o600,
		root:       root,
		name:       name,
		createOnly: true,
	}, nil
}

type preparedSigningOperations struct {
	writes       []preparedVersionWrite
	changedFiles []string
	projectRoot  rootfs.Root
}

func prepareSigningOperations(built *signingPlanBuild) (*preparedSigningOperations, error) {
	if built == nil || built.project == nil {
		return nil, fmt.Errorf("signing plan build is nil")
	}
	project := built.project
	projectRoot, err := rootfs.New(project.rootDir)
	if err != nil {
		return nil, err
	}
	projectRoot = projectRoot.AllowingInternalSymlinks()
	prepared := &preparedSigningOperations{projectRoot: projectRoot}
	fail := func(failure error) (*preparedSigningOperations, error) {
		_ = closeVersionWrites(prepared.writes)
		_ = prepared.projectRoot.Close()
		return nil, failure
	}
	pbxprojChanged := false
	for _, operation := range built.operations {
		if operation.Source != "pbxproj" {
			continue
		}
		if err := applySigningPBXOperation(operation); err != nil {
			return fail(err)
		}
		pbxprojChanged = true
	}
	if pbxprojChanged {
		write, err := project.preparePBXProjWrite(projectRoot)
		if err != nil {
			return fail(err)
		}
		write.preserveMetadata = true
		prepared.writes = append(prepared.writes, write)
	}

	xcconfigMutations := make(map[string]map[string]xcconfigMutation)
	xcconfigPaths := make(map[string]string)
	for _, operation := range built.operations {
		if operation.Source != "xcconfig" {
			continue
		}
		if operation.NewValue == nil {
			return fail(fmt.Errorf("xcconfig removal is not supported for %s", operation.Setting))
		}
		pathKey := signingXCConfigOperationKey(operation.Path, built.fileIdentities)
		if xcconfigMutations[pathKey] == nil {
			xcconfigMutations[pathKey] = make(map[string]xcconfigMutation)
			xcconfigPaths[pathKey] = operation.Path
		}
		mutation := xcconfigMutations[pathKey][operation.Setting]
		if mutation.setting != "" && mutation.value != *operation.NewValue {
			return fail(fmt.Errorf("conflicting xcconfig operations for %s", operation.Path))
		}
		mutation.setting = operation.Setting
		mutation.value = *operation.NewValue
		mutation.configurations = appendVersionConfigurationOnce(mutation.configurations, operation.configuration)
		xcconfigMutations[pathKey][operation.Setting] = mutation
	}
	paths := make([]string, 0, len(xcconfigMutations))
	for pathKey := range xcconfigMutations {
		paths = append(paths, pathKey)
	}
	sort.Slice(paths, func(left, right int) bool {
		return xcconfigPaths[paths[left]] < xcconfigPaths[paths[right]]
	})
	for _, pathKey := range paths {
		path := xcconfigPaths[pathKey]
		target, err := project.versionFileTarget(projectRoot, path, built.plan.AllowExternalXCConfig)
		if err != nil {
			if target.root.Path() != "" && target.ownsRoot {
				_ = target.root.Close()
			}
			return fail(fmt.Errorf("prepare xcconfig %s: %w", path, err))
		}
		write, _, changed, err := prepareXCConfigWrite(target, xcconfigMutations[pathKey])
		if err != nil {
			_ = target.root.Close()
			return fail(err)
		}
		if changed {
			write.preserveMetadata = true
			prepared.writes = append(prepared.writes, write)
		} else if target.ownsRoot {
			_ = target.root.Close()
		}
	}
	// Preserve metadata for every ordinary destination before any transaction
	// can begin. WriteFilePreservingMode repeats these checks at commit time,
	// but preflighting the complete set keeps a late hard-link, symlink, or
	// ownership/permission failure from occurring after an earlier file was
	// already replaced.
	for _, write := range prepared.writes {
		if !write.preserveMetadata {
			continue
		}
		if err := write.root.CheckWriteFilePreservingMode(write.name); err != nil {
			return fail(fmt.Errorf("preflight metadata preservation for %s: %w", write.path, err))
		}
	}
	prepared.changedFiles = make([]string, 0, len(prepared.writes))
	for _, write := range prepared.writes {
		prepared.changedFiles = append(prepared.changedFiles, write.path)
	}
	sort.Strings(prepared.changedFiles)
	return prepared, nil
}

func applySigningPBXOperation(operation signingPlanOperation) error {
	configuration := operation.configuration
	if configuration == nil {
		return fmt.Errorf("missing configuration for %s", operation.Setting)
	}
	keys := matchingBuildSettingKeys(configuration.buildSettings, operation.Setting)
	if operation.Operation == "remove" {
		for _, key := range keys {
			delete(configuration.buildSettings, key)
		}
		return nil
	}
	if operation.NewValue == nil {
		return fmt.Errorf("missing new value for %s", operation.Setting)
	}
	if len(keys) == 0 {
		configuration.buildSettings[operation.Setting] = *operation.NewValue
		return nil
	}
	for _, key := range keys {
		configuration.buildSettings[key] = *operation.NewValue
	}
	return nil
}

func cloneSigningString(value *string) *string {
	if value == nil {
		return nil
	}
	return stringPtr(*value)
}

func stringPtr(value string) *string {
	return &value
}
