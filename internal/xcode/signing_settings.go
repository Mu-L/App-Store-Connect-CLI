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
	signingTeamIDPattern   = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	signingBundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
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
}

type signingPlanOperation struct {
	SigningSettingChange
	configuration *versionConfiguration
}

type signingPlanBuild struct {
	plan       *SigningPlan
	project    *structuredVersionProject
	operations []signingPlanOperation
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

	project, err := openStructuredVersionProject(opts.ProjectPath)
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
	for _, request := range requests {
		configuration, configurationErr := signingConfigurationFor(project, request.target, request.configuration)
		if configurationErr == nil {
			selectedIDs[configuration.id] = true
			if requestedSettings[configuration.id] == nil {
				requestedSettings[configuration.id] = make(map[string]bool)
			}
			for _, setting := range request.settings {
				requestedSettings[configuration.id][setting.key] = true
			}
		}
	}
	fileConsumers, configFiles, fileIdentities, uncertainConsumers, err := project.xcconfigConsumers(selectedIDs)
	if err != nil {
		return nil, err
	}
	if err := validateSigningArtifactAliases(
		planPath,
		receiptPath,
		signingProjectInputPaths(project, settingsPath, configFiles, requests),
	); err != nil {
		return nil, err
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
				uncertainConsumers,
				opts.AllowExternalXCConfig,
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
	resolveSigningSharedCandidates(candidates)
	operations := make([]signingPlanOperation, 0, len(candidates))
	for index := range candidates {
		candidate := &candidates[index]
		if candidate.mode == "" {
			continue
		}
		if candidate.mode == "xcconfig" {
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
		if _, exists := files[path]; exists {
			return
		}
		digest, digestErr := signingFileDigest(path)
		if digestErr != nil {
			plan.Blockers = append(plan.Blockers, fmt.Sprintf("digest %s: %v", path, digestErr))
			return
		}
		files[path] = SigningPlanFile{Path: path, SHA256: digest, Source: source}
	}
	addFile(project.pbxprojPath, "pbxproj")
	addFile(settingsPath, "settings")
	for _, operation := range operations {
		if operation.Source == "xcconfig" {
			addFile(operation.Path, "xcconfig")
		}
	}
	for _, file := range files {
		plan.Files = append(plan.Files, file)
	}
	sort.Slice(plan.Files, func(left, right int) bool { return plan.Files[left].Path < plan.Files[right].Path })
	sort.Strings(plan.Blockers)
	sort.Strings(plan.Warnings)
	plan.Ready = len(plan.Blockers) == 0
	plan.PlanHash = signingPlanHash(plan)

	return &signingPlanBuild{plan: plan, project: project, operations: operations}, nil
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

func readSigningSettingsManifest(path string) (*signingSettingsManifest, error) {
	data, err := readSigningRegularFile(path, signingSettingsMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read settings file %s: %w", path, err)
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
	for _, candidate := range project.configurations {
		if !candidate.projectLevel && candidate.target == target && candidate.name == configuration {
			return candidate, nil
		}
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
	uncertainConsumers bool,
	allowExternal bool,
) (signingCandidate, string, string) {
	candidate := signingCandidate{configuration: configuration, setting: setting.key, desired: cloneSigningString(setting.value)}
	if setting.key == "CODE_SIGN_ENTITLEMENTS" && setting.value != nil {
		if err := validateSigningEntitlementsPath(project, *setting.value); err != nil {
			return candidate, signingSettingBlocker(configuration, setting.key, fmt.Errorf("validate path %q: %w", *setting.value, err)), ""
		}
	}
	keys := matchingBuildSettingKeys(configuration.buildSettings, setting.key)
	if len(keys) > 0 {
		old, _, err := project.resolveSetting(configuration, setting.key)
		if err != nil {
			return candidate, signingSettingBlocker(configuration, setting.key, err), ""
		}
		candidate.old = stringPtr(old)
		candidate.resolution = "direct"
		if signingValuesEqual(setting.value, candidate.old) {
			return candidate, "", ""
		}
		candidate.mode = "pbxproj"
		return candidate, "", ""
	}

	assignmentFiles, err := xcconfigFilesDefining(configFiles[configuration.id], setting.key)
	if err != nil {
		return candidate, signingSettingBlocker(configuration, setting.key, err), ""
	}
	old, _, resolveErr := project.resolveSetting(configuration, setting.key)
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

func resolveSigningSharedCandidates(candidates []signingCandidate) {
	desiredByFile := make(map[string]string)
	conflictByFile := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate.mode != "xcconfig" || candidate.desired == nil {
			continue
		}
		for _, path := range candidate.paths {
			key := path + "\x00" + candidate.setting
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
			if conflictByFile[path+"\x00"+candidates[index].setting] {
				candidates[index].mode = "pbxproj"
				candidates[index].paths = nil
				break
			}
		}
	}
}

func signingSettingBlocker(configuration *versionConfiguration, setting string, err error) string {
	return fmt.Sprintf("target %q configuration %q cannot resolve %s: %v", configuration.target, configuration.name, setting, err)
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
	if planPath == receiptPath {
		return fmt.Errorf("plan and receipt paths must be different")
	}
	for _, candidate := range []struct {
		label string
		path  string
	}{{"plan", planPath}, {"receipt", receiptPath}} {
		if candidate.path == projectPath {
			return fmt.Errorf("%s path must not replace the Xcode project file", candidate.label)
		}
		if candidate.path == settingsPath {
			return fmt.Errorf("%s path must not replace the settings file", candidate.label)
		}
	}
	return nil
}

// validateSigningArtifactAliases rejects an existing plan or receipt that
// resolves to any source consumed while building the plan. Lexical path
// comparisons do not catch symlink or hard-link aliases, while os.Stat plus
// os.SameFile identifies both without mutating the filesystem.
func validateSigningArtifactAliases(planPath, receiptPath string, inputPaths []string) error {
	type artifact struct {
		label string
		path  string
	}
	artifacts := []artifact{{label: "plan", path: planPath}, {label: "receipt", path: receiptPath}}
	artifactInfos := make(map[string]os.FileInfo, len(artifacts))
	for _, artifact := range artifacts {
		info, err := os.Stat(artifact.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s artifact path %s: %w", artifact.label, artifact.path, err)
		}
		artifactInfos[artifact.label] = info
	}
	if planInfo, planOK := artifactInfos["plan"]; planOK {
		if receiptInfo, receiptOK := artifactInfos["receipt"]; receiptOK && os.SameFile(planInfo, receiptInfo) {
			return newSigningInputError(fmt.Errorf("plan and receipt paths must not alias the same file"))
		}
	}

	seenInputs := make(map[string]bool, len(inputPaths))
	for _, inputPath := range inputPaths {
		inputPath = filepath.Clean(inputPath)
		if inputPath == "" || seenInputs[inputPath] {
			continue
		}
		seenInputs[inputPath] = true
		inputInfo, err := os.Stat(inputPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect project input %s: %w", inputPath, err)
		}
		for _, artifact := range artifacts {
			artifactInfo, ok := artifactInfos[artifact.label]
			if ok && os.SameFile(artifactInfo, inputInfo) {
				return newSigningInputError(fmt.Errorf("%s path aliases project input %s", artifact.label, inputPath))
			}
		}
	}
	return nil
}

func signingProjectInputPaths(
	project *structuredVersionProject,
	settingsPath string,
	configFiles map[string][]string,
	requests []signingRequest,
) []string {
	paths := []string{project.pbxprojPath, settingsPath}
	appendEntitlements := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if validateSigningRelativePath(value) == nil {
			paths = append(paths, filepath.Join(project.rootDir, filepath.FromSlash(value)))
			return
		}
		if filepath.IsAbs(value) {
			paths = append(paths, filepath.Clean(value))
		}
	}
	for _, files := range configFiles {
		paths = append(paths, files...)
	}
	for _, request := range requests {
		for _, setting := range request.settings {
			if setting.key == "CODE_SIGN_ENTITLEMENTS" && setting.value != nil {
				appendEntitlements(*setting.value)
			}
		}
	}
	for _, configuration := range project.configurations {
		if value, _, err := project.resolveSetting(configuration, "CODE_SIGN_ENTITLEMENTS"); err == nil {
			appendEntitlements(value)
		}
		for _, key := range matchingBuildSettingKeys(configuration.buildSettings, "CODE_SIGN_ENTITLEMENTS") {
			value, ok := configuration.buildSettings[key].(string)
			if ok {
				appendEntitlements(value)
			}
		}
	}
	for _, files := range configFiles {
		for _, filePath := range files {
			data, err := readSigningRegularFile(filePath, signingPlanMaxBytes)
			if err != nil {
				continue
			}
			document, err := parseXCConfig(data)
			if err != nil {
				continue
			}
			for _, assignment := range document.assignments {
				if assignment.baseKey == "CODE_SIGN_ENTITLEMENTS" {
					appendEntitlements(assignment.value)
				}
			}
		}
	}
	return paths
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
	if err := commitVersionWrites(prepared.writes); err != nil {
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
		expected[file.Path] = file
	}
	staged := make(map[string]preparedVersionWrite, len(writes))
	for _, write := range writes {
		if write.createOnly {
			continue
		}
		file, ok := expected[write.path]
		if !ok {
			return fmt.Errorf("signing plan is stale; staged source %s is not recorded in plan", write.path)
		}
		if signingFileDigestBytes(write.original) != file.SHA256 {
			return fmt.Errorf("signing plan is stale; staged source %s differs from plan", write.path)
		}
		staged[write.path] = write
	}
	for _, file := range plan.Files {
		if write, ok := staged[file.Path]; ok {
			current, _, err := readRegularVersionFile(write)
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

func signingReceiptFileChanges(plan *SigningPlan, writes []preparedVersionWrite, changedFiles []string) ([]SigningFileChange, error) {
	before := make(map[string]SigningPlanFile, len(plan.Files))
	for _, file := range plan.Files {
		before[file.Path] = file
	}
	updated := make(map[string][]byte, len(writes))
	for _, write := range writes {
		if write.createOnly || bytes.Equal(write.original, write.updated) {
			continue
		}
		updated[write.path] = write.updated
	}
	changes := make([]SigningFileChange, 0, len(changedFiles))
	for _, path := range changedFiles {
		file, ok := before[path]
		if !ok {
			return nil, fmt.Errorf("changed file %s was not present in the plan", path)
		}
		data, ok := updated[path]
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
		prepared.writes = append(prepared.writes, write)
	}

	xcconfigMutations := make(map[string]map[string]xcconfigMutation)
	for _, operation := range built.operations {
		if operation.Source != "xcconfig" {
			continue
		}
		if operation.NewValue == nil {
			return fail(fmt.Errorf("xcconfig removal is not supported for %s", operation.Setting))
		}
		if xcconfigMutations[operation.Path] == nil {
			xcconfigMutations[operation.Path] = make(map[string]xcconfigMutation)
		}
		mutation := xcconfigMutations[operation.Path][operation.Setting]
		if mutation.setting != "" && mutation.value != *operation.NewValue {
			return fail(fmt.Errorf("conflicting xcconfig operations for %s", operation.Path))
		}
		mutation.setting = operation.Setting
		mutation.value = *operation.NewValue
		mutation.configurations = appendVersionConfigurationOnce(mutation.configurations, operation.configuration)
		xcconfigMutations[operation.Path][operation.Setting] = mutation
	}
	paths := make([]string, 0, len(xcconfigMutations))
	for path := range xcconfigMutations {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		target, err := project.versionFileTarget(projectRoot, path, built.plan.AllowExternalXCConfig)
		if err != nil {
			if target.root.Path() != "" && target.ownsRoot {
				_ = target.root.Close()
			}
			return fail(fmt.Errorf("prepare xcconfig %s: %w", path, err))
		}
		write, _, changed, err := prepareXCConfigWrite(target, xcconfigMutations[path])
		if err != nil {
			_ = target.root.Close()
			return fail(err)
		}
		if changed {
			prepared.writes = append(prepared.writes, write)
		} else if target.ownsRoot {
			_ = target.root.Close()
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
