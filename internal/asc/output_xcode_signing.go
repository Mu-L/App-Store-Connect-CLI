package asc

import (
	"fmt"
	"strings"

	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

// XcodeSigningPlanOutput is the outward JSON and human-readable output for a
// local Xcode signing plan. It is intentionally separate from the plan
// artifact type so rendering changes cannot alter the artifact hash contract.
type XcodeSigningPlanOutput struct {
	SchemaVersion         int                               `json:"schemaVersion"`
	Command               string                            `json:"command"`
	GeneratedAt           string                            `json:"generatedAt"`
	PlanHash              string                            `json:"planHash"`
	Ready                 bool                              `json:"ready"`
	ProjectPath           string                            `json:"projectPath"`
	SettingsFilePath      string                            `json:"settingsFilePath"`
	PlanPath              string                            `json:"planPath"`
	ReceiptPath           string                            `json:"receiptPath"`
	AllowExternalXCConfig bool                              `json:"allowExternalXCConfig"`
	Desired               []XcodeSigningPlanTargetOutput    `json:"desired"`
	Files                 []XcodeSigningPlanFileOutput      `json:"files"`
	Changes               []XcodeSigningSettingChangeOutput `json:"changes"`
	Blockers              []string                          `json:"blockers"`
	Warnings              []string                          `json:"warnings"`
}

// XcodeSigningPlanTargetOutput describes one target in a signing plan.
type XcodeSigningPlanTargetOutput struct {
	Target         string                                `json:"target"`
	Configurations []XcodeSigningPlanConfigurationOutput `json:"configurations"`
}

// XcodeSigningPlanConfigurationOutput describes one build configuration in a
// signing plan.
type XcodeSigningPlanConfigurationOutput struct {
	Name     string                          `json:"name"`
	Settings []XcodeSigningPlanSettingOutput `json:"settings"`
}

// XcodeSigningPlanSettingOutput describes one normalized desired signing
// setting.
type XcodeSigningPlanSettingOutput struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// XcodeSigningPlanFileOutput records a source file digest bound into a plan.
type XcodeSigningPlanFileOutput struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Source string `json:"source"`
}

// XcodeSigningSettingChangeOutput records one concrete signing-setting
// operation in a plan or receipt.
type XcodeSigningSettingChangeOutput struct {
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

// XcodeSigningApplyOutput is the outward JSON and human-readable output for a
// completed local Xcode signing apply. The receipt artifact remains owned by
// the xcode package and is encoded from its domain type before this view is
// rendered.
type XcodeSigningApplyOutput struct {
	SchemaVersion int                               `json:"schemaVersion"`
	AppliedAt     string                            `json:"appliedAt"`
	Completed     bool                              `json:"completed"`
	PlanHash      string                            `json:"planHash"`
	PlanPath      string                            `json:"planPath"`
	ReceiptPath   string                            `json:"receiptPath"`
	ChangedFiles  []string                          `json:"changedFiles"`
	Files         []XcodeSigningFileChangeOutput    `json:"files"`
	Changes       []XcodeSigningSettingChangeOutput `json:"changes"`
}

// XcodeSigningFileChangeOutput binds a written file to its before and after
// digest in an apply receipt.
type XcodeSigningFileChangeOutput struct {
	Path         string `json:"path"`
	Source       string `json:"source"`
	BeforeSHA256 string `json:"beforeSha256"`
	AfterSHA256  string `json:"afterSha256"`
}

// NewXcodeSigningPlanOutput converts the domain artifact into the registered
// outward output type without sharing mutable slices or pointer fields.
func NewXcodeSigningPlanOutput(plan *localxcode.SigningPlan) *XcodeSigningPlanOutput {
	if plan == nil {
		return nil
	}
	return &XcodeSigningPlanOutput{
		SchemaVersion:         plan.SchemaVersion,
		Command:               plan.Command,
		GeneratedAt:           plan.GeneratedAt,
		PlanHash:              plan.PlanHash,
		Ready:                 plan.Ready,
		ProjectPath:           plan.ProjectPath,
		SettingsFilePath:      plan.SettingsFilePath,
		PlanPath:              plan.PlanPath,
		ReceiptPath:           plan.ReceiptPath,
		AllowExternalXCConfig: plan.AllowExternalXCConfig,
		Desired:               cloneXcodeSigningPlanTargets(plan.Desired),
		Files:                 cloneXcodeSigningPlanFiles(plan.Files),
		Changes:               cloneXcodeSigningSettingChanges(plan.Changes),
		Blockers:              cloneStrings(plan.Blockers),
		Warnings:              cloneStrings(plan.Warnings),
	}
}

// NewXcodeSigningApplyOutput converts the domain receipt into the registered
// outward output type without sharing mutable slices or pointer fields.
func NewXcodeSigningApplyOutput(result *localxcode.SigningApplyResult) *XcodeSigningApplyOutput {
	if result == nil {
		return nil
	}
	return &XcodeSigningApplyOutput{
		SchemaVersion: result.SchemaVersion,
		AppliedAt:     result.AppliedAt,
		Completed:     result.Completed,
		PlanHash:      result.PlanHash,
		PlanPath:      result.PlanPath,
		ReceiptPath:   result.ReceiptPath,
		ChangedFiles:  cloneStrings(result.ChangedFiles),
		Files:         cloneXcodeSigningFileChanges(result.Files),
		Changes:       cloneXcodeSigningSettingChanges(result.Changes),
	}
}

func cloneXcodeSigningPlanTargets(values []localxcode.SigningPlanTarget) []XcodeSigningPlanTargetOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningPlanTargetOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningPlanTargetOutput{
			Target:         value.Target,
			Configurations: cloneXcodeSigningPlanConfigurations(value.Configurations),
		}
	}
	return cloned
}

func cloneXcodeSigningPlanConfigurations(values []localxcode.SigningPlanConfiguration) []XcodeSigningPlanConfigurationOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningPlanConfigurationOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningPlanConfigurationOutput{
			Name:     value.Name,
			Settings: cloneXcodeSigningPlanSettings(value.Settings),
		}
	}
	return cloned
}

func cloneXcodeSigningPlanSettings(values []localxcode.SigningPlanSetting) []XcodeSigningPlanSettingOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningPlanSettingOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningPlanSettingOutput{
			Key:   value.Key,
			Value: cloneString(value.Value),
		}
	}
	return cloned
}

func cloneXcodeSigningPlanFiles(values []localxcode.SigningPlanFile) []XcodeSigningPlanFileOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningPlanFileOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningPlanFileOutput{
			Path:   value.Path,
			SHA256: value.SHA256,
			Source: value.Source,
		}
	}
	return cloned
}

func cloneXcodeSigningSettingChanges(values []localxcode.SigningSettingChange) []XcodeSigningSettingChangeOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningSettingChangeOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningSettingChangeOutput{
			Target:        value.Target,
			Configuration: value.Configuration,
			Setting:       value.Setting,
			Operation:     value.Operation,
			Resolution:    value.Resolution,
			OldValue:      cloneString(value.OldValue),
			NewValue:      cloneString(value.NewValue),
			Path:          value.Path,
			Source:        value.Source,
		}
	}
	return cloned
}

func cloneXcodeSigningFileChanges(values []localxcode.SigningFileChange) []XcodeSigningFileChangeOutput {
	if values == nil {
		return nil
	}
	cloned := make([]XcodeSigningFileChangeOutput, len(values))
	for index, value := range values {
		cloned[index] = XcodeSigningFileChangeOutput{
			Path:         value.Path,
			Source:       value.Source,
			BeforeSHA256: value.BeforeSHA256,
			AfterSHA256:  value.AfterSHA256,
		}
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func xcodeSigningPlanOutputRows(plan *XcodeSigningPlanOutput) ([]string, [][]string) {
	if plan == nil {
		plan = &XcodeSigningPlanOutput{}
	}
	return []string{"field", "value"}, [][]string{
		{"ready", fmt.Sprintf("%t", plan.Ready)},
		{"plan", plan.PlanPath},
		{"plan hash", plan.PlanHash},
		{"changes", fmt.Sprintf("%d", len(plan.Changes))},
		{"blockers", strings.Join(plan.Blockers, "; ")},
		{"warnings", strings.Join(plan.Warnings, "; ")},
	}
}

func xcodeSigningApplyOutputRows(result *XcodeSigningApplyOutput) ([]string, [][]string) {
	if result == nil {
		result = &XcodeSigningApplyOutput{}
	}
	return []string{"field", "value"}, [][]string{
		{"applied", "true"},
		{"completed", fmt.Sprintf("%t", result.Completed)},
		{"plan", result.PlanPath},
		{"receipt", result.ReceiptPath},
		{"plan hash", result.PlanHash},
		{"changed files", strings.Join(result.ChangedFiles, ", ")},
	}
}
