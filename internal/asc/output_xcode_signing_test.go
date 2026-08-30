package asc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	localxcode "github.com/rudrankriyam/App-Store-Connect-CLI/internal/xcode"
)

func TestXcodeSigningOutputsAreRegistered(t *testing.T) {
	ensureOutputRegistryPopulated()

	if !isRegistryTypeRegistered(typeForPtr[XcodeSigningPlanOutput]()) {
		t.Fatal("XcodeSigningPlanOutput is not registered with the output renderer")
	}
	if !isRegistryTypeRegistered(typeForPtr[XcodeSigningApplyOutput]()) {
		t.Fatal("XcodeSigningApplyOutput is not registered with the output renderer")
	}
}

func TestXcodeSigningPlanOutputPreservesArtifactJSONShape(t *testing.T) {
	value := "Manual"
	oldValue := "Automatic"
	plan := &localxcode.SigningPlan{
		SchemaVersion:         1,
		Command:               "asc xcode signing plan",
		GeneratedAt:           "2026-08-30T00:00:00Z",
		PlanHash:              "plan-hash",
		Ready:                 true,
		ProjectPath:           "/tmp/Demo.xcodeproj",
		SettingsFilePath:      "/tmp/settings.json",
		PlanPath:              "/tmp/plan.json",
		ReceiptPath:           "/tmp/receipt.json",
		AllowExternalXCConfig: true,
		Desired: []localxcode.SigningPlanTarget{{
			Target: "Demo",
			Configurations: []localxcode.SigningPlanConfiguration{{
				Name:     "Release",
				Settings: []localxcode.SigningPlanSetting{{Key: "CODE_SIGN_STYLE", Value: &value}},
			}},
		}},
		Files: []localxcode.SigningPlanFile{{
			Path:   "/tmp/Demo.xcodeproj/project.pbxproj",
			SHA256: "source-hash",
			Source: "pbxproj",
		}},
		Changes: []localxcode.SigningSettingChange{{
			Target:        "Demo",
			Configuration: "Release",
			Setting:       "CODE_SIGN_STYLE",
			Operation:     "set",
			Resolution:    "direct",
			OldValue:      &oldValue,
			NewValue:      &value,
			Path:          "/tmp/Demo.xcodeproj/project.pbxproj",
			Source:        "pbxproj",
		}},
		Blockers: []string{},
		Warnings: []string{"warning"},
	}

	output := NewXcodeSigningPlanOutput(plan)
	if output == nil {
		t.Fatal("NewXcodeSigningPlanOutput returned nil")
	}
	if reflect.TypeOf(output) == reflect.TypeOf(plan) {
		t.Fatal("expected outward plan output to be distinct from the artifact type")
	}

	assertEquivalentJSON(t, plan, output)
}

func TestXcodeSigningApplyOutputPreservesReceiptJSONShape(t *testing.T) {
	oldValue := "Automatic"
	newValue := "Manual"
	result := &localxcode.SigningApplyResult{
		SchemaVersion: 1,
		AppliedAt:     "2026-08-30T00:00:00Z",
		Completed:     true,
		PlanHash:      "plan-hash",
		PlanPath:      "/tmp/plan.json",
		ReceiptPath:   "/tmp/receipt.json",
		ChangedFiles:  []string{"/tmp/Demo.xcodeproj/project.pbxproj"},
		Files: []localxcode.SigningFileChange{{
			Path:         "/tmp/Demo.xcodeproj/project.pbxproj",
			Source:       "pbxproj",
			BeforeSHA256: "before",
			AfterSHA256:  "after",
		}},
		Changes: []localxcode.SigningSettingChange{{
			Target:        "Demo",
			Configuration: "Release",
			Setting:       "CODE_SIGN_STYLE",
			Operation:     "set",
			Resolution:    "direct",
			OldValue:      &oldValue,
			NewValue:      &newValue,
			Path:          "/tmp/Demo.xcodeproj/project.pbxproj",
			Source:        "pbxproj",
		}},
	}

	output := NewXcodeSigningApplyOutput(result)
	if output == nil {
		t.Fatal("NewXcodeSigningApplyOutput returned nil")
	}
	assertEquivalentJSON(t, result, output)
}

func TestXcodeSigningOutputsUseRegisteredHumanRenderers(t *testing.T) {
	plan := NewXcodeSigningPlanOutput(&localxcode.SigningPlan{
		Ready:    true,
		PlanPath: "/tmp/plan.json",
		PlanHash: "plan-hash",
		Changes: []localxcode.SigningSettingChange{{
			Target:        "Demo",
			Configuration: "Release",
			Setting:       "CODE_SIGN_STYLE",
			Operation:     "set",
			Resolution:    "direct",
		}},
	})
	apply := NewXcodeSigningApplyOutput(&localxcode.SigningApplyResult{
		Completed:    true,
		PlanPath:     "/tmp/plan.json",
		ReceiptPath:  "/tmp/receipt.json",
		PlanHash:     "plan-hash",
		ChangedFiles: []string{"/tmp/Demo.xcodeproj/project.pbxproj"},
	})

	for _, test := range []struct {
		name string
		data any
		want []string
	}{
		{name: "plan", data: plan, want: []string{"ready", "plan hash", "changes"}},
		{name: "apply", data: apply, want: []string{"completed", "receipt", "changed files"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, renderer := range []struct {
				name string
				fn   func(any) error
			}{
				{name: "table", fn: PrintTable},
				{name: "markdown", fn: PrintMarkdown},
			} {
				renderer := renderer
				t.Run(renderer.name, func(t *testing.T) {
					output := captureStdout(t, func() error { return renderer.fn(test.data) })
					for _, want := range test.want {
						if !strings.Contains(strings.ToLower(output), want) {
							t.Fatalf("output missing %q: %s", want, output)
						}
					}
				})
			}
		})
	}
}

func assertEquivalentJSON(t *testing.T, want, got any) {
	t.Helper()

	var wantValue any
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want JSON: %v", err)
	}
	if err := json.Unmarshal(wantJSON, &wantValue); err != nil {
		t.Fatalf("decode want JSON: %v", err)
	}

	var gotValue any
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got JSON: %v", err)
	}
	if err := json.Unmarshal(gotJSON, &gotValue); err != nil {
		t.Fatalf("decode got JSON: %v", err)
	}

	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("outward JSON changed artifact shape:\nwant: %s\n got: %s", wantJSON, gotJSON)
	}
}
