package asc

import (
	"strings"
	"testing"
)

func TestPrintTableWebXcodeCloudWorkflowsListUsesRegistry(t *testing.T) {
	result := &WebXcodeCloudWorkflowsListResult{
		ProductID: "prod-1",
		Workflows: []WebXcodeCloudWorkflowListItem{
			{ID: "wf-1", Name: "TestFlight Deploy", Description: "Build on main"},
			{ID: "wf-2", Name: "PR Check"},
		},
	}

	output := captureStdout(t, func() error { return PrintTable(result) })
	for _, want := range []string{"Workflow ID", "Name", "Description", "wf-1", "TestFlight Deploy", "Build on main", "wf-2", "PR Check"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q: %q", want, output)
		}
	}
}

func TestPrintMarkdownWebXcodeCloudWorkflowsListUsesRegistry(t *testing.T) {
	result := &WebXcodeCloudWorkflowsListResult{
		ProductID: "prod-1",
		Workflows: []WebXcodeCloudWorkflowListItem{
			{ID: "wf-1", Name: "Nightly"},
		},
	}

	output := captureStdout(t, func() error { return PrintMarkdown(result) })
	for _, want := range []string{"Workflow ID", "Name", "Description", "wf-1", "Nightly"} {
		if !strings.Contains(output, want) {
			t.Fatalf("markdown output missing %q: %q", want, output)
		}
	}
}

func TestPrintWebXcodeCloudNextBuildNumberUsesRegistry(t *testing.T) {
	previous := 101
	result := &WebXcodeCloudNextBuildNumberResult{
		ProductID:               "prod-1",
		PreviousNextBuildNumber: &previous,
		NextBuildNumber:         102,
		Updated:                 true,
	}

	table := captureStdout(t, func() error { return PrintTable(result) })
	markdown := captureStdout(t, func() error { return PrintMarkdown(result) })
	for name, output := range map[string]string{"table": table, "markdown": markdown} {
		for _, want := range []string{"Product ID", "Previous Next Build Number", "Next Build Number", "Updated", "prod-1", "101", "102", "true"} {
			if !strings.Contains(output, want) {
				t.Fatalf("%s output missing %q: %q", name, want, output)
			}
		}
	}
}
