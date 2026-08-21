package xcodecloud

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func printXcodeCloudDoctorResult(result *xcodeCloudDoctorResult, output string, pretty bool) error {
	return shared.PrintOutputWithRenderers(
		result,
		output,
		pretty,
		func() error { renderXcodeCloudDoctorResult(result, false); return nil },
		func() error { renderXcodeCloudDoctorResult(result, true); return nil },
	)
}

func renderXcodeCloudDoctorResult(result *xcodeCloudDoctorResult, markdown bool) {
	buildNumber := "N/A"
	if result.Run.BuildNumber > 0 {
		buildNumber = strconv.Itoa(result.Run.BuildNumber)
	}
	summaryRows := [][]string{
		{"runId", result.Run.BuildRunID},
		{"buildNumber", buildNumber},
		{"executionProgress", shared.OrNA(result.Run.ExecutionProgress)},
		{"completionStatus", shared.OrNA(result.Run.CompletionStatus)},
		{"totalActions", strconv.Itoa(result.Summary.TotalActions)},
		{"failedActions", strconv.Itoa(result.Summary.FailedActions)},
		{"errors", strconv.Itoa(result.Summary.Errors)},
		{"warnings", strconv.Itoa(result.Summary.Warnings)},
		{"artifacts", strconv.Itoa(result.Summary.Artifacts)},
		{"logBundles", strconv.Itoa(result.Summary.LogBundles)},
		{"logBundlesInspected", strconv.Itoa(result.Summary.LogBundlesInspected)},
		{"conclusion", result.Conclusion},
		{"nextAction", result.NextAction},
	}
	shared.RenderSection("Summary", []string{"field", "value"}, summaryRows, markdown)

	actionRows := make([][]string, 0, len(result.Actions))
	for _, action := range result.Actions {
		actionRows = append(actionRows, []string{
			action.ID,
			action.Name,
			action.ActionType,
			action.ExecutionProgress,
			action.CompletionStatus,
			strconv.Itoa(len(action.Issues)),
			strconv.Itoa(len(action.Artifacts)),
		})
	}
	shared.RenderSection("Actions", []string{"id", "name", "type", "progress", "status", "issues", "artifacts"}, actionRows, markdown)

	issueRows := make([][]string, 0, result.Summary.Errors+result.Summary.Warnings)
	artifactRows := make([][]string, 0, result.Summary.Artifacts)
	for _, action := range result.Actions {
		for _, issue := range action.Issues {
			location := ""
			if issue.FileSource != nil {
				location = issue.FileSource.Path
				if issue.FileSource.LineNumber > 0 {
					location = fmt.Sprintf("%s:%d", location, issue.FileSource.LineNumber)
				}
			}
			issueRows = append(issueRows, []string{action.ID, issue.IssueType, issue.Category, issue.Message, location})
		}
		for _, artifact := range action.Artifacts {
			artifactRows = append(artifactRows, []string{
				action.ID,
				artifact.ID,
				artifact.FileType,
				artifact.FileName,
				strconv.Itoa(artifact.FileSize),
			})
		}
	}
	shared.RenderSection("Issues", []string{"actionId", "type", "category", "message", "location"}, issueRows, markdown)
	shared.RenderSection("Artifacts", []string{"actionId", "id", "type", "name", "bytes"}, artifactRows, markdown)

	logRows := make([][]string, 0, len(result.LogBundles))
	for _, bundle := range result.LogBundles {
		codes := make([]string, 0, len(bundle.Diagnostics))
		for _, diagnostic := range bundle.Diagnostics {
			codes = append(codes, diagnostic.Code)
		}
		logRows = append(logRows, []string{
			bundle.ActionID,
			bundle.ArtifactID,
			strconv.FormatBool(bundle.Inspected),
			shared.OrNA(bundle.ExportStatus),
			strings.Join(codes, ","),
			bundle.SavedPath,
		})
	}
	shared.RenderSection("Log Bundles", []string{"actionId", "artifactId", "inspected", "exportStatus", "diagnostics", "savedPath"}, logRows, markdown)

	coverageRows := make([][]string, 0, len(result.CoverageWarnings))
	for _, warning := range result.CoverageWarnings {
		coverageRows = append(coverageRows, []string{warning.ID, warning.Message, warning.Remediation})
	}
	shared.RenderSection("Coverage Warnings", []string{"id", "message", "remediation"}, coverageRows, markdown)
}
