package xcodecloud

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

type xcodeCloudDoctorOptions struct {
	Wait         bool
	PollInterval time.Duration
	SkipLogs     bool
	SaveLogs     string
}

type xcodeCloudDoctorResult struct {
	Run              *asc.XcodeCloudStatusResult       `json:"run"`
	Summary          xcodeCloudDoctorSummary           `json:"summary"`
	Actions          []xcodeCloudDoctorAction          `json:"actions"`
	LogBundles       []xcodeCloudDoctorLogBundle       `json:"logBundles"`
	CoverageWarnings []xcodeCloudDoctorCoverageWarning `json:"coverageWarnings"`
	Conclusion       string                            `json:"conclusion"`
	NextAction       string                            `json:"nextAction"`
}

type xcodeCloudDoctorSummary struct {
	TotalActions        int `json:"totalActions"`
	FailedActions       int `json:"failedActions"`
	SkippedActions      int `json:"skippedActions"`
	Errors              int `json:"errors"`
	Warnings            int `json:"warnings"`
	Artifacts           int `json:"artifacts"`
	LogBundles          int `json:"logBundles"`
	LogBundlesInspected int `json:"logBundlesInspected"`
}

type xcodeCloudDoctorAction struct {
	ID                string                     `json:"id"`
	Name              string                     `json:"name,omitempty"`
	ActionType        string                     `json:"actionType,omitempty"`
	ExecutionProgress string                     `json:"executionProgress,omitempty"`
	CompletionStatus  string                     `json:"completionStatus,omitempty"`
	IsRequiredToPass  *bool                      `json:"isRequiredToPass,omitempty"`
	Issues            []xcodeCloudDoctorIssue    `json:"issues"`
	Artifacts         []xcodeCloudDoctorArtifact `json:"artifacts"`
}

type xcodeCloudDoctorIssue struct {
	ID         string            `json:"id"`
	IssueType  string            `json:"issueType,omitempty"`
	Category   string            `json:"category,omitempty"`
	Message    string            `json:"message,omitempty"`
	FileSource *asc.FileLocation `json:"fileSource,omitempty"`
}

type xcodeCloudDoctorArtifact struct {
	ID       string `json:"id"`
	FileType string `json:"fileType,omitempty"`
	FileName string `json:"fileName,omitempty"`
	FileSize int    `json:"fileSize,omitempty"`
}

type xcodeCloudDoctorCoverageWarning struct {
	ID          string `json:"id"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// XcodeCloudDoctorCommand returns the xcode-cloud doctor subcommand.
func XcodeCloudDoctorCommand() *ffcli.Command {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)

	runID := fs.String("run-id", "", "Build run ID to diagnose")
	wait := fs.Bool("wait", false, "Wait for the build run to complete before diagnosing it")
	pollInterval := fs.Duration("poll-interval", 10*time.Second, "Poll interval when waiting")
	timeout := fs.Duration("timeout", 0, "Timeout for Xcode Cloud requests (0 = use ASC_TIMEOUT or 30m default)")
	skipLogs := fs.Bool("skip-logs", false, "Skip automatic inspection of failed-action log bundles")
	saveLogs := fs.String("save-logs", "", "Directory in which to retain inspected log bundles")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "doctor",
		ShortUsage: "asc xcode-cloud doctor --run-id \"BUILD_RUN_ID\" [flags]",
		ShortHelp:  "Diagnose an Xcode Cloud build run and inspect failure logs.",
		LongHelp: `Diagnose an Xcode Cloud build run.

The command combines run status, actions, issues, and artifacts into one report.
For failed runs, it inspects failed-action LOG_BUNDLE artifacts in memory and
reports App Store import diagnostics when those details are present. Use
--save-logs to retain the downloaded bundles. A failed build is report data and
does not make doctor exit non-zero.

Examples:
  asc xcode-cloud doctor --run-id "BUILD_RUN_ID"
  asc xcode-cloud doctor --run-id "BUILD_RUN_ID" --wait
  asc xcode-cloud doctor --run-id "BUILD_RUN_ID" --wait --save-logs ./xcode-cloud-logs
  asc xcode-cloud doctor --run-id "BUILD_RUN_ID" --skip-logs --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.WithDiagnostic(shared.UsageError("xcode-cloud doctor does not accept positional arguments"), shared.DiagnosticInvalidInput, "")
			}
			runIDValue := strings.TrimSpace(*runID)
			if runIDValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --run-id is required")
				return shared.MissingRequiredUsageError("--run-id")
			}
			if *timeout < 0 {
				return shared.UsageError("--timeout must be greater than or equal to 0")
			}
			if *wait && *pollInterval <= 0 {
				return shared.UsageError("--poll-interval must be greater than 0")
			}
			if !*wait && flagWasSet(fs, "poll-interval") {
				return shared.UsageError("--poll-interval requires --wait")
			}
			if *skipLogs && strings.TrimSpace(*saveLogs) != "" {
				return shared.UsageError("--save-logs and --skip-logs are mutually exclusive")
			}
			if flagWasSet(fs, "save-logs") && strings.TrimSpace(*saveLogs) == "" {
				return shared.UsageError("--save-logs must not be empty")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("xcode-cloud doctor: %w", err)
			}

			requestCtx, cancel := contextWithXcodeCloudTimeout(ctx, *timeout)
			defer cancel()

			result, err := diagnoseXcodeCloudRun(requestCtx, client, runIDValue, xcodeCloudDoctorOptions{
				Wait:         *wait,
				PollInterval: *pollInterval,
				SkipLogs:     *skipLogs,
				SaveLogs:     strings.TrimSpace(*saveLogs),
			})
			if err != nil {
				return fmt.Errorf("xcode-cloud doctor: %w", err)
			}

			return printXcodeCloudDoctorResult(result, *output.Output, *output.Pretty)
		},
	}
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(current *flag.Flag) {
		if current.Name == name {
			set = true
		}
	})
	return set
}

func diagnoseXcodeCloudRun(ctx context.Context, client *asc.Client, runID string, options xcodeCloudDoctorOptions) (*xcodeCloudDoctorResult, error) {
	var (
		run *asc.CiBuildRunResponse
		err error
	)
	if options.Wait {
		run, err = waitForBuildRunForDoctor(ctx, client, runID, options.PollInterval)
	} else {
		run, err = getCiBuildRun(ctx, client, runID)
	}
	if err != nil {
		return nil, err
	}

	actions, err := listBuildActionsForRunAllowEmpty(ctx, client, runID)
	if err != nil {
		return nil, err
	}

	result := &xcodeCloudDoctorResult{
		Run:              buildStatusResult(run),
		Actions:          make([]xcodeCloudDoctorAction, 0, len(actions)),
		LogBundles:       make([]xcodeCloudDoctorLogBundle, 0),
		CoverageWarnings: make([]xcodeCloudDoctorCoverageWarning, 0),
	}
	for _, action := range actions {
		actionResult, err := diagnoseXcodeCloudAction(ctx, client, action)
		if err != nil {
			return nil, err
		}
		result.Actions = append(result.Actions, actionResult)
	}

	summarizeXcodeCloudDoctorResult(result)
	if options.SkipLogs && result.Summary.LogBundles > 0 && doctorRunFailed(result) {
		result.CoverageWarnings = append(result.CoverageWarnings, xcodeCloudDoctorCoverageWarning{
			ID:          "log_bundle_inspection_skipped",
			Message:     "Log bundle inspection was disabled with --skip-logs.",
			Remediation: "Re-run without --skip-logs to inspect failed-action log bundles.",
		})
	}
	if shouldInspectDoctorLogs(result, options) {
		if err := inspectXcodeCloudDoctorLogs(ctx, client, result, options); err != nil {
			return nil, err
		}
	}
	finishXcodeCloudDoctorResult(result)
	return result, nil
}

func waitForBuildRunForDoctor(ctx context.Context, client *asc.Client, runID string, pollInterval time.Duration) (*asc.CiBuildRunResponse, error) {
	lastStatus := "unknown"
	run, err := asc.PollUntil(ctx, pollInterval, func(ctx context.Context) (*asc.CiBuildRunResponse, bool, error) {
		resp, err := getCiBuildRun(ctx, client, runID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check status: %w", err)
		}
		lastStatus = string(resp.Data.Attributes.ExecutionProgress)
		return resp, asc.IsBuildRunComplete(resp.Data.Attributes.ExecutionProgress), nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("canceled waiting for build run %s (last status: %s)", runID, lastStatus)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("timed out waiting for build run %s (last status: %s)", runID, lastStatus)
		}
		return nil, err
	}
	return run, nil
}

func diagnoseXcodeCloudAction(ctx context.Context, client *asc.Client, action asc.CiBuildActionResource) (xcodeCloudDoctorAction, error) {
	actionID := strings.TrimSpace(action.ID)
	result := xcodeCloudDoctorAction{
		ID:                actionID,
		Name:              action.Attributes.Name,
		ActionType:        action.Attributes.ActionType,
		ExecutionProgress: string(action.Attributes.ExecutionProgress),
		CompletionStatus:  string(action.Attributes.CompletionStatus),
		IsRequiredToPass:  action.Attributes.IsRequiredToPass,
		Issues:            make([]xcodeCloudDoctorIssue, 0),
		Artifacts:         make([]xcodeCloudDoctorArtifact, 0),
	}
	if actionID == "" {
		return result, nil
	}

	issues, err := listAllXcodeCloudActionIssues(ctx, client, actionID)
	if err != nil {
		return result, fmt.Errorf("list issues for action %q: %w", actionID, err)
	}
	for _, issue := range issues {
		result.Issues = append(result.Issues, xcodeCloudDoctorIssue{
			ID:         issue.ID,
			IssueType:  issue.Attributes.IssueType,
			Category:   issue.Attributes.Category,
			Message:    issue.Attributes.Message,
			FileSource: issue.Attributes.FileSource,
		})
	}

	artifacts, err := listAllXcodeCloudActionArtifacts(ctx, client, actionID)
	if err != nil {
		return result, fmt.Errorf("list artifacts for action %q: %w", actionID, err)
	}
	for _, artifact := range artifacts {
		result.Artifacts = append(result.Artifacts, xcodeCloudDoctorArtifact{
			ID:       artifact.ID,
			FileType: artifact.Attributes.FileType,
			FileName: artifact.Attributes.FileName,
			FileSize: artifact.Attributes.FileSize,
		})
	}
	return result, nil
}

func listAllXcodeCloudActionIssues(ctx context.Context, client *asc.Client, actionID string) ([]asc.CiIssueResource, error) {
	resp, err := client.GetCiBuildActionIssues(ctx, actionID, asc.WithCiIssuesLimit(200))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(resp.Links.Next) == "" {
		return resp.Data, nil
	}
	allPages, err := asc.PaginateAll(ctx, resp, func(ctx context.Context, nextURL string) (asc.PaginatedResponse, error) {
		return client.GetCiBuildActionIssues(ctx, actionID, asc.WithCiIssuesNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	allIssues, ok := allPages.(*asc.CiIssuesResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected issues response type %T", allPages)
	}
	return allIssues.Data, nil
}

func listAllXcodeCloudActionArtifacts(ctx context.Context, client *asc.Client, actionID string) ([]asc.CiArtifactResource, error) {
	resp, err := client.GetCiBuildActionArtifacts(ctx, actionID, asc.WithCiArtifactsLimit(200))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(resp.Links.Next) == "" {
		return resp.Data, nil
	}
	allPages, err := asc.PaginateAll(ctx, resp, func(ctx context.Context, nextURL string) (asc.PaginatedResponse, error) {
		return client.GetCiBuildActionArtifacts(ctx, actionID, asc.WithCiArtifactsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	allArtifacts, ok := allPages.(*asc.CiArtifactsResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected artifacts response type %T", allPages)
	}
	return allArtifacts.Data, nil
}

func summarizeXcodeCloudDoctorResult(result *xcodeCloudDoctorResult) {
	result.Summary.TotalActions = len(result.Actions)
	for _, action := range result.Actions {
		switch strings.ToUpper(strings.TrimSpace(action.CompletionStatus)) {
		case "FAILED", "ERRORED", "CANCELED":
			result.Summary.FailedActions++
		case "SKIPPED":
			result.Summary.SkippedActions++
		}
		for _, issue := range action.Issues {
			switch strings.ToUpper(strings.TrimSpace(issue.IssueType)) {
			case "ERROR", "TEST_FAILURE":
				result.Summary.Errors++
			case "WARNING", "ANALYZER_WARNING":
				result.Summary.Warnings++
			}
		}
		result.Summary.Artifacts += len(action.Artifacts)
		for _, artifact := range action.Artifacts {
			if strings.EqualFold(strings.TrimSpace(artifact.FileType), "LOG_BUNDLE") {
				result.Summary.LogBundles++
			}
		}
	}
}

func shouldInspectDoctorLogs(result *xcodeCloudDoctorResult, options xcodeCloudDoctorOptions) bool {
	if options.SkipLogs || result.Summary.LogBundles == 0 {
		return false
	}
	if strings.TrimSpace(options.SaveLogs) != "" {
		return true
	}
	return !strings.EqualFold(strings.TrimSpace(result.Run.CompletionStatus), string(asc.CiBuildRunCompletionStatusSucceeded)) &&
		asc.IsBuildRunComplete(asc.CiBuildRunExecutionProgress(result.Run.ExecutionProgress))
}

func finishXcodeCloudDoctorResult(result *xcodeCloudDoctorResult) {
	status := strings.ToUpper(strings.TrimSpace(result.Run.CompletionStatus))
	if !strings.EqualFold(result.Run.ExecutionProgress, string(asc.CiBuildRunExecutionProgressComplete)) {
		result.Conclusion = "The Xcode Cloud build run is not complete."
		result.NextAction = "Re-run this command with --wait to diagnose the terminal result."
		return
	}
	if status == string(asc.CiBuildRunCompletionStatusSucceeded) {
		result.Conclusion = "The Xcode Cloud build run completed successfully."
		result.NextAction = "No corrective action is required."
		return
	}

	hasImportDiagnostic := false
	hasSuccessfulExport := false
	for _, bundle := range result.LogBundles {
		if bundle.ExportStatus == "SUCCEEDED" {
			hasSuccessfulExport = true
		}
		if len(bundle.Diagnostics) > 0 {
			hasImportDiagnostic = true
		}
	}
	if hasImportDiagnostic {
		result.Conclusion = "The Xcode Cloud log bundles contain App Store import diagnostics."
		result.NextAction = "Resolve the reported ITMS diagnostics, then start a new build run."
		return
	}
	if hasSuccessfulExport || doctorHasAppStorePreparationIssue(result) {
		if hasSuccessfulExport {
			result.Conclusion = "The archive export succeeded, but Xcode Cloud reported a later failure without an ITMS-level import diagnostic."
			result.NextAction = "Check the App Store Connect delivery notification or build processing state for the server-side import rejection."
		} else if result.Summary.LogBundles > 0 && result.Summary.LogBundlesInspected == 0 {
			result.Conclusion = "Xcode Cloud reported an App Store Connect preparation failure, but its available log bundles were not inspected."
			result.NextAction = "Re-run without --skip-logs, then check App Store Connect if the logs still contain no import detail."
		} else {
			result.Conclusion = "Xcode Cloud reported an App Store Connect preparation failure without an ITMS-level import diagnostic."
			result.NextAction = "Check the App Store Connect delivery notification or build processing state for the server-side import rejection."
		}
		coverageMessage := "The Xcode Cloud API did not expose a detailed App Store import rejection."
		if result.Summary.LogBundlesInspected > 0 {
			coverageMessage = "The Xcode Cloud API and inspected log bundles did not expose a detailed App Store import rejection."
		}
		result.CoverageWarnings = append(result.CoverageWarnings, xcodeCloudDoctorCoverageWarning{
			ID:          "app_store_import_detail_unavailable",
			Message:     coverageMessage,
			Remediation: "Check the App Store Connect delivery notification or build processing state; do not infer an ITMS root cause from the generic Xcode Cloud issue.",
		})
		return
	}

	if result.Summary.LogBundles > 0 && result.Summary.LogBundlesInspected == 0 {
		result.Conclusion = "The Xcode Cloud build run failed, but its available log bundles were not inspected."
		result.NextAction = "Re-run without --skip-logs or download the listed log bundle artifacts for inspection."
	} else if result.Summary.Errors > 0 {
		result.Conclusion = "The Xcode Cloud build run failed and reported actionable issues."
		result.NextAction = "Resolve the reported issues, then start a new build run."
	} else {
		result.Conclusion = "The Xcode Cloud build run failed without a more specific diagnostic."
		result.NextAction = "Review the available issues and artifacts in the report."
	}
}

func doctorRunFailed(result *xcodeCloudDoctorResult) bool {
	if result == nil || result.Run == nil {
		return false
	}
	return asc.IsBuildRunComplete(asc.CiBuildRunExecutionProgress(result.Run.ExecutionProgress)) &&
		!strings.EqualFold(strings.TrimSpace(result.Run.CompletionStatus), string(asc.CiBuildRunCompletionStatusSucceeded))
}

func doctorHasAppStorePreparationIssue(result *xcodeCloudDoctorResult) bool {
	for _, action := range result.Actions {
		for _, issue := range action.Issues {
			text := strings.ToLower(issue.Category + " " + issue.Message)
			if strings.Contains(text, "app store connect") || strings.Contains(text, "prepare build for app store") {
				return true
			}
		}
	}
	return false
}
