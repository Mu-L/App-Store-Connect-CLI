package agerating

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

const ageRatingAuditWorkers = 5

// AgeRatingAuditRow reports one app's social-media capability responses.
type AgeRatingAuditRow struct {
	AppID                    string   `json:"appId"`
	Name                     string   `json:"name,omitempty"`
	BundleID                 string   `json:"bundleId,omitempty"`
	SocialMedia              string   `json:"socialMedia"`
	SocialMediaAgeRestricted string   `json:"socialMediaAgeRestricted"`
	MessagingAndChat         string   `json:"messagingAndChat"`
	AgeAssurance             string   `json:"ageAssurance"`
	MissingResponses         []string `json:"missingResponses"`
	Ready                    bool     `json:"ready"`
	Error                    string   `json:"error,omitempty"`
}

// AgeRatingAuditResult summarizes social-media capability readiness per app.
type AgeRatingAuditResult struct {
	Apps         []AgeRatingAuditRow `json:"apps"`
	ReadyCount   int                 `json:"readyCount"`
	MissingCount int                 `json:"missingCount"`
	ErrorCount   int                 `json:"errorCount"`
}

// AgeRatingAuditCommand returns the age-rating audit subcommand.
func AgeRatingAuditCommand() *ffcli.Command {
	fs := flag.NewFlagSet("age-rating audit", flag.ExitOnError)

	appIDs := shared.BindOnceCSVFlag(fs, "app", "Restrict the audit to specific app IDs (comma-separated; default: every app)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "audit",
		ShortUsage: "asc age-rating audit [--app \"APP_ID,APP_ID\"] [flags]",
		ShortHelp:  "Audit social-media age rating responses across apps.",
		LongHelp: `Audit social-media age rating responses across apps.

Starting September 2026, Apple requires responses to the social-media
capability questions in the age rating questionnaire for every new submission
and app update. This command sweeps apps and reports which declarations still
have unset responses.

A response counts as missing when:
  - socialMedia is unset
  - messagingAndChat is unset
  - socialMediaAgeRestricted is unset while socialMedia is true

ageAssurance is reported for context but only matters when declaring
socialMediaAgeRestricted true; use "asc age-rating edit" to fill gaps.

Examples:
  asc age-rating audit
  asc age-rating audit --app "123456789,987654321"
  asc age-rating audit --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("age-rating audit does not accept positional arguments")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("age-rating audit: %w", err)
			}

			only := []string{}
			for _, id := range strings.Split(appIDs.String(), ",") {
				if trimmed := strings.TrimSpace(id); trimmed != "" {
					only = append(only, trimmed)
				}
			}
			apps, err := auditTargetApps(ctx, client, only)
			if err != nil {
				return fmt.Errorf("age-rating audit: %w", err)
			}
			if len(apps) == 0 {
				return fmt.Errorf("age-rating audit: no apps matched")
			}

			rows := auditDeclarations(ctx, client, apps)

			result := AgeRatingAuditResult{Apps: rows}
			for _, row := range rows {
				switch {
				case row.Error != "":
					result.ErrorCount++
				case row.Ready:
					result.ReadyCount++
				default:
					result.MissingCount++
				}
			}

			if result.MissingCount > 0 {
				fmt.Fprintf(
					os.Stderr,
					"%d of %d apps are missing social-media age rating responses; Apple requires them for new submissions and updates starting September 2026.\n",
					result.MissingCount,
					len(rows),
				)
			} else if result.ErrorCount == 0 {
				fmt.Fprintf(os.Stderr, "All %d apps have the social-media age rating responses set.\n", len(rows))
			}

			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error {
					renderAgeRatingAuditResult(result, false)
					return nil
				},
				func() error {
					renderAgeRatingAuditResult(result, true)
					return nil
				},
			)
		},
	}
}

type auditApp struct {
	id       string
	name     string
	bundleID string
}

func auditTargetApps(ctx context.Context, client *asc.Client, only []string) ([]auditApp, error) {
	requestCtx, cancel := shared.ContextWithTimeout(ctx)
	defer cancel()

	wanted := map[string]bool{}
	for _, id := range only {
		wanted[strings.TrimSpace(id)] = true
	}

	apps := []auditApp{}
	next := ""
	for {
		opts := []asc.AppsOption{asc.WithAppsLimit(200)}
		if next != "" {
			opts = append(opts, asc.WithAppsNextURL(next))
		}
		resp, err := client.GetApps(requestCtx, opts...)
		if err != nil {
			return nil, err
		}
		for _, app := range resp.Data {
			if len(wanted) > 0 && !wanted[app.ID] {
				continue
			}
			apps = append(apps, auditApp{id: app.ID, name: app.Attributes.Name, bundleID: app.Attributes.BundleID})
		}
		next = strings.TrimSpace(resp.Links.Next)
		if next == "" {
			break
		}
	}

	for id := range wanted {
		if id == "" {
			continue
		}
		found := false
		for _, app := range apps {
			if app.id == id {
				found = true
				break
			}
		}
		if !found {
			apps = append(apps, auditApp{id: id})
		}
	}
	return apps, nil
}

func auditDeclarations(ctx context.Context, client *asc.Client, apps []auditApp) []AgeRatingAuditRow {
	rows := make([]AgeRatingAuditRow, len(apps))
	jobs := make(chan int)

	var workers sync.WaitGroup
	workerCount := min(ageRatingAuditWorkers, len(apps))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				rows[index] = auditDeclaration(ctx, client, apps[index])
			}
		}()
	}
	for index := range apps {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return rows
}

func auditDeclaration(ctx context.Context, client *asc.Client, app auditApp) AgeRatingAuditRow {
	row := AgeRatingAuditRow{
		AppID:            app.id,
		Name:             app.name,
		BundleID:         app.bundleID,
		MissingResponses: []string{},
	}

	requestCtx, cancel := shared.ContextWithTimeout(ctx)
	defer cancel()

	resp, err := fetchAgeRatingDeclaration(requestCtx, client, app.id, "", "", nil)
	if err != nil {
		row.Error = err.Error()
		row.SocialMedia = "-"
		row.SocialMediaAgeRestricted = "-"
		row.MessagingAndChat = "-"
		row.AgeAssurance = "-"
		return row
	}

	attrs := resp.Data.Attributes
	socialMedia := nullableBoolValue(attrs.SocialMedia)
	row.SocialMedia = auditBoolStatus(socialMedia)
	row.SocialMediaAgeRestricted = auditBoolStatus(nullableBoolValue(attrs.SocialMediaAgeRestricted))
	row.MessagingAndChat = auditBoolStatus(attrs.MessagingAndChat)
	row.AgeAssurance = auditBoolStatus(attrs.AgeAssurance)

	if socialMedia == nil {
		row.MissingResponses = append(row.MissingResponses, "socialMedia")
	}
	if attrs.MessagingAndChat == nil {
		row.MissingResponses = append(row.MissingResponses, "messagingAndChat")
	}
	if boolIsTrue(socialMedia) && nullableBoolValue(attrs.SocialMediaAgeRestricted) == nil {
		row.MissingResponses = append(row.MissingResponses, "socialMediaAgeRestricted")
	}
	row.Ready = len(row.MissingResponses) == 0
	return row
}

func auditBoolStatus(value *bool) string {
	if value == nil {
		return "UNSET"
	}
	return fmt.Sprintf("%t", *value)
}

func renderAgeRatingAuditResult(result AgeRatingAuditResult, markdown bool) {
	headers := []string{"App ID", "Name", "Social Media", "Age Restricted", "Messaging & Chat", "Age Assurance", "Missing"}
	rows := make([][]string, 0, len(result.Apps))
	for _, row := range result.Apps {
		missing := strings.Join(row.MissingResponses, ", ")
		if row.Error != "" {
			missing = "error: " + row.Error
		}
		rows = append(rows, []string{
			row.AppID,
			row.Name,
			row.SocialMedia,
			row.SocialMediaAgeRestricted,
			row.MessagingAndChat,
			row.AgeAssurance,
			missing,
		})
	}
	if markdown {
		asc.RenderMarkdown(headers, rows)
		return
	}
	asc.RenderTable(headers, rows)
}
