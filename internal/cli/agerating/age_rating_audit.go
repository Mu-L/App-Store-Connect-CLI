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

// AgeRatingAuditCommand returns the age-rating audit subcommand.
func AgeRatingAuditCommand() *ffcli.Command {
	fs := flag.NewFlagSet("age-rating audit", flag.ExitOnError)

	appIDs := shared.BindOnceCSVFlag(fs, "app", "[experimental] Restrict the audit to specific app IDs (comma-separated)")
	paginate := fs.Bool("paginate", false, "[experimental] Fetch all app pages (default: first page only)")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "audit",
		ShortUsage: "asc age-rating audit [--app \"APP_ID,APP_ID\"] [--paginate] [flags]",
		ShortHelp:  "[experimental] Audit social-media age rating responses across apps.",
		LongHelp: `[experimental] Audit social-media age rating responses across apps.

This command is experimental.

Starting September 2026, Apple requires responses to the social-media
capability questions in the age rating questionnaire for every new submission
and app update. By default, this command audits the first app page (up to 200
apps). Pass --paginate to audit every app page, or --app to audit specific IDs.

A response counts as missing when:
  - socialMedia is unset, or false while socialMediaAgeRestricted is true
  - messagingAndChat is unset
  - socialMediaAgeRestricted is unset while socialMedia is true
  - ageAssurance is unset or false while socialMediaAgeRestricted is true
  - userGeneratedContent is false while socialMedia or socialMediaAgeRestricted is true

Use "asc age-rating edit" to fill gaps.

Examples:
  asc age-rating audit
  asc age-rating audit --paginate
  asc age-rating audit --app "123456789,987654321"
  asc age-rating audit --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("age-rating audit does not accept positional arguments")
			}

			appProvided := false
			fs.Visit(func(parsed *flag.Flag) {
				appProvided = appProvided || parsed.Name == "app"
			})
			only := shared.SplitUniqueCSV(appIDs.String())
			if appProvided && len(only) == 0 {
				return shared.UsageError("--app must include at least one app ID")
			}

			client, err := shared.GetASCClient()
			if err != nil {
				return fmt.Errorf("age-rating audit: %w", err)
			}
			apps, moreApps, err := auditTargetApps(ctx, client, only, *paginate)
			if err != nil {
				return fmt.Errorf("age-rating audit: %w", err)
			}
			if len(apps) == 0 {
				return fmt.Errorf("age-rating audit: no apps matched")
			}

			rows := auditDeclarations(ctx, client, apps)

			result := asc.AgeRatingAuditResult{Apps: rows}
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
			if len(only) == 0 && moreApps {
				fmt.Fprintln(os.Stderr, "Warning: more apps exist; use --paginate to audit every app.")
			}

			if err := shared.PrintOutput(&result, *output.Output, *output.Pretty); err != nil {
				return err
			}
			if result.ErrorCount > 0 {
				noun := "apps"
				if result.ErrorCount == 1 {
					noun = "app"
				}
				err := fmt.Errorf("age-rating audit: %d %s could not be audited; see per-app errors in the output", result.ErrorCount, noun)
				fmt.Fprintln(os.Stderr, err)
				return shared.NewReportedError(err)
			}
			return nil
		},
	}
}

type auditApp struct {
	id       string
	name     string
	bundleID string
}

func auditTargetApps(ctx context.Context, client *asc.Client, only []string, paginate bool) ([]auditApp, bool, error) {
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
			return nil, false, err
		}
		for _, app := range resp.Data {
			if len(wanted) > 0 && !wanted[app.ID] {
				continue
			}
			apps = append(apps, auditApp{id: app.ID, name: app.Attributes.Name, bundleID: app.Attributes.BundleID})
		}
		next = strings.TrimSpace(resp.Links.Next)
		if next == "" || !paginate {
			break
		}
	}

	for _, id := range only {
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
	return apps, next != "", nil
}

func auditDeclarations(ctx context.Context, client *asc.Client, apps []auditApp) []asc.AgeRatingAuditRow {
	rows := make([]asc.AgeRatingAuditRow, len(apps))
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

func auditDeclaration(ctx context.Context, client *asc.Client, app auditApp) asc.AgeRatingAuditRow {
	row := asc.AgeRatingAuditRow{
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
	socialMediaAgeRestricted := nullableBoolValue(attrs.SocialMediaAgeRestricted)
	row.SocialMedia = auditBoolStatus(socialMedia)
	row.SocialMediaAgeRestricted = auditBoolStatus(socialMediaAgeRestricted)
	row.MessagingAndChat = auditBoolStatus(attrs.MessagingAndChat)
	row.AgeAssurance = auditBoolStatus(attrs.AgeAssurance)

	if socialMedia == nil {
		row.MissingResponses = append(row.MissingResponses, "socialMedia")
	}
	if attrs.MessagingAndChat == nil {
		row.MissingResponses = append(row.MissingResponses, "messagingAndChat")
	}
	if boolIsTrue(socialMedia) && socialMediaAgeRestricted == nil {
		row.MissingResponses = append(row.MissingResponses, "socialMediaAgeRestricted")
	}
	if boolIsTrue(socialMediaAgeRestricted) && boolIsFalse(socialMedia) {
		row.MissingResponses = append(row.MissingResponses, "socialMedia")
	}
	if (boolIsTrue(socialMedia) || boolIsTrue(socialMediaAgeRestricted)) && boolIsFalse(attrs.UserGeneratedContent) {
		row.MissingResponses = append(row.MissingResponses, "userGeneratedContent")
	}
	if boolIsTrue(socialMediaAgeRestricted) && !boolIsTrue(attrs.AgeAssurance) {
		row.MissingResponses = append(row.MissingResponses, "ageAssurance")
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
