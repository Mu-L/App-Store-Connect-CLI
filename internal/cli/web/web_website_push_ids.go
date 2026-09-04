package web

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

var listDeveloperWebsitePushIDsFn = func(ctx context.Context, client *webcore.Client) (*webcore.DeveloperWebsitePushIDsListResult, error) {
	return client.ListDeveloperWebsitePushIDs(ctx)
}

// WebWebsitePushIDsCommand returns the read-only Website Push ID command group.
func WebWebsitePushIDsCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web website-push-ids", flag.ExitOnError)

	return &ffcli.Command{
		Name:       "website-push-ids",
		ShortUsage: "asc web website-push-ids <subcommand> [flags]",
		ShortHelp:  "[experimental] Read Website Push IDs via Developer Portal web sessions.",
		LongHelp: `[experimental] WEB SESSION WORKFLOWS

Read Website Push IDs through Apple's Developer Portal web-session endpoint.
Only the captured legacy list operation is available in this slice.

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			WebWebsitePushIDsListCommand(),
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// WebWebsitePushIDsListCommand lists Website Push IDs visible to the selected
// Developer Portal team. Apple’s legacy endpoint has no captured continuation
// contract, so this command requests its fixed first page only.
func WebWebsitePushIDsListCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web website-push-ids list", flag.ExitOnError)
	authFlags := bindWebSessionFlags(fs)
	portalFlags := bindDeveloperPortalFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc web website-push-ids list [flags]",
		ShortHelp:  "[experimental] List Website Push IDs via a Developer Portal web session.",
		LongHelp: `[experimental] List Website Push IDs via a Developer Portal web session.

WEB SESSION WORKFLOWS

List the Website Push IDs visible to the selected Apple Developer team. The
command returns Apple's complete legacy response envelope in JSON. Formatted
output shows only a small scalar projection of each entry.

Examples:
  asc web website-push-ids list --output table
  asc web website-push-ids list --developer-team "TEAM_ID" --output json

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("web website-push-ids list does not accept positional arguments")
			}
			if err := validateDeveloperPortalFlags(portalFlags); err != nil {
				return err
			}
			if _, err := shared.ValidateOutputFormat(*output.Output, *output.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}

			session, requestCtx, cancel, err := resolveWebSessionForCommand(ctx, authFlags)
			defer cancel()
			if err != nil {
				return withWebAuthHint(err, "web website-push-ids list")
			}

			var result *webcore.DeveloperWebsitePushIDsListResult
			err = withWebSpinner("Loading Developer Portal Website Push IDs", func() error {
				var listErr error
				result, listErr = listDeveloperWebsitePushIDsFn(requestCtx, newDeveloperPortalClient(session, portalFlags))
				return listErr
			})
			if err != nil {
				return withWebAuthHint(err, "web website-push-ids list")
			}
			if result == nil {
				return fmt.Errorf("web website-push-ids list failed: missing list result")
			}
			persistDeveloperPortalSession(session)

			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error { return renderDeveloperWebsitePushIDsTable(result) },
				func() error { return renderDeveloperWebsitePushIDsMarkdown(result) },
			)
		},
	}
}

func developerWebsitePushIDsHeaders() []string {
	return []string{"Website Push ID", "Name", "Identifier"}
}

func developerWebsitePushIDsRows(result *webcore.DeveloperWebsitePushIDsListResult) [][]string {
	if result == nil {
		return nil
	}
	rows := make([][]string, 0, len(result.WebsitePushIDList))
	for _, entry := range result.WebsitePushIDList {
		rows = append(rows, []string{
			shared.OrNA(developerWebsitePushIDValue(entry, "websitePushId", "id")),
			shared.OrNA(developerWebsitePushIDValue(entry, "name")),
			shared.OrNA(developerWebsitePushIDValue(entry, "identifier")),
		})
	}
	return rows
}

func developerWebsitePushIDValue(entry webcore.DeveloperWebsitePushID, keys ...string) string {
	for _, key := range keys {
		value, ok := entry[key]
		if !ok || value == nil {
			continue
		}
		if text, ok := value.(string); ok {
			return strings.TrimSpace(text)
		}
		return fmt.Sprint(value)
	}
	return ""
}

func renderDeveloperWebsitePushIDsTable(result *webcore.DeveloperWebsitePushIDsListResult) error {
	var rows [][]string
	if result != nil {
		rows = developerWebsitePushIDsRows(result)
	}
	asc.RenderTable(developerWebsitePushIDsHeaders(), rows)
	return nil
}

func renderDeveloperWebsitePushIDsMarkdown(result *webcore.DeveloperWebsitePushIDsListResult) error {
	var rows [][]string
	if result != nil {
		rows = developerWebsitePushIDsRows(result)
	}
	asc.RenderMarkdown(developerWebsitePushIDsHeaders(), rows)
	return nil
}
