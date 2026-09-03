package web

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

var getWebAppLastCompatibleVersionsFn = func(ctx context.Context, client *webcore.Client, appID string) (*webcore.AppLastCompatibleVersions, error) {
	return client.GetAppLastCompatibleVersions(ctx, appID)
}

// WebAppsLastCompatibleVersionCommand returns the last-compatible-version command group.
func WebAppsLastCompatibleVersionCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web apps last-compatible-version", flag.ExitOnError)

	return &ffcli.Command{
		Name:       "last-compatible-version",
		ShortUsage: "asc web apps last-compatible-version <subcommand> [flags]",
		ShortHelp:  "Inspect per-version download availability via web sessions.",
		LongHelp: `WEB SESSION WORKFLOWS

Read the per-version download availability that App Store Connect exposes as
Last-Compatible Version Settings, where a previously released version can be
made unavailable for download on older operating systems and devices.

The public App Store Connect API's OpenAPI snapshot documents downloadable on
appStoreVersions, and asc versions list/view --output json preserves it when
Apple returns the attribute. The default public versions table does not include
it. This command reads App Store Connect's own Last-Compatible Version Settings
iris request, including its sparse fieldset, relationship order, and limit.

This command is read-only. Making a version unavailable for download is not
reversible from every state, and the write request body is not captured yet, so
keep using the App Store Connect web UI for that change.

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			WebAppsLastCompatibleVersionViewCommand(),
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// WebAppsLastCompatibleVersionViewCommand returns the last-compatible-version view command.
func WebAppsLastCompatibleVersionViewCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web apps last-compatible-version view", flag.ExitOnError)

	appID := fs.String("app", "", "App Store Connect app ID (or ASC_APP_ID)")
	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "view",
		ShortUsage: "asc web apps last-compatible-version view --app APP_ID [flags]",
		ShortHelp:  "View per-version download availability.",
		LongHelp: `WEB SESSION WORKFLOWS

List every app store version with the downloadable flag App Store Connect uses
for Last-Compatible Version Settings. Versions follow Apple's appStoreVersions
relationship order. Apple omits downloadable for versions that never carried
the setting; those rows report "unknown" instead of a guessed default.

Apple returns both appStoreState and appVersionState inconsistently across
versions. Both are printed exactly as returned; neither is remapped.

Examples:
  asc web apps last-compatible-version view --app 6759231657
  asc web apps last-compatible-version view --app 6759231657 --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageErrorf("unexpected argument(s): %s", strings.Join(args, " "))
			}

			resolvedAppID := strings.TrimSpace(shared.ResolveAppID(*appID))
			if resolvedAppID == "" {
				fmt.Fprintln(os.Stderr, "Error: --app is required (or set ASC_APP_ID)")
				return shared.MissingRequiredUsageError("--app")
			}

			session, err := resolveWebSessionForCommand(ctx, authFlags)
			if err != nil {
				return err
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			var result *webcore.AppLastCompatibleVersions
			err = withWebSpinner("Fetching last-compatible version settings", func() error {
				var err error
				result, err = getWebAppLastCompatibleVersionsFn(requestCtx, newWebClientFn(session), resolvedAppID)
				return err
			})
			if err != nil {
				return withWebAuthHint(err, "web apps last-compatible-version view")
			}

			return printWebAppLastCompatibleVersions(result, *output.Output, *output.Pretty)
		},
	}
}

var webAppLastCompatibleVersionHeaders = []string{"version_id", "version", "platform", "app_store_state", "app_version_state", "downloadable", "created_date"}

func printWebAppLastCompatibleVersions(result *webcore.AppLastCompatibleVersions, output string, pretty bool) error {
	return shared.PrintOutputWithRenderers(
		result,
		output,
		pretty,
		func() error {
			asc.RenderTable(webAppLastCompatibleVersionHeaders, webAppLastCompatibleVersionRows(result))
			return nil
		},
		func() error {
			asc.RenderMarkdown(webAppLastCompatibleVersionHeaders, webAppLastCompatibleVersionRows(result))
			return nil
		},
	)
}

func webAppLastCompatibleVersionRows(result *webcore.AppLastCompatibleVersions) [][]string {
	if result == nil {
		return nil
	}
	rows := make([][]string, 0, len(result.Versions))
	for _, version := range result.Versions {
		rows = append(rows, []string{
			version.ID,
			webAppValueOrUnknown(version.VersionString),
			webAppValueOrUnknown(version.Platform),
			webAppValueOrUnknown(version.AppStoreState),
			webAppValueOrUnknown(version.AppVersionState),
			formatWebCompatibilityBool(version.Downloadable),
			webAppValueOrUnknown(version.CreatedDate),
		})
	}
	return rows
}
