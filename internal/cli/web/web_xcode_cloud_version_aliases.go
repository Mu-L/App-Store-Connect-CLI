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

func webVersionAliasesGroup() *ffcli.Command {
	fs := flag.NewFlagSet("web xcode-cloud settings version-aliases", flag.ExitOnError)
	return &ffcli.Command{
		Name:       "version-aliases",
		ShortUsage: "asc web xcode-cloud settings version-aliases <subcommand> [flags]",
		ShortHelp:  "Inspect Xcode Cloud custom version aliases.",
		UsageFunc:  shared.DefaultUsageFunc,
		FlagSet:    fs,
		Subcommands: []*ffcli.Command{
			webVersionAliasesList(),
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}
}

func webVersionAliasesList() *ffcli.Command {
	fs := flag.NewFlagSet("web xcode-cloud settings version-aliases list", flag.ExitOnError)
	sessionFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)
	productID := fs.String("product-id", "", "Xcode Cloud product ID (required)")

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc web xcode-cloud settings version-aliases list --product-id ID [flags]",
		ShortHelp:  "List up to 100 Xcode Cloud custom version aliases.",
		LongHelp: `WEB SESSION WORKFLOWS

List up to 100 custom version aliases for an Xcode Cloud product. The captured
response contract does not expose continuation metadata, so this command
intentionally does not claim full pagination.



Example:
  asc web xcode-cloud settings version-aliases list --product-id "UUID" --apple-id "user@example.com"`,
		UsageFunc: shared.DefaultUsageFunc,
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("web xcode-cloud settings version-aliases list does not accept positional arguments")
			}
			pid := strings.TrimSpace(*productID)
			if pid == "" {
				fmt.Fprintln(os.Stderr, "Error: --product-id is required")
				return shared.MissingRequiredUsageError("--product-id")
			}

			session, requestCtx, cancel, err := resolveWebSessionForCommand(ctx, sessionFlags)
			defer cancel()
			if err != nil {
				return err
			}
			teamID := strings.TrimSpace(session.PublicProviderID)
			if teamID == "" {
				return fmt.Errorf("xcode-cloud settings version-aliases list failed: session has no public provider ID")
			}

			response, err := newCIClientFn(session).GetCIVersionAliases(requestCtx, teamID, pid)
			if err != nil {
				return withWebAuthHint(err, "xcode-cloud settings version-aliases list")
			}
			result := &asc.WebXcodeCloudVersionAliasesResult{
				ProductID:      pid,
				VersionAliases: make([]asc.WebXcodeCloudVersionAlias, 0, len(response.Items)),
			}
			for _, item := range response.Items {
				result.VersionAliases = append(result.VersionAliases, webVersionAliasOutput(item))
			}
			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error { return asc.PrintTable(result) },
				func() error { return asc.PrintMarkdown(result) },
			)
		},
	}
}

func webVersionAliasOutput(item webcore.CIVersionAlias) asc.WebXcodeCloudVersionAlias {
	return asc.WebXcodeCloudVersionAlias{
		ID:             item.ID,
		Name:           item.Name,
		Type:           item.Type,
		Locked:         item.Locked,
		BuildName:      item.BuildName,
		BuildSupported: item.BuildSupported,
	}
}
