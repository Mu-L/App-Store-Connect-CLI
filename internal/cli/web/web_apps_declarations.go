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

var (
	listWebAppDeclarationsFn = func(ctx context.Context, client *webcore.Client, accountID, appID string) ([]webcore.AppDeclaration, error) {
		return client.ListAppDeclarations(ctx, accountID, appID)
	}
	viewWebMedicalDeviceDeclarationFn = func(ctx context.Context, client *webcore.Client, accountID, appID string) (*webcore.MedicalDeviceDeclarationState, error) {
		return client.GetMedicalDeviceDeclaration(ctx, accountID, appID)
	}
)

const declarationsLongHelp = `WEB SESSION WORKFLOWS

Read the App Store Regulations & Permits declarations App Store Connect tracks
for an app under App Information. Apple does not expose these declarations on
the public App Store Connect API, so this command uses the same web-session
compliance-form endpoint the website uses.

Requirements Apple reports here include the regulated medical device
declaration and any other declaration Apple requires for the app; a requirement
that is still at ` + "`PENDING_COLLECTION`" + ` blocks App Store submission.

`

// WebAppsDeclarationsCommand returns the app declarations command group.
func WebAppsDeclarationsCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web apps declarations", flag.ExitOnError)

	return &ffcli.Command{
		Name:       "declarations",
		ShortUsage: "asc web apps declarations <subcommand> [flags]",
		ShortHelp:  "Read App Store Regulations & Permits declarations via web sessions.",
		LongHelp:   declarationsLongHelp,
		FlagSet:    fs,
		UsageFunc:  shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			WebAppsDeclarationsListCommand(),
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// WebAppsDeclarationsListCommand lists the compliance declarations for an app.
func WebAppsDeclarationsListCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web apps declarations list", flag.ExitOnError)

	appID := fs.String("app", "", "App Store Connect app ID (or ASC_APP_ID)")
	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "list",
		ShortUsage: "asc web apps declarations list --app APP_ID [flags]",
		ShortHelp:  "List App Store Regulations & Permits declarations for an app.",
		LongHelp: declarationsLongHelp + `Examples:
  asc web apps declarations list --app "6748252780"
  asc web apps declarations list --app "6748252780" --output json

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageErrorf("unexpected argument(s): %s", strings.Join(args, " "))
			}

			resolvedAppID := strings.TrimSpace(shared.ResolveAppID(*appID))
			if resolvedAppID == "" {
				return shared.UsageError("--app is required (or set ASC_APP_ID)")
			}

			accountID, client, err := resolveWebComplianceClient(ctx, authFlags, "web apps declarations list")
			if err != nil {
				return err
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			declarations := []webcore.AppDeclaration{}
			err = withWebSpinner("Fetching app declarations", func() error {
				result, err := listWebAppDeclarationsFn(requestCtx, client, accountID, resolvedAppID)
				if err != nil {
					return err
				}
				declarations = append(declarations, result...)
				return nil
			})
			if err != nil {
				return withWebAuthHint(err, "web apps declarations list")
			}

			headers := []string{"Requirement", "Status", "Required", "Requirement ID", "Form ID"}
			rows := make([][]string, 0, len(declarations))
			for _, declaration := range declarations {
				rows = append(rows, []string{
					declaration.RequirementName,
					valueOrNA(declaration.Status),
					fmt.Sprintf("%t", declaration.Required),
					valueOrNA(declaration.RequirementID),
					valueOrNA(declaration.FormID),
				})
			}

			return shared.PrintOutputWithRenderers(
				declarations,
				*output.Output,
				*output.Pretty,
				func() error {
					asc.RenderTable(headers, rows)
					return nil
				},
				func() error {
					asc.RenderMarkdown(headers, rows)
					return nil
				},
			)
		},
	}
}

// WebAppsMedicalDeviceViewCommand reads the regulated medical device declaration.
func WebAppsMedicalDeviceViewCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web apps medical-device view", flag.ExitOnError)

	appID := fs.String("app", "", "App Store Connect app ID (or ASC_APP_ID)")
	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "view",
		ShortUsage: "asc web apps medical-device view --app APP_ID [flags]",
		ShortHelp:  "Read the regulated medical device declaration via web API.",
		LongHelp: `WEB SESSION WORKFLOWS

Read the stored regulated medical device declaration for an app.

The reported declaration is "no" or "yes" once the form has been answered, and
empty while the declaration is still outstanding.

Examples:
  asc web apps medical-device view --app "6748252780"

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageErrorf("unexpected argument(s): %s", strings.Join(args, " "))
			}

			resolvedAppID := strings.TrimSpace(shared.ResolveAppID(*appID))
			if resolvedAppID == "" {
				return shared.UsageError("--app is required (or set ASC_APP_ID)")
			}

			accountID, client, err := resolveWebComplianceClient(ctx, authFlags, "web apps medical-device view")
			if err != nil {
				return err
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			var state *webcore.MedicalDeviceDeclarationState
			err = withWebSpinner("Fetching regulated medical device declaration", func() error {
				var err error
				state, err = viewWebMedicalDeviceDeclarationFn(requestCtx, client, accountID, resolvedAppID)
				return err
			})
			if err != nil {
				return withWebAuthHint(err, "web apps medical-device view")
			}
			if state == nil {
				return fmt.Errorf("web apps medical-device view failed: missing declaration state")
			}

			headers := []string{"App ID", "Requirement", "Declaration", "Status", "Required", "Countries/Regions"}
			rows := [][]string{{
				state.AppID,
				state.RequirementName,
				valueOrNA(state.Declaration),
				valueOrNA(state.Status),
				fmt.Sprintf("%t", state.Required),
				valueOrNA(strings.Join(state.CountriesOrRegions, ",")),
			}}

			return shared.PrintOutputWithRenderers(
				state,
				*output.Output,
				*output.Pretty,
				func() error {
					asc.RenderTable(headers, rows)
					return nil
				},
				func() error {
					asc.RenderMarkdown(headers, rows)
					return nil
				},
			)
		},
	}
}

// resolveWebComplianceClient resolves the web session and account id shared by
// the compliance-form commands.
func resolveWebComplianceClient(ctx context.Context, authFlags webSessionFlags, command string) (string, *webcore.Client, error) {
	session, err := resolveWebSessionForCommand(ctx, authFlags)
	if err != nil {
		return "", nil, err
	}

	accountID := strings.TrimSpace(session.PublicProviderID)
	if accountID == "" {
		return "", nil, fmt.Errorf("%s failed: web session is missing public provider/account id (run 'asc web auth login')", command)
	}
	return accountID, newWebClientFn(session), nil
}
