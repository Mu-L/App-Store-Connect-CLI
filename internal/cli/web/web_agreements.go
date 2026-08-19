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

var getAgreementsStatusFn = func(ctx context.Context, client *webcore.Client) (*webcore.AgreementsStatusResult, error) {
	return client.GetAgreementsStatus(ctx)
}

var acceptAgreementsFn = func(ctx context.Context, client *webcore.Client, req webcore.AgreementsAcceptRequest) (*webcore.AgreementsAcceptResult, error) {
	return client.AcceptAgreements(ctx, req)
}

// WebAgreementsCommand returns the Apple Developer Program agreements group.
func WebAgreementsCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web agreements", flag.ExitOnError)

	return &ffcli.Command{
		Name:       "agreements",
		ShortUsage: "asc web agreements <subcommand> [flags]",
		ShortHelp:  "Check and accept Apple Developer Program agreements.",
		LongHelp: `WEB SESSION WORKFLOWS

Check and accept Apple Developer Program agreements, such as the Apple
Developer Program License Agreement, through Apple web-session endpoints.
The public App Store Connect API has no endpoint for these agreements.

Examples:
  asc web agreements status
  asc web agreements accept --agreement-id "AGREEMENT_ID" --confirm

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{
			WebAgreementsStatusCommand(),
			WebAgreementsAcceptCommand(),
		},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// WebAgreementsStatusCommand reports pending and accepted program agreements.
func WebAgreementsStatusCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web agreements status", flag.ExitOnError)

	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "status",
		ShortUsage: "asc web agreements status [flags]",
		ShortHelp:  "Show Apple Developer Program agreement status.",
		LongHelp: `WEB SESSION WORKFLOWS

Show the App Store Connect agreement alert banner and the team's Apple
Developer Program agreement history, including whether an updated agreement
is waiting for the Account Holder.

An agreement is reported as pending when App Store Connect shows an agreement
alert banner or when the agreement's accepted date is older than its
effective date.

Example:
  asc web agreements status

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("web agreements status does not accept positional arguments")
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			session, err := resolveWebSessionForCommand(requestCtx, authFlags)
			if err != nil {
				return err
			}
			client := newWebClientFn(session)

			var result *webcore.AgreementsStatusResult
			err = withWebSpinner("Fetching Apple Developer Program agreement status", func() error {
				var statusErr error
				result, statusErr = getAgreementsStatusFn(requestCtx, client)
				return statusErr
			})
			if err != nil {
				return withWebAuthHint(err, "web agreements status")
			}
			if result == nil {
				return fmt.Errorf("web agreements status failed: missing status result")
			}
			// Developer Portal bootstrap can add origin-specific cookies to the
			// shared jar. Cache them best-effort after the operation succeeds.
			_ = persistWebSessionFn(session)

			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error { return renderWebAgreementsStatusTable(result) },
				func() error { return renderWebAgreementsStatusMarkdown(result) },
			)
		},
	}
}

// WebAgreementsAcceptCommand accepts a pending program agreement.
func WebAgreementsAcceptCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web agreements accept", flag.ExitOnError)

	agreementID := fs.String("agreement-id", "", "Developer Portal agreement ID to accept (from `asc web agreements status`)")
	confirm := fs.Bool("confirm", false, "Confirm accepting the agreement on behalf of the Account Holder")
	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "accept",
		ShortUsage: "asc web agreements accept --agreement-id AGREEMENT_ID --confirm [flags]",
		ShortHelp:  "Accept an Apple Developer Program agreement.",
		LongHelp: `WEB SESSION WORKFLOWS

Accept an Apple Developer Program agreement, such as an updated Apple
Developer Program License Agreement, for the web session's team.

Accepting an agreement is a legal action. Apple only allows the team's
Account Holder to accept agreements; sessions for other roles fail with an
Apple error. Find pending agreement IDs with:
  asc web agreements status

Example:
  asc web agreements accept --agreement-id "AGREEMENT_ID" --confirm

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("web agreements accept does not accept positional arguments")
			}

			resolvedAgreementID := strings.TrimSpace(*agreementID)
			switch {
			case resolvedAgreementID == "":
				return shared.UsageError("--agreement-id is required")
			case !*confirm:
				return shared.UsageError("--confirm is required")
			}

			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()

			session, err := resolveWebSessionForCommand(requestCtx, authFlags)
			if err != nil {
				return err
			}
			client := newWebClientFn(session)

			var result *webcore.AgreementsAcceptResult
			err = withWebSpinner("Accepting Apple Developer Program agreement", func() error {
				var acceptErr error
				result, acceptErr = acceptAgreementsFn(requestCtx, client, webcore.AgreementsAcceptRequest{
					AgreementIDs: []string{resolvedAgreementID},
				})
				return acceptErr
			})
			if err != nil {
				return withWebAuthHint(err, "web agreements accept")
			}
			if result == nil {
				return fmt.Errorf("web agreements accept failed: missing accept result")
			}
			// Developer Portal bootstrap can add origin-specific cookies to the
			// shared jar. Cache them best-effort after the operation succeeds.
			_ = persistWebSessionFn(session)

			return shared.PrintOutputWithRenderers(
				result,
				*output.Output,
				*output.Pretty,
				func() error { return renderWebAgreementsAcceptTable(result) },
				func() error { return renderWebAgreementsAcceptMarkdown(result) },
			)
		},
	}
}

func webAgreementsStatusRows(result *webcore.AgreementsStatusResult) [][]string {
	rows := make([][]string, 0, len(result.Agreements))
	for _, agreement := range result.Agreements {
		rows = append(rows, []string{
			agreement.AgreementID,
			agreement.Title,
			agreement.Version,
			agreement.Status,
			fmt.Sprintf("%t", agreement.Pending),
			agreement.DateAgreeBy,
		})
	}
	return rows
}

var webAgreementsStatusHeaders = []string{"Agreement ID", "Title", "Version", "Status", "Pending", "Accept By"}

func renderWebAgreementsStatusTable(result *webcore.AgreementsStatusResult) error {
	asc.RenderTable(webAgreementsStatusHeaders, webAgreementsStatusRows(result))
	return nil
}

func renderWebAgreementsStatusMarkdown(result *webcore.AgreementsStatusResult) error {
	asc.RenderMarkdown(webAgreementsStatusHeaders, webAgreementsStatusRows(result))
	return nil
}

func webAgreementsAcceptRow(result *webcore.AgreementsAcceptResult) [][]string {
	acceptedAt := ""
	for _, agreement := range result.Agreements {
		if agreement.DateAccepted != "" {
			acceptedAt = agreement.DateAccepted
			break
		}
	}
	return [][]string{{
		result.TeamID,
		strings.Join(result.AgreementIDs, ", "),
		result.Status,
		acceptedAt,
	}}
}

var webAgreementsAcceptHeaders = []string{"Team ID", "Agreement IDs", "Status", "Accepted At"}

func renderWebAgreementsAcceptTable(result *webcore.AgreementsAcceptResult) error {
	asc.RenderTable(webAgreementsAcceptHeaders, webAgreementsAcceptRow(result))
	return nil
}

func renderWebAgreementsAcceptMarkdown(result *webcore.AgreementsAcceptResult) error {
	asc.RenderMarkdown(webAgreementsAcceptHeaders, webAgreementsAcceptRow(result))
	return nil
}
