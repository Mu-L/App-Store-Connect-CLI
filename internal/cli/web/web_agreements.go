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

var getAgreementsStatusFn = func(ctx context.Context, client *webcore.Client) (*asc.WebAgreementsStatusResult, error) {
	return client.GetAgreementsStatus(ctx)
}

var acceptAgreementsFn = func(ctx context.Context, client *webcore.Client, req webcore.AgreementsAcceptRequest) (*asc.WebAgreementsAcceptResult, error) {
	return client.AcceptAgreements(ctx, req)
}

// WebAgreementsCommand returns the Apple Developer Program agreements group.
func WebAgreementsCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web agreements", flag.ExitOnError)

	return &ffcli.Command{
		Name:       "agreements",
		ShortUsage: "asc web agreements <subcommand> [flags]",
		ShortHelp:  "[experimental] Check and accept Apple Developer Program agreements.",
		LongHelp: `WEB SESSION WORKFLOWS

This command is experimental.

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
		ShortHelp:  "[experimental] Show Apple Developer Program agreement status.",
		LongHelp: `WEB SESSION WORKFLOWS

This command is experimental.

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

			var result *asc.WebAgreementsStatusResult
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

			return shared.PrintOutput(result, *output.Output, *output.Pretty)
		},
	}
}

// WebAgreementsAcceptCommand accepts one or more pending program agreements.
func WebAgreementsAcceptCommand() *ffcli.Command {
	fs := flag.NewFlagSet("web agreements accept", flag.ExitOnError)

	var agreementIDs shared.MultiStringFlag
	fs.Var(&agreementIDs, "agreement-id", "[experimental] Developer Portal agreement ID to accept (from `asc web agreements status`; repeatable)")
	confirm := fs.Bool("confirm", false, "[experimental] Confirm accepting the agreements on behalf of the Account Holder")
	authFlags := bindWebSessionFlags(fs)
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "accept",
		ShortUsage: "asc web agreements accept --agreement-id AGREEMENT_ID [--agreement-id AGREEMENT_ID ...] --confirm [flags]",
		ShortHelp:  "[experimental] Accept Apple Developer Program agreements.",
		LongHelp: `WEB SESSION WORKFLOWS

This command is experimental.

Accept one or more Apple Developer Program agreements, such as an updated
Apple Developer Program License Agreement, for the web session's team.
Repeat --agreement-id to accept several agreements in a single request; every
agreement must be named explicitly.

Accepting an agreement is a legal action. Apple only allows the team's
Account Holder to accept agreements; sessions for other roles fail with an
Apple error. Find pending agreement IDs with:
  asc web agreements status

After the write, the command re-reads the team's agreement history and fails
with a non-zero exit when any requested agreement is still pending or missing.
The receipt reflects that re-read server state.

Examples:
  asc web agreements accept --agreement-id "AGREEMENT_ID" --confirm
  asc web agreements accept --agreement-id "AGREEMENT_ID" --agreement-id "OTHER_AGREEMENT_ID" --confirm

`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("web agreements accept does not accept positional arguments")
			}

			resolvedAgreementIDs := uniqueTrimmedStrings(agreementIDs)
			switch {
			case len(resolvedAgreementIDs) == 0:
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

			var accepted *asc.WebAgreementsAcceptResult
			err = withWebSpinner("Accepting Apple Developer Program agreements", func() error {
				var acceptErr error
				accepted, acceptErr = acceptAgreementsFn(requestCtx, client, webcore.AgreementsAcceptRequest{
					AgreementIDs: resolvedAgreementIDs,
				})
				return acceptErr
			})
			if err != nil {
				return withWebAuthHint(err, "web agreements accept")
			}
			if accepted == nil {
				return fmt.Errorf("web agreements accept failed: missing accept result")
			}

			var status *asc.WebAgreementsStatusResult
			err = withWebSpinner("Verifying Apple Developer Program agreement status", func() error {
				var statusErr error
				status, statusErr = getAgreementsStatusFn(requestCtx, client)
				return statusErr
			})
			if err != nil {
				return fmt.Errorf("web agreements accept failed: the accept request succeeded but re-reading agreement status failed; run 'asc web agreements status' to confirm the result: %w", err)
			}
			if status == nil {
				return fmt.Errorf("web agreements accept failed: the accept request succeeded but the agreement status re-read returned no result")
			}
			result, err := verifyAcceptedAgreements(accepted.TeamID, resolvedAgreementIDs, status)
			if err != nil {
				return fmt.Errorf("web agreements accept failed: %w", err)
			}
			// Developer Portal bootstrap can add origin-specific cookies to the
			// shared jar. Cache them best-effort after the operation succeeds.
			_ = persistWebSessionFn(session)

			return shared.PrintOutput(result, *output.Output, *output.Pretty)
		},
	}
}

// verifyAcceptedAgreements builds the accept receipt from the re-read agreement
// history. Every requested agreement must be present and no longer pending.
func verifyAcceptedAgreements(teamID string, requestedIDs []string, status *asc.WebAgreementsStatusResult) (*asc.WebAgreementsAcceptResult, error) {
	byID := make(map[string]asc.WebAgreement, len(status.Agreements))
	for _, agreement := range status.Agreements {
		byID[agreement.AgreementID] = agreement
	}
	if strings.TrimSpace(teamID) == "" {
		teamID = status.TeamID
	}

	var missing, pending []string
	agreements := make([]asc.WebAgreement, 0, len(requestedIDs))
	for _, id := range requestedIDs {
		agreement, ok := byID[id]
		switch {
		case !ok:
			missing = append(missing, id)
		case agreement.Pending:
			pending = append(pending, id)
		default:
			agreements = append(agreements, agreement)
		}
	}
	if len(missing) > 0 || len(pending) > 0 {
		var problems []string
		if len(pending) > 0 {
			problems = append(problems, fmt.Sprintf("agreement(s) %s are still pending after acceptance", strings.Join(pending, ", ")))
		}
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("agreement(s) %s are not present in the team's agreement history", strings.Join(missing, ", ")))
		}
		return nil, fmt.Errorf("%s; run 'asc web agreements status' to inspect", strings.Join(problems, "; "))
	}
	return &asc.WebAgreementsAcceptResult{
		TeamID:       teamID,
		AgreementIDs: requestedIDs,
		Status:       "accepted",
		Verified:     true,
		Agreements:   agreements,
	}, nil
}

func uniqueTrimmedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
