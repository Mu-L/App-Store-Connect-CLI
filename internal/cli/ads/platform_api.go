package ads

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

// PlatformAPICommand returns the raw Apple Ads Platform API command group.
func PlatformAPICommand() *ffcli.Command {
	fs := flag.NewFlagSet("ads api", flag.ExitOnError)
	return &ffcli.Command{
		Name:        "api",
		ShortUsage:  "asc ads api <subcommand> [flags]",
		ShortHelp:   "Make raw Apple Ads Platform API v1 requests.",
		LongHelp:    "Make raw Apple Ads Platform API v1 requests.",
		FlagSet:     fs,
		UsageFunc:   shared.DefaultUsageFunc,
		Subcommands: []*ffcli.Command{PlatformAPIRequestCommand()},
		Exec: func(ctx context.Context, args []string) error {
			return flag.ErrHelp
		},
	}
}

// PlatformAPIRequestCommand returns the raw Apple Ads Platform API request command.
func PlatformAPIRequestCommand() *ffcli.Command {
	fs := flag.NewFlagSet("ads api request", flag.ExitOnError)
	method := fs.String("method", "GET", "HTTP method: GET, POST, PUT, DELETE")
	path := fs.String("path", "", "Relative v1 path or Apple Ads Platform API URL")
	file := fs.String("file", "", "Path to JSON request payload")
	confirm := fs.Bool("confirm", false, "Confirm destructive Apple Ads Platform requests")
	common := commonFlags{
		AdsProfile: fs.String("ads-profile", "", "Use named Apple Ads authentication profile"),
		AdAccount:  fs.String("ad-account", "", "Apple Ads ad account ID (or ASC_ADS_AD_ACCOUNT_ID env)"),
	}
	output := shared.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "request",
		ShortUsage: "asc ads api request --method METHOD --path v1/... [flags]",
		ShortHelp:  "Make a raw Apple Ads Platform API v1 request.",
		LongHelp: `Make a raw Apple Ads Platform API v1 request.

Examples:
  asc ads api request --method GET --path v1/me
  asc ads api request --method POST --path v1/campaigns/query --file query.json --ad-account "123"`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if err := rejectUnexpectedArgs(args); err != nil {
				return err
			}
			methodValue := strings.ToUpper(strings.TrimSpace(*method))
			switch methodValue {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
			default:
				return shared.UsageError("--method must be one of: GET, POST, PUT, DELETE")
			}
			pathValue := strings.TrimSpace(*path)
			if pathValue == "" {
				fmt.Fprintln(os.Stderr, "Error: --path is required")
				return shared.MissingRequiredUsageError()
			}
			if methodValue == http.MethodDelete && !*confirm {
				return shared.UsageError("--confirm is required")
			}
			contextKind, err := rawPlatformRequestContextKind(methodValue, pathValue)
			if err != nil {
				return shared.UsageError(err.Error())
			}
			if contextKind == appleads.ContextNone && value(common.AdAccount) != "" {
				return shared.UsageError("--ad-account is not supported for this context-free endpoint")
			}
			pathOnly, err := platformPathOnly(pathValue)
			if err != nil {
				return shared.UsageError(err.Error())
			}
			if rawPlatformRequestRequiresConfirm(methodValue, pathOnly, nil) && !*confirm {
				return shared.UsageError("--confirm is required")
			}
			var payload json.RawMessage
			if strings.TrimSpace(*file) != "" {
				payload, err = shared.ReadJSONFilePayloadKind(*file, shared.JSONPayloadAny)
				if err != nil {
					return fmt.Errorf("ads api request: %w", err)
				}
			}
			if rawPlatformRequestRequiresConfirm(methodValue, pathOnly, payload) && !*confirm {
				return shared.UsageError("--confirm is required")
			}
			client, err := resolvePlatformClient(ctx, common, contextKind)
			if err != nil {
				return fmt.Errorf("ads api request: %w", err)
			}
			requestCtx, cancel := requestContext(ctx)
			defer cancel()
			resp, err := client.RequestForVersion(requestCtx, appleads.APIVersionPlatformV1, methodValue, pathValue, nil, payload, contextKind)
			if err != nil {
				return fmt.Errorf("ads api request: %w", err)
			}
			return shared.PrintOutput(resp, *output.Output, *output.Pretty)
		},
	}
}

func rawPlatformRequestRequiresConfirm(method, pathOnly string, payload json.RawMessage) bool {
	if method == http.MethodDelete {
		return true
	}

	resourcePath := strings.TrimPrefix(pathOnly, "v1/")
	switch {
	case method == http.MethodPost:
		switch resourcePath {
		case "recommendations/daily-budgets/apply",
			"recommendations/daily-budgets/dismiss",
			"recommendations/target-cpas/apply",
			"recommendations/target-cpas/dismiss":
			return true
		}
	case method == http.MethodPut && isSingleChildPath(resourcePath, "ad-accounts"):
		var object map[string]json.RawMessage
		if err := json.Unmarshal(payload, &object); err == nil {
			_, hasDelegations := object["delegations"]
			return hasDelegations
		}
	}
	return false
}

func rawPlatformRequestRequiresAdAccount(method, pathValue string) (bool, error) {
	kind, err := rawPlatformRequestContextKind(method, pathValue)
	return kind == appleads.ContextAdAccount, err
}

func rawPlatformRequestContextKind(method, pathValue string) (appleads.ContextKind, error) {
	pathOnly, err := platformPathOnly(pathValue)
	if err != nil {
		return appleads.ContextNone, err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	resourcePath := strings.TrimPrefix(pathOnly, "v1/")

	switch {
	case method == http.MethodGet && (resourcePath == "me" || resourcePath == "acls" || resourcePath == "advertiser-resources"):
		return appleads.ContextNone, nil
	case method == http.MethodGet && isSingleChildPath(resourcePath, "orgs"):
		return appleads.ContextNone, nil
	case method == http.MethodPost && resourcePath == "ad-accounts":
		return appleads.ContextNone, nil
	case method == http.MethodPost && resourcePath == "shared-budgets":
		return appleads.ContextNone, nil
	case (method == http.MethodPut || method == http.MethodDelete) && isSingleChildPath(resourcePath, "shared-budgets"):
		return appleads.ContextNone, nil
	case method == http.MethodPost && resourcePath == "shared-budgets/query":
		return appleads.ContextAdAccountOptional, nil
	case method == http.MethodGet && isSingleChildPath(resourcePath, "shared-budgets"):
		return appleads.ContextAdAccountOptional, nil
	default:
		return appleads.ContextAdAccount, nil
	}
}

func platformPathOnly(pathValue string) (string, error) {
	trimmed := strings.TrimSpace(pathValue)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("--path must be a valid URL or v1 path: %w", err)
	}
	if parsed.IsAbs() {
		if parsed.Scheme != "https" || parsed.User != nil || parsed.Host != "api.ads.apple.com" || !strings.HasPrefix(parsed.Path, "/v1/") {
			return "", fmt.Errorf("--path must be an Apple Ads Platform API v1 URL")
		}
		pathOnly := strings.TrimPrefix(parsed.Path, "/")
		if err := validatePlatformRelativePath(pathOnly); err != nil {
			return "", err
		}
		return pathOnly, nil
	}
	pathOnly := strings.TrimPrefix(parsed.Path, "/")
	if !strings.HasPrefix(pathOnly, "v1/") {
		return "", fmt.Errorf("--path must start with v1/")
	}
	if err := validatePlatformRelativePath(pathOnly); err != nil {
		return "", err
	}
	return pathOnly, nil
}

func validatePlatformRelativePath(pathOnly string) error {
	if adsPathHasTraversal(pathOnly) {
		return fmt.Errorf("--path must not contain path traversal")
	}
	relative, err := url.Parse(strings.TrimPrefix(pathOnly, "v1/"))
	if err != nil || relative.IsAbs() || relative.Host != "" || relative.User != nil || strings.HasPrefix(relative.Path, "/") || adsPathHasTraversal(relative.Path) {
		return fmt.Errorf("--path must not escape the Apple Ads Platform API v1 base URL")
	}
	return nil
}

func isSingleChildPath(path, parent string) bool {
	parts := strings.Split(path, "/")
	return len(parts) == 2 && parts[0] == parent && strings.TrimSpace(parts[1]) != ""
}

func adsPathHasTraversal(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
