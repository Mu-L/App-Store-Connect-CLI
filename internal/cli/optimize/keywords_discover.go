package optimize

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/ads"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

const (
	keywordDiscoverSchemaVersion = "1"
	keywordDiscoverDefaultLimit  = 50

	keywordSuggestionSourceKeyword = "keyword_suggestions"
	keywordSuggestionSourcePhrase  = "phrase_suggestions"
)

var collectSearchDataForDiscover = ads.CollectSearchOptimizationData

// KeywordsDiscoverCommand returns the official Apple Ads keyword suggestion
// command.
func KeywordsDiscoverCommand() *ffcli.Command {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	appID := fs.String("app", "", "[experimental] App Store app ID (required, or ASC_APP_ID env)")
	country := fs.String("country", "us", "[experimental] ISO alpha-2 Apple Ads country or region")
	genre := fs.String("genre", "", "[experimental] Apple Ads genre; optional, and only narrows the shared Apple Ads collection")
	adAccount := fs.String("ad-account", "", "[experimental] Apple Ads ad account ID (or ASC_ADS_AD_ACCOUNT_ID/profile default)")
	adsProfile := fs.String("ads-profile", "", "[experimental] Use named Apple Ads authentication profile")
	limit := fs.Int("limit", keywordDiscoverDefaultLimit, "[experimental] Maximum suggestions to return")
	output := shared.BindOutputFlags(fs)

	return &ffcli.Command{
		Name:       "discover",
		ShortUsage: "asc optimize keywords discover --app APP_ID [flags]",
		ShortHelp:  "List official Apple Ads keyword suggestions for an app. [experimental]",
		LongHelp: `List keyword candidates from Apple's official Ads suggestion endpoints. [experimental]

Suggestions come only from Apple's documented keyword and phrase suggestion
endpoints. No campaign is required. Undocumented endpoints, including the
iTunes search autocomplete endpoint, are deliberately out of scope.

Terms are normalized, deduplicated across both endpoints, and reported with the
endpoint each one came from. Apple Ads is the only source for this command, so
unlike the other keyword commands it fails when that source is unavailable
instead of degrading. Credentials come from --ad-account, --ads-profile, the
ASC_ADS_AD_ACCOUNT_ID environment variable, or a stored Apple Ads profile.

The report also carries scoreKeywords, a comma-separated list of the
suggestions that satisfy keyword hygiene, ready to pass straight to
` + "`asc optimize keywords score --keywords`" + `. Suggestions that are too long, too
short, too many words, or contain the comma delimiter remain listed but are
left out of that field.

Examples:
  asc optimize keywords discover --app "1234567890" --country US
  asc optimize keywords discover --app "1234567890" --country US --ad-account "987654321" --limit 25
  asc optimize keywords discover --app "1234567890" --country US --output table`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if len(args) > 0 {
				return shared.UsageError("optimize keywords discover does not accept positional arguments")
			}

			resolvedAppID, err := normalizeKeywordAppID(*appID)
			if err != nil {
				return err
			}
			normalizedCountry, err := normalizeKeywordCountry(*country)
			if err != nil {
				return err
			}
			normalizedGenre := strings.ToUpper(strings.TrimSpace(*genre))
			if normalizedGenre != "" && !searchPlanGenrePattern.MatchString(normalizedGenre) {
				return shared.UsageError("--genre must be an Apple Ads genre identifier such as PRODUCTIVITY_UTILITIES")
			}
			if *limit < 1 {
				return shared.UsageError("--limit must be at least 1")
			}

			window, err := resolveSearchPlanWindow(keywordScorePopularityWindow, time.Now())
			if err != nil {
				return shared.UsageError(err.Error())
			}
			requestCtx, cancel := shared.ContextWithTimeout(ctx)
			defer cancel()
			data, err := collectSearchDataForDiscover(requestCtx, *adsProfile, *adAccount, ads.SearchOptimizationRequest{
				AppID:           resolvedAppID,
				Country:         strings.ToUpper(normalizedCountry),
				Genre:           normalizedGenre,
				Start:           window.Start,
				End:             window.End,
				PopularityStart: window.PopularityStart,
				PopularityEnd:   window.PopularityEnd,
			})
			if err != nil {
				return keywordDiscoverUnavailableError(err.Error())
			}

			report := buildKeywordDiscoverReport(keywordDiscoverBuildInput{
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
				AppID:       resolvedAppID,
				Country:     strings.ToUpper(normalizedCountry),
				Genre:       normalizedGenre,
				Limit:       *limit,
				Sources:     suggestionSources(data.Sources),
				Suggestions: data.Suggestions,
			})
			if len(report.Keywords) == 0 {
				if cause := unavailableSuggestionCause(report.Sources); cause != "" {
					return keywordDiscoverUnavailableError(cause)
				}
			}

			return shared.PrintOutput(&report, *output.Output, *output.Pretty)
		},
	}
}

type keywordDiscoverBuildInput struct {
	GeneratedAt string
	AppID       string
	Country     string
	Genre       string
	Limit       int
	Sources     []asc.KeywordDiscoverSourceStatus
	Suggestions []ads.SearchSuggestion
}

func buildKeywordDiscoverReport(input keywordDiscoverBuildInput) asc.KeywordDiscoverReport {
	seen := make(map[string]struct{}, len(input.Suggestions))
	suggestions := make([]asc.KeywordSuggestion, 0, len(input.Suggestions))
	duplicates := 0

	for _, suggestion := range input.Suggestions {
		keyword := strings.ToLower(strings.Join(strings.Fields(suggestion.Text), " "))
		if keyword == "" {
			continue
		}
		if _, duplicate := seen[keyword]; duplicate {
			duplicates++
			continue
		}
		seen[keyword] = struct{}{}
		suggestions = append(suggestions, asc.KeywordSuggestion{
			Keyword:    keyword,
			Source:     strings.TrimSpace(suggestion.Kind),
			Popularity: suggestion.Popularity,
		})
	}

	summary := asc.KeywordDiscoverSummary{Available: len(suggestions)}
	truncated := false
	if input.Limit > 0 && len(suggestions) > input.Limit {
		suggestions = suggestions[:input.Limit]
		truncated = true
	}

	scoreReady := make([]string, 0, len(suggestions))
	for _, suggestion := range suggestions {
		summary.Suggestions++
		switch suggestion.Source {
		case "phrase":
			summary.PhraseSource++
		default:
			summary.KeywordSource++
		}
		if len(scoreReady) < keywordMaxCount && isScoreReadyKeyword(suggestion.Keyword) {
			scoreReady = append(scoreReady, suggestion.Keyword)
		}
	}
	summary.Duplicates = duplicates
	summary.ScoreReady = len(scoreReady)

	return asc.KeywordDiscoverReport{
		SchemaVersion: keywordDiscoverSchemaVersion,
		GeneratedAt:   input.GeneratedAt,
		AppID:         input.AppID,
		Country:       input.Country,
		Genre:         input.Genre,
		Limit:         input.Limit,
		Truncated:     truncated,
		Sources:       input.Sources,
		Summary:       summary,
		ScoreKeywords: strings.Join(scoreReady, ","),
		Keywords:      suggestions,
	}
}

// isScoreReadyKeyword reports whether a suggestion satisfies the same keyword
// hygiene that `asc optimize keywords score` enforces, so scoreKeywords can be
// passed straight through without being rejected.
func isScoreReadyKeyword(keyword string) bool {
	if strings.ContainsRune(keyword, ',') {
		return false
	}
	_, err := normalizeKeywordList(keyword)
	return err == nil
}

func suggestionSources(sources []ads.SearchOptimizationSourceStatus) []asc.KeywordDiscoverSourceStatus {
	filtered := make([]asc.KeywordDiscoverSourceStatus, 0, 2)
	for _, source := range sources {
		if source.Name == keywordSuggestionSourceKeyword || source.Name == keywordSuggestionSourcePhrase {
			filtered = append(filtered, asc.KeywordDiscoverSourceStatus{
				Name:   source.Name,
				Status: source.Status,
				Count:  source.Count,
				Error:  source.Error,
			})
		}
	}
	return filtered
}

func unavailableSuggestionCause(sources []asc.KeywordDiscoverSourceStatus) string {
	causes := make([]string, 0, len(sources))
	for _, source := range sources {
		if source.Status != keywordStatusUnavailable {
			return ""
		}
		causes = append(causes, source.Name+": "+source.Error)
	}
	if len(causes) == 0 {
		return ""
	}
	return strings.Join(causes, "; ")
}

func keywordDiscoverUnavailableError(cause string) error {
	return fmt.Errorf(
		"optimize keywords discover: Apple Ads keyword suggestions are unavailable: %s. "+
			"Provide Apple Ads credentials with --ad-account or --ads-profile, or run `asc ads auth login`",
		cause,
	)
}
