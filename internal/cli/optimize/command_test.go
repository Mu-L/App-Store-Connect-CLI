package optimize

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/ads"
)

func TestSearchPlanCommandHelpDescribesOfficialReadOnlyWorkflow(t *testing.T) {
	command := SearchPlanCommand()
	joined := command.ShortUsage + "\n" + command.LongHelp
	for _, want := range []string{
		"asc optimize search plan",
		"official Apple Ads Platform API v1",
		"does not mutate",
		"--out-dir",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("help missing %q:\n%s", want, joined)
		}
	}
}

func TestSearchPlanCommandValidatesRequiredFlagsBeforeAuthentication(t *testing.T) {
	t.Setenv("ASC_APP_ID", "")
	command := SearchPlanCommand()
	err := command.ParseAndRun(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "--app is required") {
		t.Fatalf("error = %v, want --app required", err)
	}
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestSearchPlanCommandRejectsInvalidCountryGenreLocaleAndWindow(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "country", args: []string{"--app", "1", "--version", "4.4.4", "--ad-account", "2", "--country", "USA", "--genre", "PRODUCTIVITY_UTILITIES", "--locale", "en-US"}, want: "--country must be an ISO alpha-2 code"},
		{name: "genre", args: []string{"--app", "1", "--version", "4.4.4", "--ad-account", "2", "--country", "US", "--genre", "bad genre", "--locale", "en-US"}, want: "--genre"},
		{name: "locale", args: []string{"--app", "1", "--version", "4.4.4", "--ad-account", "2", "--country", "US", "--genre", "PRODUCTIVITY_UTILITIES", "--locale", "english"}, want: "--locale"},
		{name: "window", args: []string{"--app", "1", "--version", "4.4.4", "--ad-account", "2", "--country", "US", "--genre", "PRODUCTIVITY_UTILITIES", "--locale", "en-US", "--window", "31d"}, want: "--window"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := SearchPlanCommand()
			err := command.ParseAndRun(context.Background(), test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("error = %v, want usage error", err)
			}
		})
	}
}

func TestSearchPlanCommandRejectsPositionalArguments(t *testing.T) {
	command := SearchPlanCommand()
	err := command.Exec(context.Background(), []string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "does not accept positional arguments") {
		t.Fatalf("error = %v", err)
	}
}

func TestOptimizeGroupsReturnHelp(t *testing.T) {
	for _, command := range []*flag.FlagSet{OptimizeCommand().FlagSet, SearchCommand().FlagSet} {
		if command == nil {
			t.Fatal("group command is missing a FlagSet")
		}
	}
	if err := OptimizeCommand().Exec(context.Background(), nil); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("optimize Exec error = %v, want flag.ErrHelp", err)
	}
}

func TestSearchPlanCommandRendersSupportedOutputsAndWritesArtifacts(t *testing.T) {
	previousMetadata := resolveSearchMetadataForPlan
	previousAds := collectSearchDataForPlan
	t.Cleanup(func() {
		resolveSearchMetadataForPlan = previousMetadata
		collectSearchDataForPlan = previousAds
	})
	resolveSearchMetadataForPlan = func(_ context.Context, appSelector, version, platform, locale string) (resolvedSearchMetadata, error) {
		if appSelector != "123456789" || version != "4.4.4" || platform != "IOS" || locale != "en-US" {
			t.Fatalf("metadata inputs = (%q, %q, %q, %q)", appSelector, version, platform, locale)
		}
		return resolvedSearchMetadata{
			AppID: "123456789", VersionID: "version-1", Platform: "IOS",
			Metadata: searchMetadataSnapshot{Name: "Focus Keeper", Subtitle: "Habit tracker", Keywords: "focus,timer"},
		}, nil
	}
	collectSearchDataForPlan = func(_ context.Context, profile, account string, request ads.SearchOptimizationRequest) (ads.SearchOptimizationData, error) {
		if profile != "Ads" || account != "987654321" || request.AppID != "123456789" || request.Country != "US" || request.Genre != "PRODUCTIVITY_UTILITIES" {
			t.Fatalf("Ads inputs = (%q, %q, %+v)", profile, account, request)
		}
		return ads.SearchOptimizationData{
			Sources: []ads.SearchOptimizationSourceStatus{
				{Name: "keyword_suggestions", Status: "available", Count: 1},
				{Name: "phrase_suggestions", Status: "unavailable", Error: "request unavailable"},
				{Name: "search_term_performance", Status: "empty"},
			},
			Suggestions:  []ads.SearchSuggestion{{Text: "daily habits", Popularity: intPtr(72), Kind: "keyword"}},
			Popularities: []ads.SearchPopularity{{Term: "daily habits", Popularity100: intPtr(72), Popularity5: intPtr(4), RankInGenre: intPtr(8)}},
		}, nil
	}

	baseArgs := []string{
		"--app", "123456789", "--version", "4.4.4", "--ad-account", "987654321", "--ads-profile", "Ads",
		"--country", "us", "--genre", "productivity_utilities", "--locale", "en-US",
	}
	for _, format := range []string{"json", "table", "markdown"} {
		t.Run(format, func(t *testing.T) {
			args := append(append([]string(nil), baseArgs...), "--output", format)
			if format == "json" {
				args = append(args, "--out-dir", filepath.Join(t.TempDir(), "plan"))
			}
			stdout := captureSearchPlanStdout(t, func() error {
				return SearchPlanCommand().ParseAndRun(context.Background(), args)
			})
			for _, want := range []string{"daily habits", "metadata_candidate", "untested_candidate", "phrase_suggestions", "unavailable", "request unavailable"} {
				if !strings.Contains(stdout, want) {
					t.Fatalf("%s output missing %q:\n%s", format, want, stdout)
				}
			}
			if format != "json" {
				normalizedOutput := strings.ToLower(stdout)
				for _, want := range []string{"Popularity 1-5", "Popularity 1-100", "Genre Rank", "Sources", "Notices"} {
					if !strings.Contains(normalizedOutput, strings.ToLower(want)) {
						t.Fatalf("%s output missing report section %q:\n%s", format, want, stdout)
					}
				}
			}
			if format == "json" {
				outIndex := len(args) - 1
				if _, err := os.Stat(filepath.Join(args[outIndex], searchPlanReportArtifact)); err != nil {
					t.Fatalf("report artifact: %v", err)
				}
			}
		})
	}
}

func captureSearchPlanStdout(t *testing.T, run func() error) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	runErr := run()
	_ = writer.Close()
	os.Stdout = previous
	data, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if runErr != nil {
		t.Fatalf("run error = %v", runErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data)
}
