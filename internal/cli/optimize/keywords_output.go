package optimize

import (
	"strconv"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func renderKeywordRankTable(report KeywordRankReport) error {
	renderKeywordRankHuman(report, false)
	return nil
}

func renderKeywordRankMarkdown(report KeywordRankReport) error {
	renderKeywordRankHuman(report, true)
	return nil
}

func renderKeywordRankHuman(report KeywordRankReport, markdown bool) {
	shared.RenderSection("Keyword Rank", []string{"Field", "Value"}, [][]string{
		{"App", report.AppID},
		{"Store", report.Country + " · " + formatSearchPlanPlatform(report.Platform)},
		{"Keywords", strconv.Itoa(report.Summary.Keywords)},
		{"Ranked", strconv.Itoa(report.Summary.Ranked)},
		{"Absent", strconv.Itoa(report.Summary.Absent)},
		{"Unavailable", strconv.Itoa(report.Summary.Unavailable)},
	}, markdown)

	rows := make([][]string, 0, len(report.Rows))
	for _, row := range report.Rows {
		rows = append(rows, []string{
			row.Keyword,
			formatOptionalInt(row.Rank),
			formatOptionalInt(row.TotalResults),
			row.Status,
			compactSearchPlanDiagnostic(row.Error),
		})
	}
	shared.RenderSection("Keywords", []string{"Keyword", "Rank", "Results", "Status", "Error"}, rows, markdown)
}
func renderKeywordDiscoverTable(report KeywordDiscoverReport) error {
	renderKeywordDiscoverHuman(report, false)
	return nil
}

func renderKeywordDiscoverMarkdown(report KeywordDiscoverReport) error {
	renderKeywordDiscoverHuman(report, true)
	return nil
}

func renderKeywordDiscoverHuman(report KeywordDiscoverReport, markdown bool) {
	summaryRows := [][]string{
		{"App", report.AppID},
		{"Store", report.Country},
		{"Suggestions", strconv.Itoa(report.Summary.Suggestions) + " of " + strconv.Itoa(report.Summary.Available)},
		{"From Keywords", strconv.Itoa(report.Summary.KeywordSource)},
		{"From Phrases", strconv.Itoa(report.Summary.PhraseSource)},
		{"Duplicates Removed", strconv.Itoa(report.Summary.Duplicates)},
		{"Ready To Score", strconv.Itoa(report.Summary.ScoreReady)},
	}
	if report.Genre != "" {
		summaryRows = append(summaryRows, []string{"Genre", formatSearchPlanSourceName(report.Genre)})
	}
	if report.Truncated {
		summaryRows = append(summaryRows, []string{"Truncated", "true (--limit " + strconv.Itoa(report.Limit) + ")"})
	}
	shared.RenderSection("Keyword Discovery", []string{"Field", "Value"}, summaryRows, markdown)

	rows := make([][]string, 0, len(report.Keywords))
	for _, suggestion := range report.Keywords {
		rows = append(rows, []string{
			suggestion.Keyword,
			suggestion.Source,
			formatOptionalInt(suggestion.Popularity),
		})
	}
	shared.RenderSection("Suggestions", []string{"Keyword", "Source", "Popularity"}, rows, markdown)

	sourceRows := make([][]string, 0, len(report.Sources))
	for _, source := range report.Sources {
		sourceRows = append(sourceRows, []string{
			formatSearchPlanSourceName(source.Name),
			source.Status,
			strconv.Itoa(source.Count),
			compactSearchPlanDiagnostic(source.Error),
		})
	}
	shared.RenderSection("Sources", []string{"Source", "Status", "Count", "Notes"}, sourceRows, markdown)

	if report.ScoreKeywords != "" {
		shared.RenderSection(
			"Score Input",
			[]string{"Flag", "Value"},
			[][]string{{"--keywords", report.ScoreKeywords}},
			markdown,
		)
	}
}
