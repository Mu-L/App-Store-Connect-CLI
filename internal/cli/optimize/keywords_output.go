package optimize

import (
	"strconv"
	"strings"

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

func renderKeywordScoreTable(report KeywordScoreReport) error {
	renderKeywordScoreHuman(report, false)
	return nil
}

func renderKeywordScoreMarkdown(report KeywordScoreReport) error {
	renderKeywordScoreHuman(report, true)
	return nil
}

func renderKeywordScoreHuman(report KeywordScoreReport, markdown bool) {
	summaryRows := [][]string{
		{"Store", report.Country},
		{"Keywords", strconv.Itoa(report.Summary.Keywords)},
		{"Scored", strconv.Itoa(report.Summary.Scored)},
		{"Unavailable", strconv.Itoa(report.Summary.Unavailable)},
		{"Brand Matches", strconv.Itoa(report.Summary.BrandMatches)},
	}
	if report.AppID != "" {
		summaryRows = append([][]string{{"App", report.AppID}}, summaryRows...)
		summaryRows = append(summaryRows, []string{"Ranked", strconv.Itoa(report.Summary.WithRank)})
	}
	if report.Genre != "" {
		summaryRows = append(summaryRows, []string{"Genre", formatSearchPlanSourceName(report.Genre)})
	}
	shared.RenderSection("Keyword Score", []string{"Field", "Value"}, summaryRows, markdown)

	rows := make([][]string, 0, len(report.Rows))
	for _, row := range report.Rows {
		rows = append(rows, []string{
			row.Keyword,
			formatKeywordDifficulty(row.DifficultyScore),
			formatKeywordDifficulty(row.MinDifficultyScore),
			formatKeywordPopularity(row.Popularity),
			formatOptionalInt(row.AppCount),
			formatOptionalInt(row.Rank),
			formatKeywordMatchLabel(row.KeywordMatch),
			formatOptionalBool(row.IsBrandKeyword),
			row.Status,
		})
	}
	shared.RenderSection(
		"Keywords",
		[]string{"Keyword", "Difficulty", "Min Difficulty", "Popularity", "Apps", "Rank", "Match", "Brand", "Status"},
		rows,
		markdown,
	)

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
}

func formatKeywordDifficulty(value *float64) string {
	if value == nil {
		return "—"
	}
	return strconv.FormatFloat(*value, 'f', 1, 64)
}

func formatKeywordPopularity(popularity *KeywordPopularity) string {
	if popularity == nil {
		return "—"
	}
	return formatOptionalInt(popularity.Popularity5) + " / " + formatOptionalInt(popularity.Popularity100)
}

func formatOptionalBool(value *bool) string {
	if value == nil {
		return "—"
	}
	return strconv.FormatBool(*value)
}

func formatKeywordMatchLabel(match string) string {
	switch match {
	case "":
		return "—"
	case keywordMatchNone:
		return "none"
	default:
		return strings.ToLower(strings.Join(splitCamelCaseWords(match), " "))
	}
}

func splitCamelCaseWords(value string) []string {
	words := make([]string, 0, 3)
	var current strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' && current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}
