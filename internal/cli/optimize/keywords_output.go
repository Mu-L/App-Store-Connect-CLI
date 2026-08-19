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
