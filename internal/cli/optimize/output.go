package optimize

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func renderSearchPlanTable(report SearchPlanReport) error {
	renderSearchPlanHuman(report, false)
	return nil
}

func renderSearchPlanMarkdown(report SearchPlanReport) error {
	renderSearchPlanHuman(report, true)
	return nil
}

func searchPlanHeaders() []string {
	return []string{"Term", "Popularity 1-5", "Popularity 1-100", "Genre Rank", "Share", "Installs", "CPA", "Actions", "Confidence", "Sources"}
}

func searchPlanRows(rows []SearchPlanRow) [][]string {
	result := make([][]string, 0, len(rows))
	for _, row := range rows {
		result = append(result, []string{
			row.Term,
			formatSearchPlanPopularity5(row),
			formatOptionalInt(row.Popularity100),
			formatOptionalInt(row.RankInGenre),
			formatSearchPlanShare(row.ImpressionShareLow, row.ImpressionShareHigh),
			formatOptionalInt64(row.TotalInstalls),
			formatSearchPlanMoney(row.CPA),
			strings.Join(row.Actions, ","),
			row.Confidence,
			strings.Join(row.Sources, ","),
		})
	}
	return result
}

func renderSearchPlanHuman(report SearchPlanReport, markdown bool) {
	shared.RenderSection("Summary", []string{"Field", "Value"}, [][]string{
		{"App", report.AppID},
		{"Version", report.Version},
		{"Platform", report.Platform},
		{"Store", report.Country},
		{"Genre", report.Genre},
		{"Locale", report.Locale},
		{"Paid Window", formatSearchPlanWindow(report.Window.Start, report.Window.End)},
		{"Popularity Window", formatSearchPlanWindow(report.Window.PopularityStart, report.Window.PopularityEnd)},
		{"Terms", strconv.Itoa(report.Summary.Terms)},
		{"Daily Budget Recommendations", strconv.Itoa(report.Summary.DailyBudgetRecommendations)},
		{"Target CPA Recommendations", strconv.Itoa(report.Summary.TargetCPARecommendations)},
	}, markdown)

	sourceRows := make([][]string, 0, len(report.Sources))
	for _, source := range report.Sources {
		sourceRows = append(sourceRows, []string{source.Name, source.Status, strconv.Itoa(source.Count), source.Error})
	}
	shared.RenderSection("Sources", []string{"Source", "Status", "Count", "Error"}, sourceRows, markdown)

	if len(report.Notices) > 0 {
		noticeRows := make([][]string, 0, len(report.Notices))
		for index, notice := range report.Notices {
			noticeRows = append(noticeRows, []string{strconv.Itoa(index + 1), notice})
		}
		shared.RenderSection("Notices", []string{"#", "Notice"}, noticeRows, markdown)
	}

	shared.RenderSection("Search Plan", searchPlanHeaders(), searchPlanRows(report.Rows), markdown)

	if len(report.Artifacts) > 0 {
		artifactRows := make([][]string, 0, len(report.Artifacts))
		for _, artifact := range report.Artifacts {
			artifactRows = append(artifactRows, []string{artifact})
		}
		shared.RenderSection("Artifacts", []string{"Path"}, artifactRows, markdown)
	}
}

func formatSearchPlanPopularity5(row SearchPlanRow) string {
	if row.Popularity5 != nil {
		return strconv.Itoa(*row.Popularity5)
	}
	return formatOptionalInt(row.ImpressionSharePopularity5)
}

func formatOptionalInt(value *int) string {
	if value == nil {
		return "—"
	}
	return strconv.Itoa(*value)
}

func formatOptionalInt64(value *int64) string {
	if value == nil {
		return "—"
	}
	return strconv.FormatInt(*value, 10)
}

func formatSearchPlanShare(low, high *float64) string {
	if low == nil || high == nil {
		return "—"
	}
	if *low == *high {
		return strconv.FormatFloat(*low*100, 'f', 0, 64) + "%"
	}
	return strconv.FormatFloat(*low*100, 'f', 0, 64) + "–" + strconv.FormatFloat(*high*100, 'f', 0, 64) + "%"
}

func formatSearchPlanMoney(value *SearchPlanMoney) string {
	if value == nil {
		return "—"
	}
	return value.Amount + " " + value.Currency
}

func formatSearchPlanWindow(start, end string) string {
	if start == "" && end == "" {
		return "—"
	}
	return fmt.Sprintf("%s through %s", shared.OrNA(start), shared.OrNA(end))
}
