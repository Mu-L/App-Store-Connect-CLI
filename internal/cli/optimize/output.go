package optimize

import (
	"strconv"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

func renderSearchPlanTable(report SearchPlanReport) error {
	asc.RenderTable(searchPlanHeaders(), searchPlanRows(report.Rows))
	return nil
}

func renderSearchPlanMarkdown(report SearchPlanReport) error {
	asc.RenderMarkdown(searchPlanHeaders(), searchPlanRows(report.Rows))
	return nil
}

func searchPlanHeaders() []string {
	return []string{"Term", "Popularity", "Share", "Installs", "CPA", "Actions", "Confidence", "Sources"}
}

func searchPlanRows(rows []SearchPlanRow) [][]string {
	result := make([][]string, 0, len(rows))
	for _, row := range rows {
		result = append(result, []string{
			row.Term,
			formatOptionalInt(row.Popularity100),
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
