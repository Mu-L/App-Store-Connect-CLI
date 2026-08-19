package asc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKeywordRankReportJSONContract(t *testing.T) {
	totalResults := 0
	report := KeywordRankReport{
		SchemaVersion: "1",
		AppID:         "1234567890",
		Country:       "US",
		Platform:      "IOS",
		Workers:       2,
		Summary: KeywordRankSummary{
			Keywords: 1,
			Absent:   1,
		},
		Rows: []KeywordRankRow{{
			Keyword:      "focus timer",
			TotalResults: &totalResults,
			Status:       "empty",
		}},
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	output := string(encoded)
	for _, want := range []string{
		`"schemaVersion":"1"`,
		`"appId":"1234567890"`,
		`"totalResults"`,
		`"rank":null`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %s: %s", want, output)
		}
	}
}
