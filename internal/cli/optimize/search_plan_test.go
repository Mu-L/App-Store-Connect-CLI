package optimize

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/ads"
)

func TestBuildSearchPlanJoinsOfficialEvidenceWithoutInventingMissingValues(t *testing.T) {
	input := searchPlanBuildInput{
		AppID:     "123456789",
		Version:   "4.4.4",
		VersionID: "version-1",
		Platform:  "IOS",
		Country:   "US",
		Genre:     "PRODUCTIVITY_UTILITIES",
		Locale:    "en-US",
		Window: searchPlanWindow{
			Start: "2026-07-19",
			End:   "2026-08-17",
		},
		Metadata: searchMetadataSnapshot{
			Name:     "Focus Keeper",
			Subtitle: "A simple habit tracker",
			Keywords: "focus,timer",
		},
		Ads: ads.SearchOptimizationData{
			DailyBudgetRecommendationItems: []json.RawMessage{json.RawMessage(`{"id":"budget-1"}`)},
			DailyBudgetRecommendations:     1,
			Sources: []ads.SearchOptimizationSourceStatus{
				{Name: "keyword_suggestions", Status: "available", Count: 2},
				{Name: "search_term_popularity", Status: "available", Count: 3},
				{Name: "impression_share", Status: "available", Count: 2},
				{Name: "search_term_performance", Status: "available", Count: 3},
			},
			Suggestions: []ads.SearchSuggestion{
				{Text: "daily habits", Popularity: intPtr(72), Kind: "keyword"},
				{Text: "mood journal", Popularity: intPtr(69), Kind: "phrase"},
			},
			Popularities: []ads.SearchPopularity{
				{Term: "habit tracker", Popularity100: intPtr(88), RankInGenre: intPtr(1)},
				{Term: "daily habits", Popularity100: intPtr(72), RankInGenre: intPtr(8)},
				{Term: "free planner", Popularity100: intPtr(64), RankInGenre: intPtr(15)},
			},
			ImpressionShares: []ads.SearchImpressionShare{
				{Term: "habit tracker", Low: floatPtr(0.07), High: floatPtr(0.07), Rank: intPtr(6)},
				{Term: "mood journal", Low: floatPtr(0.91), High: floatPtr(1), Rank: intPtr(1)},
			},
			SearchTerms: []ads.SearchTermPerformance{
				{Term: "habit tracker", KeywordText: "habits", MatchType: "BROAD", CampaignID: 44, AdGroupID: 55, Impressions: 1000, Taps: 70, TotalInstalls: 31, SpendAmount: "36.58", SpendCurrency: "USD"},
				{Term: "free planner", KeywordText: "planner", MatchType: "BROAD", CampaignID: 44, AdGroupID: 55, Impressions: 500, Taps: 12, TotalInstalls: 0, SpendAmount: "8.40", SpendCurrency: "USD"},
				{Term: "mood journal", KeywordText: "mood journal", MatchType: "EXACT", CampaignID: 44, AdGroupID: 55, Impressions: 800, Taps: 50, TotalInstalls: 18, SpendAmount: "18.00", SpendCurrency: "USD"},
			},
			Keywords: []ads.SearchTargetingKeyword{
				{Text: "mood journal", MatchType: "EXACT", CampaignID: 44, AdGroupID: 55},
			},
		},
	}

	report := buildSearchPlan(input)
	if report.SchemaVersion != "1" {
		t.Fatalf("SchemaVersion = %q, want 1", report.SchemaVersion)
	}
	if len(report.Recommendations.DailyBudgets) != 1 || !strings.Contains(string(report.Recommendations.DailyBudgets[0]), "budget-1") {
		t.Fatalf("recommendations = %+v", report.Recommendations)
	}

	habit := findSearchPlanRow(t, report.Rows, "habit tracker")
	if habit.Popularity100 == nil || *habit.Popularity100 != 88 {
		t.Fatalf("habit popularity = %v, want 88", habit.Popularity100)
	}
	if habit.CPA == nil || habit.CPA.Amount != "1.18" || habit.CPA.Currency != "USD" {
		t.Fatalf("habit CPA = %+v, want USD 1.18", habit.CPA)
	}
	if !slices.Contains(habit.MetadataFields, "subtitle") {
		t.Fatalf("habit metadata fields = %v, want subtitle", habit.MetadataFields)
	}
	assertActions(t, habit.Actions, "promote_exact", "defend")
	if slices.Contains(habit.Actions, "metadata_candidate") {
		t.Fatalf("habit actions = %v, must not duplicate covered metadata", habit.Actions)
	}
	if habit.Confidence != "proven" {
		t.Fatalf("habit confidence = %q, want proven", habit.Confidence)
	}

	daily := findSearchPlanRow(t, report.Rows, "daily habits")
	assertActions(t, daily.Actions, "metadata_candidate", "untested_candidate")
	if daily.TotalInstalls != nil {
		t.Fatalf("daily habits installs = %v, want unavailable rather than zero", daily.TotalInstalls)
	}
	if daily.SuggestionPopularity == nil || *daily.SuggestionPopularity != 72 {
		t.Fatalf("daily suggestion popularity = %v, want 72", daily.SuggestionPopularity)
	}

	negative := findSearchPlanRow(t, report.Rows, "free planner")
	assertActions(t, negative.Actions, "negative_candidate")
	if negative.TotalInstalls == nil || *negative.TotalInstalls != 0 {
		t.Fatalf("free planner installs = %v, want observed zero", negative.TotalInstalls)
	}

	saturated := findSearchPlanRow(t, report.Rows, "mood journal")
	assertActions(t, saturated.Actions, "saturated", "metadata_candidate")
	if slices.Contains(saturated.Actions, "promote_exact") {
		t.Fatalf("mood actions = %v, existing exact target must suppress promotion", saturated.Actions)
	}
}

func TestBuildSearchPlanSuppressesExistingNegativeCandidate(t *testing.T) {
	report := buildSearchPlan(searchPlanBuildInput{
		Metadata: searchMetadataSnapshot{},
		Ads: ads.SearchOptimizationData{
			SearchTerms:      []ads.SearchTermPerformance{{Term: "free planner", CampaignID: 44, AdGroupID: 55, Taps: 20, TotalInstalls: 0}},
			NegativeKeywords: []ads.SearchNegativeKeyword{{Text: "free planner", CampaignID: 44, AdGroupID: 55, MatchType: "EXACT"}},
		},
	})
	row := findSearchPlanRow(t, report.Rows, "free planner")
	if slices.Contains(row.Actions, "negative_candidate") {
		t.Fatalf("actions = %v, existing negative must suppress candidate", row.Actions)
	}
}

func TestBuildSearchPlanUsesLatestImpressionSharePeriod(t *testing.T) {
	report := buildSearchPlan(searchPlanBuildInput{
		Ads: ads.SearchOptimizationData{ImpressionShares: []ads.SearchImpressionShare{
			{Term: "habit tracker", Day: "2026-08-17", Low: floatPtr(0.3), High: floatPtr(0.4), Rank: intPtr(3)},
			{Term: "habit tracker", Day: "2026-08-16", Low: floatPtr(0.8), High: floatPtr(0.9), Rank: intPtr(1)},
		}},
	})
	row := findSearchPlanRow(t, report.Rows, "habit tracker")
	if row.ImpressionSharePeriod != "2026-08-17" || row.ImpressionShareLow == nil || *row.ImpressionShareLow != 0.3 || row.ImpressionShareRank == nil || *row.ImpressionShareRank != 3 {
		t.Fatalf("latest impression share = %+v", row)
	}
}

func TestWriteSearchPlanArtifactsAreReviewableAndImportCompatible(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "optimization")
	report := SearchPlanReport{
		SchemaVersion: "1",
		AppID:         "123456789",
		Version:       "4.4.4",
		Locale:        "en-US",
		Metadata:      searchMetadataSnapshot{Keywords: "focus,timer"},
		Rows: []SearchPlanRow{
			{Term: "daily habits", Actions: []string{"metadata_candidate", "untested_candidate"}, AdGroupID: int64Ptr(55)},
			{Term: "habit tracker", Actions: []string{"promote_exact"}, CampaignID: int64Ptr(44), AdGroupID: int64Ptr(55)},
			{Term: "free planner", Actions: []string{"negative_candidate"}, CampaignID: int64Ptr(44), AdGroupID: int64Ptr(55)},
		},
	}

	artifacts, err := writeSearchPlanArtifacts(dir, report)
	if err != nil {
		t.Fatalf("writeSearchPlanArtifacts() error = %v", err)
	}
	if len(artifacts) != 4 {
		t.Fatalf("artifacts = %v, want four files", artifacts)
	}

	reportData, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded SearchPlanReport
	if err := json.Unmarshal(reportData, &decoded); err != nil || decoded.SchemaVersion != "1" {
		t.Fatalf("report artifact decode = (%+v, %v)", decoded, err)
	}

	csvFile, err := os.Open(filepath.Join(dir, "metadata-candidates.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(csvFile).ReadAll()
	_ = csvFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || strings.Join(rows[0], ",") != "locale,keywords" || rows[1][0] != "en-US" {
		t.Fatalf("metadata CSV = %#v", rows)
	}
	if got := rows[1][1]; got != "focus,timer,daily habits" {
		t.Fatalf("metadata keywords = %q", got)
	}

	assertBulkArtifact(t, filepath.Join(dir, "exact-keywords.json"), "habit tracker", "EXACT")
	assertBulkArtifact(t, filepath.Join(dir, "negative-keywords.json"), "free planner", "EXACT")
}

func TestMetadataCandidateArtifactHonorsKeywordLimitAndDuplicates(t *testing.T) {
	report := SearchPlanReport{
		Locale:   "en-US",
		Metadata: searchMetadataSnapshot{Keywords: strings.Repeat("a", 95)},
		Rows: []SearchPlanRow{
			{Term: "tool", Actions: []string{"metadata_candidate"}},
			{Term: "tool", Actions: []string{"metadata_candidate"}},
			{Term: "x", Actions: []string{"metadata_candidate"}},
		},
	}
	data, err := buildMetadataCandidatesCSV(report)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("a", 95) + ",tool"
	if len(rows) != 2 || rows[1][1] != want {
		t.Fatalf("metadata candidates = %#v, want %q", rows, want)
	}
}

func TestWriteSearchPlanArtifactsRejectsFileAsOutputDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSearchPlanArtifacts(path, SearchPlanReport{}); err == nil {
		t.Fatal("writeSearchPlanArtifacts() succeeded with a file as --out-dir")
	}
}

func TestResolveSearchPlanWindowRejectsNonWholeOrOutOfRangeDuration(t *testing.T) {
	for _, value := range []string{"1d", "31d", "36h", "nonsense"} {
		if _, err := resolveSearchPlanWindow(value, time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("resolveSearchPlanWindow(%q) succeeded, want error", value)
		}
	}
	window, err := resolveSearchPlanWindow("30d", time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if window.Start != "2026-07-19" || window.End != "2026-08-17" || window.PopularityStart != "2026-08-09" || window.PopularityEnd != "2026-08-15" {
		t.Fatalf("window = %+v", window)
	}
}

func findSearchPlanRow(t *testing.T, rows []SearchPlanRow, term string) SearchPlanRow {
	t.Helper()
	for _, row := range rows {
		if row.Term == term {
			return row
		}
	}
	t.Fatalf("missing row %q in %+v", term, rows)
	return SearchPlanRow{}
}

func assertActions(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, action := range want {
		if !slices.Contains(got, action) {
			t.Fatalf("actions = %v, want %q", got, action)
		}
	}
}

func assertBulkArtifact(t *testing.T, path, text, matchType string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Items []struct {
			Data struct {
				Text      string `json:"text"`
				MatchType string `json:"matchType"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) != 1 || payload.Items[0].Data.Text != text || payload.Items[0].Data.MatchType != matchType {
		t.Fatalf("bulk artifact %s = %+v", path, payload)
	}
}

func intPtr(value int) *int           { return &value }
func int64Ptr(value int64) *int64     { return &value }
func floatPtr(value float64) *float64 { return &value }
