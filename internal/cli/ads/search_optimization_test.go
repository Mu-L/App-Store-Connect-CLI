package ads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/appleads"
)

func TestFetchSearchOptimizationDataUsesOfficialEndpointsAndPreservesPartialFailures(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s for %s, want POST", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-AP-Context"); got != "adAccountId=account-1;" {
			t.Errorf("X-AP-Context = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode %s body: %v", r.URL.Path, err)
		}
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/v1/campaigns/query":
			assertFilter(t, body, "promotedObjectId", "123456789")
			writeJSON(t, w, `{"result":[{"id":44,"name":"US Search","status":"ENABLED","displayStatus":"RUNNING","promotedObjectId":"123456789","targeting":{"countryOrRegion":{"include":["US"]}}}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
		case "/v1/suggestions/keywords/query":
			assertFilter(t, body, "countriesOrRegions", "US")
			writeJSON(t, w, `{"result":[{"text":"habit tracker","popularity":80}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
		case "/v1/suggestions/phrases/query":
			http.Error(w, `{"errors":[{"message":"request unavailable"}]}`, http.StatusBadRequest)
		case "/v1/insights/apps/search-term-popularity/query":
			assertFilter(t, body, "genre", "PRODUCTIVITY_UTILITIES")
			writeJSON(t, w, `{"result":{"rows":[{"week":"2026-08-09","countryOrRegion":"US","genre":"PRODUCTIVITY_UTILITIES","searchTerm":"habit tracker","rankInGenre":2,"searchPopularity1to100":88}]},"pagination":{"offset":0,"pageSize":5000,"totalCount":1}}`)
		case "/v1/insights/apps/impression-share/query":
			writeJSON(t, w, `{"result":{"rows":[{"day":"2026-08-17","promotedObjectId":"123456789","countryOrRegion":"US","searchTerm":"habit tracker","lowImpressionShare":0.07,"highImpressionShare":0.07,"rank":6,"searchPopularity1to5":4}]},"pagination":{"offset":0,"pageSize":5000,"totalCount":1}}`)
		case "/v1/eligibilities/apps/query":
			writeJSON(t, w, `{"result":[{"adamId":123456789,"supplyPlacement":"APPSTORE_SEARCH_RESULTS","supplySource":"APPSTORE","state":"ELIGIBLE","countryOrRegion":"US","deviceClass":"IPHONE"}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
		case "/v1/recommendations/daily-budgets/query":
			writeJSON(t, w, `{"result":[{"id":"budget-1","campaignId":44,"state":"AVAILABLE"}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
		case "/v1/recommendations/target-cpas/query":
			writeJSON(t, w, `{"result":[],"pagination":{"offset":0,"pageSize":1000,"totalCount":0}}`)
		case "/v1/keywords/query":
			assertFilter(t, body, "campaignId", float64(44))
			writeJSON(t, w, `{"result":[{"id":88,"campaignId":44,"adGroupId":55,"text":"habits","matchType":"BROAD","status":"ENABLED"}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
		case "/v1/negative-keywords/query":
			writeJSON(t, w, `{"result":[],"pagination":{"offset":0,"pageSize":1000,"totalCount":0}}`)
		case "/v1/reports/apps/searchterms/query":
			assertFilter(t, body, "campaignId", float64(44))
			writeJSON(t, w, `{"result":{"rows":[{"metadata":{"searchTermText":"habit tracker","keyword":{"id":88,"text":"habits","matchType":"BROAD"},"campaignId":44,"adGroupId":55,"countryOrRegion":"US"},"totalMetrics":{"localSpend":{"amount":"36.58","currency":"USD"},"impressions":1000,"taps":70,"tapInstalls":28,"totalInstalls":31}}]},"pagination":{"offset":0,"pageSize":5000,"totalCount":1}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := appleads.NewClient(
		appleads.Credentials{AccessToken: "token", AdAccountID: "account-1"},
		appleads.WithPlatformBaseURL(server.URL+"/v1/"),
	)
	if err != nil {
		t.Fatal(err)
	}

	data, err := fetchSearchOptimizationData(context.Background(), client, SearchOptimizationRequest{
		AppID:           "123456789",
		Country:         "US",
		Genre:           "PRODUCTIVITY_UTILITIES",
		Start:           "2026-07-19",
		End:             "2026-08-17",
		PopularityStart: "2026-08-09",
		PopularityEnd:   "2026-08-15",
	})
	if err != nil {
		t.Fatalf("fetchSearchOptimizationData() error = %v", err)
	}
	if len(data.Suggestions) != 1 || data.Suggestions[0].Text != "habit tracker" {
		t.Fatalf("suggestions = %+v", data.Suggestions)
	}
	if len(data.Popularities) != 1 || data.Popularities[0].Term != "habit tracker" {
		t.Fatalf("popularities = %+v", data.Popularities)
	}
	if len(data.SearchTerms) != 1 || data.SearchTerms[0].TotalInstalls != 31 || data.SearchTerms[0].AdGroupID != 55 {
		t.Fatalf("search terms = %+v", data.SearchTerms)
	}
	if data.DailyBudgetRecommendations != 1 || data.TargetCPARecommendations != 0 {
		t.Fatalf("recommendations = (%d, %d)", data.DailyBudgetRecommendations, data.TargetCPARecommendations)
	}
	if len(data.DailyBudgetRecommendationItems) != 1 || !strings.Contains(string(data.DailyBudgetRecommendationItems[0]), "budget-1") {
		t.Fatalf("daily budget recommendation items = %s", data.DailyBudgetRecommendationItems)
	}
	phraseSource := findOptimizationSource(t, data.Sources, "phrase_suggestions")
	if phraseSource.Status != "unavailable" || !strings.Contains(phraseSource.Error, "400") {
		t.Fatalf("phrase source = %+v", phraseSource)
	}
	if requests["/v1/negative-keywords/query"] != 2 {
		t.Fatalf("negative keyword requests = %d, want campaign and ad-group scopes", requests["/v1/negative-keywords/query"])
	}
}

func TestQueryOptimizationListPaginatesRequestBody(t *testing.T) {
	var offsets []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Pagination struct {
				Offset int `json:"offset"`
			} `json:"pagination"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		offsets = append(offsets, body.Pagination.Offset)
		if body.Pagination.Offset == 0 {
			writeJSON(t, w, `{"result":[{"text":"one","popularity":1}],"pagination":{"offset":0,"pageSize":1,"totalCount":2}}`)
			return
		}
		writeJSON(t, w, `{"result":[{"text":"two","popularity":2}],"pagination":{"offset":1,"pageSize":1,"totalCount":2}}`)
	}))
	defer server.Close()
	client, err := appleads.NewClient(appleads.Credentials{AccessToken: "token", AdAccountID: "account-1"}, appleads.WithPlatformBaseURL(server.URL+"/v1/"))
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := appleads.PlatformEndpointByCommandPath("suggestions", "keywords", "find")
	if !ok {
		t.Fatal("missing endpoint spec")
	}
	items, err := queryOptimizationList[SearchSuggestion](context.Background(), client, spec, map[string]any{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 1 {
		t.Fatalf("items=%+v offsets=%v", items, offsets)
	}
}

func TestFetchOptimizationPhraseSuggestionsReadsPhraseField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"result":[{"phrase":"best habit tracker","popularity":82}],"pagination":{"offset":0,"pageSize":1000,"totalCount":1}}`)
	}))
	defer server.Close()
	client, err := appleads.NewClient(
		appleads.Credentials{AccessToken: "token", AdAccountID: "account-1"},
		appleads.WithPlatformBaseURL(server.URL+"/v1/"),
	)
	if err != nil {
		t.Fatal(err)
	}

	items, err := fetchOptimizationSuggestions(context.Background(), client, SearchOptimizationRequest{
		AppID: "123456789", Country: "US",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Text != "best habit tracker" || items[0].Kind != "phrase" || items[0].Popularity == nil || *items[0].Popularity != 82 {
		t.Fatalf("phrase suggestions = %+v", items)
	}
}

func TestFetchSearchOptimizationDataFailsWhenEveryIntelligenceSourceIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[{"message":"unavailable"}]}`, http.StatusBadRequest)
	}))
	defer server.Close()
	client, err := appleads.NewClient(
		appleads.Credentials{AccessToken: "token", AdAccountID: "account-1"},
		appleads.WithPlatformBaseURL(server.URL+"/v1/"),
	)
	if err != nil {
		t.Fatal(err)
	}

	data, err := fetchSearchOptimizationData(context.Background(), client, SearchOptimizationRequest{
		AppID: "123456789", Country: "US", Genre: "PRODUCTIVITY_UTILITIES",
		Start: "2026-07-19", End: "2026-08-17", PopularityStart: "2026-08-09", PopularityEnd: "2026-08-15",
	})
	if err == nil || !strings.Contains(err.Error(), "all official Apple Ads optimization sources are unavailable") {
		t.Fatalf("error = %v", err)
	}
	if source := findOptimizationSource(t, data.Sources, "search_term_performance"); source.Status != "unavailable" || !strings.Contains(source.Error, "campaign scope unavailable") {
		t.Fatalf("search term source = %+v", source)
	}
}

func assertFilter(t *testing.T, body map[string]any, field string, want any) {
	t.Helper()
	filters, _ := body["filters"].([]any)
	for _, raw := range filters {
		filter, _ := raw.(map[string]any)
		if filter["field"] != field {
			continue
		}
		value := filter["value"]
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				if item == want {
					return
				}
			}
		default:
			if typed == want {
				return
			}
		}
	}
	t.Fatalf("body filters do not contain %s=%v: %#v", field, want, body)
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(payload))
}

func findOptimizationSource(t *testing.T, sources []SearchOptimizationSourceStatus, name string) SearchOptimizationSourceStatus {
	t.Helper()
	for _, source := range sources {
		if source.Name == name {
			return source
		}
	}
	t.Fatalf("missing source %q in %+v", name, sources)
	return SearchOptimizationSourceStatus{}
}
