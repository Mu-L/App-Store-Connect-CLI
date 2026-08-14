package appleads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestPaginateAllPlatformGeoUsesPageSizeAndAggregates(t *testing.T) {
	spec, ok := PlatformEndpointByCommandPath("geo", "search")
	if !ok {
		t.Fatal("missing geo search endpoint")
	}
	requests := []url.Values{}
	client, err := NewClient(Credentials{AccessToken: "ACCESS", AdAccountID: "account"}, WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.Query())
		switch req.URL.Query().Get("offset") {
		case "5":
			return jsonResponse(http.StatusOK, `{"result":[{"id":"geo-6"},{"id":"geo-7"}],"pagination":{"totalCount":9,"offset":5,"pageSize":2}}`), nil
		case "7":
			return jsonResponse(http.StatusOK, `{"result":[{"id":"geo-8"},{"id":"geo-9"}],"pagination":{"totalCount":9,"offset":7,"pageSize":2}}`), nil
		default:
			t.Fatalf("unexpected offset %q", req.URL.Query().Get("offset"))
			return nil, nil
		}
	})}))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	raw, err := client.PaginateAll(context.Background(), spec, nil, url.Values{"supplySource": {"APPSTORE"}, "query": {"San Francisco"}}, 5, 2, nil)
	if err != nil {
		t.Fatalf("PaginateAll() error: %v", err)
	}
	var got platformPaginatedEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(got.Result) != 4 {
		t.Fatalf("result count = %d, want 4", len(got.Result))
	}
	if got.Pagination.TotalCount == nil || *got.Pagination.TotalCount != 9 {
		t.Fatalf("totalCount = %v, want 9", got.Pagination.TotalCount)
	}
	if got.Pagination.Offset != 5 || got.Pagination.PageSize != 2 {
		t.Fatalf("pagination = %+v, want offset 5 pageSize 2", got.Pagination)
	}
	if len(requests) != 2 {
		t.Fatalf("request count = %d, want 2", len(requests))
	}
	for index, wantOffset := range []string{"5", "7"} {
		if got := requests[index].Get("offset"); got != wantOffset {
			t.Errorf("request[%d] offset = %q, want %q", index, got, wantOffset)
		}
		if got := requests[index].Get("pageSize"); got != "2" {
			t.Errorf("request[%d] pageSize = %q, want 2", index, got)
		}
		if _, present := requests[index]["limit"]; present {
			t.Errorf("request[%d] unexpectedly set legacy limit: %v", index, requests[index])
		}
	}
}

func TestPaginateAllPlatformGeoStopsOnEmptyPageWithoutTotalCount(t *testing.T) {
	spec, ok := PlatformEndpointByCommandPath("geo", "search")
	if !ok {
		t.Fatal("missing geo search endpoint")
	}
	offsets := []string{}
	client, err := NewClient(Credentials{AccessToken: "ACCESS", AdAccountID: "account"}, WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		offset := req.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		switch offset {
		case "0":
			return jsonResponse(http.StatusOK, `{"result":[{"id":"geo-1"},{"id":"geo-2"}],"pagination":{"offset":0,"pageSize":2}}`), nil
		case "2":
			return jsonResponse(http.StatusOK, `{"result":[],"pagination":{"offset":2,"pageSize":2}}`), nil
		default:
			t.Fatalf("unexpected offset %q", offset)
			return nil, nil
		}
	})}))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	raw, err := client.PaginateAll(context.Background(), spec, nil, url.Values{"supplySource": {"APPSTORE"}}, 0, 2, nil)
	if err != nil {
		t.Fatalf("PaginateAll() error: %v", err)
	}
	var got platformPaginatedEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if len(got.Result) != 2 {
		t.Fatalf("result count = %d, want 2", len(got.Result))
	}
	if got.Pagination.TotalCount != nil {
		t.Fatalf("totalCount = %v, want omitted", got.Pagination.TotalCount)
	}
	if !reflect.DeepEqual(offsets, []string{"0", "2"}) {
		t.Fatalf("offsets = %v, want [0 2]", offsets)
	}
}

func TestPaginateAllPlatformGETCapsUnboundedPages(t *testing.T) {
	spec, ok := PlatformEndpointByCommandPath("geo", "search")
	if !ok {
		t.Fatal("missing geo search endpoint")
	}
	requests := 0
	client, err := NewClient(Credentials{AccessToken: "ACCESS", AdAccountID: "account"}, WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return jsonResponse(http.StatusOK, `{"result":[{"id":"geo"}],"pagination":{"offset":`+req.URL.Query().Get("offset")+`,"pageSize":1}}`), nil
	})}))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.PaginateAll(context.Background(), spec, nil, url.Values{"supplySource": {"APPSTORE"}}, 0, 1, nil)
	if err == nil {
		t.Fatal("PaginateAll() unexpectedly succeeded for an unbounded result")
	}
	if got, want := requests, maxPlatformPaginationPages; got != want {
		t.Fatalf("request count = %d, want %d", got, want)
	}
	for _, want := range []string{"1000-page safety limit", "narrow your query", "--offset"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
}
