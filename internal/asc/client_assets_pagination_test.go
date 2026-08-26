package asc

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestGetAllAppScreenshotSetsFollowsNextURL(t *testing.T) {
	const next = BaseURL + "/v1/appStoreVersionLocalizations/loc-1/appScreenshotSets?cursor=sets-2&limit=17"
	requestCount := 0
	client := newTestClient(
		t, func(req *http.Request) {
			switch requestCount {
			case 0:
				if req.URL.Path != "/v1/appStoreVersionLocalizations/loc-1/appScreenshotSets" {
					t.Fatalf("first request path = %q", req.URL.Path)
				}
				if got := req.URL.Query().Get("limit"); got != "1" {
					t.Fatalf("first request limit = %q, want 1", got)
				}
			case 1:
				if got := req.URL.String(); got != next {
					t.Fatalf("continuation URL = %q, want %q", got, next)
				}
			default:
				t.Fatalf("unexpected request %d: %s", requestCount+1, req.URL)
			}
			requestCount++
		},
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshotSets","id":"set-1","attributes":{"screenshotDisplayType":"APP_IPHONE_65"}}],"links":{"next":"`+next+`"}}`),
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshotSets","id":"set-2","attributes":{"screenshotDisplayType":"APP_IPAD_PRO_129"}}],"links":{}}`),
	)

	response, err := client.GetAllAppScreenshotSets(context.Background(), "loc-1", WithAppScreenshotSetsLimit(1))
	if err != nil {
		t.Fatalf("GetAllAppScreenshotSets() error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
	if len(response.Data) != 2 || response.Data[0].ID != "set-1" || response.Data[1].ID != "set-2" {
		t.Fatalf("unexpected screenshot sets: %#v", response.Data)
	}
}

func TestGetAllAppScreenshotsFollowsNextURL(t *testing.T) {
	const next = BaseURL + "/v1/appScreenshotSets/set-1/appScreenshots?cursor=screenshots-2"
	requestCount := 0
	client := newTestClient(
		t, func(req *http.Request) {
			switch requestCount {
			case 0:
				if req.URL.Path != "/v1/appScreenshotSets/set-1/appScreenshots" {
					t.Fatalf("first request path = %q", req.URL.Path)
				}
			case 1:
				if got := req.URL.String(); got != next {
					t.Fatalf("continuation URL = %q, want %q", got, next)
				}
			default:
				t.Fatalf("unexpected request %d: %s", requestCount+1, req.URL)
			}
			requestCount++
		},
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshots","id":"shot-1","attributes":{"fileName":"01-home.png"}}],"links":{"next":"`+next+`"}}`),
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshots","id":"shot-2","attributes":{"fileName":"02-settings.png"}}],"links":{}}`),
	)

	response, err := client.GetAllAppScreenshots(context.Background(), "set-1")
	if err != nil {
		t.Fatalf("GetAllAppScreenshots() error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("request count = %d, want 2", requestCount)
	}
	if len(response.Data) != 2 || response.Data[0].ID != "shot-1" || response.Data[1].ID != "shot-2" {
		t.Fatalf("unexpected screenshots: %#v", response.Data)
	}
}

func TestGetAllAppScreenshotsRejectsRepeatedNextURL(t *testing.T) {
	const next = BaseURL + "/v1/appScreenshotSets/set-1/appScreenshots?cursor=repeat"
	client := newTestClient(
		t, nil,
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshots","id":"shot-1"}],"links":{"next":"`+next+`"}}`),
		jsonResponse(http.StatusOK, `{"data":[{"type":"appScreenshots","id":"shot-2"}],"links":{"next":"`+next+`"}}`),
	)

	_, err := client.GetAllAppScreenshots(context.Background(), "set-1")
	if !errors.Is(err, ErrRepeatedPaginationURL) {
		t.Fatalf("error = %v, want ErrRepeatedPaginationURL", err)
	}
}
