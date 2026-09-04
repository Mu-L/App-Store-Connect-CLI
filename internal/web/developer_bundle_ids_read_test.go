package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestListDeveloperBundleIDsUsesCapturedCollectionProxyContract(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == developerPortalTeamsPath:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), nil), nil
		case r.Method == http.MethodPost && r.URL.Path == developerServicesPath+"/bundleIds":
			if got := r.Header.Get("X-HTTP-Method-Override"); got != http.MethodGet {
				t.Fatalf("method override = %q, want GET", got)
			}
			body := mustReadBody(t, r)
			var request developerPortalProxyReadRequest
			if err := json.Unmarshal(body, &request); err != nil {
				t.Fatalf("decode collection request: %v", err)
			}
			if request.TeamID != "TEAM123456" {
				t.Fatalf("teamId = %q, want TEAM123456", request.TeamID)
			}
			query, err := url.ParseQuery(request.URLEncodedQueryParams)
			if err != nil {
				t.Fatalf("parse urlEncodedQueryParams: %v", err)
			}
			for key, want := range map[string]string{
				"limit":            "1000",
				"sort":             "name",
				"filter[platform]": "IOS,MACOS",
			} {
				if got := query.Get(key); got != want {
					t.Errorf("query %s = %q, want %q", key, got, want)
				}
			}
			if strings.Contains(string(body), "cookie") {
				t.Fatal("request body unexpectedly contains cookie material")
			}
			return developerPortalTestResponse(http.StatusOK, `{
				"data":[{
					"type":"bundleIds","id":"bundle-1",
					"attributes":{
						"identifier":"com.example.app","name":"Example App","platform":"IOS",
						"bundleType":"STANDARD","wildcard":false,"seedId":"TEAM123456",
						"dateCreated":"2026-09-01T00:00:00Z","dateModified":"2026-09-02T00:00:00Z",
						"entitlementGroupName":"Example","platformName":"iOS",
						"deploymentDataNotice":false,"responseId":"response-1",
						"bundleIdCapabilitiesSettingOption":"default"
					},
					"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"cap-1"}]}},
					"links":{"self":"/bundleIds/bundle-1"}
				}],
				"included":[{"type":"bundleIdCapabilities","id":"cap-1","attributes":{"capabilityType":"ICLOUD"}}],
				"links":{"self":"/bundleIds"}
			}`, nil), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.ListDeveloperBundleIDs(context.Background())
	if err != nil {
		t.Fatalf("ListDeveloperBundleIDs() error: %v", err)
	}
	if len(result.Data) != 1 || result.Data[0].ID != "bundle-1" || result.Data[0].Type != "bundleIds" {
		t.Fatalf("unexpected data: %+v", result.Data)
	}
	if got := stringAttr(result.Data[0].Attributes, "identifier"); got != "com.example.app" {
		t.Fatalf("identifier = %q, want com.example.app", got)
	}
	if got := boolAttr(result.Data[0].Attributes, "wildcard"); got {
		t.Fatalf("wildcard = true, want false")
	}
	if len(result.Included) != 1 || result.Included[0].ID != "cap-1" {
		t.Fatalf("unexpected included resources: %+v", result.Included)
	}
	if got := result.Links["self"]; got != "/bundleIds" {
		t.Fatalf("self link = %#v, want /bundleIds", got)
	}
}

func TestGetDeveloperBundleIDUsesCapturedDetailContract(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == developerPortalTeamsPath:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), nil), nil
		case r.Method == http.MethodPost && r.URL.Path == developerServicesPath+"/bundleIds/bundle-1":
			if got := r.Header.Get("X-HTTP-Method-Override"); got != http.MethodGet {
				t.Fatalf("method override = %q, want GET", got)
			}
			wantFields := developerBundleIDDetailFields
			if got := r.URL.Query().Get("fields[bundleIds]"); got != wantFields {
				t.Fatalf("fields[bundleIds] = %q, want %q", got, wantFields)
			}
			wantInclude := strings.Join(developerBundleIDDetailIncludes, ",")
			if got := r.URL.Query().Get("include"); got != wantInclude {
				t.Fatalf("include = %q, want %q", got, wantInclude)
			}
			body := mustReadBody(t, r)
			if !bytes.Equal(bytes.TrimSpace(body), []byte(`{"teamId":"TEAM123456"}`)) {
				t.Fatalf("detail body = %s, want team-only JSON body", body)
			}
			return developerPortalTestResponse(http.StatusOK, `{
				"data":{"type":"bundleIds","id":"bundle-1","attributes":{"name":"Example App","identifier":"com.example.app","platform":"IOS","wildcard":false,"seedId":"TEAM123456"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"cap-1"}]}}},
				"included":[{"type":"bundleIdCapabilities","id":"cap-1","attributes":{"capabilityType":"PUSH_NOTIFICATIONS","enabled":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"PUSH_NOTIFICATIONS"}}}}]
			}`, nil), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.GetDeveloperBundleID(context.Background(), "bundle-1")
	if err != nil {
		t.Fatalf("GetDeveloperBundleID() error: %v", err)
	}
	if result.Data.ID != "bundle-1" || result.Data.Type != "bundleIds" {
		t.Fatalf("unexpected data: %+v", result.Data)
	}
	if len(result.Included) != 1 || result.Included[0].Attributes["capabilityType"] != "PUSH_NOTIFICATIONS" {
		t.Fatalf("unexpected included resources: %+v", result.Included)
	}
}

func TestDeveloperBundleIDReadsSurfaceAPIError(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == developerPortalTeamsPath {
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), nil), nil
		}
		if r.Method == http.MethodPost && r.URL.Path == developerServicesPath+"/bundleIds" {
			return developerPortalTestResponse(http.StatusUnprocessableEntity, `{"errors":[{"code":"PORTAL_ERROR","detail":"private detail"}]}`, http.Header{"X-Apple-Request-UUID": {"request-2290"}}), nil
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		return nil, nil
	})

	_, err := client.ListDeveloperBundleIDs(context.Background())
	if err == nil {
		t.Fatal("ListDeveloperBundleIDs() error = nil, want API error")
	}
	if !strings.Contains(err.Error(), "422") || !strings.Contains(err.Error(), "request-2290") {
		t.Fatalf("error = %q, want status and request ID", err)
	}
	if strings.Contains(err.Error(), "private detail") {
		t.Fatalf("API error leaked response detail: %q", err)
	}
}

func TestGetDeveloperBundleIDSurfacesAPIError(t *testing.T) {
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost && r.URL.Path == developerPortalTeamsPath {
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), nil), nil
		}
		if r.Method == http.MethodPost && r.URL.Path == developerServicesPath+"/bundleIds/bundle-1" {
			return developerPortalTestResponse(http.StatusNotFound, `{"errors":[{"code":"NOT_FOUND","detail":"private detail"}]}`, http.Header{"X-Apple-Request-UUID": {"request-detail-2290"}}), nil
		}
		t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		return nil, nil
	})

	_, err := client.GetDeveloperBundleID(context.Background(), "bundle-1")
	if err == nil {
		t.Fatal("GetDeveloperBundleID() error = nil, want API error")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "request-detail-2290") {
		t.Fatalf("error = %q, want status and request ID", err)
	}
	if strings.Contains(err.Error(), "private detail") {
		t.Fatalf("API error leaked response detail: %q", err)
	}
}

func mustReadBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return body
}
