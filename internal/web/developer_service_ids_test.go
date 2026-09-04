package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestListDeveloperServiceIDsUsesServicesFilterAndPreservesRawEnvelope(t *testing.T) {
	const raw = `{"data":[{"type":"bundleIds","id":"service-1","attributes":{"name":"Example Service","identifier":"com.example.service","platform":"SERVICES"}}],"links":{},"meta":{},"unknownTopLevel":{"keep":true}}`
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case developerPortalTeamsPath:
			if r.Method != http.MethodPost {
				t.Fatalf("bootstrap method = %s, want POST", r.Method)
			}
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case "/services-account/v1/bundleIds":
			if r.Method != http.MethodPost || r.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("collection transport = %s override=%q, want POST override GET", r.Method, r.Header.Get("X-HTTP-Method-Override"))
			}
			proxy := decodeDeveloperPortalProxyReadRequest(t, r)
			if proxy.URLEncodedQueryParams != "limit=1000&sort=name&filter[platform]=SERVICES" {
				t.Fatalf("collection query string = %q, want captured source order", proxy.URLEncodedQueryParams)
			}
			query, err := url.ParseQuery(proxy.URLEncodedQueryParams)
			if err != nil {
				t.Fatalf("collection query: %v", err)
			}
			if proxy.TeamID != "TEAM123456" || query.Get("filter[platform]") != "SERVICES" || query.Get("limit") != "1000" || query.Get("sort") != "name" {
				t.Fatalf("collection request = team %q query %q", proxy.TeamID, query.Encode())
			}
			return developerPortalTestResponse(http.StatusOK, raw, nil), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.ListDeveloperServiceIDs(context.Background())
	if err != nil {
		t.Fatalf("ListDeveloperServiceIDs() error: %v", err)
	}
	if len(result.Data) != 1 || result.Data[0].ID != "service-1" {
		t.Fatalf("unexpected result: %+v", result.Data)
	}
	if string(result.Raw) != raw {
		t.Fatalf("raw envelope changed: %s", result.Raw)
	}
}

func TestGetDeveloperServiceIDRejectsNonServicesPlatformBeforeMutation(t *testing.T) {
	var requests int
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/services-account/v1/bundleIds/service-1" || r.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("detail transport = %s %s override=%q", r.Method, r.URL.String(), r.Header.Get("X-HTTP-Method-Override"))
			}
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("Example App", "IOS"), nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requests, r.Method, r.URL.String())
			return nil, nil
		}
	})

	_, err := client.GetDeveloperServiceID(context.Background(), "service-1")
	if err == nil || !strings.Contains(err.Error(), `want "SERVICES"`) {
		t.Fatalf("GetDeveloperServiceID() error = %v, want platform rejection", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want bootstrap and detail only", requests)
	}
}

func TestCreateDeveloperServiceIDUsesPrivatePayloadAndVerifies(t *testing.T) {
	var requests int
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/services-account/v1/bundleIds" || r.Header.Get("X-HTTP-Method-Override") != "" {
				t.Fatalf("create transport = %s %s override=%q", r.Method, r.URL.String(), r.Header.Get("X-HTTP-Method-Override"))
			}
			var payload developerServiceIDCreatePayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode create payload: %v", err)
			}
			if payload.TeamID != "TEAM123456" || payload.Data.Type != "bundleIds" {
				t.Fatalf("create envelope = %+v", payload)
			}
			want := map[string]string{
				"identifier": "com.example.service",
				"name":       "Example Service",
				"platform":   "SERVICES",
				"seedId":     "TEAM123456",
				"teamId":     "TEAM123456",
			}
			if !mapsEqual(payload.Data.Attributes, want) || len(payload.Data.Relationships.BundleIDCapabilities.Data) != 0 {
				t.Fatalf("create data = %+v", payload.Data)
			}
			return developerPortalTestResponse(http.StatusCreated, serviceIDDetailFixture("Example Service", "SERVICES"), nil), nil
		case 3:
			if r.Method != http.MethodPost || r.URL.Path != "/services-account/v1/bundleIds/service-1" || r.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("verification transport = %s %s override=%q", r.Method, r.URL.String(), r.Header.Get("X-HTTP-Method-Override"))
			}
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("Example Service", "SERVICES"), nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requests, r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.CreateDeveloperServiceID(context.Background(), DeveloperServiceIDCreateRequest{Identifier: "com.example.service", Name: "Example Service"})
	if err != nil {
		t.Fatalf("CreateDeveloperServiceID() error: %v", err)
	}
	if result.ServiceID != "service-1" || result.Status != "created" || !result.Verified {
		t.Fatalf("unexpected receipt: %+v", result)
	}
}

func TestRenameDeveloperServiceIDPreservesCapabilityGraph(t *testing.T) {
	var requests int
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("Old Name", "SERVICES"), nil), nil
		case 3:
			if r.Method != http.MethodPatch || r.URL.Path != "/services-account/v1/bundleIds/service-1" || r.Header.Get("X-HTTP-Method-Override") != "" {
				t.Fatalf("rename transport = %s %s override=%q", r.Method, r.URL.String(), r.Header.Get("X-HTTP-Method-Override"))
			}
			var payload developerBundleIDPatchRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode rename payload: %v", err)
			}
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(payload.Data.Attributes, &attrs); err != nil {
				t.Fatalf("decode rename attributes: %v", err)
			}
			var name, identifier, platform, teamID string
			_ = json.Unmarshal(attrs["name"], &name)
			_ = json.Unmarshal(attrs["identifier"], &identifier)
			_ = json.Unmarshal(attrs["platform"], &platform)
			_ = json.Unmarshal(attrs["teamId"], &teamID)
			if name != "New Name" || identifier != "com.example.service" || platform != "SERVICES" || teamID != "TEAM123456" {
				t.Fatalf("rename attrs = %s", payload.Data.Attributes)
			}
			if _, ok := attrs["~permissions.delete"]; ok {
				t.Fatal("rename payload included read-only delete permission")
			}
			if got := string(payload.Data.Relationships["bundleIdCapabilities"]); !strings.Contains(got, `"id":"cap-1"`) || !strings.Contains(got, `"id":"cap-2"`) {
				t.Fatalf("rename dropped capability graph: %s", got)
			}
			return developerPortalTestResponse(http.StatusOK, `{}`, nil), nil
		case 4:
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("New Name", "SERVICES"), nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requests, r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.RenameDeveloperServiceID(context.Background(), DeveloperServiceIDRenameRequest{ServiceID: "service-1", Name: "New Name"})
	if err != nil {
		t.Fatalf("RenameDeveloperServiceID() error: %v", err)
	}
	if result.Status != "renamed" || !result.Verified || result.Identifier != "com.example.service" {
		t.Fatalf("unexpected receipt: %+v", result)
	}
}

func TestRenameDeveloperServiceIDRejectsIncompleteIdentityBeforeMutation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "missing identifier",
			mutate: func(body string) string {
				return strings.Replace(body, `"identifier":"com.example.service",`, "", 1)
			},
			wantErr: "missing its identifier attribute",
		},
		{
			name: "non-string name",
			mutate: func(body string) string {
				return strings.Replace(body, `"name":"Old Name"`, `"name":123`, 1)
			},
			wantErr: "non-string name attribute",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
				requests++
				switch requests {
				case 1:
					return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
				case 2:
					body := tc.mutate(serviceIDDetailFixture("Old Name", "SERVICES"))
					return developerPortalTestResponse(http.StatusOK, body, nil), nil
				default:
					t.Fatalf("unexpected mutation request %d: %s %s", requests, r.Method, r.URL.String())
					return nil, nil
				}
			})

			_, err := client.RenameDeveloperServiceID(context.Background(), DeveloperServiceIDRenameRequest{ServiceID: "service-1", Name: "New Name"})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RenameDeveloperServiceID() error = %v, want %q", err, tc.wantErr)
			}
			if requests != 2 {
				t.Fatalf("requests = %d, want bootstrap and preflight only", requests)
			}
		})
	}
}

func TestDeleteDeveloperServiceIDUsesLogicalDeleteAndVerifies404(t *testing.T) {
	var requests int
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("Example Service", "SERVICES"), nil), nil
		case 3:
			if r.Method != http.MethodPost || r.URL.Path != "/services-account/v1/bundleIds/service-1" || r.Header.Get("X-HTTP-Method-Override") != http.MethodDelete {
				t.Fatalf("delete transport = %s %s override=%q", r.Method, r.URL.String(), r.Header.Get("X-HTTP-Method-Override"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode delete body: %v", err)
			}
			if len(body) != 0 {
				t.Fatalf("delete body = %#v, want empty JSON object", body)
			}
			return developerPortalTestResponse(http.StatusOK, `{}`, nil), nil
		case 4:
			return developerPortalTestResponse(http.StatusNotFound, `{"errors":[{"code":"NOT_FOUND"}]}`, nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requests, r.Method, r.URL.String())
			return nil, nil
		}
	})

	result, err := client.DeleteDeveloperServiceID(context.Background(), DeveloperServiceIDDeleteRequest{ServiceID: "service-1"})
	if err != nil {
		t.Fatalf("DeleteDeveloperServiceID() error: %v", err)
	}
	if result.Status != "deleted" || !result.Verified || !result.Changed {
		t.Fatalf("unexpected receipt: %+v", result)
	}
}

func TestRenameDeveloperServiceIDMarks5xxAsUnknownWithoutRetry(t *testing.T) {
	var requests int
	client := developerPortalTestClient(t, func(r *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"csrf"}, "csrf_ts": {"csrf-ts"}}), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, serviceIDDetailFixture("Old Name", "SERVICES"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusInternalServerError, `{}`, nil), nil
		default:
			t.Fatalf("unexpected retry/request %d: %s %s", requests, r.Method, r.URL.String())
			return nil, nil
		}
	})

	_, err := client.RenameDeveloperServiceID(context.Background(), DeveloperServiceIDRenameRequest{ServiceID: "service-1", Name: "New Name"})
	var unverified *DeveloperServiceIDUnverifiedError
	if !errors.As(err, &unverified) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("RenameDeveloperServiceID() error = %v, want unknown write error", err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want no automatic retry or post-read after 5xx", requests)
	}
}

func serviceIDDetailFixture(name, platform string) string {
	return `{"data":{"id":"service-1","type":"bundleIds","attributes":{"name":"` + name + `","identifier":"com.example.service","platform":"` + platform + `","seedId":"TEAM123456","~permissions.delete":true,"~permissions.edit":true},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"cap-1"},{"type":"bundleIdCapabilities","id":"cap-2"}]}}},"included":[{"type":"bundleIdCapabilities","id":"cap-1","attributes":{"enabled":true,"settings":[{"key":"KEEP","value":"one"}]},"relationships":{"capability":{"data":{"type":"capabilities","id":"APPLE_ID_AUTH"}}}},{"type":"bundleIdCapabilities","id":"cap-2","attributes":{"enabled":false,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"PUSH_NOTIFICATIONS"}}}}]}`
}

func mapsEqual(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}
