package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestListDeveloperAppGroupsUsesPortalFormEndpoint(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected list request %s %s", request.Method, request.URL.String())
			}
			assertDeveloperPortalForm(t, request, url.Values{
				"teamId":     {"TEAM123456"},
				"pageNumber": {"1"},
				"pageSize":   {"500"},
				"sort":       {"name=asc"},
			})
			return developerPortalTestResponse(http.StatusOK, `{
				"resultCode":0,
				"pageNumber":1,
				"pageSize":500,
				"totalRecords":2,
				"applicationGroupList":[
					{"name":"Shared","prefix":"TEAM123456","identifier":"group.com.example.shared","status":"current","applicationGroup":"GROUP12345"},
					{"name":"Preview","prefix":"TEAM123456","identifier":"group.com.example.preview","status":"current","applicationGroup":"GROUP67890"}
				]
			}`, nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requestNumber, request.Method, request.URL.String())
			return nil, nil
		}
	})

	result, err := client.ListDeveloperAppGroups(context.Background(), DeveloperAppGroupsListOptions{})
	if err != nil {
		t.Fatalf("ListDeveloperAppGroups() error: %v", err)
	}
	if len(result.Data) != 2 || result.Data[0].ID != "GROUP12345" || result.Data[0].Identifier != "group.com.example.shared" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestCreateDeveloperAppGroupUsesPortalFormEndpoint(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected CSRF priming request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "" || request.Header.Get("csrf_ts") != "" {
				t.Fatalf("CSRF priming request reused tokens from another endpoint scope")
			}
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 3:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/addApplicationGroup.action" {
				t.Fatalf("unexpected create request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "primed-csrf" || request.Header.Get("csrf_ts") != "primed-ts" {
				t.Fatalf("create request missing CSRF headers")
			}
			assertDeveloperPortalForm(t, request, url.Values{
				"teamId":     {"TEAM123456"},
				"name":       {"Example Preview"},
				"identifier": {"group.com.example.preview"},
			})
			return developerPortalTestResponse(http.StatusOK, `{
				"resultCode":0,
				"applicationGroup":{"name":"Example Preview","prefix":"TEAM123456","identifier":"group.com.example.preview","status":"current","applicationGroup":"GROUP12345"}
			}`, nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.CreateDeveloperAppGroup(context.Background(), DeveloperAppGroupCreateRequest{
		Name:       "Example Preview",
		Identifier: "group.com.example.preview",
	})
	if err != nil {
		t.Fatalf("CreateDeveloperAppGroup() error: %v", err)
	}
	if result.ID != "GROUP12345" || result.Name != "Example Preview" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestValidateDeveloperAppGroupIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantErr    string
	}{
		{name: "valid", identifier: "group.com.example-shared"},
		{name: "missing prefix", identifier: "com.example.shared", wantErr: "must start with \"group.\""},
		{name: "empty suffix", identifier: "group.", wantErr: "must include a name after \"group.\""},
		{name: "invalid character", identifier: "group.com/example", wantErr: "may contain only letters, numbers, hyphens, and periods"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDeveloperAppGroupIdentifier(test.identifier)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateDeveloperAppGroupIdentifier() error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateDeveloperAppGroupIdentifier() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestListDeveloperAppGroupsPaginates(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2, 3:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected path: %s", request.URL.Path)
			}
			if err := request.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error: %v", err)
			}
			wantPage := strconv.Itoa(requestNumber - 1)
			if request.PostForm.Get("pageNumber") != wantPage {
				t.Fatalf("pageNumber = %q, want %q", request.PostForm.Get("pageNumber"), wantPage)
			}
			id := "GROUP" + wantPage
			return developerPortalTestResponse(http.StatusOK, fmt.Sprintf(`{
				"resultCode":0,"pageNumber":%s,"pageSize":1,"totalRecords":2,
				"applicationGroupList":[{"name":"Group %s","identifier":"group.com.example.%s","applicationGroup":"%s"}]
			}`, wantPage, wantPage, wantPage, id), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.ListDeveloperAppGroups(context.Background(), DeveloperAppGroupsListOptions{Paginate: true})
	if err != nil {
		t.Fatalf("ListDeveloperAppGroups() error: %v", err)
	}
	if len(result.Data) != 2 || result.Data[1].ID != "GROUP2" {
		t.Fatalf("unexpected paginated result: %+v", result)
	}
}

func TestListDeveloperAppGroupsStopsAfterFirstPageByDefault(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, `{
				"resultCode":0,"pageNumber":1,"pageSize":1,"totalRecords":2,
				"applicationGroupList":[{"name":"Group 1","identifier":"group.com.example.1","applicationGroup":"GROUP1"}]
			}`, nil), nil
		default:
			t.Fatalf("default list fetched unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.ListDeveloperAppGroups(context.Background(), DeveloperAppGroupsListOptions{})
	if err != nil {
		t.Fatalf("ListDeveloperAppGroups() error: %v", err)
	}
	if len(result.Data) != 1 || result.Data[0].ID != "GROUP1" {
		t.Fatalf("unexpected first-page result: %+v", result)
	}
}

func TestDeveloperAppGroupsRejectsPortalErrorEnvelope(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		if requestNumber == 1 {
			return assertDeveloperPortalBootstrap(t, request), nil
		}
		return developerPortalTestResponse(http.StatusOK, `{"resultCode":35,"userString":"Identifier already exists","requestId":"request-1"}`, nil), nil
	})

	_, err := client.CreateDeveloperAppGroup(context.Background(), DeveloperAppGroupCreateRequest{Name: "Example", Identifier: "group.com.example.shared"})
	if err == nil || !strings.Contains(err.Error(), "result code 35") || !strings.Contains(err.Error(), "Identifier already exists") || !strings.Contains(err.Error(), "request-1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeveloperAppGroupsRejectsMalformedSuccessEnvelope(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		if requestNumber == 1 {
			return assertDeveloperPortalBootstrap(t, request), nil
		}
		return developerPortalTestResponse(http.StatusOK, `{"applicationGroupList":[]}`, nil), nil
	})

	_, err := client.ListDeveloperAppGroups(context.Background(), DeveloperAppGroupsListOptions{})
	if err == nil || !strings.Contains(err.Error(), "missing resultCode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeveloperAppGroupsSurfacesHTTPError(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		if requestNumber == 1 {
			return assertDeveloperPortalBootstrap(t, request), nil
		}
		return developerPortalTestResponse(http.StatusInternalServerError, `{"error":"portal unavailable"}`, http.Header{"X-Apple-Request-UUID": {"apple-request-1"}}), nil
	})

	_, err := client.ListDeveloperAppGroups(context.Background(), DeveloperAppGroupsListOptions{})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssignDeveloperAppGroupPreservesBundleGraph(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" || request.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("unexpected bundle read %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, `{
				"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app","platform":"IOS","permissions":{"delete":true,"edit":true},"~permissions.delete":true,"~permissions.edit":true},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"push-1"}]}}},
				"included":[{"type":"bundleIdCapabilities","id":"push-1","attributes":{"enabled":true,"settings":[],"ownerType":"BUNDLE","editable":true,"inputs":[],"responseId":"response-1"},"relationships":{"capability":{"data":{"type":"capabilities","id":"PUSH_NOTIFICATIONS"}}}}]
			}`, nil), nil
		case 3:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected CSRF priming request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "" || request.Header.Get("csrf_ts") != "" {
				t.Fatalf("CSRF priming request reused tokens from another endpoint scope")
			}
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			if request.Method != http.MethodPatch || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" {
				t.Fatalf("unexpected bundle patch %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "primed-csrf" || request.Header.Get("csrf_ts") != "primed-ts" {
				t.Fatalf("bundle patch missing primed CSRF headers")
			}
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" || request.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("expected verification re-read, got %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP12345"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.AssignDeveloperAppGroup(context.Background(), DeveloperAppGroupAssignRequest{BundleID: "bundle-1", GroupID: "GROUP12345"})
	if err != nil {
		t.Fatalf("AssignDeveloperAppGroup() error: %v", err)
	}
	if !result.Changed || result.Status != "assigned" {
		t.Fatalf("unexpected result: %+v", result)
	}

	var payload developerBundleIDPatchRequest
	if err := json.Unmarshal(patchBody, &payload); err != nil {
		t.Fatalf("decode patch: %v; body=%s", err, patchBody)
	}
	var bundleAttributes map[string]json.RawMessage
	if err := json.Unmarshal(payload.Data.Attributes, &bundleAttributes); err != nil {
		t.Fatalf("decode Bundle ID attributes: %v", err)
	}
	if string(bundleAttributes["teamId"]) != `"TEAM123456"` || string(bundleAttributes["identifier"]) != `"com.example.app"` {
		t.Fatalf("team and writable attributes not preserved: %s", payload.Data.Attributes)
	}
	for _, key := range []string{"permissions", "~permissions.delete", "~permissions.edit"} {
		if _, ok := bundleAttributes[key]; ok {
			t.Fatalf("read-only Bundle ID attribute %q was sent in PATCH: %s", key, payload.Data.Attributes)
		}
	}
	var capabilities developerResourceRelationship
	if err := json.Unmarshal(payload.Data.Relationships["bundleIdCapabilities"], &capabilities); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if len(capabilities.Data) != 2 {
		t.Fatalf("capability count = %d, want existing plus APP_GROUPS", len(capabilities.Data))
	}
	var existingAttributes map[string]json.RawMessage
	if err := json.Unmarshal(capabilities.Data[0].Attributes, &existingAttributes); err != nil {
		t.Fatalf("decode existing capability attributes: %v", err)
	}
	if len(existingAttributes) != 2 || string(existingAttributes["enabled"]) != "true" || string(existingAttributes["settings"]) != "[]" {
		t.Fatalf("PATCH contained read-only capability attributes: %s", capabilities.Data[0].Attributes)
	}
	if _, ok := capabilities.Data[0].Relationships["capability"]; !ok {
		t.Fatalf("existing capability relationship was not preserved: %+v", capabilities.Data[0].Relationships)
	}
	appGroupsCapability := capabilities.Data[1]
	if capability, err := developerBundleIDCapabilityID(appGroupsCapability); err != nil || capability != "APP_GROUPS" {
		t.Fatalf("unexpected app groups capability: %+v, err=%v", appGroupsCapability, err)
	}
	var groups developerResourceRelationship
	if err := json.Unmarshal(appGroupsCapability.Relationships["appGroups"], &groups); err != nil {
		t.Fatalf("decode appGroups: %v", err)
	}
	if len(groups.Data) != 1 || groups.Data[0].ID != "GROUP12345" || groups.Data[0].Type != "appGroups" {
		t.Fatalf("unexpected appGroups relationship: %+v", groups.Data)
	}
}

func TestAssignDeveloperAppGroupFailsWhenVerificationDiffers(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	_, err := client.AssignDeveloperAppGroup(context.Background(), DeveloperAppGroupAssignRequest{BundleID: "bundle-1", GroupID: "GROUP2"})
	if err == nil || !strings.Contains(err.Error(), "accepted the update but") {
		t.Fatalf("expected verification error, got %v", err)
	}
}

func TestAssignDeveloperAppGroupIsIdempotent(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, `{
				"data":{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}},
				"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":[{"type":"appGroups","id":"GROUP12345"}]}}}]
			}`, nil), nil
		default:
			t.Fatalf("idempotent assignment sent unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.AssignDeveloperAppGroup(context.Background(), DeveloperAppGroupAssignRequest{BundleID: "bundle-1", GroupID: "GROUP12345"})
	if err != nil {
		t.Fatalf("AssignDeveloperAppGroup() error: %v", err)
	}
	if result.Changed || result.Status != "already-assigned" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDeleteDeveloperAppGroupRefusesWhenStillAssigned(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected group lookup %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345", "GROUP67890"), nil), nil
		case 3:
			assertDeveloperBundleIDsListRead(t, request, "")
			return developerPortalTestResponse(http.StatusOK, `{
				"data":[{"id":"bundle-2","type":"bundleIds","attributes":{"name":"Widget","identifier":"com.example.widget"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"push-2"}]}}}],
				"included":[{"type":"bundleIdCapabilities","id":"push-2","attributes":{"enabled":true,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"PUSH_NOTIFICATIONS"}}}}],
				"links":{"next":"https://developer.apple.com/services-account/v1/bundleIds?cursor=page-2&limit=200"}
			}`, nil), nil
		case 4:
			assertDeveloperBundleIDsListRead(t, request, "page-2")
			return developerPortalTestResponse(http.StatusOK, `{
				"data":[
					{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}},
					{"id":"bundle-3","type":"bundleIds","attributes":{"name":"Other","identifier":"com.example.other"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-3"}]}}}
				],
				"included":[
					{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":[{"type":"appGroups","id":"GROUP12345"},{"type":"appGroups","id":"GROUP67890"}]}}},
					{"type":"bundleIdCapabilities","id":"groups-3","attributes":{"enabled":true,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":[{"type":"appGroups","id":"GROUP67890"}]}}}
				],
				"links":{}
			}`, nil), nil
		default:
			t.Fatalf("delete of an assigned App Group sent unexpected request %d: %s %s", requestNumber, request.Method, request.URL.String())
			return nil, nil
		}
	})

	_, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
	var inUse *DeveloperAppGroupInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("expected DeveloperAppGroupInUseError, got %v", err)
	}
	if inUse.GroupID != "GROUP12345" || inUse.Identifier != "group.com.example.GROUP12345" {
		t.Fatalf("unexpected in-use error details: %+v", inUse)
	}
	if len(inUse.Assignments) != 1 || inUse.Assignments[0].BundleID != "bundle-1" || inUse.Assignments[0].Identifier != "com.example.app" {
		t.Fatalf("unexpected assignments: %+v", inUse.Assignments)
	}
	for _, expected := range []string{"still assigned", "com.example.app", "bundle-1", "unassign"} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q does not mention %q", err.Error(), expected)
		}
	}
}

func TestDeleteDeveloperAppGroupUsesPortalFormEndpointAndVerifies(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected group lookup %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345", "GROUP67890"), nil), nil
		case 3:
			assertDeveloperBundleIDsListRead(t, request, "")
			return developerPortalTestResponse(http.StatusOK, `{
				"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}}],
				"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true,"settings":[]},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":[{"type":"appGroups","id":"GROUP67890"}]}}}]
			}`, http.Header{"csrf": {"v1-csrf"}, "csrf_ts": {"v1-ts"}}), nil
		case 4:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected CSRF priming request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "" || request.Header.Get("csrf_ts") != "" {
				t.Fatalf("CSRF priming request reused tokens from another endpoint scope")
			}
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 5:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/deleteApplicationGroup.action" {
				t.Fatalf("unexpected delete request %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "primed-csrf" || request.Header.Get("csrf_ts") != "primed-ts" {
				t.Fatalf("delete request missing primed CSRF headers")
			}
			assertDeveloperPortalForm(t, request, url.Values{
				"teamId":           {"TEAM123456"},
				"applicationGroup": {"GROUP12345"},
			})
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"resultString":"","userString":""}`, nil), nil
		case 6:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected verification request %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP67890"), nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requestNumber, request.Method, request.URL.String())
			return nil, nil
		}
	})

	result, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
	if err != nil {
		t.Fatalf("DeleteDeveloperAppGroup() error: %v", err)
	}
	if !result.Deleted || result.Status != "deleted" || result.GroupID != "GROUP12345" || result.Identifier != "group.com.example.GROUP12345" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDeleteDeveloperAppGroupFailsWhenGroupStillListedAfterDelete(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2, 6:
			return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"data":[],"included":[]}`, nil), nil
		case 4:
			return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0}`, nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	_, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
	if err == nil || !strings.Contains(err.Error(), "still listed") {
		t.Fatalf("expected verification failure, got %v", err)
	}
}

func TestDeleteDeveloperAppGroupFailsWhenVerificationListIsMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"missing collection": `{"resultCode":0}`,
		"null collection":    `{"resultCode":0,"applicationGroupList":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
				switch requestNumber {
				case 1:
					return assertDeveloperPortalBootstrap(t, request), nil
				case 2:
					return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), nil), nil
				case 3:
					return developerPortalTestResponse(http.StatusOK, `{"data":[],"included":[]}`, nil), nil
				case 4:
					return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
				case 5:
					return developerPortalTestResponse(http.StatusOK, `{"resultCode":0}`, nil), nil
				case 6:
					return developerPortalTestResponse(http.StatusOK, body, nil), nil
				default:
					t.Fatalf("unexpected request %d", requestNumber)
					return nil, nil
				}
			})

			result, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
			if err == nil || !strings.Contains(err.Error(), "verification failed") {
				t.Fatalf("expected verification failure, got result=%+v err=%v", result, err)
			}
		})
	}
}

func TestDeleteDeveloperAppGroupFailsClosedOnUnknownGroupOrUnreadableAssignments(t *testing.T) {
	t.Run("unknown group", func(t *testing.T) {
		client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
			switch requestNumber {
			case 1:
				return assertDeveloperPortalBootstrap(t, request), nil
			case 2:
				return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP67890"), nil), nil
			default:
				t.Fatalf("unknown group lookup sent unexpected request %d", requestNumber)
				return nil, nil
			}
		})
		_, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("expected not-found error, got %v", err)
		}
	})

	t.Run("capability missing from included", func(t *testing.T) {
		client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
			switch requestNumber {
			case 1:
				return assertDeveloperPortalBootstrap(t, request), nil
			case 2:
				return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), nil), nil
			case 3:
				return developerPortalTestResponse(http.StatusOK, `{
					"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}}],
					"included":[]
				}`, nil), nil
			default:
				t.Fatalf("unreadable assignment graph sent unexpected request %d", requestNumber)
				return nil, nil
			}
		})
		_, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
		if err == nil || !strings.Contains(err.Error(), "cannot determine App Group assignments") {
			t.Fatalf("expected fail-closed assignment error, got %v", err)
		}
	})

	for name, body := range map[string]string{
		"empty envelope":                       `{}`,
		"null data":                            `{"data":null,"included":[]}`,
		"null capability relationship":         `{"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":null}}}],"included":[]}`,
		"capability relationship without data": `{"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"links":{}}}}],"included":[]}`,
		"non-bundle entry":                     `{"data":[{"id":"app-1","type":"apps","attributes":{"identifier":"com.example.app"}}],"included":[]}`,
		"invalid capability reference": `{
			"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"capabilities","id":"groups-1"},{"type":"bundleIdCapabilities","id":""}]}}}],
			"included":[]
		}`,
		"omitted app group relationship": `{
			"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}}],
			"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}}}}]
		}`,
		"null app group relationship": `{
			"data":[{"id":"bundle-1","type":"bundleIds","attributes":{"identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}}],
			"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":null}}}]
		}`,
	} {
		t.Run("malformed bundle list "+name, func(t *testing.T) {
			client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
				switch requestNumber {
				case 1:
					return assertDeveloperPortalBootstrap(t, request), nil
				case 2:
					return developerPortalTestResponse(http.StatusOK, developerAppGroupsListFixture("GROUP12345"), nil), nil
				case 3:
					return developerPortalTestResponse(http.StatusOK, body, nil), nil
				default:
					t.Fatalf("malformed Bundle ID envelope must not lead to request %d", requestNumber)
					return nil, nil
				}
			})
			_, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "GROUP12345"})
			if err == nil || !strings.Contains(err.Error(), "cannot determine App Group assignments") {
				t.Fatalf("expected fail-closed assignment error, got %v", err)
			}
		})
	}

	t.Run("missing group id", func(t *testing.T) {
		client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
			t.Fatalf("validation failure sent request %d", requestNumber)
			return nil, nil
		})
		if _, err := client.DeleteDeveloperAppGroup(context.Background(), DeveloperAppGroupDeleteRequest{GroupID: "  "}); err == nil || !strings.Contains(err.Error(), "group id is required") {
			t.Fatalf("expected validation error, got %v", err)
		}
	})
}

func TestSetDeveloperAppGroupsConvergesAndReportsDiff(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" || request.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("unexpected bundle read %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1", "GROUP2"), nil), nil
		case 3:
			if request.URL.Path != "/services-account/QH65B2/account/ios/identifiers/listApplicationGroups.action" {
				t.Fatalf("unexpected CSRF priming request %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			if request.Method != http.MethodPatch || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" {
				t.Fatalf("unexpected bundle patch %s %s", request.Method, request.URL.String())
			}
			if request.Header.Get("csrf") != "primed-csrf" || request.Header.Get("csrf_ts") != "primed-ts" {
				t.Fatalf("bundle patch missing primed CSRF headers")
			}
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			if request.Method != http.MethodPost || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" || request.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
				t.Fatalf("unexpected verification read %s %s", request.Method, request.URL.String())
			}
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP2", "GROUP3"), nil), nil
		default:
			t.Fatalf("unexpected request %d: %s %s", requestNumber, request.Method, request.URL.String())
			return nil, nil
		}
	})

	result, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1", GroupIDs: []string{"GROUP2", "GROUP3", "GROUP2"}})
	if err != nil {
		t.Fatalf("SetDeveloperAppGroups() error: %v", err)
	}
	if !result.Changed || result.Status != "updated" || result.BundleID != "bundle-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if strings.Join(result.GroupIDs, ",") != "GROUP2,GROUP3" || strings.Join(result.Added, ",") != "GROUP3" || strings.Join(result.Removed, ",") != "GROUP1" {
		t.Fatalf("unexpected diff: %+v", result)
	}

	capabilities := decodeDeveloperBundlePatchCapabilities(t, patchBody)
	if len(capabilities) != 2 {
		t.Fatalf("capability count = %d, want PUSH_NOTIFICATIONS plus APP_GROUPS", len(capabilities))
	}
	if id, err := developerBundleIDCapabilityID(capabilities[0]); err != nil || id != "PUSH_NOTIFICATIONS" {
		t.Fatalf("unrelated capability not preserved: %+v err=%v", capabilities[0], err)
	}
	groups, enabled := decodeDeveloperAppGroupsCapability(t, capabilities[1])
	if !enabled || strings.Join(groups, ",") != "GROUP2,GROUP3" {
		t.Fatalf("unexpected APP_GROUPS patch: enabled=%t groups=%v", enabled, groups)
	}
}

func TestSetDeveloperAppGroupsIsNoOpWhenCurrentSetMatches(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1", "GROUP2"), nil), nil
		default:
			t.Fatalf("no-op set sent unexpected request %d: %s %s", requestNumber, request.Method, request.URL.String())
			return nil, nil
		}
	})

	result, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1", GroupIDs: []string{"GROUP2", "GROUP1"}})
	if err != nil {
		t.Fatalf("SetDeveloperAppGroups() error: %v", err)
	}
	if result.Changed || result.Status != "unchanged" || len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if strings.Join(result.GroupIDs, ",") != "GROUP2,GROUP1" {
		t.Fatalf("unexpected desired set echo: %+v", result.GroupIDs)
	}
}

func TestSetDeveloperAppGroupsFailsWhenVerificationDiffers(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	_, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1", GroupIDs: []string{"GROUP2"}})
	if err == nil || !strings.Contains(err.Error(), "still reports") {
		t.Fatalf("expected verification failure, got %v", err)
	}
	var unverified *DeveloperAppGroupUnverifiedError
	if !errors.As(err, &unverified) {
		t.Fatalf("expected DeveloperAppGroupUnverifiedError so callers can warn about an accepted write, got %T: %v", err, err)
	}
}

func TestAppGroupMutationsFailClosedWhenCapabilityGraphIsUnreadable(t *testing.T) {
	bundles := map[string]string{
		"omitted relationships":        `{"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"}},"included":[]}`,
		"omitted capability relation":  `{"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"profiles":{"data":[]}}},"included":[]}`,
		"null capability relationship": `{"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":null}}},"included":[]}`,
		"omitted app groups on APP_GROUPS capability": `{
			"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}},
			"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}}}}]
		}`,
		"null app groups on APP_GROUPS capability": `{
			"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app"},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"groups-1"}]}}},
			"included":[{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":null}}}]
		}`,
		"bundle id mismatch": `{"data":{"id":"bundle-2","type":"bundleIds","attributes":{"name":"Other","identifier":"com.example.other"},"relationships":{"bundleIdCapabilities":{"data":[]}}},"included":[]}`,
	}
	mutations := map[string]func(*Client) error{
		"assign": func(client *Client) error {
			_, err := client.AssignDeveloperAppGroup(context.Background(), DeveloperAppGroupAssignRequest{BundleID: "bundle-1", GroupID: "GROUP1"})
			return err
		},
		"unassign": func(client *Client) error {
			_, err := client.UnassignDeveloperAppGroup(context.Background(), DeveloperAppGroupUnassignRequest{BundleID: "bundle-1", GroupID: "GROUP1"})
			return err
		},
		"set": func(client *Client) error {
			_, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1", GroupIDs: []string{"GROUP1"}})
			return err
		},
	}
	for bundleName, bundle := range bundles {
		for mutationName, mutate := range mutations {
			t.Run(mutationName+" "+bundleName, func(t *testing.T) {
				client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
					switch requestNumber {
					case 1:
						return assertDeveloperPortalBootstrap(t, request), nil
					case 2:
						return developerPortalTestResponse(http.StatusOK, bundle, nil), nil
					default:
						t.Fatalf("unreadable capability graph must not lead to request %d (%s %s)", requestNumber, request.Method, request.URL.Path)
						return nil, nil
					}
				})
				err := mutate(client)
				if err == nil || !strings.Contains(err.Error(), "cannot safely update Bundle ID") {
					t.Fatalf("expected fail-closed Bundle ID read error, got %v", err)
				}
			})
		}
	}
}

func TestSetDeveloperAppGroupsRejectsEmptyInput(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		t.Fatalf("validation failure sent request %d", requestNumber)
		return nil, nil
	})
	if _, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1"}); err == nil || !strings.Contains(err.Error(), "at least one group id is required") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{GroupIDs: []string{"GROUP1"}}); err == nil || !strings.Contains(err.Error(), "bundle id is required") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestUnassignDeveloperAppGroupRemovesGroupAndVerifies(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1", "GROUP2"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			if request.Method != http.MethodPatch || request.URL.Path != "/services-account/v1/bundleIds/bundle-1" {
				t.Fatalf("unexpected bundle patch %s %s", request.Method, request.URL.String())
			}
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.UnassignDeveloperAppGroup(context.Background(), DeveloperAppGroupUnassignRequest{BundleID: "bundle-1", GroupID: "GROUP2"})
	if err != nil {
		t.Fatalf("UnassignDeveloperAppGroup() error: %v", err)
	}
	if !result.Changed || result.Status != "unassigned" || strings.Join(result.RemainingGroupIDs, ",") != "GROUP1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	capabilities := decodeDeveloperBundlePatchCapabilities(t, patchBody)
	groups, enabled := decodeDeveloperAppGroupsCapability(t, capabilities[1])
	if !enabled || strings.Join(groups, ",") != "GROUP1" {
		t.Fatalf("unexpected APP_GROUPS patch: enabled=%t groups=%v", enabled, groups)
	}
}

func TestUnassignDeveloperAppGroupDisablesCapabilityWhenLastGroupRemoved(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(false), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.UnassignDeveloperAppGroup(context.Background(), DeveloperAppGroupUnassignRequest{BundleID: "bundle-1", GroupID: "GROUP1"})
	if err != nil {
		t.Fatalf("UnassignDeveloperAppGroup() error: %v", err)
	}
	if !result.Changed || result.Status != "unassigned" || len(result.RemainingGroupIDs) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	capabilities := decodeDeveloperBundlePatchCapabilities(t, patchBody)
	groups, enabled := decodeDeveloperAppGroupsCapability(t, capabilities[1])
	if enabled || len(groups) != 0 {
		t.Fatalf("expected APP_GROUPS disabled with no groups, got enabled=%t groups=%v", enabled, groups)
	}
}

func TestUnassignDeveloperAppGroupClearsGroupFromDisabledCapability(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(false, "GROUP1", "GROUP2"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(false, "GROUP2"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.UnassignDeveloperAppGroup(context.Background(), DeveloperAppGroupUnassignRequest{BundleID: "bundle-1", GroupID: "GROUP1"})
	if err != nil {
		t.Fatalf("UnassignDeveloperAppGroup() error: %v", err)
	}
	if !result.Changed || result.Status != "unassigned" || strings.Join(result.RemainingGroupIDs, ",") != "GROUP2" {
		t.Fatalf("unexpected result: %+v", result)
	}
	capabilities := decodeDeveloperBundlePatchCapabilities(t, patchBody)
	groups, enabled := decodeDeveloperAppGroupsCapability(t, capabilities[1])
	if enabled || strings.Join(groups, ",") != "GROUP2" {
		t.Fatalf("expected APP_GROUPS to stay disabled with only GROUP2 listed, got enabled=%t groups=%v", enabled, groups)
	}
}

func TestSetDeveloperAppGroupsEnablesDisabledCapabilityListingDesiredGroups(t *testing.T) {
	var patchBody []byte
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(false, "GROUP1"), nil), nil
		case 3:
			return developerPortalTestResponse(http.StatusOK, `{"resultCode":0,"applicationGroupList":[]}`, http.Header{"csrf": {"primed-csrf"}, "csrf_ts": {"primed-ts"}}), nil
		case 4:
			var err error
			patchBody, err = io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}
			return developerPortalTestResponse(http.StatusOK, `{"data":{"type":"bundleIds","id":"bundle-1"}}`, nil), nil
		case 5:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		default:
			t.Fatalf("unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.SetDeveloperAppGroups(context.Background(), DeveloperAppGroupSetRequest{BundleID: "bundle-1", GroupIDs: []string{"GROUP1"}})
	if err != nil {
		t.Fatalf("SetDeveloperAppGroups() error: %v", err)
	}
	if !result.Changed || result.Status != "updated" || len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	capabilities := decodeDeveloperBundlePatchCapabilities(t, patchBody)
	groups, enabled := decodeDeveloperAppGroupsCapability(t, capabilities[1])
	if !enabled || strings.Join(groups, ",") != "GROUP1" {
		t.Fatalf("expected APP_GROUPS enabled with GROUP1, got enabled=%t groups=%v", enabled, groups)
	}
}

func TestUnassignDeveloperAppGroupIsIdempotent(t *testing.T) {
	client := newDeveloperAppGroupsTestClient(t, func(requestNumber int, request *http.Request) (*http.Response, error) {
		switch requestNumber {
		case 1:
			return assertDeveloperPortalBootstrap(t, request), nil
		case 2:
			return developerPortalTestResponse(http.StatusOK, developerBundleAppGroupsFixture(true, "GROUP1"), nil), nil
		default:
			t.Fatalf("idempotent unassign sent unexpected request %d", requestNumber)
			return nil, nil
		}
	})

	result, err := client.UnassignDeveloperAppGroup(context.Background(), DeveloperAppGroupUnassignRequest{BundleID: "bundle-1", GroupID: "GROUP9"})
	if err != nil {
		t.Fatalf("UnassignDeveloperAppGroup() error: %v", err)
	}
	if result.Changed || result.Status != "not-assigned" || strings.Join(result.RemainingGroupIDs, ",") != "GROUP1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func developerAppGroupsListFixture(groupIDs ...string) string {
	entries := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		entries = append(entries, fmt.Sprintf(`{"name":"Group %s","prefix":"TEAM123456","identifier":"group.com.example.%s","status":"current","applicationGroup":"%s"}`, id, id, id))
	}
	return fmt.Sprintf(`{"resultCode":0,"pageNumber":1,"pageSize":500,"totalRecords":%d,"applicationGroupList":[%s]}`, len(groupIDs), strings.Join(entries, ","))
}

func developerBundleAppGroupsFixture(enabled bool, groupIDs ...string) string {
	groups := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		groups = append(groups, fmt.Sprintf(`{"type":"appGroups","id":"%s"}`, id))
	}
	return fmt.Sprintf(`{
		"data":{"id":"bundle-1","type":"bundleIds","attributes":{"name":"Example","identifier":"com.example.app","platform":"IOS","permissions":{"delete":true,"edit":true}},"relationships":{"bundleIdCapabilities":{"data":[{"type":"bundleIdCapabilities","id":"push-1"},{"type":"bundleIdCapabilities","id":"groups-1"}]}}},
		"included":[
			{"type":"bundleIdCapabilities","id":"push-1","attributes":{"enabled":true,"settings":[],"editable":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"PUSH_NOTIFICATIONS"}}}},
			{"type":"bundleIdCapabilities","id":"groups-1","attributes":{"enabled":%t,"settings":[],"editable":true},"relationships":{"capability":{"data":{"type":"capabilities","id":"APP_GROUPS"}},"appGroups":{"data":[%s]}}}
		]
	}`, enabled, strings.Join(groups, ","))
}

func assertDeveloperBundleIDsListRead(t *testing.T, request *http.Request, wantCursor string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/services-account/v1/bundleIds" || request.Header.Get("X-HTTP-Method-Override") != http.MethodGet {
		t.Fatalf("unexpected Bundle ID list read %s %s", request.Method, request.URL.String())
	}
	proxy := decodeDeveloperPortalProxyReadRequest(t, request)
	if proxy.TeamID != "TEAM123456" {
		t.Fatalf("Bundle ID list teamId = %q", proxy.TeamID)
	}
	query, err := url.ParseQuery(proxy.URLEncodedQueryParams)
	if err != nil {
		t.Fatalf("ParseQuery() error: %v", err)
	}
	if query.Get("cursor") != wantCursor {
		t.Fatalf("cursor = %q, want %q", query.Get("cursor"), wantCursor)
	}
	if !strings.Contains(query.Get("include"), "bundleIdCapabilities.appGroups") {
		t.Fatalf("Bundle ID list include = %q, want appGroups", query.Get("include"))
	}
	if query.Get("limit") == "" {
		t.Fatalf("Bundle ID list is missing limit: %q", proxy.URLEncodedQueryParams)
	}
}

func decodeDeveloperBundlePatchCapabilities(t *testing.T, patchBody []byte) []developerResource {
	t.Helper()
	var payload developerBundleIDPatchRequest
	if err := json.Unmarshal(patchBody, &payload); err != nil {
		t.Fatalf("decode patch: %v; body=%s", err, patchBody)
	}
	var bundleAttributes map[string]json.RawMessage
	if err := json.Unmarshal(payload.Data.Attributes, &bundleAttributes); err != nil {
		t.Fatalf("decode Bundle ID attributes: %v", err)
	}
	if string(bundleAttributes["teamId"]) != `"TEAM123456"` {
		t.Fatalf("teamId missing from PATCH attributes: %s", payload.Data.Attributes)
	}
	if _, ok := bundleAttributes["permissions"]; ok {
		t.Fatalf("read-only permissions attribute was sent in PATCH: %s", payload.Data.Attributes)
	}
	var capabilities developerResourceRelationship
	if err := json.Unmarshal(payload.Data.Relationships["bundleIdCapabilities"], &capabilities); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	return capabilities.Data
}

func decodeDeveloperAppGroupsCapability(t *testing.T, capability developerResource) ([]string, bool) {
	t.Helper()
	if id, err := developerBundleIDCapabilityID(capability); err != nil || id != "APP_GROUPS" {
		t.Fatalf("unexpected capability: %+v err=%v", capability, err)
	}
	enabled, err := developerBundleIDCapabilityEnabled(capability)
	if err != nil {
		t.Fatalf("decode enabled: %v", err)
	}
	var groups developerResourceRelationship
	if err := json.Unmarshal(capability.Relationships["appGroups"], &groups); err != nil {
		t.Fatalf("decode appGroups: %v", err)
	}
	ids := make([]string, 0, len(groups.Data))
	for _, group := range groups.Data {
		if group.Type != "appGroups" {
			t.Fatalf("unexpected appGroups relationship type: %+v", group)
		}
		ids = append(ids, group.ID)
	}
	return ids, enabled
}

func newDeveloperAppGroupsTestClient(t *testing.T, handler func(int, *http.Request) (*http.Response, error)) *Client {
	t.Helper()
	requestNumber := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestNumber++
		response, err := handler(requestNumber, request)
		if err != nil {
			t.Errorf("test Developer Portal handler: %v", err)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		if response == nil {
			t.Error("test Developer Portal handler returned a nil response")
			http.Error(writer, "missing test response", http.StatusInternalServerError)
			return
		}
		for name, values := range response.Header {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(response.StatusCode)
		if response.Body != nil {
			defer func() { _ = response.Body.Close() }()
			if _, err := io.Copy(writer, response.Body); err != nil {
				t.Errorf("write test Developer Portal response: %v", err)
			}
		}
	}))
	t.Cleanup(server.Close)
	return &Client{httpClient: server.Client(), developerPortalURL: server.URL}
}

func assertDeveloperPortalBootstrap(t *testing.T, request *http.Request) *http.Response {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/services-account/QH65B2/account/listTeams.action" {
		t.Fatalf("unexpected bootstrap request %s %s", request.Method, request.URL.String())
	}
	return developerPortalTestResponse(http.StatusOK, developerPortalTeamsFixture(), http.Header{"csrf": {"bootstrap-csrf"}, "csrf_ts": {"bootstrap-ts"}})
}

func assertDeveloperPortalForm(t *testing.T, request *http.Request, expected url.Values) {
	t.Helper()
	if got := request.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
		t.Fatalf("Content-Type = %q", got)
	}
	if err := request.ParseForm(); err != nil {
		t.Fatalf("ParseForm() error: %v", err)
	}
	for key, values := range expected {
		if got := request.PostForm[key]; strings.Join(got, "\x00") != strings.Join(values, "\x00") {
			t.Fatalf("form %s = %q, want %q", key, got, values)
		}
	}
}
