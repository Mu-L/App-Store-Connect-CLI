package asc

import (
	"context"
	"net/http"
	"testing"
)

func TestGetCertificates_SendsQuerySurface(t *testing.T) {
	response := jsonResponse(http.StatusOK, `{"data":[]}`)
	client := newTestClient(t, func(req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/certificates" {
			t.Fatalf("request = %s %s, want GET /v1/certificates", req.Method, req.URL.Path)
		}
		values := req.URL.Query()
		wantQuery := map[string]string{
			"filter[displayName]":     "Alpha,Beta",
			"filter[certificateType]": "IOS_DISTRIBUTION,PASS_TYPE_ID",
			"filter[serialNumber]":    "SN1,SN2",
			"filter[id]":              "cert-1,cert-2",
			"sort":                    "-displayName",
			"fields[certificates]":    "displayName,serialNumber",
			"fields[passTypeIds]":     "name,identifier",
			"include":                 "passTypeId",
			"limit":                   "5",
		}
		for key, want := range wantQuery {
			if got := values.Get(key); got != want {
				t.Errorf("query %s = %q, want %q", key, got, want)
			}
		}
		if len(values) != len(wantQuery) {
			t.Errorf("query = %s, want exactly %d parameters", values.Encode(), len(wantQuery))
		}
		assertAuthorized(t, req)
	}, response)

	if _, err := client.GetCertificates(
		context.Background(),
		WithCertificatesFilterDisplayNames([]string{"Alpha", "Beta"}),
		WithCertificatesTypes([]string{"IOS_DISTRIBUTION", "PASS_TYPE_ID"}),
		WithCertificatesFilterSerialNumbers([]string{"SN1", "SN2"}),
		WithCertificatesFilterIDs([]string{"cert-1", "cert-2"}),
		WithCertificatesSort("-displayName"),
		WithCertificatesFields([]string{"displayName", "serialNumber"}),
		WithCertificatesPassTypeIDFields([]string{"name", "identifier"}),
		WithCertificatesInclude([]string{"passTypeId"}),
		WithCertificatesLimit(5),
	); err != nil {
		t.Fatalf("GetCertificates() error: %v", err)
	}
}

func TestGetCertificate_DetailQueryOnlyAllowsSparseFieldsAndInclude(t *testing.T) {
	response := jsonResponse(http.StatusOK, `{"data":{"type":"certificates","id":"cert-1","attributes":{"name":"Certificate","certificateType":"IOS_DISTRIBUTION"}}}`)
	client := newTestClient(t, func(req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/certificates/cert-1" {
			t.Fatalf("request = %s %s, want GET /v1/certificates/cert-1", req.Method, req.URL.Path)
		}
		values := req.URL.Query()
		wantQuery := map[string]string{
			"fields[certificates]": "displayName,serialNumber",
			"fields[passTypeIds]":  "name,identifier",
			"include":              "passTypeId",
		}
		for key, want := range wantQuery {
			if got := values.Get(key); got != want {
				t.Errorf("query %s = %q, want %q", key, got, want)
			}
		}
		if len(values) != len(wantQuery) {
			t.Errorf("query = %s, want exactly %d parameters", values.Encode(), len(wantQuery))
		}
		assertAuthorized(t, req)
	}, response)

	if _, err := client.GetCertificate(
		context.Background(),
		"cert-1",
		WithCertificatesFilterDisplayNames([]string{"Alpha"}),
		WithCertificatesTypes([]string{"IOS_DISTRIBUTION"}),
		WithCertificatesFilterSerialNumbers([]string{"SN1"}),
		WithCertificatesFilterIDs([]string{"cert-1"}),
		WithCertificatesSort("-displayName"),
		WithCertificatesFields([]string{"displayName", "serialNumber"}),
		WithCertificatesPassTypeIDFields([]string{"name", "identifier"}),
		WithCertificatesInclude([]string{"passTypeId"}),
		WithCertificatesLimit(5),
	); err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
}
