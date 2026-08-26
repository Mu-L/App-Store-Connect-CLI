package asc

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestBuildCiProductsQueryIncludesOpenAPIOptions(t *testing.T) {
	query := &ciProductsQuery{}
	for _, option := range []CiProductsOption{
		WithCiProductsProductTypes([]string{" app ", "framework"}),
		WithCiProductsAppID("app-1"),
		WithCiProductsFields([]string{"name", "productType"}),
		WithCiProductsAppFields([]string{"name", "bundleId"}),
		WithCiProductsBundleIDFields([]string{"identifier", "platform"}),
		WithCiProductsScmRepositoryFields([]string{"repositoryName", "ownerName"}),
		WithCiProductsInclude([]string{"app", "bundleId", "primaryRepositories"}),
		WithCiProductsPrimaryRepositoriesLimit(25),
		WithCiProductsLimit(10),
	} {
		option(query)
	}

	values, err := url.ParseQuery(buildCiProductsQuery(query))
	if err != nil {
		t.Fatalf("ParseQuery() error: %v", err)
	}
	want := map[string]string{
		"filter[productType]":        "APP,FRAMEWORK",
		"filter[app]":                "app-1",
		"fields[ciProducts]":         "name,productType",
		"fields[apps]":               "name,bundleId",
		"fields[bundleIds]":          "identifier,platform",
		"fields[scmRepositories]":    "repositoryName,ownerName",
		"include":                    "app,bundleId,primaryRepositories",
		"limit[primaryRepositories]": "25",
		"limit":                      "10",
	}
	for key, expected := range want {
		if got := values.Get(key); got != expected {
			t.Errorf("query[%q] = %q, want %q", key, got, expected)
		}
	}
}

func TestGetCiProductsWithOpenAPIQueryOptions(t *testing.T) {
	response := jsonResponse(http.StatusOK, `{"data":[{"type":"ciProducts","id":"product-1"}]}`)
	client := newTestClient(t, func(req *http.Request) {
		if req.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", req.Method)
		}
		if req.URL.Path != "/v1/ciProducts" {
			t.Fatalf("expected path /v1/ciProducts, got %s", req.URL.Path)
		}
		values := req.URL.Query()
		want := map[string]string{
			"filter[productType]":        "APP,FRAMEWORK",
			"filter[app]":                "app-1",
			"fields[ciProducts]":         "name,productType",
			"fields[apps]":               "name,bundleId",
			"fields[bundleIds]":          "identifier,platform",
			"fields[scmRepositories]":    "repositoryName,ownerName",
			"include":                    "app,bundleId,primaryRepositories",
			"limit[primaryRepositories]": "25",
			"limit":                      "10",
		}
		for key, expected := range want {
			if got := values.Get(key); got != expected {
				t.Errorf("query[%q] = %q, want %q", key, got, expected)
			}
		}
		assertAuthorized(t, req)
	}, response)

	if _, err := client.GetCiProducts(
		context.Background(),
		WithCiProductsProductTypes([]string{"APP", "FRAMEWORK"}),
		WithCiProductsAppID("app-1"),
		WithCiProductsFields([]string{"name", "productType"}),
		WithCiProductsAppFields([]string{"name", "bundleId"}),
		WithCiProductsBundleIDFields([]string{"identifier", "platform"}),
		WithCiProductsScmRepositoryFields([]string{"repositoryName", "ownerName"}),
		WithCiProductsInclude([]string{"app", "bundleId", "primaryRepositories"}),
		WithCiProductsPrimaryRepositoriesLimit(25),
		WithCiProductsLimit(10),
	); err != nil {
		t.Fatalf("GetCiProducts() error: %v", err)
	}
}
