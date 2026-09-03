package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// fetchJSONAPIPages follows links.next across JSON:API list responses, merging
// data and included resources. Duplicate or self-referential next paths abort
// with a pagination-loop error instead of spinning.
func (c *Client) fetchJSONAPIPages(ctx context.Context, path, responseName string) (jsonAPIListPayload, error) {
	return c.fetchJSONAPIPagesFrom(ctx, c.baseURL, path, responseName)
}

// fetchJSONAPIPagesFrom is fetchJSONAPIPages against an explicit JSON:API base,
// so iris v2 collections can follow absolute next links without rejoining them
// onto the client's iris v1 baseURL.
func (c *Client) fetchJSONAPIPagesFrom(ctx context.Context, baseURL, path, responseName string) (jsonAPIListPayload, error) {
	nextPath := strings.TrimSpace(path)
	if nextPath == "" {
		return jsonAPIListPayload{}, fmt.Errorf("%s path is required", responseName)
	}

	combined := jsonAPIListPayload{
		Data:     make([]jsonAPIResource, 0),
		Included: make([]jsonAPIResource, 0),
	}
	visited := map[string]struct{}{}

	for nextPath != "" {
		if _, seen := visited[nextPath]; seen {
			return jsonAPIListPayload{}, fmt.Errorf("%s pagination loop detected", responseName)
		}
		visited[nextPath] = struct{}{}
		currentPath := nextPath

		responseBody, err := c.doJSONAPIRequest(ctx, baseURL, http.MethodGet, nextPath)
		if err != nil {
			return jsonAPIListPayload{}, err
		}
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(responseBody, &envelope); err != nil {
			return jsonAPIListPayload{}, fmt.Errorf("failed to parse %s response: %w", responseName, err)
		}
		trimmedData := bytes.TrimSpace(envelope.Data)
		if len(trimmedData) == 0 || bytes.Equal(trimmedData, []byte("null")) {
			return jsonAPIListPayload{}, fmt.Errorf("%s response missing non-null data", responseName)
		}

		var payload jsonAPIListPayload
		if err := json.Unmarshal(responseBody, &payload); err != nil {
			return jsonAPIListPayload{}, fmt.Errorf("failed to parse %s response: %w", responseName, err)
		}
		combined.Data = append(combined.Data, payload.Data...)
		combined.Included = append(combined.Included, payload.Included...)

		nextLink, err := extractNextLink(payload.Links)
		if err != nil {
			return jsonAPIListPayload{}, fmt.Errorf("failed to parse %s pagination links: %w", responseName, err)
		}
		if strings.TrimSpace(nextLink) == "" {
			nextPath = ""
			continue
		}
		nextPath, err = resolveJSONAPINextPath(nextLink, currentPath, baseURL)
		if err != nil {
			return jsonAPIListPayload{}, fmt.Errorf("failed to normalize %s pagination link: %w", responseName, err)
		}
	}

	return combined, nil
}

func (c *Client) doJSONAPIRequest(ctx context.Context, baseURL, method, path string) ([]byte, error) {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json")
	headers.Set("X-Requested-With", "XMLHttpRequest")
	headers.Set("Origin", appStoreBaseURL)
	headers.Set("Referer", appStoreBaseURL+"/")
	return c.doRequestBase(ctx, baseURL, method, path, nil, headers)
}

func resolveJSONAPINextPath(nextLink, currentPath, baseURL string) (string, error) {
	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base url: %w", err)
	}
	current, err := url.Parse(currentPath)
	if err != nil {
		return "", fmt.Errorf("invalid current path: %w", err)
	}
	currentURL := baseURLParsed.ResolveReference(current)
	ref, err := url.Parse(nextLink)
	if err != nil {
		return "", fmt.Errorf("invalid next link: %w", err)
	}
	return normalizeNextPath(currentURL.ResolveReference(ref).String(), baseURL)
}
