package web

import (
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

		responseBody, err := c.doRequest(ctx, http.MethodGet, nextPath, nil)
		if err != nil {
			return jsonAPIListPayload{}, err
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
		nextPath, err = resolveJSONAPINextPath(nextLink, currentPath, c.baseURL)
		if err != nil {
			return jsonAPIListPayload{}, fmt.Errorf("failed to normalize %s pagination link: %w", responseName, err)
		}
	}

	return combined, nil
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
