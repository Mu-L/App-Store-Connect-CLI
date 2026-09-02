package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

		nextPath, err = nextLookupPagePath(payload.Links, c.baseURL, responseName)
		if err != nil {
			return jsonAPIListPayload{}, err
		}
	}

	return combined, nil
}
