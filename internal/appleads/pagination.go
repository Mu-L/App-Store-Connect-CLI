package appleads

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// PageDetail is the Apple Ads offset pagination envelope.
type PageDetail struct {
	ItemsPerPage int `json:"itemsPerPage"`
	StartIndex   int `json:"startIndex"`
	TotalResults int `json:"totalResults"`
}

type paginatedEnvelope struct {
	Data       []json.RawMessage `json:"data"`
	Pagination PageDetail        `json:"pagination"`
}

type platformPageDetail struct {
	TotalCount *int `json:"totalCount,omitempty"`
	Offset     int  `json:"offset"`
	PageSize   int  `json:"pageSize"`
}

type platformPaginatedEnvelope struct {
	Result     []json.RawMessage  `json:"result"`
	Pagination platformPageDetail `json:"pagination"`
}

const maxPlatformPaginationPages = 1000

// PaginateAll fetches all pages for an offset-paginated endpoint.
func (c *Client) PaginateAll(ctx context.Context, spec EndpointSpec, pathParams map[string]string, query url.Values, startOffset, pageSize int, body json.RawMessage) (RawResponse, error) {
	if spec.Version == APIVersionPlatformV1 {
		return c.paginatePlatformGET(ctx, spec, pathParams, query, startOffset, pageSize, body)
	}
	maxLimit := MaxPageLimit(spec)
	if pageSize <= 0 {
		pageSize = maxLimit
	}
	if pageSize > maxLimit {
		pageSize = maxLimit
	}

	offset := startOffset
	if offset < 0 {
		offset = 0
	}
	var aggregated []json.RawMessage
	total := -1
	for {
		pageQuery := cloneValues(query)
		pageQuery.Set("limit", strconv.Itoa(pageSize))
		pageQuery.Set("offset", strconv.Itoa(offset))
		raw, err := c.Do(ctx, spec, pathParams, pageQuery, body)
		if err != nil {
			return nil, err
		}
		var page paginatedEnvelope
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("parse paginated response: %w", err)
		}
		aggregated = append(aggregated, page.Data...)
		itemsPerPage := page.Pagination.ItemsPerPage
		if itemsPerPage <= 0 {
			itemsPerPage = len(page.Data)
		}
		total = page.Pagination.TotalResults
		if len(page.Data) == 0 {
			break
		}
		nextOffset := page.Pagination.StartIndex + itemsPerPage
		if total >= 0 && nextOffset >= total {
			break
		}
		if nextOffset <= offset {
			nextOffset = offset + len(page.Data)
		}
		offset = nextOffset
	}

	out := paginatedEnvelope{
		Data: aggregated,
		Pagination: PageDetail{
			ItemsPerPage: pageSize,
			StartIndex:   max(0, startOffset),
			TotalResults: total,
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return RawResponse(data), nil
}

func (c *Client) paginatePlatformGET(ctx context.Context, spec EndpointSpec, pathParams map[string]string, query url.Values, startOffset, pageSize int, body json.RawMessage) (RawResponse, error) {
	if spec.Method != "GET" || len(body) != 0 {
		return nil, fmt.Errorf("platform API v1 body pagination is not supported by the GET offset paginator")
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	offset := max(0, startOffset)
	pageSizeParam := platformPageSizeParam(spec)
	var aggregated []json.RawMessage
	var total *int
	pages := 0
	for {
		if pages >= maxPlatformPaginationPages {
			return nil, fmt.Errorf("platform API v1 pagination exceeded the %d-page safety limit; narrow your query or use --offset to continue from a smaller result set", maxPlatformPaginationPages)
		}
		pages++
		pageQuery := cloneValues(query)
		pageQuery.Set(pageSizeParam, strconv.Itoa(pageSize))
		pageQuery.Set("offset", strconv.Itoa(offset))
		raw, err := c.Do(ctx, spec, pathParams, pageQuery, body)
		if err != nil {
			return nil, err
		}
		var page platformPaginatedEnvelope
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("parse paginated response: %w", err)
		}
		aggregated = append(aggregated, page.Result...)
		if page.Pagination.TotalCount != nil {
			value := *page.Pagination.TotalCount
			total = &value
		}
		if len(page.Result) == 0 {
			break
		}
		step := page.Pagination.PageSize
		if step <= 0 {
			step = len(page.Result)
		}
		nextOffset := page.Pagination.Offset + step
		if total != nil && nextOffset >= *total {
			break
		}
		if total == nil && len(page.Result) < step {
			break
		}
		if nextOffset <= offset {
			nextOffset = offset + len(page.Result)
		}
		offset = nextOffset
	}

	out := platformPaginatedEnvelope{
		Result: aggregated,
		Pagination: platformPageDetail{
			TotalCount: total,
			Offset:     max(0, startOffset),
			PageSize:   pageSize,
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return RawResponse(data), nil
}

// platformPageSizeParam returns the query parameter used to control the page
// size for a Platform API v1 GET endpoint. Most endpoints use limit, while
// geo search follows the service's pageSize spelling.
func platformPageSizeParam(spec EndpointSpec) string {
	for _, param := range spec.QueryParams {
		if param.Name == "pageSize" {
			return "pageSize"
		}
	}
	return "limit"
}

// MaxPageLimit returns the endpoint-specific maximum page size.
func MaxPageLimit(spec EndpointSpec) int {
	if spec.Version == APIVersionPlatformV1 {
		for _, param := range spec.QueryParams {
			if param.Name == "limit" && param.Max > 0 {
				return param.Max
			}
		}
		return 0
	}
	maxLimit := maxAppleAdsPageLimit
	for _, param := range spec.QueryParams {
		if param.Name == "limit" && param.Max > 0 {
			maxLimit = param.Max
			break
		}
	}
	return maxLimit
}

func cloneValues(values url.Values) url.Values {
	cloned := url.Values{}
	for key, items := range values {
		for _, item := range items {
			cloned.Add(key, item)
		}
	}
	return cloned
}
