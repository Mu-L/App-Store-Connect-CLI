package asc

import (
	"context"
	"fmt"
	"strings"
)

// Asset collection options are intentionally separate from relationship options:
// these endpoints return full resources and accept their own links.next URLs.
type appScreenshotSetsQuery struct {
	listQuery
}

type appScreenshotsQuery struct {
	listQuery
}

// AppScreenshotSetsOption configures screenshot-set collection requests.
type AppScreenshotSetsOption func(*appScreenshotSetsQuery)

// AppScreenshotsOption configures screenshot collection requests.
type AppScreenshotsOption func(*appScreenshotsQuery)

func buildAppScreenshotSetsQuery(query *appScreenshotSetsQuery) string {
	return buildListQuery(&query.listQuery)
}

func buildAppScreenshotsQuery(query *appScreenshotsQuery) string {
	return buildListQuery(&query.listQuery)
}

// WithAppScreenshotSetsLimit sets the maximum number of screenshot sets to return.
func WithAppScreenshotSetsLimit(limit int) AppScreenshotSetsOption {
	return func(query *appScreenshotSetsQuery) {
		if limit > 0 {
			query.limit = limit
		}
	}
}

// WithAppScreenshotSetsNextURL uses an Apple-supplied next page URL directly.
func WithAppScreenshotSetsNextURL(next string) AppScreenshotSetsOption {
	return func(query *appScreenshotSetsQuery) {
		if strings.TrimSpace(next) != "" {
			query.nextURL = strings.TrimSpace(next)
		}
	}
}

// WithAppScreenshotsLimit sets the maximum number of screenshots to return.
func WithAppScreenshotsLimit(limit int) AppScreenshotsOption {
	return func(query *appScreenshotsQuery) {
		if limit > 0 {
			query.limit = limit
		}
	}
}

// WithAppScreenshotsNextURL uses an Apple-supplied next page URL directly.
func WithAppScreenshotsNextURL(next string) AppScreenshotsOption {
	return func(query *appScreenshotsQuery) {
		if strings.TrimSpace(next) != "" {
			query.nextURL = strings.TrimSpace(next)
		}
	}
}

// GetAllAppScreenshotSets retrieves every screenshot set using automatic pagination.
func (c *Client) GetAllAppScreenshotSets(ctx context.Context, localizationID string, opts ...AppScreenshotSetsOption) (*AppScreenshotSetsResponse, error) {
	firstPage, err := c.GetAppScreenshotSets(ctx, localizationID, opts...)
	if err != nil {
		return nil, err
	}

	result, err := paginateAssetResponse(ctx, firstPage, func(ctx context.Context, nextURL string) (PaginatedResponse, error) {
		return c.GetAppScreenshotSets(ctx, "", WithAppScreenshotSetsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetAllAppScreenshots retrieves every screenshot for a set using automatic pagination.
func (c *Client) GetAllAppScreenshots(ctx context.Context, setID string, opts ...AppScreenshotsOption) (*AppScreenshotsResponse, error) {
	firstPage, err := c.GetAppScreenshots(ctx, setID, opts...)
	if err != nil {
		return nil, err
	}

	result, err := paginateAssetResponse(ctx, firstPage, func(ctx context.Context, nextURL string) (PaginatedResponse, error) {
		return c.GetAppScreenshots(ctx, "", WithAppScreenshotsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// paginateAssetResponse keeps collection wrappers typed while sharing the
// standard repeated-next protection and envelope aggregation.
func paginateAssetResponse[T any](ctx context.Context, firstPage *Response[T], fetchNext PaginateFunc) (*Response[T], error) {
	result, err := PaginateAll(ctx, firstPage, fetchNext)
	if err != nil {
		return nil, err
	}
	response, ok := result.(*Response[T])
	if !ok {
		return nil, fmt.Errorf("unexpected paginated response type %T", result)
	}
	return response, nil
}

// GetAllAppStoreVersionLocalizationScreenshotSets retrieves every screenshot
// set for an App Store version localization.
func (c *Client) GetAllAppStoreVersionLocalizationScreenshotSets(ctx context.Context, localizationID string, opts ...AppStoreVersionLocalizationScreenshotSetsOption) (*AppScreenshotSetsResponse, error) {
	firstPage, err := c.GetAppStoreVersionLocalizationScreenshotSets(ctx, localizationID, opts...)
	if err != nil {
		return nil, err
	}

	result, err := paginateAssetResponse(ctx, firstPage, func(ctx context.Context, nextURL string) (PaginatedResponse, error) {
		return c.GetAppStoreVersionLocalizationScreenshotSets(ctx, "", WithAppStoreVersionLocalizationScreenshotSetsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetAllAppCustomProductPageLocalizationScreenshotSets retrieves every
// screenshot set for a custom product page localization.
func (c *Client) GetAllAppCustomProductPageLocalizationScreenshotSets(ctx context.Context, localizationID string, opts ...AppCustomProductPageLocalizationScreenshotSetsOption) (*AppScreenshotSetsResponse, error) {
	firstPage, err := c.GetAppCustomProductPageLocalizationScreenshotSets(ctx, localizationID, opts...)
	if err != nil {
		return nil, err
	}

	result, err := paginateAssetResponse(ctx, firstPage, func(ctx context.Context, nextURL string) (PaginatedResponse, error) {
		return c.GetAppCustomProductPageLocalizationScreenshotSets(ctx, "", WithAppCustomProductPageLocalizationScreenshotSetsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetAllAppStoreVersionExperimentTreatmentLocalizationScreenshotSets retrieves
// every screenshot set for an experiment treatment localization.
func (c *Client) GetAllAppStoreVersionExperimentTreatmentLocalizationScreenshotSets(ctx context.Context, localizationID string, opts ...AppStoreVersionExperimentTreatmentLocalizationScreenshotSetsOption) (*AppScreenshotSetsResponse, error) {
	firstPage, err := c.GetAppStoreVersionExperimentTreatmentLocalizationScreenshotSets(ctx, localizationID, opts...)
	if err != nil {
		return nil, err
	}

	result, err := paginateAssetResponse(ctx, firstPage, func(ctx context.Context, nextURL string) (PaginatedResponse, error) {
		return c.GetAppStoreVersionExperimentTreatmentLocalizationScreenshotSets(ctx, "", WithAppStoreVersionExperimentTreatmentLocalizationScreenshotSetsNextURL(nextURL))
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
