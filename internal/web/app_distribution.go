package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

const (
	// AppDistributionTypeAppStore is Apple's public App Store distribution value.
	AppDistributionTypeAppStore = "APP_STORE"
	// AppDistributionTypeCustom is Apple's private custom-app distribution value.
	AppDistributionTypeCustom = "CUSTOM"
	// AppDistributionTypeDirectURL is Apple's unlisted/direct URL value. The
	// distribution setter refuses to change this read-only flow.
	AppDistributionTypeDirectURL = "DIRECT_URL"

	// AppDistributionEducationDiscounted enables the education discount.
	AppDistributionEducationDiscounted = "DISCOUNTED"
	// AppDistributionEducationNotDiscounted disables the education discount.
	AppDistributionEducationNotDiscounted = "NOT_DISCOUNTED"
	// AppDistributionEducationNotApplicable is Apple's custom-app value.
	AppDistributionEducationNotApplicable = "NOT_APPLICABLE"
)

// AppDistribution captures the app-level distribution method attributes that
// App Store Connect exposes only through the internal web API.
type AppDistribution struct {
	AppID                 string `json:"appId"`
	Name                  string `json:"name,omitempty"`
	BundleID              string `json:"bundleId,omitempty"`
	DistributionType      string `json:"distributionType,omitempty"`
	EducationDiscountType string `json:"educationDiscountType,omitempty"`
}

// AppDistributionSetRequest describes one app-level distribution update.
// DistributionType must be APP_STORE or CUSTOM. For APP_STORE, an empty
// EducationDiscountType preserves the current DISCOUNTED or NOT_DISCOUNTED
// value returned by the preflight read. CUSTOM always uses NOT_APPLICABLE.
type AppDistributionSetRequest struct {
	AppID                 string
	DistributionType      string
	EducationDiscountType string
}

// AppDistributionUnverifiedError reports a distribution write whose provider
// outcome could not be established. Callers should inspect the returned
// receipt and verify the app before retrying.
type AppDistributionUnverifiedError struct {
	Err error
}

func (e *AppDistributionUnverifiedError) Error() string {
	if e == nil || e.Err == nil {
		return "app distribution update outcome is uncertain"
	}
	return e.Err.Error()
}

func (e *AppDistributionUnverifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// GetAppDistribution retrieves the app-level distribution method settings.
//
// The public App Store Connect API does not expose distributionType, so this
// reads the internal apps resource, which returns the attribute verbatim.
func (c *Client) GetAppDistribution(ctx context.Context, appID string) (*AppDistribution, error) {
	return c.getAppDistribution(ctx, appID, false)
}

func (c *Client) getAppDistribution(ctx context.Context, appID string, includeFields bool) (*AppDistribution, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, fmt.Errorf("app id is required")
	}

	path := "/apps/" + url.PathEscape(appID)
	if includeFields {
		path += "?fields[apps]=distributionType,educationDiscountType"
	}
	responseBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Data jsonAPIResource `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse app distribution response: %w", err)
	}

	result := &AppDistribution{
		AppID:                 strings.TrimSpace(payload.Data.ID),
		Name:                  stringAttr(payload.Data.Attributes, "name"),
		BundleID:              stringAttr(payload.Data.Attributes, "bundleId"),
		DistributionType:      stringAttr(payload.Data.Attributes, "distributionType"),
		EducationDiscountType: stringAttr(payload.Data.Attributes, "educationDiscountType"),
	}
	if result.AppID == "" {
		result.AppID = appID
	}
	return result, nil
}

// SetAppDistribution updates the app-level distribution method and verifies
// both resulting attributes with a follow-up read. It never changes custom
// organization or user rows. Ambiguous PATCH failures are read back once and
// returned with an uncertain receipt; no retry is attempted.
func (c *Client) SetAppDistribution(ctx context.Context, request AppDistributionSetRequest) (*asc.WebAppDistributionSetResult, error) {
	appID := strings.TrimSpace(request.AppID)
	if appID == "" {
		return nil, fmt.Errorf("app id is required")
	}

	distributionType := strings.ToUpper(strings.TrimSpace(request.DistributionType))
	switch distributionType {
	case AppDistributionTypeAppStore, AppDistributionTypeCustom:
	default:
		return nil, fmt.Errorf("distribution type must be %s or %s", AppDistributionTypeAppStore, AppDistributionTypeCustom)
	}

	educationDiscountType := strings.ToUpper(strings.TrimSpace(request.EducationDiscountType))
	if educationDiscountType != "" {
		switch educationDiscountType {
		case AppDistributionEducationDiscounted, AppDistributionEducationNotDiscounted, AppDistributionEducationNotApplicable:
		default:
			return nil, fmt.Errorf("education discount type must be %s, %s, or %s", AppDistributionEducationDiscounted, AppDistributionEducationNotDiscounted, AppDistributionEducationNotApplicable)
		}
	}
	if distributionType == AppDistributionTypeCustom {
		if educationDiscountType != "" && educationDiscountType != AppDistributionEducationNotApplicable {
			return nil, fmt.Errorf("custom distribution requires education discount type %s", AppDistributionEducationNotApplicable)
		}
		educationDiscountType = AppDistributionEducationNotApplicable
	} else if educationDiscountType == AppDistributionEducationNotApplicable {
		return nil, fmt.Errorf("public distribution requires education discount type %s or %s", AppDistributionEducationDiscounted, AppDistributionEducationNotDiscounted)
	}

	current, err := c.getAppDistribution(ctx, appID, true)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, fmt.Errorf("cannot safely update app distribution: missing preflight response")
	}

	currentDistributionType := strings.ToUpper(strings.TrimSpace(current.DistributionType))
	switch currentDistributionType {
	case AppDistributionTypeAppStore, AppDistributionTypeCustom:
	case AppDistributionTypeDirectURL:
		return nil, fmt.Errorf("cannot change DIRECT_URL distribution through this command; use the unlisted distribution flow")
	default:
		return nil, fmt.Errorf("cannot safely update app distribution: Apple returned unsupported distribution type %q", current.DistributionType)
	}

	if distributionType == AppDistributionTypeAppStore && educationDiscountType == "" {
		educationDiscountType = strings.ToUpper(strings.TrimSpace(current.EducationDiscountType))
		if educationDiscountType != AppDistributionEducationDiscounted && educationDiscountType != AppDistributionEducationNotDiscounted {
			return nil, fmt.Errorf("public distribution requires --education-discount when the current education discount type is unavailable")
		}
	}

	result := &asc.WebAppDistributionSetResult{
		AppID:                 appID,
		DistributionType:      distributionType,
		EducationDiscountType: educationDiscountType,
		Changed:               false,
		Verified:              true,
		Status:                "unchanged",
	}
	if currentDistributionType == distributionType && strings.EqualFold(strings.TrimSpace(current.EducationDiscountType), educationDiscountType) {
		return result, nil
	}

	attributes := map[string]string{
		"educationDiscountType": educationDiscountType,
	}
	if currentDistributionType != distributionType {
		attributes["distributionType"] = distributionType
	}
	payload := struct {
		Data struct {
			ID         string            `json:"id"`
			Type       string            `json:"type"`
			Attributes map[string]string `json:"attributes"`
		} `json:"data"`
	}{}
	payload.Data.ID = appID
	payload.Data.Type = "apps"
	payload.Data.Attributes = attributes

	result.Changed = true
	result.Verified = false
	result.Status = "uncertain"
	_, writeErr := c.doRequest(ctx, http.MethodPatch, "/apps/"+url.PathEscape(appID), payload)
	if writeErr != nil {
		if !isAmbiguousAppDistributionWriteFailure(writeErr) {
			return nil, writeErr
		}
		if ctx != nil && ctx.Err() != nil {
			return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("%w; verification unavailable because command context expired/canceled; inspect state before retry: %w", writeErr, ctx.Err())}
		}
		observed, verifyErr := c.getAppDistribution(ctx, appID, true)
		if verifyErr != nil {
			return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("%w; the update may have been applied but verification also failed: %w", writeErr, verifyErr)}
		}
		result.Verified = appDistributionMatches(observed, distributionType, educationDiscountType)
		if result.Verified {
			return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("%w; follow-up read reports the requested state, but the PATCH result is uncertain", writeErr)}
		}
		return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("%w; follow-up read does not report the requested state", writeErr)}
	}

	if ctx != nil && ctx.Err() != nil {
		return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("app distribution update was accepted by Apple; verification unavailable because command context expired/canceled; inspect state before retry: %w", ctx.Err())}
	}
	observed, verifyErr := c.getAppDistribution(ctx, appID, true)
	if verifyErr != nil {
		return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("app distribution update was accepted by Apple but verification failed: %w", verifyErr)}
	}
	if !appDistributionMatches(observed, distributionType, educationDiscountType) {
		return result, &AppDistributionUnverifiedError{Err: fmt.Errorf("app distribution update was accepted by Apple but app %q does not report the requested distribution state", appID)}
	}
	result.Verified = true
	result.Status = "verified"
	return result, nil
}

func appDistributionMatches(observed *AppDistribution, distributionType, educationDiscountType string) bool {
	if observed == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(observed.DistributionType), distributionType) &&
		strings.EqualFold(strings.TrimSpace(observed.EducationDiscountType), educationDiscountType)
}

func isAmbiguousAppDistributionWriteFailure(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status >= http.StatusInternalServerError
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}
