package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// lastCompatibleVersionFields mirrors the sparse fieldset App Store Connect's
// own Last-Compatible Version Settings screen requests for appStoreVersions.
const lastCompatibleVersionFields = "appStoreState,appVersionState,platform,versionString,downloadable,createdDate,distributions,reviewType"

// lastCompatibleVersionLimit mirrors the appStoreVersions limit App Store
// Connect requests for the same screen.
const lastCompatibleVersionLimit = "2000"

// AppLastCompatibleVersions lists per-version download availability for an app.
type AppLastCompatibleVersions struct {
	AppID    string                     `json:"appId"`
	Name     string                     `json:"name,omitempty"`
	BundleID string                     `json:"bundleId,omitempty"`
	Versions []AppLastCompatibleVersion `json:"versions"`
}

// AppLastCompatibleVersion describes one app store version's download availability.
type AppLastCompatibleVersion struct {
	ID              string `json:"id"`
	VersionString   string `json:"versionString,omitempty"`
	Platform        string `json:"platform,omitempty"`
	AppStoreState   string `json:"appStoreState,omitempty"`
	AppVersionState string `json:"appVersionState,omitempty"`
	ReviewType      string `json:"reviewType,omitempty"`
	CreatedDate     string `json:"createdDate,omitempty"`
	Downloadable    *bool  `json:"downloadable,omitempty"`
}

// GetAppLastCompatibleVersions reads per-version download availability, the
// setting App Store Connect exposes as Last-Compatible Version Settings.
//
// The public App Store Connect API does not expose the appStoreVersions
// downloadable attribute, so this reads the internal app resource.
func (c *Client) GetAppLastCompatibleVersions(ctx context.Context, appID string) (*AppLastCompatibleVersions, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, fmt.Errorf("app id is required")
	}

	query := url.Values{}
	query.Set("include", "appStoreVersions")
	query.Set("fields[appStoreVersions]", lastCompatibleVersionFields)
	query.Set("limit[appStoreVersions]", lastCompatibleVersionLimit)
	path := "/apps/" + url.PathEscape(appID) + "?" + query.Encode()

	responseBody, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Data     jsonAPIResource   `json:"data"`
		Included []jsonAPIResource `json:"included"`
	}
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse last compatible version response: %w", err)
	}

	result := &AppLastCompatibleVersions{
		AppID:    strings.TrimSpace(payload.Data.ID),
		Name:     stringAttr(payload.Data.Attributes, "name"),
		BundleID: stringAttr(payload.Data.Attributes, "bundleId"),
		Versions: make([]AppLastCompatibleVersion, 0),
	}
	if result.AppID == "" {
		result.AppID = appID
	}

	for _, ref := range relationshipRefs(payload.Data, "appStoreVersions") {
		version := AppLastCompatibleVersion{ID: strings.TrimSpace(ref.ID)}
		if resource := findIncludedResource(payload.Included, ref); resource != nil {
			version.VersionString = stringAttr(resource.Attributes, "versionString")
			version.Platform = stringAttr(resource.Attributes, "platform")
			version.AppStoreState = stringAttr(resource.Attributes, "appStoreState")
			version.AppVersionState = stringAttr(resource.Attributes, "appVersionState")
			version.ReviewType = stringAttr(resource.Attributes, "reviewType")
			version.CreatedDate = stringAttr(resource.Attributes, "createdDate")
			version.Downloadable = boolAttrPtr(resource.Attributes, "downloadable")
		}
		result.Versions = append(result.Versions, version)
	}

	return result, nil
}
