package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
)

const (
	developerPortalLegacyPath        = "/services-account/QH65B2"
	developerAppGroupsListPath       = "/account/ios/identifiers/listApplicationGroups.action"
	developerAppGroupsCreatePath     = "/account/ios/identifiers/addApplicationGroup.action"
	developerAppGroupsDeletePath     = "/account/ios/identifiers/deleteApplicationGroup.action"
	developerAppGroupsPageSize       = 500
	developerAppGroupsCapabilityType = "APP_GROUPS"
	developerBundleIDsListPageSize   = 200
	developerBundleIDsListMaxPages   = 100
)

var developerBundleIDsListIncludes = []string{
	"bundleIdCapabilities",
	"bundleIdCapabilities.capability",
	"bundleIdCapabilities.appGroups",
}

// DeveloperAppGroup is an App Group identifier returned by Apple Developer Portal.
type DeveloperAppGroup struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	Prefix     string `json:"prefix,omitempty"`
	Status     string `json:"status,omitempty"`
}

// DeveloperAppGroupsListResult contains App Groups visible to the selected team.
type DeveloperAppGroupsListResult struct {
	Data []DeveloperAppGroup `json:"data"`
}

// DeveloperAppGroupsListOptions controls App Group list pagination.
type DeveloperAppGroupsListOptions struct {
	Paginate bool
}

// DeveloperAppGroupCreateRequest registers an App Group identifier.
type DeveloperAppGroupCreateRequest struct {
	Name       string
	Identifier string
}

// DeveloperAppGroupAssignRequest associates an App Group with a Bundle ID.
type DeveloperAppGroupAssignRequest struct {
	BundleID string
	GroupID  string
}

// DeveloperAppGroupAssignResult summarizes an App Group assignment.
type DeveloperAppGroupAssignResult struct {
	BundleID string `json:"bundleId"`
	GroupID  string `json:"groupId"`
	Changed  bool   `json:"changed"`
	Status   string `json:"status"`
}

// DeveloperAppGroupUnassignRequest removes one App Group from a Bundle ID.
type DeveloperAppGroupUnassignRequest struct {
	BundleID string
	GroupID  string
}

// DeveloperAppGroupSetRequest replaces a Bundle ID's complete App Group set.
type DeveloperAppGroupSetRequest struct {
	BundleID string
	GroupIDs []string
}

// DeveloperAppGroupDeleteRequest deletes an App Group registration.
type DeveloperAppGroupDeleteRequest struct {
	GroupID string
}

// DeveloperAppGroupAssignment names a Bundle ID that references an App Group.
type DeveloperAppGroupAssignment struct {
	BundleID   string `json:"bundleId"`
	Identifier string `json:"identifier,omitempty"`
	Name       string `json:"name,omitempty"`
}

// DeveloperAppGroupInUseError is returned when a delete is refused because the
// App Group is still referenced by at least one Bundle ID.
type DeveloperAppGroupInUseError struct {
	GroupID     string
	Identifier  string
	Assignments []DeveloperAppGroupAssignment
}

func (e *DeveloperAppGroupInUseError) Error() string {
	group := e.GroupID
	if e.Identifier != "" {
		group = fmt.Sprintf("%s (%s)", e.GroupID, e.Identifier)
	}
	names := make([]string, 0, len(e.Assignments))
	for _, assignment := range e.Assignments {
		label := assignment.Identifier
		if label == "" {
			label = assignment.Name
		}
		if label == "" {
			names = append(names, assignment.BundleID)
			continue
		}
		names = append(names, fmt.Sprintf("%s (%s)", label, assignment.BundleID))
	}
	noun := "Bundle IDs"
	if len(e.Assignments) == 1 {
		noun = "Bundle ID"
	}
	return fmt.Sprintf("App Group %s is still assigned to %d %s: %s; run 'asc web app-groups unassign --bundle-id BUNDLE_RESOURCE_ID --group-id %s --confirm' for each Bundle ID before deleting",
		group, len(e.Assignments), noun, strings.Join(names, ", "), e.GroupID)
}

// developerAppGroupsState is the raw APP_GROUPS capability state of a Bundle
// ID. GroupIDs lists every group in the relationship data even when Apple
// reports the capability disabled, because the Developer Portal still treats
// those groups as referenced (and refuses to delete them).
type developerAppGroupsState struct {
	Enabled  bool
	GroupIDs []string
}

func (s developerAppGroupsState) matches(enabled bool, groupIDs []string) bool {
	return s.Enabled == enabled && len(differenceStrings(groupIDs, s.GroupIDs)) == 0 && len(differenceStrings(s.GroupIDs, groupIDs)) == 0
}

type developerBundleIDListResponse struct {
	Data     []developerResource `json:"data"`
	Included []developerResource `json:"included"`
	Links    struct {
		Next string `json:"next"`
	} `json:"links"`
}

type developerPortalLegacyResponse struct {
	ResultCode   *int   `json:"resultCode"`
	ResultString string `json:"resultString"`
	UserString   string `json:"userString"`
	RequestID    string `json:"requestId"`
}

type developerAppGroupPayload struct {
	Name             string `json:"name"`
	Prefix           string `json:"prefix"`
	Identifier       string `json:"identifier"`
	Status           string `json:"status"`
	ApplicationGroup string `json:"applicationGroup"`
}

type developerAppGroupsListResponse struct {
	developerPortalLegacyResponse
	PageNumber           int                        `json:"pageNumber"`
	PageSize             int                        `json:"pageSize"`
	TotalRecords         int                        `json:"totalRecords"`
	ApplicationGroupList []developerAppGroupPayload `json:"applicationGroupList"`
}

type developerAppGroupCreateResponse struct {
	developerPortalLegacyResponse
	ApplicationGroup developerAppGroupPayload `json:"applicationGroup"`
}

// ListDeveloperAppGroups lists App Groups through the selected Developer Portal team.
func (c *Client) ListDeveloperAppGroups(ctx context.Context, options DeveloperAppGroupsListOptions) (*DeveloperAppGroupsListResult, error) {
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return nil, fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}
	return c.listDeveloperAppGroupPages(ctx, teamID, options.Paginate)
}

func (c *Client) listDeveloperAppGroupPages(ctx context.Context, teamID string, paginate bool) (*DeveloperAppGroupsListResult, error) {
	result := &DeveloperAppGroupsListResult{Data: []DeveloperAppGroup{}}
	for pageNumber := 1; ; pageNumber++ {
		body, err := c.doDeveloperPortalLegacyFormRequest(ctx, developerAppGroupsListPath, url.Values{
			"teamId":     {teamID},
			"pageNumber": {strconv.Itoa(pageNumber)},
			"pageSize":   {strconv.Itoa(developerAppGroupsPageSize)},
			"sort":       {"name=asc"},
		}, false)
		if err != nil {
			return nil, err
		}

		var page developerAppGroupsListResponse
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("failed to parse Developer Portal App Groups response: %w", err)
		}
		if err := validateDeveloperPortalLegacyResponse(page.developerPortalLegacyResponse); err != nil {
			return nil, err
		}
		for _, group := range page.ApplicationGroupList {
			decoded, err := decodeDeveloperAppGroup(group)
			if err != nil {
				return nil, err
			}
			result.Data = append(result.Data, decoded)
		}

		if !paginate || len(page.ApplicationGroupList) == 0 || page.TotalRecords <= len(result.Data) {
			break
		}
	}
	return result, nil
}

// DeleteDeveloperAppGroup deletes an App Group registration. It fails closed
// when the group is still referenced by any Bundle ID and verifies the deletion
// by re-reading the team's App Group list.
func (c *Client) DeleteDeveloperAppGroup(ctx context.Context, request DeveloperAppGroupDeleteRequest) (*asc.WebAppGroupDeleteResult, error) {
	request.GroupID = strings.TrimSpace(request.GroupID)
	if request.GroupID == "" {
		return nil, fmt.Errorf("group id is required")
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return nil, fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}

	groups, err := c.listDeveloperAppGroupPages(ctx, teamID, true)
	if err != nil {
		return nil, err
	}
	group, found := findDeveloperAppGroup(groups, request.GroupID)
	if !found {
		return nil, fmt.Errorf("app group %q not found in the selected Developer Portal team", request.GroupID)
	}

	assignments, err := c.listDeveloperAppGroupAssignments(ctx, request.GroupID)
	if err != nil {
		return nil, err
	}
	if len(assignments) > 0 {
		return nil, &DeveloperAppGroupInUseError{GroupID: group.ID, Identifier: group.Identifier, Assignments: assignments}
	}

	if err := c.primeDeveloperAppGroupCSRF(ctx); err != nil {
		return nil, err
	}
	body, err := c.doDeveloperPortalLegacyFormRequest(ctx, developerAppGroupsDeletePath, url.Values{
		"teamId":           {teamID},
		"applicationGroup": {request.GroupID},
	}, true)
	if err != nil {
		return nil, err
	}
	var response developerPortalLegacyResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse Developer Portal App Group delete response: %w", err)
	}
	if err := validateDeveloperPortalLegacyResponse(response); err != nil {
		return nil, err
	}

	remaining, err := c.listDeveloperAppGroupPages(ctx, teamID, true)
	if err != nil {
		return nil, fmt.Errorf("developer portal accepted the delete but verification failed: %w", err)
	}
	if _, stillListed := findDeveloperAppGroup(remaining, request.GroupID); stillListed {
		return nil, fmt.Errorf("developer portal accepted the delete but App Group %q is still listed; re-run 'asc web app-groups list' before retrying", request.GroupID)
	}
	return &asc.WebAppGroupDeleteResult{
		GroupID:    group.ID,
		Identifier: group.Identifier,
		Name:       group.Name,
		Deleted:    true,
		Status:     "deleted",
	}, nil
}

func findDeveloperAppGroup(result *DeveloperAppGroupsListResult, groupID string) (DeveloperAppGroup, bool) {
	if result == nil {
		return DeveloperAppGroup{}, false
	}
	for _, group := range result.Data {
		if group.ID == groupID {
			return group, true
		}
	}
	return DeveloperAppGroup{}, false
}

// listDeveloperAppGroupAssignments walks every Bundle ID in the selected team
// and returns the ones whose APP_GROUPS capability references groupID. Any
// Bundle ID whose capability graph cannot be resolved is an error so callers
// never treat an unreadable graph as "unassigned".
func (c *Client) listDeveloperAppGroupAssignments(ctx context.Context, groupID string) ([]DeveloperAppGroupAssignment, error) {
	query := make(url.Values)
	query.Set("fields[bundleIds]", "name,identifier,platform")
	query.Set("include", strings.Join(developerBundleIDsListIncludes, ","))
	query.Set("limit", strconv.Itoa(developerBundleIDsListPageSize))

	assignments := []DeveloperAppGroupAssignment{}
	seenNext := make(map[string]struct{})
	for page := 0; ; page++ {
		if page >= developerBundleIDsListMaxPages {
			return nil, fmt.Errorf("developer portal Bundle ID listing exceeded %d pages while checking App Group assignments", developerBundleIDsListMaxPages)
		}
		body, err := c.doDeveloperPortalProxyRead(ctx, "/bundleIds", query, developerPortalHeaders(""))
		if err != nil {
			return nil, err
		}
		var response developerBundleIDListResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to parse Developer Portal Bundle ID list response: %w", err)
		}
		// A missing or null collection is not an empty team; treat it as
		// unreadable so the delete preflight stays fail-closed.
		if response.Data == nil {
			return nil, fmt.Errorf("cannot determine App Group assignments: Developer Portal Bundle ID list response has no data collection")
		}
		includedByID := make(map[string]developerResource, len(response.Included))
		for _, resource := range response.Included {
			if resource.Type == "bundleIdCapabilities" && strings.TrimSpace(resource.ID) != "" {
				includedByID[resource.ID] = resource
			}
		}
		for _, bundle := range response.Data {
			if bundle.Type != "bundleIds" {
				continue
			}
			assignment, referenced, err := developerBundleIDReferencesAppGroup(bundle, includedByID, groupID)
			if err != nil {
				return nil, err
			}
			if referenced {
				assignments = append(assignments, assignment)
			}
		}

		next := strings.TrimSpace(response.Links.Next)
		if next == "" {
			break
		}
		if _, repeated := seenNext[next]; repeated {
			return nil, fmt.Errorf("developer portal Bundle ID listing repeated pagination cursor while checking App Group assignments")
		}
		seenNext[next] = struct{}{}
		nextURL, err := url.Parse(next)
		if err != nil {
			return nil, fmt.Errorf("invalid Developer Portal Bundle ID pagination link: %w", err)
		}
		// Overlay the cursor link on the original query so the include and
		// field selections survive even if Apple returns a cursor-only link.
		for key, values := range nextURL.Query() {
			query[key] = values
		}
	}
	return assignments, nil
}

func developerBundleIDReferencesAppGroup(bundle developerResource, includedByID map[string]developerResource, groupID string) (DeveloperAppGroupAssignment, bool, error) {
	assignment := DeveloperAppGroupAssignment{BundleID: strings.TrimSpace(bundle.ID)}
	if len(bundle.Attributes) > 0 {
		var attributes struct {
			Name       string `json:"name"`
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(bundle.Attributes, &attributes); err != nil {
			return assignment, false, fmt.Errorf("failed to parse Bundle ID %q attributes: %w", bundle.ID, err)
		}
		assignment.Name = strings.TrimSpace(attributes.Name)
		assignment.Identifier = strings.TrimSpace(attributes.Identifier)
	}
	label := assignment.Identifier
	if label == "" {
		label = assignment.BundleID
	}

	rawRelationship, ok := bundle.Relationships["bundleIdCapabilities"]
	if !ok {
		return assignment, false, fmt.Errorf("cannot determine App Group assignments for Bundle ID %q: Developer Portal omitted its capability relationships", label)
	}
	var relationship developerResourceRelationship
	if err := json.Unmarshal(rawRelationship, &relationship); err != nil {
		return assignment, false, fmt.Errorf("cannot determine App Group assignments for Bundle ID %q: %w", label, err)
	}
	for _, reference := range relationship.Data {
		if reference.Type != "bundleIdCapabilities" {
			continue
		}
		capability, included := includedByID[reference.ID]
		if !included {
			return assignment, false, fmt.Errorf("cannot determine App Group assignments for Bundle ID %q: capability %q missing from Developer Portal response", label, reference.ID)
		}
		capabilityID, err := developerBundleIDCapabilityID(capability)
		if err != nil {
			return assignment, false, fmt.Errorf("cannot determine App Group assignments for Bundle ID %q: %w", label, err)
		}
		if capabilityID != developerAppGroupsCapabilityType {
			continue
		}
		groups, err := developerAppGroupRelationships(capability)
		if err != nil {
			return assignment, false, fmt.Errorf("cannot determine App Group assignments for Bundle ID %q: %w", label, err)
		}
		if containsDeveloperResource(groups, "appGroups", groupID) {
			return assignment, true, nil
		}
	}
	return assignment, false, nil
}

// CreateDeveloperAppGroup registers an App Group through Developer Portal.
func (c *Client) CreateDeveloperAppGroup(ctx context.Context, request DeveloperAppGroupCreateRequest) (*DeveloperAppGroup, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Identifier = strings.TrimSpace(request.Identifier)
	if request.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := ValidateDeveloperAppGroupIdentifier(request.Identifier); err != nil {
		return nil, err
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	if err := c.primeDeveloperAppGroupCSRF(ctx); err != nil {
		return nil, err
	}
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return nil, fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}

	body, err := c.doDeveloperPortalLegacyFormRequest(ctx, developerAppGroupsCreatePath, url.Values{
		"teamId":     {teamID},
		"name":       {request.Name},
		"identifier": {request.Identifier},
	}, true)
	if err != nil {
		return nil, err
	}
	var response developerAppGroupCreateResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse Developer Portal App Group create response: %w", err)
	}
	if err := validateDeveloperPortalLegacyResponse(response.developerPortalLegacyResponse); err != nil {
		return nil, err
	}
	group, err := decodeDeveloperAppGroup(response.ApplicationGroup)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// AssignDeveloperAppGroup associates an App Group with a Bundle ID while
// preserving Apple's complete current capability graph. The result is verified
// by re-reading the Bundle ID.
func (c *Client) AssignDeveloperAppGroup(ctx context.Context, request DeveloperAppGroupAssignRequest) (*DeveloperAppGroupAssignResult, error) {
	request.BundleID = strings.TrimSpace(request.BundleID)
	request.GroupID = strings.TrimSpace(request.GroupID)
	if request.BundleID == "" {
		return nil, fmt.Errorf("bundle id is required")
	}
	if request.GroupID == "" {
		return nil, fmt.Errorf("group id is required")
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	current, err := c.loadDeveloperBundleID(ctx, request.BundleID)
	if err != nil {
		return nil, err
	}
	state, err := developerBundleIDAppGroupsState(current)
	if err != nil {
		return nil, err
	}
	if state.Enabled && slices.Contains(state.GroupIDs, request.GroupID) {
		return &DeveloperAppGroupAssignResult{BundleID: request.BundleID, GroupID: request.GroupID, Changed: false, Status: "already-assigned"}, nil
	}
	desired := append([]string{}, state.GroupIDs...)
	if !slices.Contains(desired, request.GroupID) {
		desired = append(desired, request.GroupID)
	}
	if err := c.patchDeveloperAppGroups(ctx, current, true, desired); err != nil {
		return nil, err
	}
	if err := c.verifyDeveloperAppGroups(ctx, request.BundleID, true, desired); err != nil {
		return nil, err
	}
	return &DeveloperAppGroupAssignResult{BundleID: request.BundleID, GroupID: request.GroupID, Changed: true, Status: "assigned"}, nil
}

// UnassignDeveloperAppGroup removes one App Group from a Bundle ID while
// preserving every other capability. It operates on the raw relationship data
// so a group listed under a disabled APP_GROUPS capability can still be
// cleared (the delete preflight counts such groups as in use). Removing the
// last group disables the capability; a capability Apple already reports
// disabled stays disabled. The result is verified by re-reading the Bundle ID.
func (c *Client) UnassignDeveloperAppGroup(ctx context.Context, request DeveloperAppGroupUnassignRequest) (*asc.WebAppGroupUnassignResult, error) {
	request.BundleID = strings.TrimSpace(request.BundleID)
	request.GroupID = strings.TrimSpace(request.GroupID)
	if request.BundleID == "" {
		return nil, fmt.Errorf("bundle id is required")
	}
	if request.GroupID == "" {
		return nil, fmt.Errorf("group id is required")
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	current, err := c.loadDeveloperBundleID(ctx, request.BundleID)
	if err != nil {
		return nil, err
	}
	state, err := developerBundleIDAppGroupsState(current)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(state.GroupIDs, request.GroupID) {
		return &asc.WebAppGroupUnassignResult{BundleID: request.BundleID, GroupID: request.GroupID, RemainingGroupIDs: append([]string{}, state.GroupIDs...), Changed: false, Status: "not-assigned"}, nil
	}
	desired := make([]string, 0, len(state.GroupIDs))
	for _, id := range state.GroupIDs {
		if id != request.GroupID {
			desired = append(desired, id)
		}
	}
	enabled := state.Enabled && len(desired) > 0
	if err := c.patchDeveloperAppGroups(ctx, current, enabled, desired); err != nil {
		return nil, err
	}
	if err := c.verifyDeveloperAppGroups(ctx, request.BundleID, enabled, desired); err != nil {
		return nil, err
	}
	return &asc.WebAppGroupUnassignResult{BundleID: request.BundleID, GroupID: request.GroupID, RemainingGroupIDs: desired, Changed: true, Status: "unassigned"}, nil
}

// SetDeveloperAppGroups converges a Bundle ID on exactly the requested App
// Group set, reports the added and removed groups, and skips the write when the
// current set already matches. The result is verified by re-reading the Bundle ID.
func (c *Client) SetDeveloperAppGroups(ctx context.Context, request DeveloperAppGroupSetRequest) (*asc.WebAppGroupSetResult, error) {
	request.BundleID = strings.TrimSpace(request.BundleID)
	if request.BundleID == "" {
		return nil, fmt.Errorf("bundle id is required")
	}
	desired := dedupeTrimmedStrings(request.GroupIDs)
	if len(desired) == 0 {
		return nil, fmt.Errorf("at least one group id is required")
	}
	if err := c.ensureDeveloperPortalSession(ctx); err != nil {
		return nil, err
	}
	current, err := c.loadDeveloperBundleID(ctx, request.BundleID)
	if err != nil {
		return nil, err
	}
	state, err := developerBundleIDAppGroupsState(current)
	if err != nil {
		return nil, err
	}
	added := differenceStrings(desired, state.GroupIDs)
	removed := differenceStrings(state.GroupIDs, desired)
	result := &asc.WebAppGroupSetResult{BundleID: request.BundleID, GroupIDs: desired, Added: added, Removed: removed}
	// A disabled capability that already lists the desired groups still needs a
	// write so the groups become effective.
	if state.matches(true, desired) {
		result.Changed = false
		result.Status = "unchanged"
		return result, nil
	}
	if err := c.patchDeveloperAppGroups(ctx, current, true, desired); err != nil {
		return nil, err
	}
	if err := c.verifyDeveloperAppGroups(ctx, request.BundleID, true, desired); err != nil {
		return nil, err
	}
	result.Changed = true
	result.Status = "updated"
	return result, nil
}

func (c *Client) patchDeveloperAppGroups(ctx context.Context, current developerBundleIDResponse, enabled bool, desired []string) error {
	payload, err := buildDeveloperAppGroupsPatchRequest(current, enabled, desired)
	if err != nil {
		return err
	}
	if err := c.primeDeveloperAppGroupCSRF(ctx); err != nil {
		return err
	}
	payload, err = addDeveloperPortalTeamID(payload, c.developerPortalTeamID())
	if err != nil {
		return err
	}
	bundleID := current.Data.ID
	_, err = c.doDeveloperPortalRequest(ctx, http.MethodPatch, "/bundleIds/"+url.PathEscape(bundleID), payload, developerPortalHeaders(bundleID), true)
	return err
}

func (c *Client) verifyDeveloperAppGroups(ctx context.Context, bundleID string, enabled bool, desired []string) error {
	updated, err := c.loadDeveloperBundleID(ctx, bundleID)
	if err != nil {
		return fmt.Errorf("developer portal accepted the update but verification failed: %w", err)
	}
	state, err := developerBundleIDAppGroupsState(updated)
	if err != nil {
		return fmt.Errorf("developer portal accepted the update but verification failed: %w", err)
	}
	if !state.matches(enabled, desired) {
		return fmt.Errorf("developer portal accepted the update but Bundle ID %q still reports APP_GROUPS enabled=%t with groups [%s] instead of enabled=%t with [%s]", bundleID, state.Enabled, strings.Join(state.GroupIDs, ", "), enabled, strings.Join(desired, ", "))
	}
	return nil
}

func (c *Client) primeDeveloperAppGroupCSRF(ctx context.Context) error {
	teamID := c.developerPortalTeamID()
	if teamID == "" {
		return fmt.Errorf("developer portal team is not selected; %s", developerPortalAuthHint)
	}
	c.clearDeveloperCSRFTokens()
	body, err := c.doDeveloperPortalLegacyFormRequest(ctx, developerAppGroupsListPath, url.Values{
		"teamId":     {teamID},
		"pageNumber": {"1"},
		"pageSize":   {strconv.Itoa(developerAppGroupsPageSize)},
		"sort":       {"name=asc"},
	}, false)
	if err != nil {
		return err
	}
	var response developerAppGroupsListResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse Developer Portal App Groups response while priming CSRF: %w", err)
	}
	if err := validateDeveloperPortalLegacyResponse(response.developerPortalLegacyResponse); err != nil {
		return err
	}
	csrf, csrfTS := c.developerCSRFTokens()
	if csrf == "" || csrfTS == "" {
		return fmt.Errorf("missing Developer Portal CSRF headers after App Groups lookup; %s", developerPortalAuthHint)
	}
	return nil
}

func decodeDeveloperAppGroup(payload developerAppGroupPayload) (DeveloperAppGroup, error) {
	group := DeveloperAppGroup{
		ID:         strings.TrimSpace(payload.ApplicationGroup),
		Name:       strings.TrimSpace(payload.Name),
		Identifier: strings.TrimSpace(payload.Identifier),
		Prefix:     strings.TrimSpace(payload.Prefix),
		Status:     strings.TrimSpace(payload.Status),
	}
	if group.ID == "" || group.Identifier == "" {
		return DeveloperAppGroup{}, fmt.Errorf("incomplete App Group resource returned by Developer Portal")
	}
	return group, nil
}

// ValidateDeveloperAppGroupIdentifier validates an App Group identifier before
// any Developer Portal request is attempted.
func ValidateDeveloperAppGroupIdentifier(identifier string) error {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return fmt.Errorf("identifier is required")
	}
	if !strings.HasPrefix(identifier, "group.") {
		return fmt.Errorf("identifier must start with \"group.\"")
	}
	suffix := strings.TrimPrefix(identifier, "group.")
	if suffix == "" {
		return fmt.Errorf("identifier must include a name after \"group.\"")
	}
	for _, character := range suffix {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.' {
			continue
		}
		return fmt.Errorf("identifier may contain only letters, numbers, hyphens, and periods")
	}
	return nil
}

func validateDeveloperPortalLegacyResponse(response developerPortalLegacyResponse) error {
	if response.ResultCode == nil {
		return fmt.Errorf("developer portal response is missing resultCode")
	}
	if *response.ResultCode == 0 {
		return nil
	}
	message := strings.TrimSpace(response.UserString)
	if message == "" {
		message = strings.TrimSpace(response.ResultString)
	}
	if message == "" {
		message = "unknown Developer Portal error"
	}
	if response.RequestID != "" {
		return fmt.Errorf("developer portal request failed (result code %d, request ID %s): %s", *response.ResultCode, response.RequestID, message)
	}
	return fmt.Errorf("developer portal request failed (result code %d): %s", *response.ResultCode, message)
}

func (c *Client) doDeveloperPortalLegacyFormRequest(ctx context.Context, path string, values url.Values, requireCSRF bool) ([]byte, error) {
	headers := developerPortalHeaders("")
	headers.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	csrf, csrfTS := c.developerCSRFTokens()
	if csrf != "" {
		headers.Set("csrf", csrf)
	}
	if csrfTS != "" {
		headers.Set("csrf_ts", csrfTS)
	}
	if requireCSRF && (csrf == "" || csrfTS == "") {
		return nil, fmt.Errorf("missing Developer Portal CSRF headers; %s", developerPortalAuthHint)
	}
	body, response, err := c.doDeveloperPortalHTTP(ctx, http.MethodPost, c.developerPortalOrigin()+developerPortalLegacyPath+path, values, headers)
	if err != nil {
		return nil, err
	}
	c.captureDeveloperCSRFTokens(response.Header)
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, developerPortalSessionError(response.StatusCode)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &APIError{Status: response.StatusCode, AppleRequestID: extractAppleRequestID(response.Header), rawBody: body}
	}
	return body, nil
}

// developerBundleIDAppGroupsState reads the APP_GROUPS capability of a Bundle
// ID: whether it is enabled and which groups it currently lists.
func developerBundleIDAppGroupsState(current developerBundleIDResponse) (developerAppGroupsState, error) {
	capabilities, err := developerBundleIDCapabilities(current)
	if err != nil {
		return developerAppGroupsState{}, err
	}
	state := developerAppGroupsState{GroupIDs: []string{}}
	found := false
	for _, capability := range capabilities {
		capabilityID, err := developerBundleIDCapabilityID(capability)
		if err != nil {
			return developerAppGroupsState{}, err
		}
		if capabilityID != developerAppGroupsCapabilityType {
			continue
		}
		if found {
			return developerAppGroupsState{}, fmt.Errorf("cannot safely update duplicate APP_GROUPS capability resources")
		}
		found = true
		state.Enabled, err = developerBundleIDCapabilityEnabled(capability)
		if err != nil {
			return developerAppGroupsState{}, err
		}
		groups, err := developerAppGroupRelationships(capability)
		if err != nil {
			return developerAppGroupsState{}, err
		}
		for _, group := range groups {
			state.GroupIDs = append(state.GroupIDs, group.ID)
		}
	}
	return state, nil
}

// buildDeveloperAppGroupsPatchRequest rewrites only the APP_GROUPS capability
// so it lists exactly the desired groups with the requested enabled state,
// while preserving every other capability and relationship Apple returned. A
// missing capability is only created when it should be enabled.
func buildDeveloperAppGroupsPatchRequest(current developerBundleIDResponse, enabled bool, desired []string) (developerBundleIDPatchRequest, error) {
	capabilities, err := developerBundleIDCapabilities(current)
	if err != nil {
		return developerBundleIDPatchRequest{}, err
	}
	groups := make([]developerResource, 0, len(desired))
	for _, groupID := range desired {
		groups = append(groups, developerResource{Type: "appGroups", ID: groupID})
	}

	updated := make([]developerResource, 0, len(capabilities)+1)
	foundAppGroups := false
	for _, capability := range capabilities {
		capabilityID, err := developerBundleIDCapabilityID(capability)
		if err != nil {
			return developerBundleIDPatchRequest{}, err
		}
		if capabilityID != developerAppGroupsCapabilityType {
			updated = append(updated, capability)
			continue
		}
		if foundAppGroups {
			return developerBundleIDPatchRequest{}, fmt.Errorf("cannot safely update duplicate APP_GROUPS capability resources")
		}
		foundAppGroups = true
		capability.Attributes, err = setDeveloperCapabilityEnabledValue(capability.Attributes, enabled)
		if err != nil {
			return developerBundleIDPatchRequest{}, err
		}
		if err := setDeveloperAppGroupRelationships(&capability, groups); err != nil {
			return developerBundleIDPatchRequest{}, err
		}
		updated = append(updated, capability)
	}
	if !foundAppGroups && enabled {
		capability := newDeveloperBundleIDCapability(developerAppGroupsCapabilityType)
		if err := setDeveloperAppGroupRelationships(&capability, groups); err != nil {
			return developerBundleIDPatchRequest{}, err
		}
		updated = append(updated, capability)
	}

	relationship, err := marshalDeveloperBundleIDCapabilitiesForPatch(updated)
	if err != nil {
		return developerBundleIDPatchRequest{}, err
	}
	relationships := cloneRawMessageMap(current.Data.Relationships)
	if relationships == nil {
		relationships = make(map[string]json.RawMessage)
	}
	relationships["bundleIdCapabilities"] = relationship

	var payload developerBundleIDPatchRequest
	payload.Data.ID = current.Data.ID
	payload.Data.Type = current.Data.Type
	payload.Data.Attributes = append(json.RawMessage(nil), current.Data.Attributes...)
	payload.Data.Relationships = relationships
	return payload, nil
}

func dedupeTrimmedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(result, trimmed) {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

// differenceStrings returns the values of left that are absent from right,
// preserving left's order.
func differenceStrings(left, right []string) []string {
	result := []string{}
	for _, value := range left {
		if !slices.Contains(right, value) {
			result = append(result, value)
		}
	}
	return result
}

func developerAppGroupRelationships(capability developerResource) ([]developerResource, error) {
	raw, exists := capability.Relationships["appGroups"]
	if !exists {
		return []developerResource{}, nil
	}
	var relationship developerResourceRelationship
	if err := json.Unmarshal(raw, &relationship); err != nil {
		return nil, fmt.Errorf("failed to parse current App Group relationships: %w", err)
	}
	for _, group := range relationship.Data {
		if group.Type != "appGroups" || strings.TrimSpace(group.ID) == "" {
			return nil, fmt.Errorf("invalid App Group relationship returned by Developer Portal")
		}
	}
	return relationship.Data, nil
}

func setDeveloperAppGroupRelationships(capability *developerResource, groups []developerResource) error {
	encoded, err := json.Marshal(developerResourceRelationship{Data: groups})
	if err != nil {
		return fmt.Errorf("failed to encode App Group relationships: %w", err)
	}
	if capability.Relationships == nil {
		capability.Relationships = make(map[string]json.RawMessage)
	}
	capability.Relationships["appGroups"] = encoded
	return nil
}

func containsDeveloperResource(resources []developerResource, resourceType, id string) bool {
	for _, resource := range resources {
		if resource.Type == resourceType && resource.ID == id {
			return true
		}
	}
	return false
}
