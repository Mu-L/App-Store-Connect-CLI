package app_events

import (
	"fmt"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

func normalizeAppEventStates(value string) ([]string, error) {
	values := shared.SplitCSVUpper(value)
	if len(values) == 0 {
		return nil, nil
	}
	for _, value := range values {
		if !containsString(appEventStateList(), value) {
			return nil, fmt.Errorf("--event-state must be one of: %s", strings.Join(appEventStateList(), ", "))
		}
	}
	return values, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func appEventStateList() []string {
	return []string{
		"DRAFT",
		"READY_FOR_REVIEW",
		"WAITING_FOR_REVIEW",
		"IN_REVIEW",
		"REJECTED",
		"ACCEPTED",
		"APPROVED",
		"PUBLISHED",
		"PAST",
		"ARCHIVED",
	}
}

func appEventFieldsList() []string {
	return []string{
		"referenceName",
		"badge",
		"eventState",
		"deepLink",
		"purchaseRequirement",
		"primaryLocale",
		"priority",
		"purpose",
		"territorySchedules",
		"archivedTerritorySchedules",
		"localizations",
	}
}

func appEventLocalizationFieldsList() []string {
	return []string{
		"locale",
		"name",
		"shortDescription",
		"longDescription",
		"appEvent",
		"appEventScreenshots",
		"appEventVideoClips",
	}
}

func appEventIncludeList() []string {
	return []string{"localizations"}
}
