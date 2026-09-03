package asc

import (
	"encoding/json"
	"fmt"
	"strings"
)

func subscriptionPlanAvailabilitiesRows(resp *SubscriptionPlanAvailabilitiesResponse) ([]string, [][]string) {
	headers := []string{"ID", "Plan Type", "Available In New Territories", "Territories"}
	rows := make([][]string, 0, len(resp.Data))
	for _, item := range resp.Data {
		territoryIDs, total, totalKnown := SubscriptionPlanAvailabilityIncludedTerritories(item.Relationships)
		rows = append(rows, []string{
			item.ID,
			string(item.Attributes.PlanType),
			formatOptionalSubscriptionBool(item.Attributes.AvailableInNewTerritories),
			formatPlanAvailabilityShowTerritoryCell(territoryIDs, total, totalKnown),
		})
	}
	return headers, rows
}

// SubscriptionPlanAvailabilityIncludedTerritories extracts included available
// territory IDs and the relationship paging total from a plan availability
// resource. totalKnown is false when paging metadata is absent.
func SubscriptionPlanAvailabilityIncludedTerritories(raw json.RawMessage) (ids []string, total int, totalKnown bool) {
	if len(raw) == 0 {
		return nil, 0, false
	}
	var relationships SubscriptionPlanAvailabilityRelationships
	if err := json.Unmarshal(raw, &relationships); err != nil || relationships.AvailableTerritories == nil {
		return nil, 0, false
	}
	ids = make([]string, 0, len(relationships.AvailableTerritories.Data))
	for _, item := range relationships.AvailableTerritories.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	total, totalKnown = ParsePagingTotalOK(relationships.AvailableTerritories.Meta)
	if !totalKnown {
		total = len(ids)
	}
	return ids, total, totalKnown
}

func formatPlanAvailabilityShowTerritoryCell(ids []string, total int, totalKnown bool) string {
	cell := formatSubscriptionPlanAvailabilityTerritoryCell(ids)
	if totalKnown && total > len(ids) {
		remainder := total - len(ids)
		if cell == "" {
			return fmt.Sprintf("(+%d more)", remainder)
		}
		return fmt.Sprintf("%s (+%d more)", cell, remainder)
	}
	return cell
}

func formatOptionalSubscriptionBool(value *bool) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%t", *value)
}
