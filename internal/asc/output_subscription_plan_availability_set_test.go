package asc

import (
	"strings"
	"testing"
)

func TestSubscriptionPlanAvailabilitySetSummaryRows(t *testing.T) {
	availableInNew := true
	result := &SubscriptionPlanAvailabilitySetResult{
		SubscriptionID:            "sub-1",
		PlanAvailabilityID:        "plan-1",
		PlanType:                  "UPFRONT",
		Changed:                   true,
		AvailableInNewTerritories: &availableInNew,
		AddedTerritories:          []string{"CAN"},
		RemovedTerritories:        []string{"DEU"},
		UnchangedTerritories:      []string{"USA"},
		AvailableTerritories:      []string{"CAN", "USA"},
	}

	headers, rows := subscriptionPlanAvailabilitySetSummaryRows(result)
	if len(headers) != 10 || len(rows) != 1 || len(rows[0]) != len(headers) {
		t.Fatalf("unexpected summary shape: headers=%v rows=%v", headers, rows)
	}
	if rows[0][3] != "true" || rows[0][4] != "false" || rows[0][5] != "true" {
		t.Fatalf("unexpected changed/created/availableInNewTerritories cells: %v", rows[0])
	}
	if rows[0][9] != "2" {
		t.Fatalf("expected 2 available territories, got %q", rows[0][9])
	}
}

func TestSubscriptionPlanAvailabilitySetTerritoryRowsSkipEmptyGroups(t *testing.T) {
	result := &SubscriptionPlanAvailabilitySetResult{
		AddedTerritories:    []string{"CAN"},
		ExcludedTerritories: []string{"USA"},
	}

	_, rows := subscriptionPlanAvailabilitySetTerritoryRows(result)
	if len(rows) != 2 {
		t.Fatalf("expected only the non-empty groups, got %v", rows)
	}
	if rows[0][0] != "added" || rows[1][0] != "excluded" {
		t.Fatalf("unexpected group ordering: %v", rows)
	}
}

func TestFormatSubscriptionPlanAvailabilityTerritoryCellSummarizesLongLists(t *testing.T) {
	territories := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		territories = append(territories, "T"+strings.Repeat("X", i%3))
	}

	cell := formatSubscriptionPlanAvailabilityTerritoryCell(territories)
	if !strings.HasSuffix(cell, "(+5 more)") {
		t.Fatalf("expected the remainder to be summarized, got %q", cell)
	}
	if got := strings.Count(cell, ","); got != 19 {
		t.Fatalf("expected 20 listed territories, got %d separators in %q", got, cell)
	}
	if short := formatSubscriptionPlanAvailabilityTerritoryCell([]string{"USA", "CAN"}); short != "USA,CAN" {
		t.Fatalf("expected short lists to render verbatim, got %q", short)
	}
}
