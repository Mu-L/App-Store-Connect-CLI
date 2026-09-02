package web

import (
	"context"
	"fmt"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func TestExistingMonthlyAvailabilityOnlyRejectsConfirmedMissingTerritory(t *testing.T) {
	unloaded := webcore.SubscriptionPlanAvailability{
		ID:                         "plan-monthly",
		PlanType:                   "MONTHLY",
		AvailableTerritoriesLoaded: false,
	}
	if availabilityExcludesTerritory(unloaded, "NOR") {
		t.Fatal("unloaded relationship must not be treated as confirmed missing")
	}

	capped := unloaded
	capped.AvailableTerritoriesLoaded = true
	capped.AvailableTerritories = make([]string, 200)
	for i := range capped.AvailableTerritories {
		capped.AvailableTerritories[i] = fmt.Sprintf("T%03d", i)
	}
	if availabilityExcludesTerritory(capped, "NOR") {
		t.Fatal("territory relationship at the response cap must not be treated as complete")
	}

	loaded := unloaded
	loaded.AvailableTerritoriesLoaded = true
	loaded.AvailableTerritories = []string{"DEU"}
	if !availabilityExcludesTerritory(loaded, "NOR") {
		t.Fatal("loaded relationship should confirm the territory is missing")
	}
}

func TestVerifyMonthlyCommitmentBootstrapRejectsStalePricePoints(t *testing.T) {
	origListAvailability := listWebSubscriptionPlanAvailabilitiesFn
	origListPrices := listWebSubscriptionPricesFn
	t.Cleanup(func() {
		listWebSubscriptionPlanAvailabilitiesFn = origListAvailability
		listWebSubscriptionPricesFn = origListPrices
	})

	listWebSubscriptionPlanAvailabilitiesFn = func(ctx context.Context, client *webcore.Client, subscriptionID string) ([]webcore.SubscriptionPlanAvailability, error) {
		return []webcore.SubscriptionPlanAvailability{{
			ID:                         "plan-monthly",
			PlanType:                   "MONTHLY",
			AvailableTerritories:       []string{"NOR"},
			AvailableTerritoriesLoaded: true,
		}}, nil
	}
	listWebSubscriptionPricesFn = func(ctx context.Context, client *webcore.Client, subscriptionID, territory string) ([]webcore.SubscriptionPrice, error) {
		return []webcore.SubscriptionPrice{{
			PlanType:     "UPFRONT",
			Territory:    "NOR",
			PricePointID: "stale-upfront",
		}, {
			PlanType:     "MONTHLY",
			Territory:    "NOR",
			PricePointID: "stale-monthly",
		}}, nil
	}

	err := verifyMonthlyCommitmentBootstrap(context.Background(), &webcore.Client{}, asc.WebSubscriptionMonthlyCommitmentBootstrapResult{
		SubscriptionID:      "sub-1",
		Territory:           "NOR",
		PlanAvailabilityID:  "plan-monthly",
		UpfrontPricePointID: "upfront-point",
		MonthlyPricePointID: "monthly-point",
	})
	if err == nil {
		t.Fatal("expected stale price points to fail verification")
	}
}
