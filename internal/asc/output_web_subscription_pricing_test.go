package asc

import "testing"

func TestWebSubscriptionMonthlyCommitmentBootstrapRows(t *testing.T) {
	headers, rows := webSubscriptionMonthlyCommitmentBootstrapRows(&WebSubscriptionMonthlyCommitmentBootstrapResult{
		SubscriptionID:      "sub-1",
		Territory:           "NOR",
		PlanAvailabilityID:  "plan-monthly",
		PlanAvailabilityNew: true,
		PricesCreated:       true,
		Verified:            true,
		CompletedStage:      WebMonthlyCommitmentStageVerified,
	})
	if len(headers) != 7 || len(rows) != 1 {
		t.Fatalf("headers=%d rows=%d", len(headers), len(rows))
	}
	if rows[0][0] != "sub-1" || rows[0][5] != "true" || rows[0][6] != WebMonthlyCommitmentStageVerified {
		t.Fatalf("unexpected row: %#v", rows[0])
	}
}
