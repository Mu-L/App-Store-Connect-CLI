package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/handlertest"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

func TestDeclarationToTupleSetNotCollected(t *testing.T) {
	tuples, err := declarationToTupleSet(privacyDeclarationFile{
		SchemaVersion: privacySchemaVersion,
		DataUsages: []privacyUsage{
			{
				DataProtections: []string{dataProtectionNotCollected},
			},
		},
	})
	if err != nil {
		t.Fatalf("declarationToTupleSet() error = %v", err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected one tuple, got %d", len(tuples))
	}
	wantKey := privacyTupleKey(privacyTuple{DataProtection: dataProtectionNotCollected})
	if _, ok := tuples[wantKey]; !ok {
		t.Fatalf("expected not-collected tuple key %q, got %#v", wantKey, tuples)
	}
}

func TestDeclarationToTupleSetRejectsCategoryForNotCollected(t *testing.T) {
	_, err := declarationToTupleSet(privacyDeclarationFile{
		SchemaVersion: privacySchemaVersion,
		DataUsages: []privacyUsage{
			{
				Category:        "NAME",
				DataProtections: []string{dataProtectionNotCollected},
			},
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "cannot include category") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeclarationToTupleSetRejectsCollectedWithoutPurpose(t *testing.T) {
	_, err := declarationToTupleSet(privacyDeclarationFile{
		SchemaVersion: privacySchemaVersion,
		DataUsages: []privacyUsage{
			{
				Category:        "NAME",
				DataProtections: []string{dataProtectionLinked},
			},
		},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "purposes is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeclarationToTupleSetAllowsTrackingWithoutPurpose(t *testing.T) {
	tuples, err := declarationToTupleSet(privacyDeclarationFile{
		SchemaVersion: privacySchemaVersion,
		DataUsages: []privacyUsage{
			{
				Category:        "PURCHASE_HISTORY",
				DataProtections: []string{dataProtectionTracking},
			},
		},
	})
	if err != nil {
		t.Fatalf("declarationToTupleSet() error = %v", err)
	}
	wantKey := privacyTupleKey(privacyTuple{
		Category:       "PURCHASE_HISTORY",
		Purpose:        "",
		DataProtection: dataProtectionTracking,
	})
	if _, ok := tuples[wantKey]; !ok {
		t.Fatalf("expected tracking tuple key %q, got %#v", wantKey, tuples)
	}
}

func TestDeclarationToTupleSetCanonicalizesTrackingPurposeAway(t *testing.T) {
	tuples, err := declarationToTupleSet(privacyDeclarationFile{
		SchemaVersion: privacySchemaVersion,
		DataUsages: []privacyUsage{
			{
				Category: "PURCHASE_HISTORY",
				Purposes: []string{"APP_FUNCTIONALITY"},
				DataProtections: []string{
					dataProtectionLinked,
					dataProtectionTracking,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("declarationToTupleSet() error = %v", err)
	}
	trackingCanonicalKey := privacyTupleKey(privacyTuple{
		Category:       "PURCHASE_HISTORY",
		Purpose:        "",
		DataProtection: dataProtectionTracking,
	})
	if _, ok := tuples[trackingCanonicalKey]; !ok {
		t.Fatalf("expected canonical tracking tuple key %q, got %#v", trackingCanonicalKey, tuples)
	}
	trackingWithPurposeKey := privacyTupleKey(privacyTuple{
		Category:       "PURCHASE_HISTORY",
		Purpose:        "APP_FUNCTIONALITY",
		DataProtection: dataProtectionTracking,
	})
	if _, ok := tuples[trackingWithPurposeKey]; ok {
		t.Fatalf("tracking tuple should not retain purpose; got %#v", tuples)
	}
}

func TestDeclarationToTupleSetRejectsMixedNotCollectedAndCollected(t *testing.T) {
	cases := []struct {
		name   string
		usages []privacyUsage
	}{
		{
			name: "not_collected_then_collected",
			usages: []privacyUsage{
				{DataProtections: []string{dataProtectionNotCollected}},
				{
					Category:        "NAME",
					Purposes:        []string{"APP_FUNCTIONALITY"},
					DataProtections: []string{dataProtectionLinked},
				},
			},
		},
		{
			name: "collected_then_not_collected",
			usages: []privacyUsage{
				{
					Category:        "NAME",
					Purposes:        []string{"APP_FUNCTIONALITY"},
					DataProtections: []string{dataProtectionLinked},
				},
				{DataProtections: []string{dataProtectionNotCollected}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := declarationToTupleSet(privacyDeclarationFile{
				SchemaVersion: privacySchemaVersion,
				DataUsages:    tc.usages,
			})
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), "cannot be combined") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDeclarationFromTupleSetGroupsByCategoryAndPurpose(t *testing.T) {
	declaration := declarationFromTupleSet(map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
		privacyTupleKey(privacyTuple{
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionTracking,
		}): {
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionTracking,
		},
	})

	if declaration.SchemaVersion != privacySchemaVersion {
		t.Fatalf("expected schemaVersion=%d, got %d", privacySchemaVersion, declaration.SchemaVersion)
	}
	if len(declaration.DataUsages) != 1 {
		t.Fatalf("expected one usage group, got %d", len(declaration.DataUsages))
	}
	got := declaration.DataUsages[0]
	if got.Category != "NAME" || len(got.Purposes) != 1 || got.Purposes[0] != "APP_FUNCTIONALITY" {
		t.Fatalf("unexpected grouped usage: %#v", got)
	}
	if !reflect.DeepEqual(got.DataProtections, []string{dataProtectionLinked, dataProtectionTracking}) {
		t.Fatalf("unexpected protections: %#v", got.DataProtections)
	}
}

func TestDeclarationFromRemoteDataUsagesEmptyDefaultsNotCollected(t *testing.T) {
	declaration := declarationFromRemoteDataUsages(nil)

	if declaration.SchemaVersion != privacySchemaVersion {
		t.Fatalf("expected schemaVersion=%d, got %d", privacySchemaVersion, declaration.SchemaVersion)
	}
	if len(declaration.DataUsages) != 1 {
		t.Fatalf("expected one default data usage, got %d", len(declaration.DataUsages))
	}
	if !reflect.DeepEqual(declaration.DataUsages[0].DataProtections, []string{dataProtectionNotCollected}) {
		t.Fatalf("unexpected default declaration: %#v", declaration.DataUsages[0])
	}
	if declaration.DataUsages[0].Category != "" || len(declaration.DataUsages[0].Purposes) != 0 {
		t.Fatalf("expected DATA_NOT_COLLECTED declaration with empty category/purposes, got %#v", declaration.DataUsages[0])
	}
}

func TestDeclarationFromRemoteDataUsagesKeepsNotCollectedProtection(t *testing.T) {
	usages := []webcore.AppDataUsage{
		{
			ID:             "u1",
			DataProtection: dataProtectionNotCollected,
		},
	}

	declaration := declarationFromRemoteDataUsages(usages)
	if declaration.SchemaVersion != privacySchemaVersion {
		t.Fatalf("expected schemaVersion=%d, got %d", privacySchemaVersion, declaration.SchemaVersion)
	}
	if len(declaration.DataUsages) != 1 {
		t.Fatalf("expected one data usage, got %#v", declaration.DataUsages)
	}
	got := declaration.DataUsages[0]
	if !reflect.DeepEqual(got.DataProtections, []string{dataProtectionNotCollected}) {
		t.Fatalf("expected DATA_NOT_COLLECTED to remain representable, got %#v", got)
	}
	if got.Category != "" || len(got.Purposes) != 0 {
		t.Fatalf("expected DATA_NOT_COLLECTED declaration with empty category/purposes, got %#v", got)
	}
	if count := countUnrepresentableRemoteUsages(usages); count != 0 {
		t.Fatalf("expected unrepresentableCount=0 for DATA_NOT_COLLECTED, got %d", count)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal usage: %v", err)
	}
	if string(raw) != `{"dataProtections":["DATA_NOT_COLLECTED"]}` {
		t.Fatalf("expected canonical not-collected JSON without empty category/purposes, got %s", raw)
	}
}

func TestDeclarationFromRemoteDataUsagesMalformedOnlyPreservesUnrepresentable(t *testing.T) {
	declaration := declarationFromRemoteDataUsages([]webcore.AppDataUsage{
		{
			ID:       "usage-malformed-1",
			Category: "PURCHASE_HISTORY",
			Purpose:  "APP_FUNCTIONALITY",
		},
	})

	if len(declaration.DataUsages) != 1 {
		t.Fatalf("expected one unrepresentable usage, got %#v", declaration.DataUsages)
	}
	got := declaration.DataUsages[0]
	if containsPrivacyProtection(got.DataProtections, dataProtectionNotCollected) {
		t.Fatalf("non-empty malformed remote usages must not collapse to DATA_NOT_COLLECTED: %#v", got)
	}
	if !reflect.DeepEqual(got.DataProtections, []string{dataProtectionUnknown}) {
		t.Fatalf("expected opaque %s marker, got %#v", dataProtectionUnknown, got)
	}
	if got.Category != "PURCHASE_HISTORY" {
		t.Fatalf("expected malformed category to be preserved, got %#v", got)
	}
}

func TestDeclarationFromRemoteDataUsagesPreservesMalformedWhenValidPresent(t *testing.T) {
	declaration := declarationFromRemoteDataUsages([]webcore.AppDataUsage{
		{
			ID:       "usage-malformed-1",
			Category: "PURCHASE_HISTORY",
			Purpose:  "APP_FUNCTIONALITY",
		},
		{
			ID:             "usage-valid-1",
			Category:       "PURCHASE_HISTORY",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
	})

	if len(declaration.DataUsages) != 1 {
		t.Fatalf("expected one grouped usage, got %#v", declaration.DataUsages)
	}
	got := declaration.DataUsages[0]
	if got.Category != "PURCHASE_HISTORY" {
		t.Fatalf("unexpected declaration category: %#v", got)
	}
	if containsPrivacyProtection(got.DataProtections, dataProtectionNotCollected) {
		t.Fatalf("mixed remote usages must not collapse malformed entries to DATA_NOT_COLLECTED: %#v", got)
	}
	if !reflect.DeepEqual(got.DataProtections, []string{dataProtectionLinked, dataProtectionUnknown}) {
		t.Fatalf("expected valid and unrepresentable protections, got %#v", got.DataProtections)
	}
}

func TestPlanFromDesiredAndRemoteIncludesDuplicateRemoteDeletes(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
	}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "NAME",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
			},
			UsageIDs: []string{"usage-1", "usage-2"},
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Adds) != 0 {
		t.Fatalf("expected no adds, got %#v", plan.Adds)
	}
	if len(plan.Deletes) != 1 {
		t.Fatalf("expected one duplicate delete, got %#v", plan.Deletes)
	}
	if plan.Deletes[0].UsageID != "usage-2" {
		t.Fatalf("expected usage-2 delete, got %#v", plan.Deletes[0])
	}
}

func TestPlanFromDesiredAndRemoteSkipsDeletesWithoutUsageID(t *testing.T) {
	desired := map[string]privacyTuple{}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "NAME",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "NAME",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
			},
			UsageIDs: nil,
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Deletes) != 0 {
		t.Fatalf("expected no deletes for remote tuples without usage IDs, got %#v", plan.Deletes)
	}
	if len(plan.SkippedDeletes) != 1 {
		t.Fatalf("expected one skipped delete for missing usage id, got %#v", plan.SkippedDeletes)
	}
	if plan.SkippedDeletes[0].Reason != "missing_usage_id" {
		t.Fatalf("expected missing_usage_id reason, got %#v", plan.SkippedDeletes[0])
	}
	if len(plan.APICalls) != 0 {
		t.Fatalf("expected no delete api calls for remote tuples without usage IDs, got %#v", plan.APICalls)
	}
}

func TestPlanFromDesiredAndRemoteIncludesDeleteForMalformedRemoteUsage(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "PURCHASE_HISTORY",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Category:       "PURCHASE_HISTORY",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
	}
	remote := remoteStateFromDataUsages([]webcore.AppDataUsage{
		{
			ID:             "usage-valid-1",
			Category:       "PURCHASE_HISTORY",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
		{
			ID:       "usage-malformed-1",
			Category: "PURCHASE_HISTORY",
			Purpose:  "APP_FUNCTIONALITY",
		},
	})

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Adds) != 0 || len(plan.Updates) != 0 {
		t.Fatalf("expected no adds/updates, got adds=%#v updates=%#v", plan.Adds, plan.Updates)
	}
	if len(plan.Deletes) != 1 {
		t.Fatalf("expected one delete for malformed remote usage, got %#v", plan.Deletes)
	}
	if plan.Deletes[0].UsageID != "usage-malformed-1" || plan.Deletes[0].DataProtection != dataProtectionUnknown {
		t.Fatalf("unexpected delete for malformed usage: %#v", plan.Deletes[0])
	}
	if len(plan.APICalls) != 1 || plan.APICalls[0].Operation != "delete_data_usage" || plan.APICalls[0].Count != 1 {
		t.Fatalf("unexpected api call summary: %#v", plan.APICalls)
	}
}

func TestPlanFromDesiredAndRemotePairsAddDeleteIntoUpdate(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		}): {
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		},
	}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
			},
			UsageIDs: []string{"usage-1"},
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Updates) != 1 {
		t.Fatalf("expected one update, got %#v", plan.Updates)
	}
	if len(plan.Adds) != 0 || len(plan.Deletes) != 0 {
		t.Fatalf("expected no adds/deletes after pairing, got adds=%#v deletes=%#v", plan.Adds, plan.Deletes)
	}
	if plan.Updates[0].UsageID != "usage-1" || plan.Updates[0].DataProtection != dataProtectionNotLinked {
		t.Fatalf("unexpected update payload: %#v", plan.Updates[0])
	}
	if len(plan.APICalls) != 1 || plan.APICalls[0].Operation != "update_data_usage" || plan.APICalls[0].Count != 1 {
		t.Fatalf("unexpected api calls: %#v", plan.APICalls)
	}
}

func TestPlanFromDesiredAndRemoteNotCollectedRemainsDeleteCreate(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{DataProtection: dataProtectionNotCollected}): {
			DataProtection: dataProtectionNotCollected,
		},
	}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionNotLinked,
			},
			UsageIDs: []string{"usage-1"},
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Updates) != 0 {
		t.Fatalf("expected no updates for DATA_NOT_COLLECTED transition, got %#v", plan.Updates)
	}
	if len(plan.Adds) != 1 || len(plan.Deletes) != 1 {
		t.Fatalf("expected one add and one delete, got adds=%#v deletes=%#v", plan.Adds, plan.Deletes)
	}
}

func TestPlanFromDesiredAndRemoteTrackingTransitionYieldsUpdateAndAdd(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		}): {
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		},
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionTracking,
		}): {
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionTracking,
		},
	}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
			},
			UsageIDs: []string{"usage-1"},
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Updates) != 1 {
		t.Fatalf("expected one update, got %#v", plan.Updates)
	}
	if len(plan.Adds) != 1 {
		t.Fatalf("expected one add, got %#v", plan.Adds)
	}
	if len(plan.Deletes) != 0 {
		t.Fatalf("expected no deletes, got %#v", plan.Deletes)
	}
	if plan.Updates[0].UsageID != "usage-1" {
		t.Fatalf("expected update to reuse usage-1, got %#v", plan.Updates[0])
	}
}

func TestPlanFromDesiredAndRemoteDoesNotPairTrackingDeleteIntoUpdate(t *testing.T) {
	desired := map[string]privacyTuple{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		},
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		}): {
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionNotLinked,
		},
	}
	remote := map[string]privacyRemoteState{
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionLinked,
		}): {
			Tuple: privacyTuple{
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
			},
			UsageIDs: []string{"usage-linked-1"},
		},
		privacyTupleKey(privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: dataProtectionTracking,
		}): {
			Tuple: privacyTuple{
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionTracking,
			},
			UsageIDs: []string{"usage-tracking-1"},
		},
	}

	plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)
	if len(plan.Updates) != 0 {
		t.Fatalf("expected no updates when replacing tracking tuple with identity tuple, got %#v", plan.Updates)
	}
	if len(plan.Adds) != 1 || len(plan.Deletes) != 1 {
		t.Fatalf("expected one add and one delete, got adds=%#v deletes=%#v", plan.Adds, plan.Deletes)
	}
	if plan.Deletes[0].DataProtection != dataProtectionTracking {
		t.Fatalf("expected tracking tuple delete, got %#v", plan.Deletes[0])
	}
}

type permutationCase struct {
	name         string
	protections  []string
	notCollected bool
}

func tupleSetForPermutation(tc permutationCase) map[string]privacyTuple {
	tuples := map[string]privacyTuple{}
	if tc.notCollected {
		tuple := privacyTuple{DataProtection: dataProtectionNotCollected}
		tuples[privacyTupleKey(tuple)] = tuple
		return tuples
	}
	for _, protection := range tc.protections {
		tuple := privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: protection,
		}
		tuples[privacyTupleKey(tuple)] = tuple
	}
	return tuples
}

func remoteStateForPermutation(tc permutationCase, duplicateFirst bool) map[string]privacyRemoteState {
	state := map[string]privacyRemoteState{}
	if tc.notCollected {
		tuple := privacyTuple{DataProtection: dataProtectionNotCollected}
		usageIDs := []string{"usage-not-collected-1"}
		if duplicateFirst {
			usageIDs = append(usageIDs, "usage-not-collected-2")
		}
		state[privacyTupleKey(tuple)] = privacyRemoteState{
			Tuple:    tuple,
			UsageIDs: usageIDs,
		}
		return state
	}

	for index, protection := range tc.protections {
		tuple := privacyTuple{
			Category:       "EMAIL_ADDRESS",
			Purpose:        "APP_FUNCTIONALITY",
			DataProtection: protection,
		}
		usageIDs := []string{fmt.Sprintf("usage-%s-%d-1", strings.ToLower(protection), index)}
		if duplicateFirst && index == 0 {
			usageIDs = append(usageIDs, fmt.Sprintf("usage-%s-%d-2", strings.ToLower(protection), index))
		}
		state[privacyTupleKey(tuple)] = privacyRemoteState{
			Tuple:    tuple,
			UsageIDs: usageIDs,
		}
	}
	return state
}

func simulatePlanResult(remote map[string]privacyRemoteState, plan privacyPlanOutput) (map[string]privacyTuple, error) {
	byUsageID := map[string]privacyTuple{}
	for _, state := range remote {
		for _, usageID := range state.UsageIDs {
			usageID = strings.TrimSpace(usageID)
			if usageID == "" {
				continue
			}
			byUsageID[usageID] = state.Tuple
		}
	}

	for _, deletion := range plan.Deletes {
		usageID := strings.TrimSpace(deletion.UsageID)
		if usageID == "" {
			return nil, fmt.Errorf("delete operation missing usage id")
		}
		if _, exists := byUsageID[usageID]; !exists {
			return nil, fmt.Errorf("delete operation references unknown usage id %s", usageID)
		}
		delete(byUsageID, usageID)
	}
	for _, update := range plan.Updates {
		usageID := strings.TrimSpace(update.UsageID)
		if usageID == "" {
			return nil, fmt.Errorf("update operation missing usage id")
		}
		if _, exists := byUsageID[usageID]; !exists {
			return nil, fmt.Errorf("update operation references unknown usage id %s", usageID)
		}
		byUsageID[usageID] = privacyTuple{
			Category:       update.Category,
			Purpose:        update.Purpose,
			DataProtection: update.DataProtection,
		}
	}
	nextGeneratedID := 0
	for _, add := range plan.Adds {
		nextGeneratedID++
		byUsageID[fmt.Sprintf("generated-%d", nextGeneratedID)] = privacyTuple{
			Category:       add.Category,
			Purpose:        add.Purpose,
			DataProtection: add.DataProtection,
		}
	}

	result := map[string]privacyTuple{}
	for _, tuple := range byUsageID {
		result[privacyTupleKey(tuple)] = tuple
	}
	return result, nil
}

func TestPlanFromDesiredAndRemotePermutationMatrixProducesDesiredState(t *testing.T) {
	desiredCases := []permutationCase{
		{name: "not_collected", notCollected: true},
		{name: "linked_only", protections: []string{dataProtectionLinked}},
		{name: "not_linked_only", protections: []string{dataProtectionNotLinked}},
		{name: "linked_tracking", protections: []string{dataProtectionLinked, dataProtectionTracking}},
		{name: "not_linked_tracking", protections: []string{dataProtectionNotLinked, dataProtectionTracking}},
		{name: "linked_not_linked", protections: []string{dataProtectionLinked, dataProtectionNotLinked}},
	}

	type remoteCase struct {
		permutationCase
		duplicateFirst bool
	}
	remoteCases := make([]remoteCase, 0, len(desiredCases)*2)
	for _, base := range desiredCases {
		remoteCases = append(remoteCases, remoteCase{
			permutationCase: base,
			duplicateFirst:  false,
		})
		if !base.notCollected {
			remoteCases = append(remoteCases, remoteCase{
				permutationCase: permutationCase{
					name:         base.name + "_dup_first",
					protections:  base.protections,
					notCollected: base.notCollected,
				},
				duplicateFirst: true,
			})
		}
	}

	for _, remoteTC := range remoteCases {
		for _, desiredTC := range desiredCases {
			caseName := remoteTC.name + "->" + desiredTC.name
			t.Run(caseName, func(t *testing.T) {
				desired := tupleSetForPermutation(desiredTC)
				remote := remoteStateForPermutation(remoteTC.permutationCase, remoteTC.duplicateFirst)

				plan := planFromDesiredAndRemote("123", "./privacy.json", desired, remote)

				seenUsageIDs := map[string]string{}
				for _, update := range plan.Updates {
					usageID := strings.TrimSpace(update.UsageID)
					if usageID == "" {
						t.Fatalf("update missing usage id: %#v", update)
					}
					seenUsageIDs[usageID] = "update"
				}
				for _, deletion := range plan.Deletes {
					usageID := strings.TrimSpace(deletion.UsageID)
					if usageID == "" {
						t.Fatalf("delete missing usage id: %#v", deletion)
					}
					if owner, exists := seenUsageIDs[usageID]; exists {
						t.Fatalf("usage id %s appears in both %s and delete operations", usageID, owner)
					}
					seenUsageIDs[usageID] = "delete"
				}

				if remoteTC.notCollected || desiredTC.notCollected {
					if len(plan.Updates) != 0 {
						t.Fatalf("DATA_NOT_COLLECTED transitions must not produce updates, got %#v", plan.Updates)
					}
				}

				gotState, err := simulatePlanResult(remote, plan)
				if err != nil {
					t.Fatalf("simulatePlanResult() error = %v", err)
				}
				if !reflect.DeepEqual(gotState, desired) {
					t.Fatalf("final tuple state mismatch, got=%#v want=%#v plan=%#v", gotState, desired, plan)
				}
			})
		}
	}
}

type fakePrivacyMutationClient struct {
	callOrder     []string
	createCounter int
}

func (f *fakePrivacyMutationClient) CreateAppDataUsage(_ context.Context, _ string, tuple webcore.DataUsageTuple) (*webcore.AppDataUsage, error) {
	f.createCounter++
	f.callOrder = append(f.callOrder, fmt.Sprintf("create:%s:%s:%s", tuple.Category, tuple.Purpose, tuple.DataProtection))
	return &webcore.AppDataUsage{
		ID:             fmt.Sprintf("created-%d", f.createCounter),
		Category:       tuple.Category,
		Purpose:        tuple.Purpose,
		DataProtection: tuple.DataProtection,
	}, nil
}

func (f *fakePrivacyMutationClient) UpdateAppDataUsage(_ context.Context, appDataUsageID string, tuple webcore.DataUsageTuple) (*webcore.AppDataUsage, error) {
	f.callOrder = append(f.callOrder, fmt.Sprintf("update:%s:%s", appDataUsageID, tuple.DataProtection))
	return &webcore.AppDataUsage{
		ID:             appDataUsageID,
		Category:       tuple.Category,
		Purpose:        tuple.Purpose,
		DataProtection: tuple.DataProtection,
	}, nil
}

func (f *fakePrivacyMutationClient) DeleteAppDataUsage(_ context.Context, appDataUsageID string) error {
	f.callOrder = append(f.callOrder, "delete:"+appDataUsageID)
	return nil
}

func TestApplyPrivacyPlanExecutesDeleteUpdateCreateOrder(t *testing.T) {
	client := &fakePrivacyMutationClient{}
	plan := privacyPlanOutput{
		Updates: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionNotLinked,
				UsageID:        "usage-update-1",
			},
		},
		Adds: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|ANALYTICS|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "ANALYTICS",
				DataProtection: dataProtectionNotLinked,
			},
		},
		Deletes: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
				UsageID:        "usage-delete-1",
			},
		},
	}

	actions, err := applyPrivacyPlan(context.Background(), client, "app-123", plan)
	if err != nil {
		t.Fatalf("applyPrivacyPlan() error = %v", err)
	}
	if !reflect.DeepEqual(client.callOrder, []string{
		"delete:usage-delete-1",
		"update:usage-update-1:DATA_NOT_LINKED_TO_YOU",
		"create:EMAIL_ADDRESS:ANALYTICS:DATA_NOT_LINKED_TO_YOU",
	}) {
		t.Fatalf("unexpected call order: %#v", client.callOrder)
	}
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %#v", actions)
	}
	if actions[0].Action != "delete" || actions[1].Action != "update" || actions[2].Action != "create" {
		t.Fatalf("unexpected action order: %#v", actions)
	}
}

func TestApplyPrivacyPlanRejectsUpdateWithoutUsageID(t *testing.T) {
	client := &fakePrivacyMutationClient{}
	_, err := applyPrivacyPlan(context.Background(), client, "app-123", privacyPlanOutput{
		Updates: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionNotLinked,
			},
		},
	})
	if err == nil {
		t.Fatal("expected missing usage id error")
	}
	if !strings.Contains(err.Error(), "missing usage id for update key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyPrivacyPlanRejectsConflictingDeleteAndUpdateUsageID(t *testing.T) {
	client := &fakePrivacyMutationClient{}
	_, err := applyPrivacyPlan(context.Background(), client, "app-123", privacyPlanOutput{
		Updates: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionNotLinked,
				UsageID:        "usage-1",
			},
		},
		Deletes: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionLinked,
				UsageID:        "usage-1",
			},
		},
	})
	if err == nil {
		t.Fatal("expected overlapping usage id error")
	}
	if !strings.Contains(err.Error(), "scheduled for both delete") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyPrivacyPlanRejectsDuplicateUpdateUsageID(t *testing.T) {
	client := &fakePrivacyMutationClient{}
	_, err := applyPrivacyPlan(context.Background(), client, "app-123", privacyPlanOutput{
		Updates: []privacyPlanChange{
			{
				Key:            "EMAIL_ADDRESS|APP_FUNCTIONALITY|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "APP_FUNCTIONALITY",
				DataProtection: dataProtectionNotLinked,
				UsageID:        "usage-1",
			},
			{
				Key:            "EMAIL_ADDRESS|ANALYTICS|DATA_NOT_LINKED_TO_YOU",
				Category:       "EMAIL_ADDRESS",
				Purpose:        "ANALYTICS",
				DataProtection: dataProtectionNotLinked,
				UsageID:        "usage-1",
			},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate update usage id error")
	}
	if !strings.Contains(err.Error(), "duplicate update usage id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePrivacyDeclarationFileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privacy.json")
	if err := os.WriteFile(path, []byte(`{
		"schemaVersion": 1,
		"dataUsages": [
			{
				"category": "NAME",
				"purposes": ["APP_FUNCTIONALITY"],
				"dataProtections": ["DATA_LINKED_TO_YOU"],
				"unknownField": "x"
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := parsePrivacyDeclarationFile(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePrivacyDeclarationFileRejectsMultipleJSONValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privacy.json")
	if err := os.WriteFile(path, []byte(`{
		"schemaVersion": 1,
		"dataUsages": [
			{
				"category": "NAME",
				"purposes": ["APP_FUNCTIONALITY"],
				"dataProtections": ["DATA_LINKED_TO_YOU"]
			}
		]
	}
	{
		"schemaVersion": 1,
		"dataUsages": [
			{
				"dataProtections": ["DATA_NOT_COLLECTED"]
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err := parsePrivacyDeclarationFile(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "multiple JSON values found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePrivacyDeclarationFileCanonicalizesTrackingPurposeAway(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privacy.json")
	if err := os.WriteFile(path, []byte(`{
		"schemaVersion": 1,
		"dataUsages": [
			{
				"category": "PURCHASE_HISTORY",
				"purposes": ["APP_FUNCTIONALITY"],
				"dataProtections": ["DATA_LINKED_TO_YOU", "DATA_USED_TO_TRACK_YOU"]
			}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	declaration, err := parsePrivacyDeclarationFile(path)
	if err != nil {
		t.Fatalf("parsePrivacyDeclarationFile() error = %v", err)
	}
	trackingFound := false
	for _, usage := range declaration.DataUsages {
		if len(usage.DataProtections) == 1 && usage.DataProtections[0] == dataProtectionTracking {
			trackingFound = true
			if len(usage.Purposes) != 0 {
				t.Fatalf("expected tracking usage purposes to be empty, got %#v", usage.Purposes)
			}
		}
	}
	if !trackingFound {
		t.Fatalf("expected canonicalized tracking usage in declaration: %#v", declaration.DataUsages)
	}
}

const privacyTestAppID = "123456789"

func TestWebPrivacyPullReportsUnknownWhenPublishedAttributeMissing(t *testing.T) {
	fixture := handlertest.New(t)
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsages":
			return privacyJSONResponse(req, `{"data":[]}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {}
				}
			}`), nil
		default:
			return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
		}
	})

	t.Run("json", func(t *testing.T) {
		cmd := WebPrivacyPullCommand()
		if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--output", "json"}); err != nil {
			t.Fatalf("parse error: %v", err)
		}

		stdout, stderr := captureWebCommandOutput(t, func() {
			if err := cmd.Exec(context.Background(), nil); err != nil {
				t.Fatalf("exec error: %v", err)
			}
		})
		assertNoPrivacySecrets(t, stdout, stderr)

		var payload map[string]any
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatalf("failed to parse stdout JSON: %v\nstdout=%s", err, stdout)
		}
		publishState, ok := payload["publishState"].(map[string]any)
		if !ok {
			t.Fatalf("expected publishState object, got %#v", payload["publishState"])
		}
		known, ok := publishState["publishedKnown"].(bool)
		if !ok {
			t.Fatalf("expected additive publishedKnown bool, got %#v", publishState["publishedKnown"])
		}
		if known {
			t.Fatal("expected publishedKnown=false when Apple omits published")
		}
		if published, ok := publishState["published"].(bool); !ok {
			t.Fatalf("expected published bool to remain present, got %#v", publishState["published"])
		} else if published && !known {
			t.Fatal("published must not report true when publication state is unknown")
		}
	})

	t.Run("table", func(t *testing.T) {
		cmd := WebPrivacyPullCommand()
		if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--output", "table"}); err != nil {
			t.Fatalf("parse error: %v", err)
		}

		stdout, stderr := captureWebCommandOutput(t, func() {
			if err := cmd.Exec(context.Background(), nil); err != nil {
				t.Fatalf("exec error: %v", err)
			}
		})
		assertNoPrivacySecrets(t, stdout, stderr)
		if strings.Contains(stdout, "Published: false") {
			t.Fatalf("pull reported unpublished instead of unknown:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Published: unknown") {
			t.Fatalf("expected Published: unknown in table output, got:\n%s", stdout)
		}
	})
}

func TestWebPrivacyPublishErrorsBeforePatchWhenPublishStateIDEmpty(t *testing.T) {
	fixture := handlertest.New(t)
	var patchCount int
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch {
			patchCount++
			return fixture.Response("did not expect PATCH %s", req.URL.Path), nil
		}
		if req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState" {
			return privacyJSONResponse(req, `{
				"data": {
					"id": "",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": false}
				}
			}`), nil
		}
		return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
	})

	cmd := WebPrivacyPublishCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var execErr error
	stdout, stderr := captureWebCommandOutput(t, func() {
		execErr = cmd.Exec(context.Background(), nil)
	})
	assertNoPrivacySecrets(t, stdout, stderr)
	if execErr == nil {
		t.Fatal("expected publish to fail when publish-state id is empty")
	}
	if !strings.Contains(execErr.Error(), "publish-state id is missing") {
		t.Fatalf("error = %v, want publish-state id is missing", execErr)
	}
	if patchCount != 0 {
		t.Fatalf("expected no PATCH before missing id error, got %d", patchCount)
	}
}

func TestWebPrivacyPublishExitsNonZeroWhenPatchDoesNotConfirmPublished(t *testing.T) {
	tests := []struct {
		name         string
		patchBody    string
		wantFragment string
	}{
		{
			name: "published false",
			patchBody: `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": false}
				}
			}`,
			wantFragment: "could not be verified",
		},
		{
			name: "published omitted",
			patchBody: `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {}
				}
			}`,
			wantFragment: "could not be verified",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := handlertest.New(t)
			stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
					return privacyJSONResponse(req, `{
						"data": {
							"id": "publish-state-1",
							"type": "appDataUsagesPublishState",
							"attributes": {"published": false}
						}
					}`), nil
				case req.Method == http.MethodPatch && req.URL.Path == "/iris/v1/appDataUsagesPublishState/publish-state-1":
					return privacyJSONResponse(req, tc.patchBody), nil
				default:
					return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
				}
			})

			cmd := WebPrivacyPublishCommand()
			if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--confirm", "--output", "json"}); err != nil {
				t.Fatalf("parse error: %v", err)
			}

			var execErr error
			stdout, stderr := captureWebCommandOutput(t, func() {
				execErr = cmd.Exec(context.Background(), nil)
			})
			assertNoPrivacySecrets(t, stdout, stderr)
			if execErr == nil {
				t.Fatal("expected publish to exit non-zero when PATCH does not confirm published")
			}
			if !strings.Contains(execErr.Error(), tc.wantFragment) {
				t.Fatalf("error = %v, want %q", execErr, tc.wantFragment)
			}
		})
	}
}

func TestWebPrivacyPublishSucceedsWhenPatchConfirmsPublished(t *testing.T) {
	fixture := handlertest.New(t)
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": false}
				}
			}`), nil
		case req.Method == http.MethodPatch && req.URL.Path == "/iris/v1/appDataUsagesPublishState/publish-state-1":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": true}
				}
			}`), nil
		default:
			return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
		}
	})

	cmd := WebPrivacyPublishCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--confirm", "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("exec error: %v", err)
		}
	})
	assertNoPrivacySecrets(t, stdout, stderr)

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v\nstdout=%s", err, stdout)
	}
	if payload["changed"] != true {
		t.Fatalf("expected changed=true, got %#v", payload["changed"])
	}
	publishState, ok := payload["publishState"].(map[string]any)
	if !ok {
		t.Fatalf("expected publishState object, got %#v", payload["publishState"])
	}
	if publishState["published"] != true {
		t.Fatalf("expected published=true, got %#v", publishState["published"])
	}
	if publishState["publishedKnown"] != true {
		t.Fatalf("expected additive publishedKnown=true, got %#v", publishState["publishedKnown"])
	}
}

func stubPrivacyWebSession(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) {
	t.Helper()
	_ = stubWebProgressLabels(t)
	t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
	t.Setenv("ASC_CONFIG_PATH", filepath.Join(t.TempDir(), "nonexistent.json"))
	t.Setenv("ASC_WEB_MIN_REQUEST_INTERVAL", "0")
	t.Cleanup(SetResolveWebSession(func(ctx context.Context, appleID, password, twoFactorCode, twoFactorCodeCommand string) (*webcore.AuthSession, string, error) {
		return &webcore.AuthSession{
			Client: &http.Client{Transport: roundTripFunc(roundTrip)},
		}, "cache", nil
	}))
}

func privacyJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func assertNoPrivacySecrets(t *testing.T, stdout, stderr string) {
	t.Helper()
	combined := stdout + stderr
	for _, secret := range []string{"Set-Cookie", "cookie=", "myacinfo", "dqsid"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("output leaked session secret %q", secret)
		}
	}
}

func containsPrivacyProtection(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestWebPrivacyPullDoesNotWriteNotCollectedForMalformedRemoteUsages(t *testing.T) {
	fixture := handlertest.New(t)
	outPath := filepath.Join(t.TempDir(), "privacy.json")
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsages":
			return privacyJSONResponse(req, `{
				"data": [{
					"id": "usage-malformed-1",
					"type": "appDataUsages",
					"relationships": {
						"category": {"data": {"type":"appDataUsageCategories","id":"PURCHASE_HISTORY"}},
						"purpose": {"data": {"type":"appDataUsagePurposes","id":"APP_FUNCTIONALITY"}}
					}
				}, {
					"id": "usage-malformed-2",
					"type": "appDataUsages",
					"relationships": {
						"category": {"data": {"type":"appDataUsageCategories","id":"EMAIL_ADDRESS"}}
					}
				}]
			}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": false}
				}
			}`), nil
		default:
			return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
		}
	})

	cmd := WebPrivacyPullCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--out", outPath, "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("exec error: %v", err)
		}
	})
	assertNoPrivacySecrets(t, stdout, stderr)

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v\nstdout=%s", err, stdout)
	}
	count, ok := payload["unrepresentableCount"].(float64)
	if !ok || count != 2 {
		t.Fatalf("expected unrepresentableCount=2, got %#v", payload["unrepresentableCount"])
	}
	declaration, ok := payload["declaration"].(map[string]any)
	if !ok {
		t.Fatalf("expected declaration object, got %#v", payload["declaration"])
	}
	assertJSONDeclarationHasNoNotCollected(t, declaration)

	fileData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read --out file: %v", err)
	}
	if strings.Contains(string(fileData), dataProtectionNotCollected) {
		t.Fatalf("--out wrote DATA_NOT_COLLECTED for non-empty malformed remote usages:\n%s", fileData)
	}
	if !strings.Contains(string(fileData), dataProtectionUnknown) {
		t.Fatalf("--out missing opaque %s marker:\n%s", dataProtectionUnknown, fileData)
	}
}

func TestWebPrivacyPullPreservesMalformedUsagesAlongsideValidOnes(t *testing.T) {
	fixture := handlertest.New(t)
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsages":
			return privacyJSONResponse(req, `{
				"data": [{
					"id": "usage-malformed-1",
					"type": "appDataUsages",
					"relationships": {
						"category": {"data": {"type":"appDataUsageCategories","id":"PURCHASE_HISTORY"}},
						"purpose": {"data": {"type":"appDataUsagePurposes","id":"APP_FUNCTIONALITY"}}
					}
				}, {
					"id": "usage-valid-1",
					"type": "appDataUsages",
					"relationships": {
						"category": {"data": {"type":"appDataUsageCategories","id":"PURCHASE_HISTORY"}},
						"purpose": {"data": {"type":"appDataUsagePurposes","id":"APP_FUNCTIONALITY"}},
						"dataProtection": {"data": {"type":"appDataUsageDataProtections","id":"DATA_LINKED_TO_YOU"}}
					}
				}]
			}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": true}
				}
			}`), nil
		default:
			return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
		}
	})

	cmd := WebPrivacyPullCommand()
	if err := cmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := cmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("exec error: %v", err)
		}
	})
	assertNoPrivacySecrets(t, stdout, stderr)

	var payload struct {
		UnrepresentableCount int `json:"unrepresentableCount"`
		Declaration          privacyDeclarationFile
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to parse stdout JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.UnrepresentableCount != 1 {
		t.Fatalf("expected unrepresentableCount=1, got %d", payload.UnrepresentableCount)
	}
	if len(payload.Declaration.DataUsages) != 1 {
		t.Fatalf("expected one grouped usage, got %#v", payload.Declaration.DataUsages)
	}
	got := payload.Declaration.DataUsages[0]
	if containsPrivacyProtection(got.DataProtections, dataProtectionNotCollected) {
		t.Fatalf("mixed pull collapsed malformed entries: %#v", got)
	}
	if !containsPrivacyProtection(got.DataProtections, dataProtectionLinked) || !containsPrivacyProtection(got.DataProtections, dataProtectionUnknown) {
		t.Fatalf("expected valid and opaque protections, got %#v", got.DataProtections)
	}
}

func TestWebPrivacyPullNotCollectedRoundTripsThroughPlan(t *testing.T) {
	fixture := handlertest.New(t)
	outPath := filepath.Join(t.TempDir(), "privacy.json")
	notCollectedUsages := `{
		"data": [{
			"id": "u1",
			"type": "appDataUsages",
			"relationships": {
				"dataProtection": {"data": {"type":"appDataUsageDataProtections","id":"DATA_NOT_COLLECTED"}}
			}
		}]
	}`
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsages":
			return privacyJSONResponse(req, notCollectedUsages), nil
		case req.Method == http.MethodGet && req.URL.Path == "/iris/v1/apps/"+privacyTestAppID+"/dataUsagePublishState":
			return privacyJSONResponse(req, `{
				"data": {
					"id": "publish-state-1",
					"type": "appDataUsagesPublishState",
					"attributes": {"published": true}
				}
			}`), nil
		default:
			return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
		}
	})

	pullCmd := WebPrivacyPullCommand()
	if err := pullCmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--out", outPath, "--output", "json"}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	stdout, stderr := captureWebCommandOutput(t, func() {
		if err := pullCmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("pull exec error: %v", err)
		}
	})
	assertNoPrivacySecrets(t, stdout, stderr)

	var payload struct {
		UnrepresentableCount int `json:"unrepresentableCount"`
		Declaration          privacyDeclarationFile
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("failed to parse pull stdout JSON: %v\nstdout=%s", err, stdout)
	}
	if payload.UnrepresentableCount != 0 {
		t.Fatalf("expected unrepresentableCount=0 for DATA_NOT_COLLECTED, got %d", payload.UnrepresentableCount)
	}
	if len(payload.Declaration.DataUsages) != 1 {
		t.Fatalf("expected one pulled usage, got %#v", payload.Declaration.DataUsages)
	}
	if !reflect.DeepEqual(payload.Declaration.DataUsages[0].DataProtections, []string{dataProtectionNotCollected}) {
		t.Fatalf("expected pulled DATA_NOT_COLLECTED, got %#v", payload.Declaration.DataUsages[0])
	}

	fileData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read --out file: %v", err)
	}
	var written privacyDeclarationFile
	if err := json.Unmarshal(fileData, &written); err != nil {
		t.Fatalf("parse --out file: %v\n%s", err, fileData)
	}
	if _, err := declarationToTupleSet(written); err != nil {
		t.Fatalf("pulled file failed plan validator: %v\n%s", err, fileData)
	}
	if strings.Contains(string(fileData), `"category"`) || strings.Contains(string(fileData), `"purposes"`) {
		t.Fatalf("expected canonical not-collected file without empty category/purposes keys:\n%s", fileData)
	}

	planCmd := WebPrivacyPlanCommand()
	if err := planCmd.FlagSet.Parse([]string{"--app", privacyTestAppID, "--file", outPath, "--output", "json"}); err != nil {
		t.Fatalf("plan parse error: %v", err)
	}

	planStdout, planStderr := captureWebCommandOutput(t, func() {
		if err := planCmd.Exec(context.Background(), nil); err != nil {
			t.Fatalf("plan exec error: %v", err)
		}
	})
	assertNoPrivacySecrets(t, planStdout, planStderr)

	var plan privacyPlanOutput
	if err := json.Unmarshal([]byte(planStdout), &plan); err != nil {
		t.Fatalf("failed to parse plan stdout JSON: %v\nstdout=%s", err, planStdout)
	}
	if len(plan.Adds) != 0 || len(plan.Deletes) != 0 || len(plan.Updates) != 0 {
		t.Fatalf("expected empty pull->plan diff, got adds=%#v deletes=%#v updates=%#v", plan.Adds, plan.Deletes, plan.Updates)
	}
}

func TestWebPrivacyApplyRefusesUnrepresentableDeclarationWithoutDeletes(t *testing.T) {
	fixture := handlertest.New(t)
	var deleteCount int
	stubPrivacyWebSession(t, func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodDelete {
			deleteCount++
			return fixture.Response("did not expect DELETE %s", req.URL.Path), nil
		}
		return fixture.Response("unexpected request: %s %s", req.Method, req.URL.Path), nil
	})

	path := filepath.Join(t.TempDir(), "privacy.json")
	if err := os.WriteFile(path, []byte(`{
		"schemaVersion": 1,
		"dataUsages": [{
			"category": "PURCHASE_HISTORY",
			"purposes": ["APP_FUNCTIONALITY"],
			"dataProtections": ["UNKNOWN_OR_MISSING"]
		}]
	}`), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cmd := WebPrivacyApplyCommand()
	if err := cmd.FlagSet.Parse([]string{
		"--app", privacyTestAppID,
		"--file", path,
		"--allow-deletes",
		"--confirm",
		"--output", "json",
	}); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var execErr error
	stdout, stderr := captureWebCommandOutput(t, func() {
		execErr = cmd.Exec(context.Background(), nil)
	})
	assertNoPrivacySecrets(t, stdout, stderr)
	if execErr == nil {
		t.Fatal("expected apply to fail closed on unrepresentable declaration")
	}
	if !strings.Contains(execErr.Error(), "unrepresentable") {
		t.Fatalf("error = %v, want unrepresentable", execErr)
	}
	if !strings.Contains(stderr, "unrepresentable") {
		t.Fatalf("stderr = %q, want unrepresentable", stderr)
	}
	if deleteCount != 0 {
		t.Fatalf("expected no deletes, got %d", deleteCount)
	}
}

func assertJSONDeclarationHasNoNotCollected(t *testing.T, declaration map[string]any) {
	t.Helper()
	usages, ok := declaration["dataUsages"].([]any)
	if !ok {
		t.Fatalf("expected dataUsages array, got %#v", declaration["dataUsages"])
	}
	raw, err := json.Marshal(usages)
	if err != nil {
		t.Fatalf("marshal dataUsages: %v", err)
	}
	if strings.Contains(string(raw), dataProtectionNotCollected) {
		t.Fatalf("declaration contained DATA_NOT_COLLECTED: %s", raw)
	}
}
