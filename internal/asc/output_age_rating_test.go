package asc

import (
	"reflect"
	"strings"
	"testing"
)

func TestPrintTableAgeRatingIncludesSocialMediaFields(t *testing.T) {
	socialMedia := true
	ageRestricted := false
	resp := &AgeRatingDeclarationResponse{
		Data: Resource[AgeRatingDeclarationAttributes]{
			ID:   "age-441",
			Type: ResourceTypeAgeRatingDeclarations,
			Attributes: AgeRatingDeclarationAttributes{
				SocialMedia:              &NullableBool{Value: &socialMedia},
				SocialMediaAgeRestricted: &NullableBool{Value: &ageRestricted},
			},
		},
	}

	output := captureStdout(t, func() error { return PrintTable(resp) })
	for _, want := range []string{"Social Media", "Social Media Age Restricted", "true", "false"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected table output to contain %q, got %q", want, output)
		}
	}
}

func TestAgeRatingAuditResultRows(t *testing.T) {
	result := &AgeRatingAuditResult{
		Apps: []AgeRatingAuditRow{
			{
				AppID:                    "app-1",
				Name:                     "Ready App",
				SocialMedia:              "true",
				SocialMediaAgeRestricted: "true",
				MessagingAndChat:         "false",
				AgeAssurance:             "true",
				Ready:                    true,
			},
			{
				AppID:            "app-2",
				Name:             "Broken App",
				MissingResponses: []string{"socialMedia", "messagingAndChat"},
				Error:            "request failed",
			},
		},
	}

	headers, rows := ageRatingAuditResultRows(result)
	wantHeaders := []string{"App ID", "Name", "Social Media", "Age Restricted", "Messaging & Chat", "Age Assurance", "Missing"}
	if !reflect.DeepEqual(headers, wantHeaders) {
		t.Fatalf("headers = %#v, want %#v", headers, wantHeaders)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %#v, want 2 rows", rows)
	}
	if got := rows[0][6]; got != "" {
		t.Fatalf("ready missing column = %q, want empty", got)
	}
	if got := rows[1][6]; got != "error: request failed" {
		t.Fatalf("error missing column = %q, want error detail", got)
	}
	ensureOutputRegistryPopulated()
	if !isRegistryTypeRegistered(typeForPtr[AgeRatingAuditResult]()) {
		t.Fatal("AgeRatingAuditResult is not registered with the output renderer")
	}
}
