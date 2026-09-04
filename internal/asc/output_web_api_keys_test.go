package asc

import (
	"strings"
	"testing"
)

func TestPrintTableWebAPIKeysListUsesRegistry(t *testing.T) {
	result := &WebAPIKeysListResult{
		Keys: []WebAPIKeyListItem{
			{KeyID: "ABC123XYZ", Name: "Release automation", Kind: "team", Roles: []string{"ADMIN"}, Active: true},
			{KeyID: "IND456ABC", Name: "Personal", Kind: "individual", Roles: []string{"APP_MANAGER"}, Active: false},
		},
	}

	output := captureStdout(t, func() error { return PrintTable(result) })
	for _, want := range []string{
		"Key ID", "Name", "Kind", "Roles", "Active",
		"ABC123XYZ", "Release automation", "team", "ADMIN", "true",
		"IND456ABC", "Personal", "individual", "APP_MANAGER", "false",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q: %q", want, output)
		}
	}
	if strings.Contains(output, "Created") || strings.Contains(output, "Creation") {
		t.Fatalf("did not expect a creation-date column: %q", output)
	}
}

func TestPrintMarkdownWebAPIKeyGetUsesRegistry(t *testing.T) {
	result := &WebAPIKeyGetResult{
		KeyID:          "ABC123XYZ",
		Name:           "Release automation",
		IssuerID:       "69a6de00-aaaa-bbbb-cccc-123456789abc",
		Roles:          []string{"ADMIN"},
		Active:         true,
		AllAppsVisible: true,
		KeyType:        "PUBLIC_API",
	}

	output := captureStdout(t, func() error { return PrintMarkdown(result) })
	for _, want := range []string{
		"Key ID", "Name", "Issuer ID", "Roles", "Active",
		"ABC123XYZ", "Release automation", "69a6de00-aaaa-bbbb-cccc-123456789abc", "ADMIN", "true",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("markdown output missing %q: %q", want, output)
		}
	}
	if strings.Contains(output, "Created") || strings.Contains(output, "Creation") {
		t.Fatalf("did not expect a creation-date column: %q", output)
	}
}

func TestPrintTableWebAPIKeyCreateIndividualUsesRegistry(t *testing.T) {
	result := &WebAPIKeyCreateIndividualResult{
		KeyID:      "IND-1",
		UserID:     "USER-1",
		P8Path:     "/tmp/ApiKey_IND-1.p8",
		Active:     true,
		Registered: true,
	}

	output := captureStdout(t, func() error { return PrintTable(result) })
	for _, want := range []string{
		"Key ID", "User ID", "Active", "Registered", "P8 Path",
		"IND-1", "USER-1", "true", "/tmp/ApiKey_IND-1.p8",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing %q: %q", want, output)
		}
	}
}

func TestPrintMarkdownWebAPIKeyCreateIndividualUsesRegistry(t *testing.T) {
	result := &WebAPIKeyCreateIndividualResult{
		KeyID:      "IND-1",
		UserID:     "USER-1",
		P8Path:     "/tmp/ApiKey_IND-1.p8",
		Active:     true,
		Registered: false,
	}

	output := captureStdout(t, func() error { return PrintMarkdown(result) })
	for _, want := range []string{
		"Key ID", "User ID", "Active", "Registered", "P8 Path",
		"IND-1", "USER-1", "true", "false", "/tmp/ApiKey_IND-1.p8",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("markdown output missing %q: %q", want, output)
		}
	}
}
