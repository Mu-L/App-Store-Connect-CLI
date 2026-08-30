package asc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSigningSyncResultPreservesSingleTargetJSONShape(t *testing.T) {
	result := &SigningSyncResult{
		Operation:       "push",
		RepoURL:         "file:///tmp/signing.git",
		BundleID:        "com.example.app",
		ProfileType:     "IOS_APP_STORE",
		Files:           []string{"profiles/appstore/profile.mobileprovision"},
		IdentityPresent: false,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal signing sync result: %v", err)
	}
	want := `{"operation":"push","repoUrl":"file:///tmp/signing.git","bundleId":"com.example.app","profileType":"IOS_APP_STORE","files":["profiles/appstore/profile.mobileprovision"],"identityPresent":false}`
	if string(data) != want {
		t.Fatalf("single-target JSON = %s, want %s", data, want)
	}
}

func TestSigningSyncResultBatchJSONOmitsSingularBundleID(t *testing.T) {
	result := &SigningSyncResult{
		Operation:       "push",
		RepoURL:         "file:///tmp/signing.git",
		BundleID:        "com.example.app",
		ProfileType:     "IOS_APP_STORE",
		Files:           []string{},
		IdentityPresent: false,
		BundleIDs:       []string{"com.example.app"},
		Targets: []SigningSyncTargetResult{{
			BundleID:       "com.example.app",
			ProfileType:    "IOS_APP_STORE",
			ProfilePath:    "profiles/appstore/com.example.app--profile.mobileprovision",
			ProfileCreated: false,
			Files:          []string{"profiles/appstore/com.example.app--profile.mobileprovision"},
		}},
	}
	result.MarkBatch()

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal batch signing sync result: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode batch signing sync result: %v", err)
	}
	if _, ok := decoded["bundleId"]; ok {
		t.Fatalf("batch JSON unexpectedly contains singular bundleId: %s", data)
	}
	for _, field := range []string{`"bundleIds":["com.example.app"]`, `"targets":[`, `"profileCreated":false`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("batch JSON missing %s: %s", field, data)
		}
	}
}

func TestSigningSyncResultRendererRegisteredAndRenders(t *testing.T) {
	ensureOutputRegistryPopulated()
	handler := requireOutputHandlerFor[SigningSyncResult](t, "SigningSyncResult")
	result := &SigningSyncResult{Targets: []SigningSyncTargetResult{{
		BundleID:       "com.example.app",
		ProfileType:    "IOS_APP_STORE",
		ProfilePath:    "profiles/appstore/com.example.app--profile.mobileprovision",
		ProfileCreated: true,
		Files:          []string{"certs/distribution/certificate.cer", "profiles/appstore/profile.mobileprovision"},
	}}}

	headers, rows, err := handler(result)
	if err != nil {
		t.Fatalf("signing sync rows handler: %v", err)
	}
	assertSingleRowEquals(t, headers,
		rows,
		[]string{"Bundle ID", "Profile Type", "Profile Path", "Profile Created", "Files"},
		[]string{"com.example.app", "IOS_APP_STORE", "profiles/appstore/com.example.app--profile.mobileprovision", "true", "certs/distribution/certificate.cer, profiles/appstore/profile.mobileprovision"})

	for _, renderer := range []struct {
		name string
		fn   func(any) error
	}{
		{name: "table", fn: PrintTable},
		{name: "markdown", fn: PrintMarkdown},
	} {
		t.Run(renderer.name, func(t *testing.T) {
			assertRenderedNonJSONContains(t, renderer.fn, result,
				"com.example.app", "IOS_APP_STORE", "profile.mobileprovision", "true")
		})
	}
}
