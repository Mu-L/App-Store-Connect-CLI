package cmdtest

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthDoctorWarnsWhenEnvironmentIdentifiersLookSwapped(t *testing.T) {
	withTempRepo(t, func(repo string) {
		t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
		t.Setenv("ASC_CONFIG_PATH", filepath.Join(repo, "config.json"))
		t.Setenv("ASC_KEY_ID", "69a6de00-aaaa-bbbb-cccc-123456789abc")
		t.Setenv("ASC_ISSUER_ID", "39MX87M9Y4")
		t.Setenv("ASC_PRIVATE_KEY_PATH", "/tmp/AuthKey.p8")

		root := RootCommand("1.2.3")
		root.FlagSet.SetOutput(io.Discard)

		stdout, _ := captureOutput(t, func() {
			if err := root.Parse([]string{"auth", "doctor"}); err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := root.Run(context.Background()); err != nil {
				t.Fatalf("run error: %v", err)
			}
		})

		if !strings.Contains(stdout, "[WARN] ASC_KEY_ID looks like an issuer ID — the values may be swapped") {
			t.Fatalf("expected swapped key ID warning, got %q", stdout)
		}
		if !strings.Contains(stdout, "[WARN] ASC_ISSUER_ID looks like a key ID — the values may be swapped") {
			t.Fatalf("expected swapped issuer ID warning, got %q", stdout)
		}
		if strings.Contains(stdout, "69a6de00") || strings.Contains(stdout, "39MX87M9Y4") {
			t.Fatalf("expected credential identifiers to be redacted, got %q", stdout)
		}
	})
}

func TestAuthDoctorStaysQuietForValidEnvironmentIdentifiers(t *testing.T) {
	withTempRepo(t, func(repo string) {
		t.Setenv("ASC_BYPASS_KEYCHAIN", "1")
		t.Setenv("ASC_CONFIG_PATH", filepath.Join(repo, "config.json"))
		t.Setenv("ASC_KEY_ID", "1234567890")
		t.Setenv("ASC_ISSUER_ID", "A7EFEF21-3432-404F-A488-083800B570FF")
		t.Setenv("ASC_PRIVATE_KEY_PATH", "/tmp/AuthKey.p8")

		root := RootCommand("1.2.3")
		root.FlagSet.SetOutput(io.Discard)

		stdout, _ := captureOutput(t, func() {
			if err := root.Parse([]string{"auth", "doctor"}); err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := root.Run(context.Background()); err != nil {
				t.Fatalf("run error: %v", err)
			}
		})

		if strings.Contains(stdout, "swapped") || strings.Contains(stdout, "is not a UUID") {
			t.Fatalf("expected no credential shape warning, got %q", stdout)
		}
	})
}
