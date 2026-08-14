package cmdtest

import (
	"strings"
	"testing"
)

func TestDistributePublishCommandSurfaceIsAgentDiscoverable(t *testing.T) {
	root := RootCommand("1.2.3")
	distribute := findSubcommand(root, "distribute")
	if distribute == nil || !strings.Contains(distribute.ShortHelp, "[experimental]") {
		t.Fatalf("unexpected distribute command: %#v", distribute)
	}
	publish := findSubcommand(root, "distribute", "publish")
	if publish == nil || !strings.Contains(publish.ShortHelp, "[experimental]") {
		t.Fatalf("unexpected distribute publish command: %#v", publish)
	}
	for _, name := range []string{
		"bundle-dir", "endpoint", "region", "bucket", "prefix", "download-endpoint", "addressing-style", "access",
		"public-base-url", "url-ttl", "download-grace", "verify-timeout", "receipt", "link-path", "output", "pretty",
	} {
		if publish.FlagSet.Lookup(name) == nil {
			t.Errorf("missing --%s", name)
		}
	}
	if usage := publish.FlagSet.Lookup("verify-timeout").Usage; !strings.Contains(usage, "ASC_UPLOAD_TIMEOUT") {
		t.Fatalf("--verify-timeout usage = %q, want IPA upload-timeout guidance", usage)
	}
}

func TestDistributePublishInvalidValueIsUsageExit(t *testing.T) {
	assertUsageExit(
		t,
		[]string{"distribute", "publish", "--bundle-dir", "bundle", "--endpoint", "http://insecure.example", "--region", "auto", "--bucket", "bucket", "--prefix", "app"},
		"--endpoint: endpoint must be an HTTPS origin",
	)
}
