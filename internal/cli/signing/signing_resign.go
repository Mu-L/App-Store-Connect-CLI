package signing

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
)

// signingResignOptions describes the local inputs for an IPA re-signing run.
// The output path is deliberately separate from the renderer format.
type signingResignOptions struct {
	IPAPath              string
	OutputPath           string
	IdentityPath         string
	IdentityPasswordPath string
	ProfilesManifestPath string
}

// SigningResignCommand returns the experimental local IPA re-signing command.
func SigningResignCommand() *ffcli.Command {
	fs := flag.NewFlagSet("resign", flag.ExitOnError)
	ipaPath := fs.String("ipa", "", "Path to the existing IPA input (required)")
	outputPath := fs.String("output", "", "Path for the newly re-signed IPA (required)")
	identityPath := fs.String("identity", "", "Path to a PKCS#12 signing identity (required)")
	identityPasswordPath := fs.String("identity-password-file", "", "Path to a file containing the PKCS#12 password")
	profilesManifestPath := fs.String("profiles-manifest", "", "Path to the strict bundle-to-profile manifest (required)")
	format := shared.BindOutputFlagsWith(fs, "format", shared.DefaultOutputFormat(), "Output format: json, table, markdown")

	return &ffcli.Command{
		Name:       "resign",
		ShortUsage: "asc signing resign --ipa PATH --output PATH --identity PATH --profiles-manifest PATH [flags]",
		ShortHelp:  "[experimental] Re-sign an existing iOS IPA with complete nested-target profile mappings.",
		LongHelp: `[experimental] Re-sign an existing iOS IPA into a new destination.

The command validates every app-like target and its exact provisioning-profile
mapping before creating an isolated temporary signing keychain. It never
overwrites the input or an existing output and never installs profiles into
the user's Xcode profile directories.

Use --format to select JSON, table, or Markdown output. The input and output
paths are separate because --output names the new IPA artifact.

Example:
  asc signing resign --ipa ./App.ipa --output ./artifacts/App-resigned.ipa --identity ./signing/distribution.p12 --identity-password-file ./secrets/p12-password --profiles-manifest ./signing/profiles.json --format json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(args) != 0 {
				return shared.UsageError("signing resign does not accept positional arguments")
			}
			if runtime.GOOS != "darwin" {
				return shared.UsageError("signing resign is supported only on macOS")
			}
			for name, value := range map[string]string{
				"--ipa":               *ipaPath,
				"--output":            *outputPath,
				"--identity":          *identityPath,
				"--profiles-manifest": *profilesManifestPath,
			} {
				if strings.TrimSpace(value) == "" {
					return shared.UsageError(name + " is required")
				}
			}
			if _, err := shared.ValidateOutputFormat(*format.Output, *format.Pretty); err != nil {
				return shared.UsageError(err.Error())
			}
			result, err := executeSigningResign(ctx, signingResignOptions{
				IPAPath:              strings.TrimSpace(*ipaPath),
				OutputPath:           strings.TrimSpace(*outputPath),
				IdentityPath:         strings.TrimSpace(*identityPath),
				IdentityPasswordPath: strings.TrimSpace(*identityPasswordPath),
				ProfilesManifestPath: strings.TrimSpace(*profilesManifestPath),
			})
			if err != nil {
				return fmt.Errorf("signing resign: %w", err)
			}
			return printSigningResignResult(result, *format.Output, *format.Pretty)
		},
	}
}

// signingResignResult is intentionally defined before the implementation so
// the command's renderer remains a stable, redacted public contract.
type signingResignResult struct {
	SchemaVersion int                         `json:"schemaVersion"`
	Command       string                      `json:"command"`
	Input         signingResignArtifactResult `json:"input"`
	Output        signingResignArtifactResult `json:"output"`
	Identity      signingResignIdentityResult `json:"identity"`
	Targets       []signingResignTargetResult `json:"targets"`
	Verification  signingResignVerification   `json:"verification"`
}

type signingResignArtifactResult struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

type signingResignIdentityResult struct {
	CertificateSHA256 string `json:"certificateSha256"`
	TeamID            string `json:"teamId"`
}

type signingResignTargetResult struct {
	Kind          string `json:"kind"`
	RelativePath  string `json:"relativePath"`
	BundleID      string `json:"bundleId"`
	ProfileClass  string `json:"profileClass"`
	ProfileUUID   string `json:"profileUuid"`
	ProfileSHA256 string `json:"profileSha256"`
	Status        string `json:"status"`
}

type signingResignVerification struct {
	Status string `json:"status"`
	Scope  string `json:"scope"`
}

func printSigningResignResult(result signingResignResult, format string, pretty bool) error {
	return shared.PrintOutputWithRenderers(
		result,
		format,
		pretty,
		func() error {
			asc.RenderTable([]string{"field", "value"}, signingResignResultRows(result))
			return nil
		},
		func() error {
			asc.RenderMarkdown([]string{"field", "value"}, signingResignResultRows(result))
			return nil
		},
	)
}

func signingResignResultRows(result signingResignResult) [][]string {
	rows := [][]string{
		{"command", result.Command},
		{"input.path", result.Input.Path},
		{"input.sizeBytes", fmt.Sprintf("%d", result.Input.SizeBytes)},
		{"input.sha256", result.Input.SHA256},
		{"output.path", result.Output.Path},
		{"output.sizeBytes", fmt.Sprintf("%d", result.Output.SizeBytes)},
		{"output.sha256", result.Output.SHA256},
		{"identity.certificateSha256", result.Identity.CertificateSHA256},
		{"identity.teamId", result.Identity.TeamID},
		{"verification.status", result.Verification.Status},
		{"verification.scope", result.Verification.Scope},
	}
	for _, target := range result.Targets {
		prefix := "target." + target.RelativePath
		rows = append(
			rows,
			[]string{prefix + ".kind", target.Kind},
			[]string{prefix + ".bundleId", target.BundleID},
			[]string{prefix + ".profileClass", target.ProfileClass},
			[]string{prefix + ".profileUuid", target.ProfileUUID},
			[]string{prefix + ".profileSha256", target.ProfileSHA256},
			[]string{prefix + ".status", target.Status},
		)
	}
	return rows
}

func executeSigningResign(ctx context.Context, options signingResignOptions) (signingResignResult, error) {
	return executeSigningResignImplementation(ctx, options)
}
