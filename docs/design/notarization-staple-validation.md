# Local notarization ticket stapling and validation

## Placement and current behavior

This change extends the existing `asc notarization` command group with two
local, macOS-only artifact operations. The current 4.11.0 command surface is
`submit`, `status`, `log`, and `list`; those commands use the Notary API and
remain unchanged. No App Store Connect endpoint or request schema is involved
in this change.

The new invocations are:

```text
asc notarization staple --file PATH --confirm [--output FORMAT] [--pretty]
asc notarization validate --file PATH [--output FORMAT] [--pretty]
```

`staple` calls Apple's local `xcrun stapler staple PATH` operation and then
calls `xcrun stapler validate PATH` before returning success. `validate` calls
only the validation operation and never mutates the artifact. Apple supports
UDIF disk images, signed flat installer packages, and supported code-signed
bundles. A ZIP is intentionally rejected as a direct target because it must be
recreated after stapling its contained item.

## Design

The command layer validates the invocation and target before any tool or auth
work. Because stapling mutates the artifact in place, `staple` requires an
explicit `--confirm` flag before it inspects the target or invokes Apple's
tool. It trims and cleans the supplied path once, resolves it to an absolute
path, rejects NULs, missing paths, final symlinks, unsafe parent symlinks,
special files, and empty regular files, and accepts regular files or directory
bundles for Apple's tool to classify. Direct `.zip` paths fail with a usage
diagnostic. Parent and final checks use the existing no-follow/rooted
filesystem helpers. Stable macOS `/etc`, `/tmp`, and `/var` filesystem aliases
are accepted at the volume boundary, while symlinks below the selected
artifact parent are rejected. The path is passed to the child as one argv
element and is never interpolated into a shell command.

The reusable local runner lives in `internal/xcode`. It requires the Darwin
platform, resolves `xcrun`, verifies that `xcrun --find stapler` succeeds, and
uses the existing command-construction and bounded wait seams. Child stdout and
stderr are directed to the caller's diagnostic writer so structured command
output remains parseable. Context cancellation is propagated through
`exec.CommandContext`; no API client or credential lookup is performed.

When a stapling child exits non-zero, the runner preserves its status in a
typed error. The CLI converts a real child status to the repository's private
process-exit marker after writing one concise stage diagnostic. A successful
staple followed by a failed validation is reported specifically as an
unverified mutation and returns the validation child status. Lookup, platform,
start, and cancellation failures retain the ordinary generic runtime mapping.

Successful computed output is represented by exported structs in
`internal/asc/output_notary.go` and registered with the normal output registry:

```json
{
  "filePath": "/absolute/path/MyApp.dmg",
  "operation": "staple",
  "stapled": true,
  "validated": true
}
```

```json
{
  "filePath": "/absolute/path/MyApp.dmg",
  "operation": "validate",
  "validated": true
}
```

JSON is written to stdout; table and Markdown render the same stage state.
Progress, child diagnostics, and corrective guidance are written to stderr.
Failed operations never emit a success result.

## Compatibility and scope

This is additive behavior. Existing Notary API commands, polling, output
shapes, authentication, and telemetry remain unchanged. The new commands do
not extract ZIPs, submit artifacts, re-sign, package, upload, un-staple, or run
Gatekeeper policy assessment. Apple's stapler may require network access for
both operations, but the CLI itself does not resolve App Store Connect auth.

## RED-GREEN and verification

Tests begin with CLI usage and output cases for required/empty `--file`,
missing `--confirm` (including the usage exit and no target/tool work),
positional arguments, direct ZIP rejection, invalid output/pretty combinations,
help discoverability, JSON/table/Markdown rendering, and unchanged existing
commands. Runner tests cover exact argv, path preservation, tool resolution,
stdout/stderr routing, child status preservation, staple-then-validate
ordering, validation-only behavior, cancellation, unsupported hosts, and
missing tools. Filesystem tests cover final and parent symlinks, missing,
special, empty, regular-file, and directory-bundle targets.

After focused tests pass, verify a built binary's help, output streams, and
usage status. Run `make build`, `make format`, `make generate-command-docs`,
`make check-docs`, `make lint`, and `ASC_BYPASS_KEYCHAIN=1 make test`. On macOS,
use a disposable copy of an existing Accepted, Developer ID-signed artifact to
run staple followed by validate; do not create a new notarization submission.

## Alternatives considered

Keeping the operations only in the API-facing command would leave the final
distributed artifact unverifiable. Calling `stapler` through a shell would
make paths with spaces or shell metacharacters unsafe. Reusing the Notary API
client would add credentials and server behavior to a purely local operation.
The direct `xcrun` argv runner keeps the boundary narrow while reusing the
repository's existing macOS command and process-test seams.

## Release and push requirements

The implementation and generated command documentation must be committed and
pushed as additive changes; existing commits in the feature branch must not be
rewritten. Before release, rerun the focused tests and the repository's build,
format, documentation, lint, and full test gates. Record the exact release
commit and pushed branch in the handoff. A macOS smoke test with an existing
Accepted artifact is required when such a disposable artifact is available.

## Unresolved risks

The automated suite uses deterministic command seams and cannot prove Apple's
ticket service behavior or the exact stapler result for every supported bundle,
disk image, and package format. No rollback is possible if Apple completes an
in-place staple before cancellation or if the follow-up validation fails; the
command reports that state but does not restore the artifact. ZIP extraction,
repackaging, and Gatekeeper assessment remain outside this change and require
separate workflows.
