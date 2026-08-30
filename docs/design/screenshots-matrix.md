# Screenshot matrix capture and review

## Scope

Issue #2230 adds the experimental `asc screenshots matrix` command. It runs an
existing local screenshot plan over a bounded device, locale, appearance, and
content-variant matrix, writes one isolated artifact directory per cell, and
creates a report that contains both successful and unsuccessful cells.

The command is local-only. It does not call the App Store Connect API, upload
artifacts, or create, boot, install, clone, or delete simulators. Target
simulators must already exist and be booted. Existing `screenshots run`,
`capture`, `frame`, and review commands retain their current behavior.

## Command placement and invocation

`ScreenshotsCommand` registers a new `shots.ShotsMatrixCommand` subcommand:

```text
asc screenshots matrix --plan .asc/screenshots-matrix.json [flags]
```

The command uses `shared.DefaultUsageFunc` and `shared.BindOutputFlags`.
Besides the standard `--output` and `--pretty` flags, it accepts `--plan`,
`--max-concurrency`, `--max-attempts`, and `--retry-backoff`. Explicit runtime
flags override the corresponding plan values. Usage validation returns
`flag.ErrHelp`/the existing usage diagnostic path and therefore exit code 2.

## Matrix plan

The matrix plan is a separate JSON/JSONC document. `version` is currently 1.
Its `base_plan` points to an existing screenshot Plan v1 document. The base
plan remains the source of the bundle ID and ordered interaction steps.

```jsonc
{
  "version": 1,
  "base_plan": ".asc/screenshots.json",
  "devices": [
    { "id": "iphone-17-pro", "udid": "SIMULATOR_UDID" },
    { "id": "ipad-pro-13", "udid": "ANOTHER_SIMULATOR_UDID" }
  ],
  "locales": ["en-US", "ja-JP"],
  "appearances": ["light", "dark"],
  "content_variants": [
    { "id": "default" },
    { "id": "empty", "launch_arguments": ["--fixture", "empty"] }
  ],
  "execution": {
    "max_concurrency": 2,
    "max_attempts": 2,
    "retry_backoff_ms": 500
  },
  "output": {
    "raw_dir": "./screenshots/matrix/raw",
    "framed_dir": "./screenshots/matrix/framed",
    "review_dir": "./screenshots/matrix/review",
    "frame": {
      "enabled": false,
      "device_by_matrix_device": {}
    }
  }
}
```

The example deliberately disables framing because matrix device labels must
never be mapped to a frame for another device family. When framing is enabled,
each matrix device needs an explicit supported mapping validated through the
existing frame-device parser.

The product of the four axis lengths must be non-zero and no more than 256
cells. Device IDs, content-variant IDs, and screenshot names must be unique and
safe path components. Device UDIDs must be present and unique across device
declarations. Appearance is case-insensitively normalized to `light` or `dark`.
Locales are non-empty and use the existing locale normalization helper.

## Execution model

Expansion order is device declaration order, locale declaration order,
appearance declaration order, then content-variant declaration order. Each
cell has the stable ID:

```text
<device-id>|<locale>|<appearance>|<content-variant-id>
```

The executor reuses the validated base `Plan` and overrides its simulator UDID
and output directory in memory. It passes locale launch overrides and literal
content-variant arguments to each `launch` step. Locale overrides are:

```text
-AppleLanguages (<language>)
-AppleLocale <locale-with-underscore>
```

Content arguments are appended without shell interpolation. A content variant
that tries to override Apple language or locale arguments is rejected during
validation.

The worker pool has a hard maximum of eight workers and a default of one. A
per-UDID mutex serializes cells targeting the same simulator so appearance
changes cannot race. Before a cell, the executor snapshots the simulator's
appearance, applies the requested appearance, executes the plan, and restores
the original state in a deferred cleanup path. A restore failure is surfaced as
`cleanup_failed` and prevents later cells on that simulator.

`max_attempts` is the total number of attempts and defaults to one, with a hard
maximum of three. Execution and framing failures retry the complete cell after
the configured backoff. Validation, cancellation, and cleanup failures do not
retry. Independent cells continue after a failure. Context cancellation stops
new work, cancels external commands, records unfinished cells as canceled, and
writes the partial report.

## Artifact and report contract

For a base screenshot step named `home`, cell artifacts use:

```text
raw/<locale>/<device-id>/<appearance>/<content-variant-id>/home.png
framed/<locale>/<device-id>/<appearance>/<content-variant-id>/home.png
```

Each attempt writes to a temporary attempt path and promotes only validated
successes to the final path. The command does not recursively delete prior
outputs; stale files are excluded from the explicit current-run manifest.

Every invocation writes `review/manifest.json` and `review/index.html`, even
when one or more cells fail. The matrix manifest has one entry per planned cell
and contains the logical device label rather than the simulator UDID. Entries
include cell axes, status, attempts, duration, step results, raw/framed paths,
dimensions, and sanitized failure stage/code. Launch arguments, raw command
output, environment values, credentials, keychain paths, and simulator UDIDs
are not persisted.

The HTML report is self-contained and network-free. It displays all cells,
including failures and cancellations, and links only to local raw/framed
artifacts. Plan-provided labels are escaped. Raw-only reports are valid when
framing is disabled. Approval and App Store upload integration are explicitly
out of scope.

The command prints the structured result through the existing output helpers.
The result includes `plan_path`, `status`, `total_cells`, `succeeded`,
`failed`, `retried`, `cells`, and `review` (with manifest and HTML paths).
Each cell error is an object containing only a sanitized `stage`, `code`, and
`message`; step errors are sanitized as well. All cells succeeding returns nil
and exit code 0. Partial or failed execution writes its result/artifacts and
then returns a runtime error for exit code 1. Invalid flags/plans return usage
exit code 2 before side effects.

## Implementation locations

- `internal/screenshots/matrix.go`: plan types, validation, expansion,
  scheduling, cell execution, retry, and result types.
- `internal/screenshots/matrix_review.go`: explicit matrix manifest and HTML
  rendering, reusing safe review rendering helpers where appropriate.
- `internal/cli/shots/shots_matrix.go`: flags, command execution, output, and
  table/Markdown renderers.
- `internal/cli/screenshots/screenshots.go`: register the subcommand.
- `internal/cli/cmdtest/shots_matrix_test.go` and package tests: CLI and unit
  coverage with injected command/frame/state runners.
- `docs/COMMANDS.md`, README or local workflow docs: generated help and usage
  example.

Prefer a small injectable process runner and appearance-state interface over
tests that require Xcode. Reuse `Plan` parsing/validation, step semantics,
`Capture`, `Frame`, and existing output conventions without changing their
public behavior.

## Verification

RED tests should cover command registration, required/invalid flags, plan
validation, deterministic expansion, path safety, literal argument forwarding,
per-UDID serialization, concurrency bounds, state restoration, retry behavior,
partial results, report escaping, and output streams/exit codes. Fake `xcrun`,
`axe`, and framing runners should prove execution without a simulator.

Run focused package tests, then:

```bash
make build
make format
make check-docs
make lint
ASC_BYPASS_KEYCHAIN=1 make test
```

On macOS, perform one opt-in smoke test with two already-booted simulators and
an installed sample app. Confirm that cells are isolated, same-device cells do
not overlap, appearance is restored, review artifacts contain failures, and no
App Store Connect request occurs.

## Alternatives rejected

Extending the existing Plan v1 schema would make a single-device sequence
carry matrix-only fields and risk changing `screenshots run` behavior. A
separate matrix document keeps the existing contract stable while reusing its
steps. Creating simulators or installing builds would make this slice depend on
build/signing lifecycle and introduce cleanup risks; prebooted explicit UDIDs
keep the first implementation deterministic and local.
