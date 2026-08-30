# Read-only Xcode toolchain doctor

## Placement and command shape

Issue #2228 adds an experimental leaf beneath the existing local `asc xcode`
group:

```text
asc xcode doctor [--developer-dir PATH] [--sdk SDK] [--output json|table|markdown] [--pretty]
```

`asc xcode --help` currently exposes `inject`, `build`, `archive`, `export`,
`export-options`, `validate`, and `version`; it does not expose a toolchain
diagnostic. The new command is local-only and does not require App Store
Connect credentials or an API request.

The effective developer directory is selected in this order:

1. explicit `--developer-dir`;
2. non-empty `DEVELOPER_DIR`;
3. `xcode-select --print-path`.

The flag is an inspection override. It must not call `xcode-select --switch`,
invoke `sudo`, change the parent process environment, or write host state.
Every child probe receives the resolved candidate as `DEVELOPER_DIR` so the
checks cannot silently use a different Xcode selection.

## Checks and output

The command checks the selected directory, runs `xcodebuild -version`, parses
the Xcode version and build version, resolves `xcodebuild` with `xcrun --find`,
and optionally resolves one SDK with `xcrun --sdk SDK --show-sdk-path`.
Beta-looking paths produce an advisory warning. Command Line Tools-only paths
are identified and cannot report a healthy full-Xcode result when the required
Xcode commands are unavailable.

The report uses the existing local `asc xcode` snake_case JSON convention. The
top-level status is `ok`, `warn`, or `fail`. Checks have stable names, status,
message, and optional path fields. The selected source is `flag`, `environment`,
or `xcode-select`. JSON is emitted on stdout; bounded diagnostics remain on
stderr. Table and Markdown render the same stable data.

Exit behavior is:

- `0` for `ok` and `warn` reports;
- `1` for an unavailable or unusable directory, Xcode tool, or requested SDK;
- `2` for invalid flags, empty explicit values, positional arguments, or an
  unsupported output format.

The command remains visible on every platform for consistent help and docs, but
execution is macOS-only and must retain the existing local Xcode unsupported
platform error contract.

## API and compatibility

This change has no App Store Connect API surface, OpenAPI operation, request
schema, or response resource. It is entirely a local macOS process and path
inspection feature.

Existing archive, export, validate, build, version, signing, profile, and
device behavior remains unchanged. In particular, this issue does not add a
developer-directory flag to those commands or select a toolchain for future
commands. A future change can consume this proven resolution contract without
recreating the diagnostics.

The command must not install or update Xcode, SDKs, simulator runtimes, or
first-launch components. It must not inspect or print credentials, complete
environment contents, or unbounded subprocess logs. Any telemetry added for
the new command records only aggregate outcome and whether selector flags were
present; path and SDK values remain local.

## Verification plan

RED coverage starts at the CLI boundary for command registration, help, flags,
output, and exit behavior, followed by core tests for selection precedence,
version parsing, path normalization, child environment propagation, probe
failures, beta warnings, SDK checks, cancellation, and bounded diagnostics.
All subprocess and filesystem interactions use injectable seams, so tests do
not require a real Xcode installation.

The focused loop is:

```bash
go test ./internal/xcode ./internal/cli/xcode ./internal/cli/cmdtest
```

The completed behavior must also pass the required repository gates:

```bash
make build
make format
make check-docs
make lint
ASC_BYPASS_KEYCHAIN=1 make test
```

On macOS, manually verify the default selection, an explicit application or
developer directory, an SDK probe, a beta-path warning when available, and
that the `xcode-select --print-path` result is unchanged before and after each
invocation.

## Alternatives

Adding a package-manager-like installer or global Xcode switch would create
privileged, destructive host behavior and a large lifecycle surface. This
design keeps selection explicit and read-only while still making the effective
toolchain observable.

Adding a developer-directory flag to every existing local command first would
duplicate validation and expand the compatibility surface. A standalone doctor
establishes one reusable, testable contract before any command-specific
integration.
