---
name: develop-asc-change
description: Design, implement, and verify behavior changes in App-Store-Connect-CLI. Use when adding or changing a command, flag, API endpoint, output format, exit code, shared CLI behavior, or when fixing or refactoring behavior that requires code and tests.
---

# Develop an ASC CLI change

Deliver one complete, reviewable behavior change through architecture, RED-GREEN implementation, realistic CLI verification, and PR-ready validation.

## Write the design note

Before implementation, record the relevant contract below. For a small fix, a brief note with the reproduced failure, intended behavior, and focused check is enough; expand the design for new public behavior or compatibility decisions.

1. Placement in the existing command taxonomy and registry.
2. Current `--help` behavior and expected invocation shape.
3. Exact OpenAPI endpoint, method, request schema, query parameters, and response shape when API-facing.
4. Flags, output formats, stdout/stderr behavior, and exit codes.
5. Compatibility, lifecycle, migration, and deprecation impact.
6. RED-GREEN tests, black-box checks, live verification, edge cases, and failure modes.
7. Credible alternatives when a material design trade-off exists.

Use established conventions for routine choices. Ask only when unresolved public command shape or compatibility decisions materially change the result, and continue independent authorized work while awaiting an answer.

Parallelize independent read-only help, schema, architecture, and test discovery with isolated subagents when available. Keep implementation, shared-file edits, commits, and pushes under one coordinated owner.

## Establish RED

- For a bug, reproduce it first and add the smallest regression test that fails for the expected reason.
- For a feature, start with CLI-level coverage of the changed observable contract; add unit or HTTP tests for distinct behavior that those tests do not cover.
- For a behavior-changing refactor, use existing characterization coverage where sufficient and add coverage for missing behavior before moving code.
- Run the focused test and record the expected failure before implementation.

Read [references/test-matrix.md](references/test-matrix.md) for applicable CLI, output, artifact, and auth cases. Reuse sufficient existing coverage; do not duplicate shared parser or renderer tests for every command.

## Validate API support

1. Search `docs/openapi/paths.txt`, then inspect the exact operation in `docs/openapi/latest.json`.
2. Validate attributes against the correct create or update request schema.
3. Validate filters and includes against the specific endpoint, not a related top-level or relationship endpoint.
4. If the API does not support the proposed behavior, do not ship a misleading flag. Use explicit client-side behavior or document the limitation.
5. Prefer the `sosumi.ai` mirror when explanatory App Store Connect API documentation is required.

## Implement narrowly

- Extend the correct `internal/cli/<domain>` package and register new top-level commands in `internal/cli/registry/registry.go`.
- Set `UsageFunc: shared.DefaultUsageFunc` for command groups and subcommands.
- Use `shared.ContextWithTimeout` or `shared.ContextWithUploadTimeout` for outbound HTTP.
- Validate required flags before side effects and return usage errors with exit code `2`.
- Write data to stdout and diagnostics to stderr. Never silently ignore accepted flags.
- Use long-form flags in documentation, tests, and examples.
- Require `--confirm` for destructive operations; do not add interactive prompts.
- Keep one logical change per commit and remove helpers made obsolete by the change. Add review fixes as new commits; do not squash, rebase, force-push, or otherwise rewrite PR history unless the user explicitly requests it.
- Deprecate stable commands or flags before removal, with warning text, transition tests, and an upgrade path.

## Reach GREEN and verify

1. Rerun the focused failing test after each small fix.
2. Run adjacent package and command tests.
3. Build a binary at a worktree-specific path and verify realistic invocations, output streams, and exit codes. Do not share a fixed `/tmp/asc` path with concurrent tasks.
4. Run a minimal live smoke test when behavior depends on App Store Connect quirks. Prefer read-only calls; live mutations and cleanup require authority under `AGENTS.md`.
5. Run focused and affected checks before opening or updating a PR. Run the full repository gate for public CLI behavior, shared code, release surfaces, meaningful defect or security fixes, or when repository policy or the user requires it:

```bash
make build
make format
make check-docs
make lint
ASC_BYPASS_KEYCHAIN=1 make test
```

If command help changed, run `make generate-command-docs` and commit the resulting `docs/COMMANDS.md` update before the gate.

Before handoff, compare the exact branch head with current `main` read-only. Follow the branch-update rules in `AGENTS.md`; a newer base alone does not justify changing the branch.

## Hand off

Use the review gates and concise handoff contract in `AGENTS.md`. Include expected invocations and compatibility trade-offs when the public contract changed; report pre-existing failures and anything not reproduced.
