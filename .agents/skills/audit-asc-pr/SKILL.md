---
name: audit-asc-pr
description: Audit App-Store-Connect-CLI pull requests end to end and fix concrete defects. Use when the user asks to audit or review a PR, decide whether a PR is valuable or slop, verify that a PR truly solves its issue, assess blast radius, or make a PR code-ready before merge.
---

# Audit an ASC CLI pull request

Perform an evidence-first review of the entire pull request. Default to fix-forward work unless the user explicitly requests review-only.

## Establish the contract

1. Read `AGENTS.md` and resolve the repository, PR number, base branch, head branch, and exact head SHA.
2. Read the PR body, every commit, linked issues, current checks, reviews, and comments.
3. Fetch thread-aware review state with GitHub GraphQL. Do not treat a flat comment list as proof that all review threads are resolved.
4. State the behavior the PR claims to change and the evidence needed to prove it.
5. Confirm whether the user authorized fixes, pushes, approval, or merge. An audit authorizes fix-forward changes in this repository, but approval and merge still require explicit user intent.

Fetch independent read-only metadata, diff, check, schema, and review-thread evidence in parallel or with isolated subagents when available. Keep one coordinated owner for edits, pushes, review replies and resolutions, approvals, and merges.

## Isolate and inspect

1. Use a dedicated worktree and local branch for the PR. Preserve the user's main checkout and unrelated worktrees.
2. Inspect the full merge-base diff and all PR commits, not only the latest commit.
3. Compare the implementation with the linked issue and current product behavior. Check architecture fit, compatibility, error paths, permissions, destructive operations, output contracts, and missing cleanup.
4. Verify claims from bots or reviewers against code, schemas, and tests before editing.
5. Identify the blast radius: commands, shared helpers, API resources, output formats, auth modes, and release surfaces affected.

## Verify behavior

1. Run the relevant current `--help` paths before judging command shape.
2. Build a binary when CLI behavior, flags, output, or exit codes changed. Exercise realistic invocations against the built binary.
3. For API-facing changes, verify the exact endpoint and method in `docs/openapi/latest.json`, including create-versus-update attributes and endpoint-specific query parameters.
4. Run focused tests first, then checks required by repository policy or proportional to the diff. Pending or unrelated advisory CI does not block the audit once required checks pass; report relevant advisory failures.
5. Prefer read-only live App Store Connect verification. When mutation is necessary, use the disposable app `6759231657`, clean up temporary resources, and record anything that could not be removed. Never mutate another app without explicit approval.
6. Preserve uncertainty when live state cannot reproduce an edge case; use deterministic fixtures or tests instead of claiming success.

## Fix forward

1. Reproduce each defect before changing code.
2. Add or adjust a failing regression test, confirm the failure, implement the smallest coherent fix, and rerun the focused test.
3. Keep commits logical and traceable to findings or review threads. Add fixes as new commits; do not squash, rebase, force-push, or otherwise rewrite the PR history unless the user explicitly requests it.
4. Push to the PR head when permitted. If the contributor branch cannot accept maintainer pushes, report the exact limitation and prepare a separate fix PR only when authorized.
5. Reply to and resolve only threads fully addressed by the pushed change.
6. Re-fetch the head SHA, checks, reviews, and GraphQL threads after every push.

Do not post a generic top-level audit summary unless the user asks. Put actionable findings in review threads when review communication is authorized.

## Apply the merge gate

Do not call the PR ready until all of the following are true:

- The latest head was audited and compared read-only with current `main`; GitHub reports no merge conflict. Do not update, rebase, or merge `main` into a clean PR merely because `main` advanced.
- Relevant focused and GitHub-required checks pass. Non-required checks may still be pending.
- No actionable unresolved review thread remains.
- Required reviews are satisfied.
- GitHub reports the PR mergeable without conflicts. Interpret `BLOCKED` or `UNSTABLE` through the required-check, required-review, and thread gates above; do not require a `CLEAN` merge state when only advisory jobs remain.
- Live or deterministic verification supports the claimed behavior.

Use `$watch-asc-pr` after the first push when required checks, required reviews, or actionable reviewers are still pending. When the user asked to loop until green, keep running watch passes after each push and fresh review result until the latest head is clean or materially blocked; do not hand off merely because required checks or reviews are pending. Do not start or continue a watch loop only for advisory jobs.

Approve or merge only when the user asked for that action. When merge is authorized, preserve the PR commits with a regular merge commit such as `gh pr merge --merge --match-head-commit <sha>`. Do not squash unless the user explicitly requests squash for that PR.

## Hand off

Report findings, fixes, commits, pushes, commands and tests run, live ASC mutations and cleanup, unresolved risks, check state, thread state, and the final merge recommendation.
