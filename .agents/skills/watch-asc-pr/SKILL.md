---
name: watch-asc-pr
description: Recheck an in-progress App-Store-Connect-CLI pull request for new review feedback, CI results, head changes, and merge readiness. Use when the user says to check for new PR comments, continue polling, fix and loop, babysit a PR, or keep working until the PR is clean.
---

# Watch an ASC CLI pull request

Run idempotent follow-up passes while preserving the existing PR context instead of restarting the full audit. A single pass is enough for a status check; a request to loop, babysit, or continue until green requires repeated passes until a terminal state below.

Resolve the mode from the request and established authority: status reads once; watch follows external state; fix-and-watch also applies authorized fixes. Watching alone does not authorize edits, commits, pushes, or review replies. Follow `AGENTS.md` for authority and validation reuse.

## Recheck current state

1. Resolve the exact PR and compare its current head SHA with the last audited or pushed SHA.
2. Fetch checks, reviews, top-level comments, and GraphQL review threads in parallel where possible. Separate required checks from advisory jobs.
3. Separate new actionable feedback from resolved, outdated, informational, duplicate, or bot-noise comments.
4. If the head changed outside this workflow, inspect the new diff before relying on prior conclusions.
5. If `main` advanced, refresh the merge-base diff and mergeability read-only. Follow the branch-update rules in `AGENTS.md`, including the exception for an authorized merge refused under strict up-to-date protection; a newer base alone does not justify changing the branch.

## Address actionable feedback

Apply fixes and external writes only when authorized. Otherwise report the verified finding and proposed fix; if it prevents progress, return `blocked` with the exact missing authority.

1. Verify every new claim against the codebase, API schema, and existing behavior. Do not follow automated feedback blindly.
2. Reproduce a valid defect and add or update a focused test before changing behavior.
3. Implement the smallest coherent fix, run the affected checks and required local review, then commit and push when authorized. Complete the final full-branch review loop in `AGENTS.md` before returning `clean`.
4. When review communication is authorized, reply to and resolve only the threads fully addressed by that push.
5. Re-fetch the PR after pushing and confirm the live head, checks, and thread state.
6. If required checks, required reviews, or an actionable reviewer are still pending, continue from the fresh exact-head state. When new valuable feedback arrives, fix it in another additive commit and repeat.

Keep fixes, pushes, review replies and resolutions, approvals, and merges serialized even when read-only checks run in parallel.

## Return one state

- `changed`: pushed a fix; include commit and validation.
- `pending`: required checks, required reviews, or actionable reviews are still running; identify exactly what remains. This is an intermediate state during a user-requested loop, not the final handoff.
- `clean`: the final full-branch local review in `AGENTS.md` is clear for the current head and base, required checks pass, required reviews are satisfied, the latest head is mergeable, and no actionable unresolved thread remains. Report advisory jobs without treating them as blockers.
- `blocked`: user input, permissions, an external outage, or an unsafe product decision prevents progress.

Do not approve or merge unless the user explicitly requested it. If merge was requested, reapply the complete merge gate from `$audit-asc-pr` immediately before merging, then use a regular merge commit that preserves the PR commits. Do not squash unless the user explicitly requested squash.

## Automation contract

When only an expected external state change remains in an authorized watch, save a checkpoint with the objective, PR, head and base SHAs, authority, validation results and inputs, unresolved feedback, last checked time, next step, stop condition, and retry history. Create or reuse one thread heartbeat, verify it, and end the turn. If scheduling is unavailable, report the pending state and checkpoint without implying that monitoring continues.

On each wake, inspect decisive state once. Reuse still-valid evidence, stay quiet when unchanged, and back off the next check. Resume work on completion, failure, or a stall. After an uncertain write, reconcile remote state before a bounded retry. Disable the heartbeat when the PR is clean, blocked, merged, closed, superseded, or awaiting a material user decision. Advisory jobs may remain pending after the clean gate passes. Do not create an unattended auto-merge loop.
