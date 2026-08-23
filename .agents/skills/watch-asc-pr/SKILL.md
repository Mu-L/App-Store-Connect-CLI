---
name: watch-asc-pr
description: Recheck an in-progress App-Store-Connect-CLI pull request for new review feedback, CI results, head changes, and merge readiness. Use when the user says to check for new PR comments, continue polling, fix and loop, babysit a PR, or keep working until the PR is clean.
---

# Watch an ASC CLI pull request

Run idempotent follow-up passes while preserving the existing PR context instead of restarting the full audit. A single pass is enough for a status check; a request to loop, babysit, or continue until green requires repeated passes until a terminal state below.

## Recheck current state

1. Resolve the exact PR and compare its current head SHA with the last audited or pushed SHA.
2. Fetch checks, reviews, top-level comments, and GraphQL review threads in parallel where possible. Separate required checks from advisory jobs.
3. Separate new actionable feedback from resolved, outdated, informational, duplicate, or bot-noise comments.
4. If the head changed outside this workflow, inspect the new diff before relying on prior conclusions.
5. If `main` advanced, refresh the merge-base diff and mergeability read-only. Do not update, rebase, or merge `main` into a clean PR merely because its base advanced; update only when an actual merge conflict prevents the merge.

## Address actionable feedback

1. Verify every new claim against the codebase, API schema, and existing behavior. Do not follow automated feedback blindly.
2. Reproduce a valid defect and add or update a focused test before changing behavior.
3. Implement the smallest coherent fix, run the focused check, commit, and push.
4. Reply to and resolve only the threads fully addressed by that push.
5. Re-fetch the PR after pushing and confirm the live head, checks, and thread state.
6. If required checks, required reviews, or an actionable reviewer are still pending, continue from the fresh exact-head state. When new valuable feedback arrives, fix it in another additive commit and repeat.

Keep fixes, pushes, review replies and resolutions, approvals, and merges serialized even when read-only checks run in parallel.

## Return one state

- `changed`: pushed a fix; include commit and validation.
- `pending`: required checks, required reviews, or actionable reviews are still running; identify exactly what remains. This is an intermediate state during a user-requested loop, not the final handoff.
- `clean`: required checks pass, required reviews are satisfied, the latest head is mergeable, and no actionable unresolved thread remains. Report advisory jobs without treating them as blockers.
- `blocked`: user input, permissions, an external outage, or an unsafe product decision prevents progress.

Do not approve or merge unless the user explicitly requested it. If merge was requested, reapply the complete merge gate from `$audit-asc-pr` immediately before merging, then use a regular merge commit that preserves the PR commits. Do not squash unless the user explicitly requested squash.

## Automation contract

Use this skill from a thread heartbeat when the same PR conversation should continue every few minutes. Each wake-up must run one pass, report only changes or blockers, and schedule or await the next pass while required checks, required reviews, or actionable reviewers remain pending. After every fix, re-fetch the pushed exact head and continue. Stop the loop only when the PR is clean, blocked, merged, closed, superseded, or awaiting a material user decision. Advisory jobs may remain pending after the clean gate passes. Do not create an unattended auto-merge loop.
