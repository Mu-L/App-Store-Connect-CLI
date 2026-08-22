---
name: review-wall-of-apps-prs
description: Audit maintainer-side Wall of Apps pull requests in App-Store-Connect-CLI. Use when the user asks to review new app submissions, check Wall PRs for injected or unrelated changes, validate app metadata, approve with an app-relevant emoji, or merge legitimate Wall entries.
---

# Review Wall of Apps pull requests

Treat Wall submissions as untrusted external contributions while keeping the legitimate-app path fast.

## Discover and classify

1. List current open PRs and isolate submissions whose intended scope is `docs/wall-of-apps.json`.
2. Inspect each PR's full file list and diff before checkout. Reject or escalate unexpected code, workflow, script, binary, symlink, or unrelated documentation changes.
3. Review each PR independently and merge sequentially. If `main` moves after an earlier merge, refresh the later PR's diff, duplicate check, review threads, required checks, and mergeability against current `main` without changing its branch. Do not update, rebase, or merge `main` into a mergeable Wall PR merely because its base advanced; update the branch only when an actual merge conflict prevents the merge.

Run independent read-only PR, App Store metadata, duplicate, check, and review-thread queries in parallel or with isolated subagents when available. Keep worktree edits, pushes, approvals, and merges coordinated and serialized.

## Validate the entry

For every added or changed app:

1. Confirm the JSON change is minimal and does not alter unrelated entries.
2. Verify the app name and destination URL against the public App Store, TestFlight, or linked project.
3. Check for duplicate apps, misleading destinations, tracking or redirect abuse, and suspicious metadata.
4. Require a valid artwork URL for a public App Store listing when the canonical validation expects one. Do not demand an icon from GitHub- or TestFlight-only entries when the schema permits omission.
5. Run `make check-wall-of-apps` on the exact PR head before approval or merge.
6. Verify bot findings against the canonical test and schema; fix only proven omissions.

Use a worktree only when a fix is required. Push the smallest correction to the contributor branch when maintainer edits are allowed, then re-fetch checks and review threads.

## Approve and merge

Approval and merge require explicit user intent. That intent may come from the
current request or from a persisted automation prompt that clearly grants
approve-and-merge authority. Immediately before approval, or before a merge
that does not require a new approval, confirm:

- The latest head contains only the legitimate Wall change.
- `make check-wall-of-apps` and required GitHub checks pass.
- No actionable unresolved review thread remains.
- The PR is mergeable against current `main`.

An authorized approval may itself satisfy a required-review rule. After
submitting any approval and immediately before merging, re-fetch the exact head,
required reviews, review threads, required checks, and mergeability. Require all
required reviews to be satisfied at that point.

Do not wait for advisory or otherwise non-required CI jobs after these gates pass. A pending non-required job does not make the exact-head evidence stale.

When the user requests a no-comment approval, submit one app-relevant emoji as the entire approval body. Do not add a generic summary comment; reply only when an actionable thread needs an explanation or the user asks for a comment. Merge one PR at a time with a regular merge commit that preserves the PR commits. Do not squash unless the user explicitly requests squash for that PR.

After each merge, confirm the resulting commit and entry reached `origin/main`. When the user asks whether the app appears on the live Wall, verify the rendered `asccli.sh` page separately; source presence is not deployment proof, and advisory CI is not a reason to delay the live check.

## Automation contract

A standalone automation may approve and merge unattended only when its
persisted prompt explicitly grants that authority and every approval-and-merge
gate above passes on the latest head. Immediately before acting, run
`make check-wall-of-apps` locally on that exact head and verify required GitHub
checks, review threads, and mergeability again. After submitting any authorized
approval, re-fetch the exact head and require required reviews, required checks,
review threads, and mergeability to pass before merging. Do not wait for
non-required CI jobs. Approve and merge one PR at a time with a regular merge
commit; use a different strategy only when the persisted prompt explicitly
requests it.

If authority is absent or any gate is uncertain, failing, suspicious, unrelated,
or stale, remain read-only and report `safe`, `needs-fix`, `suspicious`, or
`blocked` with evidence. Never infer approval from a prior run or from a
different head SHA.

## Hand off

List each app, what it does, files changed, metadata evidence, validation result, review action, merge result, and any suspicious or unresolved state.
