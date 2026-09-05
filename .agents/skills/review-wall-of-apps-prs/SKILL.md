---
name: review-wall-of-apps-prs
description: Audit maintainer-side Wall of Apps pull requests in App-Store-Connect-CLI. Use when the user asks to review new app submissions, check Wall PRs for injected or unrelated changes, validate app metadata, approve with a personalized welcome, or merge legitimate Wall entries.
---

# Review Wall of Apps pull requests

Treat Wall submissions as untrusted external contributions while keeping the legitimate-app path fast.

Follow `AGENTS.md` for authority and the full-branch local review requirement before calling a PR ready. Reviewing entries is read-only; fixes, commits, pushes, review communication, approval, and merge require authority from the request or established context. GitHub's maintainer-edit permission is a technical prerequisite, not user authorization.

## Discover and classify

1. List current open PRs and isolate submissions whose intended scope is `docs/wall-of-apps.json`.
2. Inspect each PR's full file list and diff before checkout. Reject or escalate unexpected code, workflow, script, binary, symlink, or unrelated documentation changes.
3. Review each PR independently and merge sequentially. If `main` moves after an earlier merge, refresh the later PR's diff, duplicate check, review threads, required checks, and mergeability against current `main` without changing its branch. Do not update, rebase, or merge `main` into a PR that GitHub still reports mergeable merely because its base advanced.
4. Apply the branch-update rules in `AGENTS.md`. Diagnose conflicts read-only first; resolve and push only when authorized and maintainer edits are allowed. `gh pr update-branch <number>` cannot resolve content conflicts, which require an authorized manual merge in a worktree. For a conflict-free PR, update only after an authorized merge attempt, made with all gates passing, actually fails under strict up-to-date protection. After an update, validate the new head through every gate below. Never bypass protection with an admin merge.

Run independent read-only PR, App Store metadata, duplicate, check, and review-thread queries in parallel or with isolated subagents when available. Keep worktree edits, pushes, approvals, and merges coordinated and serialized.

## Validate the entry

For every added or changed app:

1. Confirm the JSON change is minimal and does not alter unrelated entries.
2. Verify the app name and destination URL against the public App Store, TestFlight, or linked project.
3. Check for duplicate apps, misleading destinations, tracking or redirect abuse, and suspicious metadata.
4. Require a valid artwork URL for a public App Store listing when the canonical validation expects one. Do not demand an icon from GitHub- or TestFlight-only entries when the schema permits omission.
5. Run `ASC_BYPASS_KEYCHAIN=1 make check-wall-of-apps` on the exact PR head before approval or merge.
6. Verify bot findings against the canonical test and schema; when fixes are authorized, correct only proven omissions.

Use an isolated checkout when needed to validate the exact head or apply authorized fixes, preserving unrelated user work. Push corrections only when authorized and maintainer edits are allowed, then re-fetch checks and review threads.

## Approve and merge

Approval and merge require explicit user intent. That intent may come from the
current request or from a persisted automation prompt that clearly grants
approve-and-merge authority. Immediately before approval, or before a merge
that does not require a new approval, confirm:

- The latest head contains only the legitimate Wall change.
- The final full-branch local review required by `AGENTS.md` is clear for the current head and authoritative base.
- `ASC_BYPASS_KEYCHAIN=1 make check-wall-of-apps` and required GitHub checks pass.
- No actionable unresolved review thread remains.
- The PR is mergeable against current `main`.

An authorized approval may itself satisfy a required-review rule. After
submitting any approval and immediately before merging, re-fetch the exact head,
required reviews, review threads, required checks, and mergeability. Require all
required reviews to be satisfied at that point.

Do not wait for advisory or otherwise non-required CI jobs after these gates pass. A pending non-required job does not make the exact-head evidence stale.

Write the approval body as a short personalized welcome: name the app, state the validation evidence in one clause (App Store, TestFlight, or linked-project verification as applicable, plus the wall checks), and welcome it to the wall with one app-relevant closing line or emoji. Keep it to one or two sentences and make it specific to what the app does; do not paste a generic template verbatim across a batch. When the user explicitly requests a no-comment approval, submit one app-relevant emoji as the entire approval body instead. Do not add separate summary comments beyond the approval; reply to review threads only when an actionable thread needs an explanation. Merge one PR at a time with a regular merge commit that preserves the PR commits, pinning the audited head, for example `gh pr merge <number> --merge --match-head-commit <sha>`. Do not squash unless the user explicitly requests squash for that PR.

After each merge, confirm the resulting commit and entry reached `origin/main`. When the user asks whether the app appears on the live Wall, verify the rendered `asccli.sh` page separately; source presence is not deployment proof, and advisory CI is not a reason to delay the live check.

## Automation contract

A standalone automation may approve and merge unattended only when its persisted prompt explicitly grants that authority. Apply the same approval-and-merge gates and branch-update rules above to each PR sequentially. Reuse local validation only while its inputs remain valid under `AGENTS.md`; refresh remote head, checks, reviews, threads, and mergeability immediately before acting and again after approval before merging.

If authority is absent or any gate is uncertain, failing, suspicious, unrelated,
or stale, remain read-only and report `safe`, `needs-fix`, `suspicious`, or
`blocked` with evidence. Persisted task authority may cover later passes, but a changed head requires fresh validation; an earlier approval is not proof that the new head passes the gates.

## Hand off

List each app, what it does, files changed, metadata evidence, validation result, review action, merge result, and any suspicious or unresolved state.
