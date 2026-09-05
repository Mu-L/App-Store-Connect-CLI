---
name: release-asc-cli
description: Publish and verify a new release of the App-Store-Connect-CLI repository. Use only when the user explicitly asks to release, tag, or publish a specific ASC CLI version, including the full GitHub release, artifact, Homebrew, WinGet, cleanup, and release-announcement workflow.
---

# Release the ASC CLI

## Prove the release target

1. Resolve the requested plain semantic version without a `v` prefix.
2. Fetch `origin` and inspect the requested tag locally and remotely, any release, and its workflow runs before acting. For a new release, require the tag to be absent and inspect the release-worthy delta since the previous tag. When resuming, verify that the existing tag points to the previously approved release commit and resume only unfinished work; stop on a target mismatch.
3. Query open PRs and confirm the intended changes are already merged.
4. For a new release, create a clean detached worktree from the exact current `origin/main` commit. When resuming, use the tag's previously approved, verified release commit. Do not release from a dirty user checkout or an unmerged branch.
5. Inspect `.github/workflows/release.yml` and current repository guidance instead of assuming an older release procedure still applies.

## Run the release gate

For a new release, run and record the following checks. On resume, reuse completed checks only while their inputs remain valid under `AGENTS.md`; verify consumer-visible state freshly.

```bash
make format
make check-docs
make check-wall-of-apps
make lint
ASC_BYPASS_KEYCHAIN=1 make test
make build
./asc version
```

If formatting changes files, inspect the diff and stop the release gate. Prepare necessary corrections on a branch only when authorized; they must pass repository review and validation and merge through the normal PR process before restarting from the updated `origin/main`. Never tag a correction committed only in the detached release worktree. Stop on unexplained failures; do not tag around a broken gate.

## Publish

1. For a new release, refresh `origin/main` and reconfirm the worktree HEAD equals the intended current `origin/main` commit. If `origin/main` advanced, inspect the delta and restart target selection and the release gate in a clean detached worktree at the newly selected commit before tagging. Checks run in the old worktree do not validate the new commit.
2. Create an annotated tag using the exact requested version and push that tag explicitly. On resume, reuse the verified existing tag: skip the push if the remote tag already matches; if only the local tag exists, push it only within the established release authority. Never replace a mismatched remote tag.
3. Locate the tag-triggered GitHub Actions run and watch it through completion.
4. Do not retry by silently moving or recreating a published tag. Diagnose failures and preserve the immutable release history.

## Verify consumer-visible state

Verify:

- The GitHub release is published, not draft or prerelease unless requested.
- Expected macOS, Linux, Windows, and checksum assets exist.
- A downloaded macOS binary reports the requested version and passes `codesign --verify`.
- Downloaded artifact hashes match the published checksum file.
- The Homebrew formula points to the new version and hashes.
- The expected WinGet submission or PR exists and references the new version.
- Any notarization step required by the current workflow succeeded.

If the `winget` job failed, inspect its rate-limit preflight, retry history, and current submission state first. For a transient failure, prefer one rerun of the failed job before manual repair; dispatch the full workflow only after confirming it will safely reuse the existing release. Wait for the logged reset time only when the primary quota bucket is zero; back off a few minutes for secondary throttles, 5xx responses, or transport failures. After a failed retry or a non-transient error, report the exact blocker instead of looping. See `docs/WINGET.md`.

## Draft the announcement

Read [references/release-announcement.md](references/release-announcement.md) and prepare the announcement copy after the release is visibly published. Create an external Typefully draft only when the request or established context authorizes that write; otherwise return the copy locally. Never schedule or publish the post unless the user explicitly asks.

## Clean up and hand off

Remove only a clean temporary release worktree created by this run as part of its authorized cleanup; preserve unexpected changes. Report the released commit and tag, release URL, artifact verification, Homebrew and WinGet state, remaining blockers, and announcement status separately. An optional external draft does not prevent reporting a verified binary release.

## Automation boundary

Do not schedule unattended releases. After an explicitly initiated tag push, a thread heartbeat may watch the release run and finish authorized downstream verification. Save the version, immutable commit and tag, run IDs, completed checks, authority, next step, and retry history; create or reuse one heartbeat and end the turn. On wake, reconcile current state once, stay quiet and back off when unchanged, and disable the heartbeat on completion or a blocker requiring user action. Never use a heartbeat to recreate or move the tag.
