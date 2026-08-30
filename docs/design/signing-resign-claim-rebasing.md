# Opt-in cross-team entitlement claim rebasing

## Status and scope

This note defines the design issue [#2249](https://github.com/rorkai/App-Store-Connect-CLI/issues/2249). Issue [#2251](https://github.com/rorkai/App-Store-Connect-CLI/issues/2251) is the implementation follow-up that should consume this contract. It is a design for a future additive capability; it does not change the current signing implementation.

The implementation depends on [#2241](https://github.com/rorkai/App-Store-Connect-CLI/pull/2241), which introduces `asc signing resign`. Its first version deliberately refuses existing claims that are not authorized by the replacement profile. Rebasing is an explicit exception to that refusal, and must never become an implicit fallback.

The design has four boundaries:

- only a small, documented set of team-prefix claim grammars may be transformed;
- every transformed value must be authorized by the replacement profile;
- references between embedded bundles are checked as one graph before any signing mutation;
- the result reports every transformation without exposing signing secrets or arbitrary profile data.

## Placement and command contract

The feature belongs to the existing experimental `signing resign` leaf. The command remains local and offline: it reads the IPA, identity, password file, and strict profiles manifest, and does not call App Store Connect.

The intended invocation is:

```text
asc signing resign \
  --ipa PATH \
  --output PATH \
  --identity PATH \
  --profiles-manifest PATH \
  [--identity-password-file PATH] \
  [--rebase-team-claims] \
  [--format FORMAT]
```

`--rebase-team-claims` is a command-specific `[experimental]` boolean flag. It defaults to false. `--output` remains the artifact destination, and `--format` remains the result renderer; the new flag must not overload either name.

When the flag is absent, the command retains the existing #2241 contract byte-for-byte where observable: an existing unauthorized claim is refused, the diagnostic gives manual remediation, and no automatic prefix derivation occurs. When the flag is present, only claims accepted by the rules below may be transformed. It is not an authorization bypass, a profile repair operation, or a way to grant a capability that was absent from the signed input.

The flag is rejected with a usage error on unsupported platforms before the IPA, profile, identity, or password is read. Missing or malformed values remain usage errors (exit 2); artifact, signing, verification, and profile-authorization failures remain ordinary non-zero command failures. Diagnostics go to stderr. Successful structured output goes to stdout unless the existing renderer contract directs it elsewhere.

## Existing behavior and dependency boundary

The #2241 pipeline inventories the main app and embedded application targets, reads their signed entitlements, validates the replacement profile for each target, generates exact entitlement documents, signs leaf-first, and verifies the packed IPA against those generated documents. It already preserves concrete subsets of existing identity-group claims and omits optional claims that were absent from the signed input.

The current refusal is important. For example, an existing `OLDPREFIX.com.example.shared` keychain group and a replacement profile containing `NEWPREFIX.*` cannot be silently changed merely because the suffix looks familiar. The new flag makes that transformation possible only after source-prefix, claim-grammar, profile-authorization, and whole-IPA checks succeed.

The code PR should be based on the version of #2241 that has actually merged, not on a stale or conflicting head. A main-based implementation cannot import #2241-only signing files safely while that command is still being integrated. A standalone design PR may land before #2241 because this document does not alter command help, generated command docs, or implementation files. Once #2241 lands, the implementation must refresh the merge-base and repeat the relevant review and validation gates.

## Prefix model and derivation

The following identifiers are distinct and must remain distinct in code and documentation:

- `oldPrefix`: the concrete App ID prefix in the existing target's signed `application-identifier`, before the dot separating the prefix from the bundle identifier;
- `newPrefix`: the replacement profile's `ApplicationIdentifierPrefix`;
- `oldTeamID` and `newTeamID`: the signed and replacement profile team identifiers;
- `oldApplicationID` and `newApplicationID`: the complete target application identifiers, including the prefix and bundle identifier.

An App ID prefix is often, but is not required to be, the Team ID. The implementation must therefore never derive a prefix from a Team ID and must never use a broad text replacement. The replacement profile's `ApplicationIdentifierPrefix` is the source of `newPrefix`, including when it differs from the replacement profile Team ID.

For every target that has a rebased claim:

1. Require a concrete existing `application-identifier` whose suffix exactly equals that target's bundle identifier.
2. Extract `oldPrefix` from that value and validate it with the existing identity validation rules.
3. Read `newPrefix` from the target's replacement profile. A profile wildcard may authorize a concrete target value, but the generated signed document must contain the concrete `newPrefix.<bundle-id>` value.
4. Require the profile's application identifier, team identifier, and certificate identity to pass the normal #2241 checks.
5. Derive each candidate transformed value only from the target's own `oldPrefix` and the replacement profile's `newPrefix`.

No v1 flag accepts user-supplied old or new prefixes. An override would make it possible to rewrite an unrelated prefix and would need a separate strict-input design. If a future override is considered, it must match the target's observed prefix and the profile's authenticated prefix rather than replacing those observations.

## Allowlist and value grammars

The allowlist is intentionally narrow. A key is not eligible because its value happens to contain a dot or a Team ID-looking string. Each key needs a documented grammar, a typed transformer, profile fixtures, and an exact post-signing verification test.

### Initial rewrite policy

| Entitlement key | Shape | Initial policy | Rule |
| --- | --- | --- | --- |
| `keychain-access-groups` | array of strings | allow, prefix-only | Transform each concrete `<oldPrefix>.<suffix>` item to `<newPrefix>.<suffix>`; preserve order and authorize the resulting array items against the replacement profile. |
| `com.apple.developer.ubiquity-kvstore-identifier` | string | allow, prefix-only | Transform one concrete `<oldPrefix>.<suffix>` value; authorize the concrete result. |
| `com.apple.developer.parent-application-identifiers` | array of strings | allow only through the App Clip graph | Do not perform a generic prefix swap; replace only the one value proven to be the discovered main app's old application identifier, using the main app's planned new application identifier. |
| `com.apple.developer.ubiquity-container-identifiers` | array of strings | defer by default | Enable only after signed/profile fixtures prove the exact prefix grammar and replacement profile authorization behavior. |
| `com.apple.developer.icloud-container-identifiers` | array of strings | defer by default | Treat the container identifier as a shared resource reference, not as a string to rewrite, until its signed grammar and ownership rules are proven for this command. |
| `com.apple.developer.icloud-container-development-container-identifiers` | array of strings | defer by default | Same boundary as production iCloud container identifiers; no speculative rewrite. |
| `com.apple.developer.associated-appclip-app-identifiers` | array of strings | defer or graph-only | If implemented, map references to discovered App Clip targets and verify both sides; never rewrite an arbitrary sibling bundle identifier. |

The first implementation should ship only the rows marked allow, with the graph-only parent rule implemented together with the target graph. Deferred keys remain unchanged and are either profile-authorized unchanged or refused by the existing fail-closed path. Adding a key later is an additive allowlist change with its own fixtures and output tests.

### Never-rewrite policy

These claims are never changed by prefix substitution:

- `application-identifier`;
- `com.apple.application-identifier`;
- `com.apple.developer.team-identifier`;
- `get-task-allow`;
- arbitrary unknown entitlement keys;
- `com.apple.developer.icloud-services` and other capability selectors whose values are not documented prefix grammars;
- application groups, associated domains, Apple Pay identifiers, push/environment claims, pass identifiers, Network Extension claims, and similar capability values;
- `previous-application-identifiers`, unless a separate update-continuity design proves its semantics and profile authorization.

The required identity values come from the replacement profile and the normal target checks. An existing optional identity claim remains absent when it was absent from the signed input, even if the replacement profile contains a concrete or wildcard value. Rebasing cannot add a keychain group, iCloud claim, parent relationship, or any other optional access claim.

### Prefix-only transformation

For a prefix-only string, accept exactly a non-empty concrete value with the form:

```text
oldPrefix + "." + non-empty-suffix
```

The suffix is copied as an opaque identifier after structural validation; it is not parsed by splitting on every dot and it must not contain a wildcard. The transformed value is:

```text
newPrefix + "." + same-suffix
```

For an array, apply the same rule to every element. A value with a third prefix, an unprefixed value, an empty suffix, a wildcard, a non-string element, or an ambiguous grammar fails closed. There are no silent partial rewrites.

An already-new-prefix value may remain unchanged only when it is concrete and the replacement profile authorizes it. A list may therefore contain source-old values that transform and already-new values that remain unchanged. Every other prefix is a refusal. This mixed-set rule is per element and is not an invitation to accept arbitrary values.

Preserve array order, element type, and length. The recommended policy is to reject duplicate elements when the rebasing flag is active: deduplication could change entitlement semantics and would make the audit record ambiguous. If compatibility evidence requires preserving duplicates, the implementation must preserve them exactly and report each indexed transformation; it must not silently deduplicate.

### Profile authorization after transformation

The pipeline must first calculate the complete candidate entitlement document, then ask the existing profile authorization routine whether each candidate is permitted. Authorization is checked against the transformed value, not the old value. A terminal wildcard profile value may authorize a concrete rebased value, but a wildcard must never be emitted in the signed document.

The following cases all fail closed:

- the replacement profile omits a claim that exists in the signed input;
- a transformed value is not authorized by the replacement profile;
- a profile wildcard is ambiguous or does not resolve to one target prefix;
- a required identity claim remains wildcard-only or otherwise non-concrete;
- a source value cannot be classified as old-prefix or already-authorized new-prefix;
- a candidate is accepted by a capability presence check but not by its value-specific profile entitlement.

The rebasing planner returns a new entitlement map and a separate ordered list of rewrite records. It must not mutate the existing entitlement map, profile object, archive, or output tree while evaluating authorization.

## Cross-target entitlement graph

Rebasing is a whole-IPA operation. The archive inventory is the graph's node set; each node includes target kind, relative path, bundle identifier, existing concrete application identifier, replacement profile, and planned new application identifier. Bundle identifiers and relative paths must be unique, and target ordering must be stable.

All target entitlement plans are built before the first generated entitlement file, embedded profile, or signed binary is written. The graph validator then checks references using the planned values:

- references must resolve to a discovered target in the same IPA;
- the referenced target kind must be valid for the claim;
- the referenced target's planned application identifier must be concrete;
- both source and replacement profiles must authorize their respective claims;
- a failure in any node or edge rejects the complete operation without a partial output IPA.

### App Clip parent relationship

`com.apple.developer.parent-application-identifiers` is an App Clip-only array with exactly one value. For a discovered App Clip, the value is eligible only when it equals the discovered main app's old concrete `application-identifier`. The planner then uses the main app's planned new concrete application identifier as the replacement value.

The App Clip replacement profile must authorize that exact new parent value. The main app and App Clip must both be present, uniquely identified, and paired by the archive relationship; a prefix that merely looks compatible is not sufficient. Reject multiple parent values, a parent outside the IPA, a missing or ambiguous main app, a mismatched pair, or a profile that does not authorize the planned value.

### Associated App Clip references

If `com.apple.developer.associated-appclip-app-identifiers` is added to the allowlist, it is graph-only. Each main-app reference must map to one discovered App Clip, and the App Clip must map back to the same main application. The planner uses the paired target's planned application identifier and checks both replacement profiles. It never performs a generic substitution on an arbitrary bundle identifier.

Other cross-bundle or sibling references remain unchanged and must be authorized unchanged by the replacement profile. If their relationship cannot be proven, the operation fails closed rather than signing a partially rebased IPA.

## Pipeline and verification order

The implementation should make the following phases explicit:

1. Inventory the IPA and validate every existing target entitlement before side effects.
2. Resolve each target's source prefix and replacement profile identity.
3. Plan required profile-derived identity claims and allowlisted local rewrites without changing the archive.
4. Validate every candidate against the replacement profile after transformation.
5. Validate the complete cross-target graph using planned application identifiers.
6. Sort and persist generated entitlements and profiles only after all plans pass.
7. Sign leaf-first using the existing explicit target and nested-code rules; do not rebase arbitrary framework, bundle, or XPC entitlements.
8. Verify the packed IPA against the exact generated entitlement documents, the replacement profiles, and the signing identity.
9. Repack and emit the structured result atomically using the existing no-overwrite output contract.

The verification comparison must use exact generated documents, not profile-subset semantics. A profile wildcard authorizes a concrete value; it does not make a different signed value acceptable. The post-sign verifier must remain read-only and must not call a preparation function that writes temporary files.

Rewrite records are collected from the plan, not reconstructed from logs or from a second potentially different parse of the packed IPA. Sort records by target relative path, allowlisted key order, and array element index. This makes JSON, table, Markdown, tests, and retries reproducible.

## Result and audit output

The current `signing resign` command emits a structured `SigningResignResult`; it does not write a separate receipt file. This feature should extend that result additively rather than introduce a second persistence format or an overwrite-prone receipt flag.

Add an always-present, possibly empty `entitlementRewrites` array. One record represents one scalar rewrite or one array element, so mixed values and ordering are unambiguous:

```json
{
  "targetRelativePath": "Payload/App.app/PlugIns/Clip.appex",
  "bundleId": "com.example.Clip",
  "key": "keychain-access-groups",
  "elementIndex": 0,
  "from": "OLDPREFIX.com.example.shared",
  "to": "NEWPREFIX.com.example.shared"
}
```

`elementIndex` is omitted for a scalar claim and is zero-based for an array claim. Exported Go fields use the repository's camelCase JSON convention. Keep the existing schema version and add the field under the output stability rules; do not remove or rename existing fields. Rows for table and Markdown output must use the same deterministic ordering and clearly identify target, key, index, old value, and new value.

Exact old and new values are appropriate here because they are limited to explicitly allowlisted identifiers being transformed locally and are required to audit what was signed. The result must never contain passwords, private keys, profile source paths, raw profile plists, temporary paths, subprocess diagnostics, or unchanged arbitrary entitlement values. A failure diagnostic may identify target, key, element index, and a value-safe reason, but must not echo operational secrets.

When the flag is absent, `entitlementRewrites` is an empty array. A failed operation does not publish a success result or partial rewrite receipt. If a future workflow needs a durable file receipt, it must define destination preflight, mode, no-overwrite behavior, atomic publication, and redaction separately; that is outside this feature.

## Failure, compatibility, and lifecycle

The flag is experimental and additive:

- existing invocations, help behavior, output fields, refusal text, and exit mappings remain unchanged when it is omitted;
- existing profiles, signed entitlements, and optional-claim omission rules are not broadened by merely adding the flag;
- all validation occurs before signing mutations, and the output artifact is still no-replace and atomic;
- a profile authorization failure is never converted into a warning or a best-effort rewrite;
- a missing grammar, ambiguous target relationship, malformed value, or unsupported claim remains fail-closed;
- the operation remains macOS-only and has no App Store Connect network side effects.

The initial release should not migrate old invocations or change the default. Any future move from experimental to stable requires explicit help, documentation, output, and regression review. A future allowlist addition is a separate compatibility decision and must not make an existing invocation rewrite more values merely because a new binary is installed unless the opt-in flag is present.

## Implementation plan

After #2241 has merged and its command surface is current, implement the feature in these areas:

1. `internal/cli/signing/signing_resign.go`: add `RebaseTeamClaims` to command options, bind the experimental flag, and include the exact help text and plumbing.
2. `internal/cli/signing/signing_resign_entitlements.go`: add typed allowlist metadata, source-prefix parsing, scalar and list planners, duplicate/mixed-prefix checks, and post-transform profile authorization. Return rewrite records as data, not side effects.
3. `internal/cli/signing/signing_resign_archive.go`: expose a stable target graph and old/new application-identifier lookup, or place the equivalent helper in the pipeline package without duplicating archive discovery.
4. `internal/cli/signing/signing_resign_pipeline.go`: plan every target before writes, validate graph edges, propagate rewrite records, retain exact generated-document verification, and keep nested non-target code outside the rebase scope.
5. `internal/asc/output_signing_resign.go`: add exported rewrite result types and deterministic table/Markdown rows while preserving the existing result fields.
6. `internal/asc/output_signing_resign_test.go`: assert JSON field shape, empty and non-empty arrays, table headers/rows, Markdown rows, and ordering.
7. `internal/cli/signing/signing_resign_test.go`: add unit, command-boundary, planning, graph, authorization, ordering, and no-mutation coverage.
8. `internal/cli/signing/signing_resign_privacy_test.go`: assert that success and failure output do not leak credentials, profile paths, raw profiles, temporary paths, or non-allowlisted claims.
9. `commands/signing.mdx` and `docs/design/signing-ipa-resign.md`: update only after the #2241 command surface exists on the target branch. Document the opt-in flag, allowlist, graph rules, output records, and refusal examples.

`internal/cli/signing/signing_resign_manifest.go`, `internal/cli/signing/signing_json.go`, and `internal/asc/output_registry_init.go` should remain unchanged unless implementation discovers a real schema or renderer registration requirement. The standalone design PR changes only this design document.

## RED-GREEN test matrix

Tests should begin with the smallest failing assertion at the command or planner boundary, then reach green with the narrow implementation. The existing wildcard test named `TestBuildSigningResignEntitlementsKeepsConcreteValuesForWildcardProfileClaims` uses already-new values and does not prove old-prefix rebasing; add an explicit old-prefix case rather than treating it as coverage.

### Command and compatibility

- `TestSigningResignCommandExposesRebaseTeamClaimsFlag`: help shows the experimental long-form flag and its default-off meaning.
- `TestSigningResignCommandPassesRebaseTeamClaimsOption`: the flag reaches the execution options; no flag leaves the option false.
- `TestSigningResignCommandRejectsInvalidFlagShapes`: positional arguments, unsupported values, and platform-ineligible use remain usage errors with stderr diagnostics and exit 2.
- A no-flag regression test runs the current unauthorized old-team claim case and asserts the existing refusal/remediation contract is unchanged.

### Prefix and allowlist behavior

- `TestBuildSigningResignEntitlementsRequiresExplicitRebaseOptIn`: old-prefix keychain and key-value claims fail without the flag and transform with it.
- `TestRebaseSigningResignClaimUsesProfileApplicationIdentifierPrefix`: a legacy source prefix and a different replacement Team ID still use the profile App ID prefix.
- `TestRebaseSigningResignClaimRejectsUnknownThirdPrefix`: a third prefix fails closed.
- `TestRebaseSigningResignClaimRejectsMalformedUnprefixedAndWildcardValues`: empty suffixes, unprefixed values, and wildcards fail closed.
- `TestRebaseSigningResignClaimPreservesListOrderAndShape`: old and already-new values remain in original order and retain array shape.
- `TestBuildSigningResignEntitlementsMixedOldNewTeamClaims`: old values transform, authorized new values remain, and unrelated values fail.
- A duplicate-element test asserts the chosen reject-or-preserve policy; the implementation must never silently deduplicate.
- `TestBuildSigningResignEntitlementsStillOmitsAbsentOptionalClaimsWithRebase`: the flag cannot add absent optional claims from the profile.

### Profile authorization and pipeline safety

- `TestRebaseSigningResignClaimRequiresReplacementProfileAuthorization`: wildcard profile authorization accepts a concrete rebased value; concrete profiles require exact membership.
- A missing profile key, non-authorized transformed value, wildcard-only required identity, and ambiguous wildcard prefix each fail before signing.
- `TestPrepareSigningResignTreePlansAllRewritesBeforeMutation`: a later target or edge failure leaves no generated entitlement, embedded profile, or output-tree mutation.
- `TestRebaseSigningResignRewriteOrderingIsStable`: map iteration order cannot change records or generated documents.
- `TestRebaseSigningResignPostSignDocumentMatchesRewrittenEntitlements`: verification compares the exact concrete transformed document and rejects a different authorized subset.

### Cross-target graph

- `TestRebaseSigningResignParentApplicationIdentifierUsesReplacedMainApplicationID`: an App Clip parent claim follows the main app's planned concrete application identifier.
- `TestRebaseSigningResignParentRejectsMultipleParents`: more than one parent value fails.
- `TestRebaseSigningResignParentRejectsReferenceOutsideIPA`: an undiscovered parent fails.
- `TestRebaseSigningResignParentRejectsMismatchedMainClipPair`: a relationship that cannot be proven fails.
- `TestRebaseSigningResignParentRequiresBothProfilesAuthorize`: both target profiles must authorize the planned relationship.
- If associated App Clip identifiers are enabled, add a paired two-way mapping test and an arbitrary-sibling-reference rejection test.

### Output and privacy

- `TestSigningResignResultReportsEveryEntitlementRewrite`: JSON contains target, bundle, key, optional index, exact old value, and exact new value for every rewrite.
- Renderer tests assert deterministic table and Markdown rows and an empty array when the flag is absent.
- Privacy tests inject a password, profile path, temporary path, and non-allowlisted entitlement and assert that none appear in result or refusal output.
- Built-binary checks assert stdout/stderr separation, exit codes, and no duplicate error rendering.

Focused signing tests should run first with `ASC_BYPASS_KEYCHAIN=1`. Before implementation is opened for review, run the repository's required serialized gates: `make build`, `make format`, `make check-docs`, `make lint`, and `ASC_BYPASS_KEYCHAIN=1 make test`. A macOS fixture with genuinely signed nested targets should verify codesign and concrete entitlements; it must remain local and read-only with respect to App Store Connect.

## Alternatives and unresolved gates

Keeping the #2241 refusal forever is the safest option but leaves maintainers to rewrite every claim manually. It remains the default and is the fallback for every ambiguous case.

Accepting `--old-prefix` and `--new-prefix` would make the workflow appear flexible, but it delegates a security-sensitive identity decision to an unchecked string and can rewrite a different application's claims. Deriving from the signed target and authenticated replacement profile is narrower and auditable.

Rewriting every dotted string or copying the complete profile entitlement set would be shorter, but would grant or alter capabilities that were not present in the signed input. Typed allowlist planners preserve the least-privilege boundary.

Before coding, maintainers must resolve these gates with fixtures or retain the stated fail-closed defaults:

- whether iCloud and ubiquity container identifiers are genuinely prefix-scoped in the signed values used by this command;
- whether associated App Clip identifiers are included in the first graph implementation;
- whether duplicate array elements are rejected (recommended) or preserved exactly;
- whether exact old/new allowlisted values are acceptable in normal result output, with only secrets and non-allowlisted claims redacted;
- #2249 remains the canonical design issue and #2251 is the implementation follow-up; implementation work should link both issues.

No gate may be resolved by making the flag broader or by treating a passing profile capability-presence check as value authorization.
