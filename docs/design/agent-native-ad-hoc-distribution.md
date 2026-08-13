# Agent-native ad hoc distribution

## Product direction

ASC should turn a local Xcode archive into a verifiable install result that an
agent can hand to a person or another system. The public contract is based on
the outcome, not on Fastlane lanes or AWS-specific vocabulary. Each stage emits
structured output, writes deterministic artifacts under an operator-selected
root, and can be retried without repeating completed account mutations.

The complete workflow is planned as separate reviewable changes:

1. Generate modern Xcode `release-testing` export options and export an IPA.
2. Inspect the IPA and prepare a self-contained web-install bundle.
3. Publish that bundle through a caller-provided S3-compatible endpoint.
4. Reconcile registered devices and ad hoc provisioning profiles.
5. Sync and install the private signing identity under explicit local control.
6. Compose the stages into a resumable run with a durable receipt.

The first change in this stack owns only item 1. The second change owns only
local inspection and preparation from item 2; publishing remains a separate
network-facing boundary.

## PR 2 public contract

The experimental `distribute` family begins with two provider-neutral local
commands:

```text
asc distribute inspect --ipa ./App.ipa [--include-devices] [--output json|table|markdown]
asc distribute prepare --ipa ./App.ipa [--output-dir DIR] [--title TITLE] \
  [--channel CHANNEL] [--source-revision REVISION] [--source-url URL] \
  [--output json|table|markdown]
```

`inspect` opens the IPA once without following a symlink, validates every ZIP
member name, rejects encrypted members, duplicate paths, an ambiguous main app,
and oversized selected metadata, then reports app, artifact, provisioning
profile, certificate, and metadata-preparation facts. Raw device UDIDs are
omitted unless the caller explicitly requests `--include-devices`; deterministic
device-set and certificate fingerprints are safe to pass between agents.

`prepare` applies the same inspection and requires an unexpired ad hoc profile
whose bundle identifier matches the main app and contains at least one device.
It writes a deterministic descriptor followed by the unchanged IPA in this
layout:

```text
bundle.json
payload/app.ipa
```

The default path is
`.asc/distribution/<safe-bundle-id>/<version>-<build>-<first-12-ipa-sha256>`.
The descriptor contains no timestamp, absolute input path, raw device UDID, URL
manifest, or storage-provider setting. An existing byte-for-byte-equivalent
bundle is reported as reused. Any other existing destination is a conflict and
is never overwritten. A new bundle is assembled in an unpredictable sibling
directory and published with no-replace semantics so `bundle.json` is never a
receipt for a partial bundle.

Both commands print data to stdout, diagnostics to stderr, and use exit code 2
for invalid flags or missing required flags. IPA or preparation validation
failures use the ordinary non-zero command error. This is an additive
experimental surface and requires no migration.

### PR 2 security and verification

An IPA is treated as an untrusted ZIP, never extracted wholesale. Member names
must be canonical relative slash paths without traversal, backslashes, NUL or
control characters. The archive has fixed overall-size, entry, and
declared-expansion limits;
the main `Info.plist` is capped at 4 MiB and the embedded provisioning profile at
16 MiB, with both advertised-size and streamed-size enforcement. Preparation
uses rooted, no-follow reads and writes, copies from the already-open IPA file,
writes the descriptor last in staging, and refuses replacement at publication.

RED-GREEN coverage includes the complete JSON schema, explicit device
disclosure, ad hoc/development/enterprise/App Store classification, expired and
mismatched profiles, missing metadata, malicious ZIP paths, duplicate and
ambiguous app members, compressed-size limit bypasses, deterministic default
paths, exact reuse, conflict/no-overwrite behavior, table/Markdown rendering,
help/registration, built-binary stdout/stderr and exit behavior, command-doc
generation, and the repository validation gate.

Keeping install manifests out of preparation avoids pretending that URLs exist
before a publisher assigns them. Extracting the IPA to a directory would make
symlink and traversal handling much broader without adding needed metadata.
Using a mutable channel directory as the bundle identity would be convenient
for humans but would prevent safe retries and verifiable agent handoffs; channel
is therefore descriptor metadata rather than an output-path key.

The preparation result is `metadataEligible`; there is deliberately no generic
`eligible` or `installable` boolean. Inspection and the persisted descriptor
separately report profile CMS integrity, Apple profile trust, and the scoped
`complete-main-app-code-resources-entitlements-and-profile-certificate-binding`
verification. On macOS the
complete main app is safely materialized into private bounded staging,
`codesign --deep --strict` verifies its resource envelope and nested code, and
each architecture's leaf signer certificate must occur in the embedded profile.
Signed team, application identifier, debugging state, and other entitlements
must be permitted by that profile. This does not claim project-wide verification
when embedded targets exist; those IPAs remain blocked. Profile trust requires
the expected Apple provisioning signer and a chain to an exact pinned Apple
root. The verifier does not use the host root store and fails closed when a
recognized root is not carried in the CMS; supporting a newly introduced Apple
root requires a CLI update. CMS signature integrity alone is not Apple
authenticity. `prepare` refuses to write unless profile integrity, Apple trust,
and the exact complete-main-app signature scope are all `verified`.

Profile certificate fingerprints are explicitly named
`profileCertificateSha256Fingerprints`: they prove which certificates the
embedded profile permits, not which identity signed the IPA. An IPA containing
extensions, watch apps, or App Clips reports those target metadata paths but is
not marked eligible in this change; a later signing slice must validate every
target/profile pair before preparation claims project-wide readiness.

IPA processing is copied once from the already-open input into a private
snapshot so parsing, hashing, and publishing bind the same bytes. It is capped
at 8 GiB before ZIP parsing; selected metadata and the complete materialized
main app have expanded-size limits. Provenance text, IPA metadata, and ZIP member names are
bounded and reject control, Unicode format, and bidirectional-control characters.
`--source-url` must
be an absolute HTTPS URL with no user information, query, or fragment so a
deterministic descriptor cannot become a credential or signed-URL sink.

This boundary matches current production patterns without inheriting their
storage implementation: Blockstream separates local caller-URL bundle
generation from upload; Mattermost uses immutable PR, merge, and commit object
paths; Onym records structured build metadata and caps its index; ipa-server
generates the complete web-install surface across providers. Retention,
encryption, serialization, immutable object keys, channel indexes, comments,
and final install URLs remain publishing concerns rather than local preparation
concerns.

## Placement and current behavior

`asc xcode export-options generate` currently always writes
`method=app-store-connect`. `asc xcode export` implicitly generates the same
options when `--export-options` is omitted. A caller can provide a custom plist,
but ASC cannot generate the non-App-Store export used for ad hoc delivery.

Xcode 26.6 and Xcode 27 call this method `release-testing`. Both versions still
accept `ad-hoc`, but mark it deprecated. ASC will use the current Xcode name and
will not introduce the deprecated spelling as a new public value.

## PR 1 public contract

The standalone generator adds:

```text
asc xcode export-options generate \
  --archive-path .asc/artifacts/App.xcarchive \
  [--method app-store-connect|release-testing] \
  [--destination export|upload] \
  [--signing-style automatic|manual]
```

`--method` defaults to `app-store-connect`, preserving every existing
invocation. `release-testing` requires `--destination export` because it creates
a local IPA rather than an App Store Connect upload. Its default output is
`.asc/export-options-release-testing.plist`; the existing App Store default
remains `.asc/export-options-app-store.plist`.

`asc xcode export` receives the same `--method` flag for its implicit generator:

```text
asc xcode export \
  --archive-path .asc/artifacts/App.xcarchive \
  --method release-testing \
  --signing-style manual \
  --ipa-path .asc/artifacts/App.ipa
```

An explicit `--export-options` file remains authoritative and cannot be combined
with `--method`, `--signing-style`, or `--team-id`. The default export method
remains `app-store-connect`. No existing output field changes; `method` reports
the actual generated value. Invalid values are usage errors with exit code 2.
Data remains on stdout and diagnostics remain on stderr.

## Implementation and compatibility

The repository-owned generator passes the selected method to the pinned Bitrise
typed models. App Store Connect continues to use the App Store model.
Release-testing uses the non-App-Store model. Manual signing resolution receives
the selected method so profile selection matches the requested export. The
pinned resolver still classifies installed ad hoc profiles with Xcode's legacy
`ad-hoc` enum, so ASC translates only at that internal resolver boundary and
continues to emit `release-testing` in the generated plist.

The change is additive. No deprecation or migration is required. The legacy
`ad-hoc` Xcode spelling is intentionally rejected with guidance to use
`release-testing`.

## RED-GREEN and verification

Coverage must establish:

- valid generator and implicit-export parsing for both methods;
- invalid and explicitly empty method values as usage errors;
- rejection of release-testing with `destination=upload` or `xcode export --wait`;
- conflict errors when `--method` accompanies an explicit plist;
- exact `method=release-testing` plist and JSON output;
- manual generator receipt of the selected method;
- portable and Darwin typed-model parity;
- unchanged app-store-connect defaults;
- generated command documentation, focused tests, built-binary stdout/stderr and
  exit codes, followed by the repository validation gate;
- real archive export with Xcode 26.6 and Xcode 27 before the distribution stack
  is declared complete.

## Alternatives

Accepting `ad-hoc` would mirror older automation tools but create a deprecated
surface on day one. Hiding the method only inside the future distribution
orchestrator would leave `asc xcode export` incomplete and make that orchestrator
depend on a private code path. Supporting every Xcode export method in this
change would widen the review without helping the first install-link workflow.
