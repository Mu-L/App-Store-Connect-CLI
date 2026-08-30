# IPA re-signing design

## Placement and command shape

Add `resign` below the existing `signing` command group. The command is an
experimental, macOS-only local operation:

```text
asc signing resign --ipa PATH --output PATH --identity PATH --profiles-manifest PATH [--identity-password-file PATH] [--format FORMAT]
```

`--ipa`, `--output`, `--identity`, and `--profiles-manifest` are required.
The destination is create-only: an existing path is a hard conflict and there
is no overwrite flag in the first release. Positional arguments are rejected.
The output format uses the repository's standard table, JSON, and Markdown
renderers. The operation has no App Store Connect API endpoint or network
dependency.

## Current behavior and boundaries

`asc signing run` imports one identity and one profile into an isolated,
temporary keychain/profile environment for a child process. Archive signing
reconciliation discovers app-like targets and validates entitlements, while
distribution inspection can validate a main app and its nested code but
explicitly does not prepare embedded targets. None of those commands mutates
an existing IPA.

The new operation must reuse the signing identity parsing and temporary
keychain boundary, but must not install profiles globally. IPA parsing and
publication should use the bounded ZIP, `rootfs`, and `secureopen` patterns in
`internal/distribution` and `internal/xcode`.

## Local pipeline

1. Reject unsupported platform, positional arguments, missing flags, invalid
   format, and an existing output before opening private signing inputs.
2. Open the input through no-follow rooted access and snapshot it into private
   mode-0700 temporary storage. Validate archive entry names, duplicate paths,
   file/directory collisions, symlinks, encryption, declared expansion, and
   actual streamed expansion.
3. Require one `Payload/*.app` and discover only the supported app-like target
   locations: app extensions, watch applications/extensions, and App Clips.
   Validate each target's bounded `Info.plist`, bundle identifier, executable,
   platform, and Mach-O executable. Reject unrecognized nested app bundles.
4. Strictly decode the manifest before creating any keychain. It maps each
   discovered target's exact bundle identifier to a relative, regular,
   no-follow profile file. Reject unknown fields, duplicate keys, duplicate
   mappings, traversal, wildcards, and extra/missing targets.
5. Parse and verify every profile's CMS integrity and Apple trust chain,
   classify development/ad-hoc/App Store profiles, reject enterprise/unknown
   classes, and require one team and one identity certificate binding. Parse
   the PKCS#12 identity and require one usable private key, matching leaf
   certificate, current validity, and a team/certificate match for every
   profile.
6. Use the private mutable staging snapshot. For each app-like target, replace
   `embedded.mobileprovision`, derive
   provisioning-controlled entitlements from the existing signed entitlements,
   and reject any non-identity capability change that is not permitted by the
   replacement profile.
7. Create a dedicated temporary keychain using the existing recovery/journal
   and lock boundary, import the already validated identity, and sign leaf
   nested frameworks/dylibs before nested bundles, extensions, watch apps/App
   Clips, and the main app. Invoke `/usr/bin/codesign` directly with an
   explicit keychain and identity; never use `codesign --deep` for mutation.
8. Verify every target and nested Mach-O object with bounded direct tool
   invocations, including resource seal, profile, entitlements, team,
   application identifier, and signer certificate binding. Repack into a new
   IPA, validate the generated archive, and publish with no-replace atomic
   rooted output. The input is never rewritten.
9. Remove temporary keychain, generated entitlements, staging, and journal on
   all paths. Cleanup errors are joined with the primary error and cannot be
   reported as success.

## Output and errors

JSON is a schema-versioned receipt containing only input/output size and
SHA-256 digests, public leaf-certificate digest/team, target relative path and
bundle identifier, profile class/UUID/digest, and an all-target verification
status. Table and Markdown expose the same safe fields. It never emits
passwords, PKCS#12/profile source paths, temporary keychain paths, raw profile
plists, device identifiers, or raw subprocess diagnostics.

Usage validation returns exit code 2. IPA, profile, identity, entitlement,
signing, verification, cleanup, and publication failures return a nonzero
execution error. Exit 0 is possible only after output publication and parent
directory synchronization succeed. A post-rename durability error is
reported as ambiguous publication and the artifact is left in place.

## Compatibility and alternatives

This adds only an experimental command and does not alter `signing run`,
archive reconciliation, distribution inspection, or stable output schemas.
It intentionally supports only iOS device IPAs and development, ad-hoc, and
App Store profiles; other platforms, enterprise profiles, wildcards, arbitrary
entitlement files, and overwrite behavior remain unsupported.

An alternative is to shell out to Xcode export. That cannot safely express a
complete existing-IPA target/profile mapping and would make output and cleanup
less deterministic. Another alternative is to add a general-purpose signing
library. That would duplicate Apple's signing tool behavior and enlarge the
review surface; direct, bounded `/usr/bin/codesign` calls keep the trust
boundary explicit.

## RED/GREEN validation

Begin with CLI tests for registration, help, required flags, positional args,
output formats, macOS gating, and exit behavior. Add unit tests for strict
manifest decoding, archive/target inventory, profile and identity binding,
entitlement rewriting, leaf-first order, no-deep mutation, output redaction,
no-replace publication, cancellation, and cleanup. Add macOS integration
coverage with a disposable signed nested-target fixture when signing assets
are available.

Required repository gates:

```bash
make build
make format
make check-docs
make lint
ASC_BYPASS_KEYCHAIN=1 make test
```
