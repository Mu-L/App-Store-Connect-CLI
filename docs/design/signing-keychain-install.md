# Persistent signing keychain installation

## Status

Proposed for 4.12.0 as an experimental command.

## Problem

`asc signing run` already creates an isolated temporary keychain, installs one
identity for a child process, and removes the keychain afterward. Provisioning
profiles already have a separate persistent installer under
`asc profiles local install`. There is no equivalent non-interactive path for
keeping a private signing identity in a dedicated keychain across commands or
CI steps.

## Decision

Add:

```bash
asc signing keychain install \
  --identity .asc/signing/App.p12 \
  --identity-password-file .asc/secrets/p12-password \
  --keychain .asc/keychains/release.keychain-db \
  --keychain-password-file .asc/secrets/keychain-password \
  --add-to-search-list \
  --confirm
```

The command creates one new, dedicated keychain and imports exactly one
currently valid code-signing identity. It never imports into an existing
keychain. Refusing an existing destination avoids changing unrelated keys and
keeps the partition-list update scoped to the newly created identity.

The keychain and PKCS#12 passwords come only from protected regular files.
Neither secret is accepted directly as a flag, included in output, or placed
in a subprocess argument. `--confirm` is required because the keychain remains
on disk after the process exits. `--add-to-search-list` is explicit and
preserves the existing user search-list order.

An optional `--expected-certificate-sha256` binds the operation to a known
certificate. The PKCS#12 is decoded and checked for a matching private key,
current certificate validity, code-signing usage, and the expected digest
before the keychain is created.

## Failure and rollback contract

All input, destination, and output-format validation happens before the first
side effect. Once creation succeeds, any later import, verification, or search
list failure triggers deletion of the new keychain and restoration of the
original search list. A host-created automatic search-list entry is removed
immediately when `--add-to-search-list` is absent; explicit activation is the
last operation when the flag is present. If both the primary operation and
rollback fail, both errors are returned.

The command does not delete, replace, or merge an existing keychain. It does
not install provisioning profiles; use `asc profiles local install` for that
independent persistent operation. It does not change the default keychain.

## Output

JSON output is a computed result with only public information:

```json
{
  "action": "installed",
  "keychainPath": "/absolute/path/release.keychain-db",
  "certificateSha256": "...",
  "certificateSha1": "...",
  "teamId": "TEAM12345",
  "searchListUpdated": true
}
```

Human-readable renderers expose the same fields. Source identity paths and all
password material are omitted.

## Compatibility

The command is additive and macOS-only. It requires a cgo-enabled build so the
Security framework can create the keychain and import PKCS#12 data without
putting passwords in process arguments. Other platforms return a validation
error without reading secrets or creating files.
