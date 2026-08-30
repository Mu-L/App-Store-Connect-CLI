# [experimental] Local certificate identity export

## Placement and current behavior

This experimental change adds `asc certificates export` beneath the existing
`asc certificates` command group. It is an offline artifact operation and
does not add a public API endpoint or web-session operation.

Today `asc certificates csr generate` writes an RSA private key and a CSR,
while `asc certificates create` creates only certificate types supported by
the App Store Connect API. Apple Push Services and Website Push ID
certificates are obtained through Apple's Developer website. Once the
operator downloads the resulting X.509 certificate, the CLI has no safe,
deterministic way to combine it with the locally generated private key.

The public API `CertificateType` enum and `POST /v1/certificates` operation do
not expose those certificate types, so this command must not pretend to issue
or renew them remotely. The existing web-session command surface also remains
unchanged.

## Public command shape

```text
asc certificates export \
  --certificate ./push/push.cer \
  --private-key ./push/push.key \
  --password-file ./secrets/push.p12.password \
  --p12-out ./push/push.p12 \
  [--csr ./push/push.csr] [--force --confirm] \
  [--output table|json|markdown] [--pretty (JSON only)]
```

`--certificate`, `--private-key`, `--password-file`, and `--p12-out` are
required. `--csr` is optional and, when present, provides an additional
PKCS#10 signature and public-key check. `--force` together with `--confirm` is
required to replace an existing destination. `--pretty` requires
`--output json`. `--p12-out -` is rejected so binary data can never be written
to stdout.

Usage errors return exit code 2; validation and artifact-write failures return
nonzero; successful renderers write only metadata to stdout and diagnostics to
stderr. The command accepts one DER `.cer` or PEM X.509 certificate, one
unencrypted RSA or supported EC private key in an existing supported PEM
format, and one optional PEM or DER CSR.

## Validation and output

All inputs are validated before the destination is changed:

- files are regular, bounded, no-follow inputs using the repository's
  protected-file policy for private keys and passwords;
- on Windows, protected inputs must have a verifiable restricted DACL, and the
  new output is assigned and verified with a protected owner DACL before it is
  published;
- certificates, private keys, and CSRs are non-empty and contain exactly one
  supported object;
- the certificate is currently valid (`NotBefore <= now < NotAfter`);
- the private-key public key matches the certificate;
- an optional CSR has a valid signature and matches both keys.

The password is read only from `--password-file`, with one final LF or CRLF
removed and an empty result rejected. It is never accepted as a flag, emitted
in diagnostics, or included in telemetry.

The output contains exactly one private key and one leaf certificate encoded
with the existing modern PKCS#12 encoder. No CA chain is added in v1. The
file is written with mode `0600` through a same-directory atomic write. A
symlink, directory, input/output collision, or existing destination without
`--force --confirm` is rejected. A failed validation or encode leaves an
existing destination unchanged.

The experimental JSON result contains only metadata, for example:

```json
{
  "operation": "certificates export",
  "certificatePath": "./push/push.cer",
  "privateKeyPath": "./push/push.key",
  "csrPath": "./push/push.csr",
  "p12Out": "./push/push.p12",
  "certificateSha256": "64-hex-fingerprint",
  "notBefore": "2026-08-30T00:00:00Z",
  "notAfter": "2027-08-30T00:00:00Z",
  "keyType": "RSA",
  "keySize": 2048,
  "privateKeyMatched": true,
  "csrMatched": true
}
```

`csrPath` and `csrMatched` are omitted when no CSR is supplied. Table and
Markdown renderers expose the same non-secret fields. Certificate, CSR, key,
and password bytes are never printed or logged.

## Compatibility and lifecycle

The experimental subcommand is additive and does not change existing certificate, CSR,
pass-type, merchant-ID, signing, authentication, or web-session behavior.
It packages an artifact; it does not create, renew, revoke, download, or
classify a certificate. Renewal remains explicit: obtain a new certificate
through Apple's Developer website, then rerun this command, using `--force`
only when intentionally replacing an existing identity file.

The command does not touch the keychain, register Website Push IDs, enable
capabilities, send notifications, generate token credentials, or schedule
background renewal. It deliberately does not classify service purpose from
certificate subject fields because that cannot be proved from arbitrary input.

## Security hardening follow-up

The output path is checked before any input is read or destination directory is
created. Every existing parent component is inspected through an anchored,
no-follow traversal; a symlinked parent is rejected even when the final output
entry does not exist. Missing components may be created normally after that
check, while the final output remains protected by the shared rooted writer.

Publication is fail-closed for this secret artifact. A native no-replace rename
or atomic hard-link publication is required; filesystems that expose neither
primitive return an error instead of copying bytes into a visible destination.
This keeps observers from seeing a partially written identity.

On Windows, the output DACL is applied with file-specific read/write/delete
rights before any PKCS#12 bytes are written and is verified against the same
specific access mask. The staging file must not expose inherited access during
that transition. The Unix path retains the existing 0600 permission check.

Path classification remains platform-aware: a trailing backslash is a
directory separator only on platforms where `os.IsPathSeparator` reports it as
such. All user-supplied path bytes are otherwise preserved.

## Implementation

- Add `internal/cli/certificates/export.go` and register the subcommand in
  `internal/cli/certificates/certificates.go`.
- Reuse or safely extract private-key parsing, public-key comparison,
  certificate fingerprinting, protected-file reads, and atomic file writes;
  avoid importing unexported signing helpers across packages.
- Reuse `software.sslmate.com/src/go-pkcs12`'s existing modern encoder rather
  than adding a dependency or a second PKCS#12 format.
- Add an exported result type and renderer registration under `internal/asc`
  if required by the output registry.
- Update command help and generated `docs/COMMANDS.md`; do not change the
  OpenAPI snapshot or `internal/web`.

## RED-GREEN and verification

Begin with command-level tests that fail because `certificates export` is not
registered. Add focused tests for required flags, invalid flag values,
unknown/positional arguments, stdout/stderr separation, table/JSON/Markdown
output, and exit statuses. Add unit coverage for DER/PEM parsing, RSA/EC key
formats, CSR signature and key matching, validity windows, protected password
files, symlink and overwrite refusal, atomic replacement, restrictive modes,
and PKCS#12 decode round trips.

Build `/tmp/asc` and exercise valid and invalid invocations against synthetic
certificates, keys, and CSRs. A read-only certificate list call may confirm
that no public API support has appeared, but no account mutation or web
session is required for this feature.

Required repository gates:

```bash
make build
make format
make check-docs
make lint
ASC_BYPASS_KEYCHAIN=1 make test
```

## Alternatives

Adding private Developer Portal automation would depend on an unsupported,
mutable web contract and would make certificate issuance and credentials part
of this command's blast radius. Keeping the remote step manual while adding a
local, testable package operation fits the public API boundary.

Adding a second combined `certificates csr-and-export` command would duplicate
the existing CSR generator and make renewal workflows less composable. The
standalone export command keeps key/CSR generation and downloaded-certificate
packaging independently testable.
