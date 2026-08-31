# Rooted identity-checked file mutations

## Scope

This follow-up hardens the rooted file operations used by the Xcode signing
transaction. It is an internal filesystem contract, not a new CLI command or
App Store Connect API. The existing `asc xcode signing plan` and `apply`
invocations and their output contracts remain unchanged.

The transaction must carry a descriptor-backed identity from preparation to
publication and rollback. A caller-supplied `os.FileInfo` is only a snapshot;
it does not keep an inode or Windows file ID alive and cannot be the strict
rollback token.

## Contract

`internal/rootfs` exposes an opaque identity value whose fields remain private
to the package. The value owns a rooted no-follow descriptor or handle, the
identity observed through that descriptor, expected bytes, and the metadata
needed for a replacement. It is valid until the owning `Root` is closed; all
copies of a `Root` share the lifetime, and close is idempotent.

```go
type FileIdentity struct { /* unexported descriptor/handle and snapshot */ }

func (r Root) CaptureFile(name string) (*FileIdentity, error)

func (r Root) CaptureFileLimited(name string, limit int64) (*FileIdentity, error)

func (r Root) ReplaceFileIfSame(
	name string,
	expected *FileIdentity,
	data []byte,
	perm os.FileMode,
	preserveMetadata bool,
) (installed *FileIdentity, err error)

func (r Root) RemoveFileIfSameIdentity(name string, expected *FileIdentity) error

func (r Root) CreateNewFileAtomicWithIdentity(
	name string,
	data []byte,
	perm os.FileMode,
) (*FileIdentity, error)
```

An installed identity is returned only after the destination descriptor and a
final rooted entry observation prove that the staged inode was installed. A
nil identity means publication identity was not proven; callers must preserve
transaction evidence and must not perform a path-based rollback. An identity
may still accompany an error reported after that proof (for example, backup
cleanup or directory durability); the caller must revalidate it before a
later mutation. Capture and retained publication data are bounded at 8 MiB,
matching the existing Xcode signing-plan input limit; `CaptureFileLimited` can
choose a smaller bound and refuses oversize files with
`ErrFileIdentityDataTooLarge`. Oversize identity-backed replacements fail
before mutation.

The historical `os.FileInfo` methods remain compatibility adapters. They do
not acquire a retained descriptor or inherit the strict 8 MiB snapshot limit;
their existing portable fallback behavior is unchanged. New transaction code
must use the descriptor-backed methods above.

## Platform boundary and recovery

Linux `renameat2(RENAME_NOREPLACE)` and Darwin `renameatx_np(RENAME_EXCL)`
guard only the destination name. POSIX has no portable operation that renames
a pathname only when it still names a particular inode, nor a portable
unlink-by-descriptor. Strict operations therefore use a rooted quarantine and
descriptor checks to protect the ordinary concurrent editor-save cases at the
caller-visible destination: a replacement observed before quarantine is
rejected, and a replacement that appears after quarantine is never removed via
the original destination name. If the entry moved into quarantine is found to
be a different inode, it is restored to the destination with rooted
no-replace rename when that name is still absent; if the name was recreated,
the quarantine is left as evidence. A deliberate same-user actor that
enumerates or manipulates the library-owned random staging/quarantine names is
outside this portable capability boundary.

The final quarantine unlink still has no portable identity-coupled primitive.
The implementation revalidates the retained identity and removes only after a
matching observation; if the quarantine disappears, changes identity, or
cannot be removed, it performs no further cleanup mutation and returns
`ErrQuarantineCleanupUncertain` with recoverable evidence. The remaining
name-based unlink interval is an explicit Unix/Darwin limitation, not an
atomic compare-and-act guarantee.

Unpublished strict transactions apply the same rule to their private random
staging entry. While its descriptor is live, cleanup verifies the staged
identity before removal; if that observation is unavailable or mismatches,
the entry is left in place and `ErrStagingCleanupUncertain` reports the name.
The private-name race has the same explicit non-interference assumption as the
quarantine path and is not presented as an identity-coupled unlink guarantee.

`ReplaceFileIfSame` requires native no-replace publication and returns
`secureopen.ErrRenameNoReplaceUnsupported` without using the legacy hard-link
fallback. The compatibility `WriteFileIfSame*` adapters retain their historic
fallback behavior, but Xcode transaction callers do not use those adapters.

The current secureopen surface has no handle-backed compare-and-remove
primitive for Windows strict mutations. Accordingly, strict replacement and
removal return `ErrFileIdentityMutationUnsupported` before moving any entry on
Windows. This boundary can be narrowed only when a handle-backed rename and
delete implementation is available and tested for the target filesystem.
Directory durability remains separately reported where a directory handle
cannot be flushed.

Before publication, complete staged bytes and file metadata are synced. On a
failure before publication, the original identity is restored only when the
destination is still empty or the expected replacement is still present. If a
concurrent writer occupies the destination, both entries remain recoverable
and the operation reports uncertainty. After publication, rollback is another
identity-checked replacement; it never reopens a path and trusts a snapshot.

## Callers and tests

`internal/xcode/version_project.go` stores `FileIdentity` values for ordinary
project/xcconfig writes and create-only receipts. It removes the duplicate
open/Lstat checks in receipt rollback, consumes the identity returned directly
by publication, and keeps the existing portable version-command fallback
separate. Receipt verification checks the committed identity as well as its
bytes. Signing transactions do not silently fall back to check-then-act.

RED coverage must force same-content and different-content inode/file-ID
swaps between capture and mutation, replacement during quarantine cleanup,
post-publication cleanup errors with a retained identity, Root-close lifetime
failures, unsupported-platform no-mutation behavior, and symlink, hard-link,
FIFO, metadata, and directory-sync cases. Xcode regressions must prove that a
concurrent editor save is preserved and that a receipt cannot certify a failed
rollback.

An alternative is to retain the current `os.FileInfo` API and add more
post-operation checks. That remains vulnerable to identity reuse and the
final check-to-act interval, so it is not the selected contract.
