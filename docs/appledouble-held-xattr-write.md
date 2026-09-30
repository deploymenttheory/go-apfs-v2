# Held-file attribute writes

`hostdata.SetXattr(file, name, value)` creates or updates one native extended
attribute on an already-open object. Restoration providers use it when a rename
or replacement of the original pathname must not redirect a metadata write.
It works on Linux, macOS and Windows with pure Go production code.

```go
err := hostdata.SetXattr(file, "user.example", []byte{0, 1, 255})
if err != nil {
    return err
}
```

The descriptor stays pinned against concurrent `Close`. The operation does not
open `File.Name`, close the caller's file, move its position or write file data.
Hard-link aliases share the update. A held link descriptor identifies the link;
an ordinary descriptor opened through a symlink identifies the target. Linux
`O_PATH` descriptors retain the native `EBADF` refusal. Do not mutate the input
slice during the call. Applications needing stable readback must exclude other
metadata writers.

## Native result and limits

Success means the native write succeeded. It does not promise that the attribute
is visible or that readback equals the supplied bytes. Native normalization,
permissions, timestamps and other side effects belong to the filesystem. Nil and
empty slices both request a zero-length assignment; neither requests portable
delete-and-replace behavior. Use `RemoveXattr` for an explicit removal request.

| Host | Operation | Value behavior |
| --- | --- | --- |
| macOS | Supported `unix.Fsetxattr`, position/options zero | Ordinary empty values remain present; FinderInfo and resource forks have special rules |
| Linux | Supported `unix.Fsetxattr`, flags zero | Native namespaces, permissions and filesystem size limits apply; no name translation |
| Windows | Supported `NtSetEaFile` on a synchronous handle reopened relative to the held object | Empty values delete EAs; names are case-insensitive; native record/aggregate limits apply |

Windows requests `FILE_WRITE_EA` without requiring read access, backup privilege
or pathname resolution. The existing held-object reopen retains reparse-point
identity and checks the current DACL. Named operations accept their existing
ASCII subset, at most 254 bytes. Protected `$Kernel.` writes/removals are refused
because native user-mode updates can otherwise be silently ignored. The shared
single-record encoder serves both assignment and removal. Values over the
65,535-byte wire field limit fail with `ErrXattrTooLarge` before record allocation;
smaller writes can still fail the filesystem's native limits. The wire layout is
specified by Microsoft's [EA record documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).

Unix forwards the caller's buffer without applying the separate 8 MiB read
allocation limit. There are no retries, internal readback, rollback, create-only
or replace-only emulation, or atomic multi-attribute updates. Unsupported native
errors also match `ErrXattrUnsupported`; other native errors remain intact.
This API does not change best-effort `SetXattrs` behavior.

## macOS qualification

The [Apple interface](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/setxattr.2)
specifies descriptor assignment and the fixed FinderInfo size. The qualification
script calls the live host independently to check its actual behavior:

```sh
go run scripts/verify-xattr-write-native.go
```

Clang builds a small C program calling libSystem `fsetxattr` and `fgetxattr`.
The script retains both arm64/x86_64 ASTs, verifies the write call in each,
and records compiler/SDK/host identity, source hashes, commands, errors and full
readback bytes. It writes separate equivalent fixtures through C and Go, then
reads both through C. Clang is only needed for qualification.

The 22 observations cover ordinary creation, shrinking and empty assignment,
Unicode names, malformed/nonzero/zero FinderInfo, fresh and existing resource
forks, refused security writes, read/write ACL denials, files, directories,
held links, renames and hard links. The captured host's resource fork changes
from `07 08 09` to `04 08 09` after writing `04` at offset zero; a subsequent
empty write retains `04 08 09`. Ordinary attributes instead shrink to the supplied
size. Zero FinderInfo becomes invisible. A fresh empty fork is invisible. The
script also reads back a write performed while reads were denied after restoring
permissions, proving that the permitted write persisted.

These observations qualify the running macOS filesystem, not all filesystem
versions or privileged contexts. They preserve special-name behavior rather
than silently converting an assignment to deletion or truncation.

## Cross-platform tests and remaining work

`go run scripts/verify-xattrs.go` exercises real native operations on every CI OS,
rejects skipped tests and enforces above 95% strict API coverage and above 95%
coverage in each new implementation file. Tests verify independent native
readback, caller-buffer retention, ordinary empty values, file/directory/link
identity, old-name decoys, hard links, permissions, file data and position.
Windows additionally qualifies large values against a direct native assignment,
254/255-byte names, protected names, write permission without read permission
and alternate-stream retention. Linux retains `O_PATH` and permission failures.

Native Windows EAs and Linux attributes are not a lossless carrier for Darwin
metadata. This closes the held native assignment prerequisite, not the complete
AppleDouble provider. Image namespace visibility/order, cleanup readback,
special-name policy, foreign-carrier conflict handling, quarantine state,
ACL/time binding and outer creation/permission/close lifecycle remain. Large
value/streaming policy remains separate from forwarding a caller-owned buffer.

All five [roadmap gates](../pkg/appledouble/README.md#roadmap) remain open. Package
PR72 stays draft on released APFS v0.13.0 until a qualified release can be adopted;
codesign remains paused.
