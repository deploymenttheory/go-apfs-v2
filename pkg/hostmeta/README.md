# Shared host metadata

## Strict extended attributes

`XattrSize`, `ReadXattr` and `RemoveXattr` operate on an already-open `*os.File`.
The corresponding `XattrSizeNoFollow`, `ReadXattrNoFollow` and
`RemoveXattrNoFollow` operate on a path without following its final symlink.
These APIs provide strict results separately from the existing best-effort
`ListXattrs`/`SetXattrs` behavior.

```go
size, present, err := hostmeta.XattrSize(file, "user.example")
if err != nil { return err }
if present {
    // size == 0 is still a present attribute.
    value, present, err := hostmeta.ReadXattr(file, "user.example", 4096)
    // Handle err and a possible intervening disappearance before using value.
    _, _, _ = value, present, err
}
_, _ = size, present
```

| Result | Meaning |
| --- | --- |
| `present == false`, nil error | Native missing-attribute result only |
| Size zero, `present == true` | Present-empty value |
| Non-nil error | No absence/success claim; permission and I/O causes survive |
| `ErrXattrUnsupported` | Host/filesystem lacks the operation; native errno is also retained when available |
| `ErrXattrTooLarge` | Value exceeds the caller's explicit read limit; no value is returned |
| `ErrXattrChanged` | A value disappeared or its observed size changed during the two-call read; no partial value or retry |

Read limits range from zero to `MaxXattrReadSize` (8 MiB). Unix size queries and
removal do not allocate the value. Windows native EA queries require a complete
record and use at most 65,799 bytes of scratch space, including for size queries.
This is separate from the caller-bounded returned value. Reading a zero-length value uses a one-byte
buffer to make a real read rather than another size-only query. A successful
present-empty read returns a non-nil empty slice. Error results never return a
truncated value. A same-size concurrent value change is not detectable: callers
needing stable metadata must exclude concurrent mutation.

Descriptor operations use `SyscallConn.Control` to keep the handle held through
the native calls, including both phases of a read. They do not reopen `File.Name`,
close the caller's file or change file position. Renames and old-name decoys do
not redirect them. Regular files, directories and OS-supported link descriptors
are passed to the native API; a file opened through a symlink already identifies
the target. Darwin `O_SYMLINK` descriptors operate on the link itself. Linux
`O_PATH` descriptors return `EBADF` from these operations, without a pathname
fallback. Nil and closed descriptors fail.

Path operations are not a containment or identity primitive. Intermediate
components can be symlinks and each call resolves the path again. Use a suitably
opened descriptor for held-object semantics. Missing files remain errors rather
than being mistaken for missing attributes.

Darwin and Linux implementations use supported `golang.org/x/sys/unix` wrappers;
there are no new direct syscalls, native bindings or helper processes. The
namespace is the ordinary native namespace: Darwin does not request
`XATTR_SHOWCOMPRESSION`, so compression-hidden metadata is not exposed. Linux
namespace/permission rules still apply; names are not automatically remapped.
Windows implements all six strict operations using native NTFS extended
attributes through the supported `NtCreateFile`, `NtQueryEaFile` and `NtSetEaFile`
wrappers. Path opens use `FILE_FLAG_OPEN_REPARSE_POINT`; held-object opens use an
empty relative name without looking up `File.Name`. Access is checked against the
current DACL, without backup privilege. Files, directories and held symbolic links
are supported. Native EA names are case-insensitive ASCII, up to 255 bytes, with
Windows name restrictions; values follow native EA storage limits. Assigning zero
length deletes a native EA, so NTFS cannot store a present-empty EA. Removal
queries presence before deletion on the same handle; concurrent mutation is not
atomic. Protected `$Kernel.` removal is explicitly denied because Windows silently
ignores user-mode updates in that namespace. Alternate data streams remain separate
and untouched. The older best-effort `ListXattrs`/`SetXattrs` APIs and their
`XattrsSupported` constant retain their existing behavior.

`ErrXattrUnsupported` is reserved for other unimplemented hosts or an actual
filesystem capability error, never used as a blanket Windows result.

Removal requests deletion of one named attribute, returns true on success and
false/nil for native absence, and preserves other errors. Hard links share the
mutation, and metadata change time can advance. Attribute-specific effects on
compression, ACLs or other filesystem state belong to the OS. There is no
rollback, transactional attribute set or promise that an attribute hidden from
ordinary reads is safe to remove. Ordinary unrelated attributes and file contents
are preserved in the tested profile.

The Mac tests compare reads and removals with `/usr/bin/xattr`, cover file/directory
and held symlink identity, and assert real ACL-denial errors. APFS normalizes an
empty ResourceFork and all-zero FinderInfo to absence; an ordinary empty
attribute remains present. Linux tests cover permission denial, final-link
behavior and rejection of `O_PATH` handles. Windows tests perform real file/directory EA creation, query, bounded read and
removal, including 60,000-byte values, case-insensitive lookup, empty-value
normalization, moved handles, hard links, old-name decoys, dangling and held
symbolic links, alternate-stream retention and real DACL denials for every API.
No Windows lifecycle or permission test skips an unsupported result. Shared tests cover bounded allocation, changing sizes,
disappearance, nil/closed files and retained error causes. The existing CI runs
these tests and enforces **above 95% statement coverage in the new strict API**
using `go run scripts/verify-xattrs.go`; this is not a whole-repository coverage
claim. Test transcripts, coverage and source hashes are uploaded per platform.

The intended first consumer is codesign sideband policy. Apple's
[attribute helpers](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_utilities/lib/unix%2B%2B.cpp)
use ordinary descriptor queries and distinguish zero-length/nonempty values;
their policy also suppresses `EPERM` in `checkFork`. These generic APFS APIs
preserve that error so consumers can apply their own measured policy. They do
not implement codesign flags, decide whether an attribute is prohibited or
modernize the legacy compression-aware best-effort reader.

## Access and creation times

`CopyAccessTime(source, target)` copies a regular file's current Darwin access time
into a distinct open regular file with nanosecond precision. It uses held
descriptors through x/sys's `Setattrlist` wrapper and fdescfs, so moved names or
old-path decoys cannot redirect the update. Source metadata, contents and file
positions are unchanged. Only target access time is explicitly set; its metadata
change time may advance. Other timestamps, ownership, mode, ACLs and xattrs remain
unchanged. Target hard links share the update. Nil, closed, non-regular and
same-inode pairs fail; other hosts return `ErrAccessTimeUnsupported` without
mutation. The caller needs metadata-write permission on the target and must keep
both descriptors open without concurrent metadata changes. Use this after a
source read to update a privately staged clone without repeating allocation.
Replacement APIs do not implicitly copy access times.

`RecordReadAccess(file)` requests native mapped-read access-time behavior for an
open regular file on Darwin. It briefly maps one byte read-only without accessing
the mapping, so empty files and truncation cannot cause a mapped-memory fault.
The filesystem chooses the access time; contents, file position and other metadata
are unchanged. Hard links share the access-time update. Read permission is enough,
including on files whose ACL denies metadata writes. Nil, closed, non-regular,
write-only and event-only descriptors are rejected. Other hosts return
`ErrReadAccessUnsupported`; no timestamp-write emulation is performed. This is an
explicit operation and does not change replacement API defaults.

`SetCreationTime(file, when)` updates the creation time of an open regular file
on Darwin with nanosecond precision. It uses the held descriptor through x/sys's
`Setattrlist` wrapper and fdescfs; replacing the original pathname does not change
the target. Contents, access/modification times and other supported metadata remain
unchanged. Hard-link names share the update. Nil, closed and non-regular files
fail; other hosts return `ErrCreationTimeUnsupported` without emulating the time.
This is an explicit caller operation; replacement APIs retain their source
creation-time preservation contract. Call it on a private staged file before
restoring restrictive flags, then sync and commit through the caller's writer.

This package is the former `internal/hostmeta`, exposed for consumers such as
`go-macos-codesign`. APFS/HFS+ writers, extraction, capacity checks and signing
share the same implementation and platform definitions.

`ListXattrs`, `SetXattrs`, `Flags`, `Link`, `AvailableSpace` and the attribute
constants retain their existing behavior. Attribute extraction is best effort;
callers must inspect reported failures. The existing Darwin compression-aware
`ListXattrs` reader still uses direct syscalls with a wrapper fallback. That
legacy path has not been modernized by this change.

`PrepareReplacement(source, parent)` provides a separate strict contract:

```go
r, err := hostmeta.PrepareReplacement(source, filepath.Dir(destination))
if err != nil { return err }
defer r.Close()
if _, err := r.File.WriteAt(contents, 0); err != nil { return err }
if err := r.File.Truncate(int64(len(contents))); err != nil { return err }
if err := r.RestoreMetadata(); err != nil { return err }
if err := r.File.Sync(); err != nil { return err }
if err := r.File.Close(); err != nil { return err }
// Close source and verify the destination still names the expected source.
// The caller owns the decision to commit, and whether to use a rename.
return os.Rename(r.File.Name(), destination)
```

The source stays open and unchanged while the replacement is prepared. The
package owns a private staging directory and cleans it on `Close`, including
after the caller renames the staged file. Callers handle concurrency and the
final rename; no transactional or crash-durability guarantee is made.

- Darwin uses x/sys's libSystem-backed `Fclonefileat`, `Setattrlist` and
  `Fchflags` wrappers. It preserves ownership, mode, xattrs, source ACLs, birth
  time and supported flags. Its own staging directory has inherited ACLs
  cleared before cloning. No deprecated raw syscall is used by this API.
  Clone support is required; immutable, append-only and compressed inputs fail
  before commit. HFS+ and other filesystems without cloning are unsupported.
- Linux copies owner/group, mode and readable xattrs (including POSIX ACLs),
  with an 8 MiB aggregate limit each for names and values. Inherited staging
  ACLs are removed first. Linux inode flags and birth time are not preserved.
- Windows copies streams/attributes using `CopyFileW`, then restores owner,
  group and the DACL. SACL preservation is not promised. Replacing a read-only
  destination may still fail at the caller's rename.

All three implementations build with `CGO_ENABLED=0`. The new API never invokes
an external tool or signing service. Tests run on Linux, macOS and Windows in
the existing CI matrix. Darwin tests compare ACL text, xattr values, ownership,
BSD flags and creation time on the host; Windows tests compare streams and
security descriptors.
# Root-relative replacements

`PrepareReplacementAt(source, root, parent)` stages a replacement beneath an
already-open `*os.Root`. `RootReplacement.File` is writable and its `Path` is
relative to that root. Write/truncate the complete output, call
`RestoreMetadata`, sync and close the file, then use `root.Rename` to commit.
Always call `Close` to discard staging. Keep the caller-owned source open through
metadata restoration and the root open through cleanup. The API never commits
or closes those caller-owned objects and is not safe for concurrent method calls.

Darwin clones relative to the opened staging directory and uses the held
directory's `/dev/fd/N` name with the supported `Setattrlist` wrapper to clear
inherited ACLs. Linux creates through the root and copies metadata by descriptor.
Windows reopens existing handles with `ReOpenFile`, then copies bounded EAs and
alternate data streams through `BackupRead`/`BackupWrite`; it never reopens the
source by its pathname or restores backup hard-link/object-identity records.
Owner, group, DACL, creation time and ordinary Windows attributes are preserved.
The root API rejects compressed, encrypted, sparse and reparse Windows files and
bounds combined stream/EA names and data to 8 MiB. Darwin's existing clone,
protected/compressed-file limitations remain. SACLs are outside the contract.

The existing path API remains available. Both APIs run the same platform metadata
tests. Root-specific tests cover containment, a moved root with an old-path decoy,
hard-link detachment, failed restoration, cleanup and close after commit.
Concurrent source/staging-tree mutation and crash durability are not promised;
callers own source/destination identity checks and commit decisions.

Windows protocol references: [BackupRead](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread),
[BackupWrite](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite),
[WIN32_STREAM_ID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id)
and [ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).

# Directory stat metadata

`CopyDirectoryStat(source, target)` copies a bounded stat-metadata profile between
distinct, already-open directories. Both descriptors remain caller-owned; neither
contents, xattrs, alternate streams nor ACL entries are copied. It never creates,
replaces or commits a directory. Names may move without redirecting the operation.

- Darwin copies owner/group, mode, nanosecond access/modification times and
  `UF_NODUMP`, `UF_OPAQUE`, `UF_HIDDEN`. Like Apple's `COPYFILE_STAT`, it omits
  source tracked/protected flags and drops setuid/setgid on nosuid volumes.
  Other source flags and unsupported target flags are rejected before mutation.
  Creation time is not explicitly copied; setting an earlier modification time
  can lower it. Existing destination ACL entries remain unchanged.
- Linux copies owner/group, mode and nanosecond access/modification times using
  `utimensat(AT_EMPTY_PATH)` through x/sys (kernel 5.8+). It does not copy inode
  flags or birth time. Changing mode may update a destination POSIX ACL's mask.
- Windows copies read-only, hidden, system, archive and not-content-indexed
  attributes plus access/modification times. It leaves creation time, security
  descriptors and streams unchanged. Other directory attributes are rejected.
  The supported x/sys `NtCreateFile` wrapper opens an empty name relative to the
  held target with explicit directory semantics; it never resolves `File.Name`.

This is a stat operation, not Apple's full `COPYFILE_SECURITY`: that operation
also combines explicit source ACL entries with inherited destination entries.
There is no supported Darwin ACL reader in the current x/sys API, and this API
does not add native bindings, raw syscalls or helper processes to read them.
Unlike Apple's best-effort stat copy, failures are returned. An error after a
mutation can leave partial metadata changes; callers must avoid concurrent
metadata mutation and keep handles open. No rollback is promised.

Darwin tests compare the API with a test-only native `copyfile(COPYFILE_STAT)`
helper, including precise times, setgid, BSD flags and creation-time effects.
Platform tests cover invalid/same directories, held handles after name changes,
content/identity preservation, ACLs, xattrs and Windows security/stream retention.
The native helper is compiled only for tests, never for production.

Reference: Apple's [copyfile implementation](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c)
and [flag masks](https://github.com/apple-oss-distributions/copyfile/blob/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h),
pinned at `9f91eb6ced021952278816cdc76ad68da8631ccb`.

Strict Windows EA references: [query](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryeafile),
[EA wire format and zero-length deletion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989),
and [protected kernel EAs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes).
