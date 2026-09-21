# Shared host metadata

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
