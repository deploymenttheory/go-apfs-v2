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
