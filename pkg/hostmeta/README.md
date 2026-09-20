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
