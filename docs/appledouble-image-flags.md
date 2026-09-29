# Image BSD flags

BSD flags carry inode metadata such as immutable, append-only, hidden, tracked,
archived and restricted state. A metadata copy must retain these independently
of permissions, ACLs and timestamps. Both image writers now accept them, and
both image readers expose them without loading payloads or extended attributes.
The implementation is pure Go and runs identically on Linux, macOS and Windows.

## Use

```go
flags, err := sourceVolume.BSDFlags("Payload/file")
if err != nil {
    return err
}
entry.BSDFlags = &flags
```

Both `apfswrite.Entry` and `hfsplus.Entry` accept `BSDFlags *uint32`. Nil keeps the
legacy inference of `UF_COMPRESSED` from decmpfs storage. A non-nil value selects
the entire word, including explicit zero. Its compression bit must agree with
the entry's decmpfs attribute; inconsistent requests fail before output writes.
Input entries are not mutated. The first entry in a hard-link group supplies
the shared inode flags; HFS hard-link stubs retain their internal representation.
Roots, directories, regular files and symlinks all carry flags.

`Volume.BSDFlags(name)` on either reader uses `fs.ValidPath`; `"."` selects the
root. It resolves hard links and does not follow the final symlink. Lookup and
I/O errors remain errors. Keep the source image immutable during acquisition.
These APIs read and serialize image metadata; they do not call host `chflags`,
implement authorization or automatically capture flags while walking a host tree.

## Storage and native behavior

| Format | Representation |
| --- | --- |
| APFS | The inode's 32-bit BSD flag word |
| HFS+/HFSX | Owner byte, admin byte shifted by 16, plus Finder invisible for `UF_HIDDEN`; bits outside `0x00ff80ff` cannot be encoded and are refused |

The HFS reader follows native `getbsdattr` normalization: mode-less records do
not contribute BSD bytes; Finder invisible contributes `UF_HIDDEN`; file catalog
lock state supplies or clears immutable flags. The writer keeps these catalog
fields consistent with the selected word. This does not implement general
`com.apple.FinderInfo` attribute-to-catalog restoration.

Tracked APFS inodes receive a document-ID xfield and a corresponding volume next
ID. Tracked HFS inodes receive the opaque Finder document-ID field. IDs are
allocated deterministically for the **new volume**; original document identities
are not preserved. Hard links share an ID. On native HFS the root reports ID 2
and symlinks report ID zero, even with `UF_TRACKED`; the complete pinned HFS
getter confirms the symlink rule. APFS tracked symlinks have document IDs.

APFS snapshot rebuilding captures root and child flags. Because its existing
rebuild path expands compressed payloads and drops xattrs, it clears only
`UF_COMPRESSED`; other flags survive both writes. Existing hard-link, xattr and
ownership limitations of snapshot rebuilding still apply. Document IDs are
new-volume identities, not a snapshot document-identity preservation API.

Raw flag storage is not a complete implementation of special object types.
Firmlinks, dataless objects, reserved bits and privileged enforcement are outside
this qualification. Supplying such bits does not construct their dependent
objects or establish their native semantics. They need separate native evidence
and integration before an arbitrary-object preservation claim is valid.

## Qualification

`go run scripts/verify-image-security.go -flags` builds four deterministic images:
APFS, case-sensitive APFS, HFSX and HFS+. **276 native observations** cover roots,
files, directories, symlinks, hard links, a nested child and explicit/inferred
compressed payloads. Profiles cover zero, nodump, user/system immutable and
append, opaque, hidden, tracked, archived, restricted, nounlink and combinations.

The host mounts each image read-only with ownership enabled. Public
`lstatx_np` and complete unchanged pinned Libc `statx1` agree on security
properties and identity; native flags agree with the Go readers and selected
values. Native `getattrlist` independently observes **24 tracked document IDs**.
`fsck_apfs`/`fsck_hfs` accept all four images; both APFS images contain a snapshot.
Payloads, link targets and unchanged before/after image hashes are checked.

The helper compiles the complete unchanged `hfs_get_document_id_internal` and
`FndrExtendedFileInfo` definition from pinned Apple HFS sources. arm64 and x86_64
Clang ASTs, source hashes, commands and readback remain in CI artifacts. References:

- [HFS catalog flag normalization](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_catalog.c)
- [HFS flag and document-ID handling](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_vnops.c)
- [HFS opaque Finder document-ID representation](https://github.com/apple-oss-distributions/hfs/blob/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/hfs_format.h)
- [APFS format reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf)
- [Existing pinned Libc capture provenance](appledouble-image-security.md)

`go run scripts/verify-image-flags-coverage.go` replays the native corpus on all
three OSes, compares all four complete image hashes and refuses skipped focused
tests. Each new production file must exceed 95% coverage: currently **69/69
statements (100%)**, with **369 passing test records**. Tests also cover HFS
normalization, invalid requests before writes, metadata-only acquisition and
snapshot rebuilding. The ten legacy layout hashes and eight timestamp-image
hashes remain regression controls.

## Remaining integration

Image flag storage removes a prerequisite for binding the portable stat stage.
Held host acquisition, destination write adapters, creation inheritance, ordered
security/stat/xattr restoration, deferred AppleDouble ACL replacement and cleanup
remain. Carrier transport, general FinderInfo restoration, special object flags
and original document identity also need separate qualification.

All five AppleDouble completion gates remain open. Package PR72 stays draft on
the published APFS dependency. Codesign resumes only after the qualified APFS
release and downstream adoption.
