# Restoring ACLs into APFS and HFS+ images

`apfswrite.Entry.RestoreACL` and `hfsplus.Entry.RestoreACL` apply a deferred
AppleDouble ACL replacement to an in-memory image tree. Use them after selecting
the update with `appledouble.File.ACLUpdate`, once other metadata has been
restored. They share the existing `hostmeta.RestoreACL` execution policy and one
portable image backend. No native library or operating-system ACL conversion is
required in production.

```go
update, err := decodedAppleDouble.ACLUpdate(resolver)
if err != nil {
    return err
}
result, err := root.RestoreACL(destinationEntry, update)
if err != nil {
    return err
}
// result.Applied means the update is staged in root.
// CreateContainer (APFS) or CreateImage (HFS+) must still succeed.
```

Both methods take the root and the actual destination entry pointer. This binds
the operation to an object without resolving a host path or following a symlink.
The API is identical on Linux, macOS and Windows. It can update regular files,
directories, symlinks and the root itself.

## Preservation and failures

An absent or ignored malformed update is a no-op. A present empty ACL is an
actual replacement, including its global flags. Applied updates write canonical
big-endian `com.apple.system.Security` records. Numeric UID/GID, exact mode,
timestamps, payloads, resource forks and unrelated attributes remain unchanged.
The operation clones attribute maps and gives each alias separate new security
bytes; old maps, raw input records and the selected ACL are not modified.

Stored owner/group UUIDs survive replacement even when an empty/NOACL record
caused Libc's `statx` view to omit those UUID properties. Extended chmod updates
the ACL without assigning the UUID fields from its argument. Invalid stored
record extents, magic or counts contribute no UUIDs, matching the measured kernel
behavior; aligned surplus storage is removed when a valid replacement is applied.
No-op updates retain the original raw bytes, including malformed records.

Every regular-file entry sharing the destination's nonzero `LinkGroup` is updated
together, including aliases in other directories. Their numeric ownership,
resolved mode and stored security must agree. Conflicting alias metadata returns
`fs.ErrInvalid` without editing the tree; reconcile those inputs before applying
an ACL. This avoids reporting success for a later alias whose metadata the writer
would discard in favor of the first alias. Group IDs on directories and symlinks
do not make them regular-file aliases.

For an applied update, nil entries, cycles, repeated entry pointers, unsupported
types and children on non-directories fail before any map assignment. A target
outside the tree returns `fs.ErrNotExist`. These checks bind the operation; they
do not replace the writer's name, capacity or complete image validation. Callers
must exclude concurrent tree changes.

APFS inferred directories (`Mode == 0` with children) now ignore `LinkGroup`, as
explicit directories already did. Previously an inferred directory could become
a regular-file alias and lose its children when its group collided with a file.
The native corpus includes that collision and verifies the child payload survives.

## What success means

This is an offline metadata edit. It neither grants the host user access nor
models a macOS user's authorization. The image filesystem enforces its ACL when
mounted. `Applied` means a validated tree update; serialization and output I/O
remain separate operations with their own errors. No native unsupported-operation
error is invented, and this backend has no cached source security to clear.

This adapter handles deferred replacement. Ordinary security-copy merging and
fallbacks, native host adapters, privileged/sandbox contexts and full restoration
ordering remain outstanding. Host-directory acquisition still synthesizes root
metadata. Those limits apply equally on every platform.

## Qualification

The committed corpus covers **2,316 native applications across eight input/output
image pairs**: both APFS case modes, HFSX and HFS+. It includes 24 initial record
profiles, six update forms, files/directories/symlinks/hard-link pairs, roots and
zero permissions. There are 1,548 applied replacements and 768 no-ops, plus
1,152 native/output alias observations. One-entry and 128-entry replacements,
empty global flags, malformed/oversized records, UUID ownership, set-ID/sticky
bits and inferred-directory collisions are represented.

For each case the harness applies the complete unchanged `copyfile_unpack_acl`
function to the mounted input image, stages the same update with Go, writes a
new image and compares mounted results. Both public security capture and full
attribute-list observations must match; the latter expose empty ACL flags and
UUIDs omitted by `statx`. Hard-link identity is checked within each image, not
equated across separate builds. Native clock updates are not compared to the
offline tree's retained timestamps.

Zero-mode cases acquire a held descriptor during owner-controlled setup, then
restore and verify the original mode before invoking Apple's routine. The corpus
records all 772 temporary-read setups. This models the held-destination stage;
it does not claim that opening an existing `0000` file would succeed normally.

The oracle retains four hash-pinned Apple sources, the complete unchanged source
extracts and arm64/x86_64 Clang ASTs. Both output filesystems pass their native
checker. Read-only output mounts must leave image hashes unchanged. Linux, macOS
and Windows replay the corpus and reproduce every initial and final image hash.
Focused failure/alias tests and fuzzing cover invalid graphs, capture failures,
input ownership and rejection without partial edits. Each new production file
must independently exceed 95% coverage; focused tests cannot skip.

```sh
CGO_ENABLED=0 go run scripts/verify-image-acl-coverage.go
CGO_ENABLED=0 go run scripts/verify-root-layout.go
# On macOS, as an ordinary user:
CGO_ENABLED=0 go run scripts/verify-image-acl-restore.go
```

`-capture` records unapproved observations; normal qualification requires the
checked-in corpus. The [five completion gates](../pkg/appledouble/README.md#roadmap)
remain open. Package PR #72 stays draft until the completed APFS work is qualified
and released; codesign stays paused until downstream adoption.
