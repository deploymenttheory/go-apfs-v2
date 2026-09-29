# APFS volume-root metadata

`apfswrite.CreateContainer` now retains the supplied `Root` ownership, permissions,
modification time and extended attributes on APFS inode 2. Use this when rebuilding
an image whose root carries an ACL or other metadata. Previously only the root's
children reached the image; its security, attributes and ownership were silently
dropped. `VolumeSpec.Root` has the same behavior in multi-volume containers.

The implementation is pure Go on Linux, macOS and Windows. It uses the same
attribute validation, embedded values, stream allocation, inode flags and extent
records as ordinary entries. A root with no children still gets its metadata;
root streams participate in allocation, object-ID and snapshot accounting without
turning the root into a user file/directory or creating extra visible children.

```go
root := &apfswrite.Entry{
    Mode: os.ModeDir | 0750,
    UID: 501, GID: 20,
    ModTime: capturedTime,
    Xattrs: capturedRootXattrs,
    Children: children,
}
err := apfswrite.CreateContainer(output, size, &apfswrite.CreateOptions{Root: root})
```

`Name`, `Data` and `LinkGroup` on `Root` remain ignored. The root is always a
directory; an explicit symlink, device or other incompatible type is rejected.
A zero `Mode` defaults to directory 0755. An explicit `os.ModeDir` preserves
0000 permissions, and Go's setuid, setgid and sticky bits map to their Darwin
mode bits. Numeric zero UID/GID are real values. A zero Go `time.Time` uses the
writer's deterministic default; Unix epoch zero is preserved. Explicit times
respect the existing `FixedTime`/`ClampModTimes` policy. The caller's tree is not
mutated. These root-specific rules do not change ordinary entry defaults.

## Stored metadata and native access

Raw image storage and macOS's exposed attribute view are separate:

- The image reader returns all stored root attribute bytes, including present-empty
  values, large streams and resource-fork storage.
- Native security capture exposes the ACL/UUID projection qualified in
  [image security capture](appledouble-image-security.md). Ordinary native
  `getxattr` refuses the protected `com.apple.system.Security` name with `EPERM`.
- Native `getxattr` reports `ENOATTR` for resource forks on the qualified directory
  roots, including a nonempty stored fork. The writer/reader retain that storage;
  this is not a claim that macOS exposes a directory resource fork as file content.
- A foreign-owned 0711 root produces real `EACCES` for ordinary attribute reads.
  Offline image reading does not enforce host authorization. That distinction
  is preserved in the native evidence rather than reported as metadata loss.

## Qualification and compatibility

The native matrix builds 26 images: 13 root profiles on case-insensitive and
case-sensitive APFS. It includes default roots, foreign ownership/restrictive
permissions, nonempty/empty/128-entry ACLs, large attributes with and without
children, hard-linked children, empty/nonempty fork storage, a 160-attribute
multi-node tree with a snapshot, special permission bits, explicit 0000 permissions
and Unix-epoch timestamps.

Each image must pass `fsck_apfs -n`. The read-only mounted root is compared with
public `lstatx_np` and unchanged pinned Libc functions for security and inode
identity, and all four native timestamps are checked. Native xattr reads retain
length, bytes and errno for every stored attribute, including the expected
refusals. Image hashes must remain unchanged across mounting. The harness retains
full pinned Apple sources and arm64/x86_64 Clang ASTs. The original 1,444-entry
capture matrix is also rerun, now expecting supplied metadata on APFS roots.

All three OS CI jobs regenerate the 26 root profiles and replay the native corpus.
Additional unit tests cover invalid input, unchanged caller data, root-plus-RootFiles,
timestamp clamping and multi-volume isolation. The focused gate requires greater
than 95% coverage separately in `root.go` and the shared `xattr_streams.go`; no
focused test may skip.

```sh
go run scripts/verify-root-security-coverage.go
go run scripts/verify-root-layout.go
# Ordinary Mac user; fsck/native tools are test-only:
go run scripts/verify-image-security.go -roots
```

This is an intentional image-byte change when root metadata was previously
ignored. Before/after hashes against merged PR165 match for empty, plain, nested,
case-sensitive, snapshot, child-stream and hard-link APFS images with default
root metadata, plus HFS+ and HFSX controls. A supplied-root-metadata control changes
as intended. The existing single-volume golden image remains unchanged. The baseline/candidate
hashes are committed in `testdata/appledouble/native/root-layout.json`;
`verify-root-layout.go` enforces them on every OS.

This closes the APFS root writer gap identified by security capture. It does not
complete native host write/authorization adapters, privileged/sandbox qualification,
restoration ordering or end-to-end AppleDouble transport. Package PR72 remains
draft until all roadmap gates and a qualified APFS release are complete.
