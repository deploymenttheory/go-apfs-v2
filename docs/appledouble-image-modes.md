# Image permission preservation

APFS and HFS+ image entries carry Unix permissions independently of the host
operating system. `ModeExplicit` tells either writer that the supplied permissions
are exact, including `0000`. Both writers retain Go's `ModeSetuid`, `ModeSetgid`
and `ModeSticky` bits, and both readers expose those bits through `FileInfo.Mode`.
This works in pure Go on Linux, macOS and Windows.

Use explicit modes when rebuilding captured filesystem metadata or applying a
security update. Without this distinction a legitimate zero mode becomes a
default `0644` or `0755`, so an ACL operation could report success while changing
the file's access permissions.

```go
entry := &apfswrite.Entry{
    Name:         "restricted",
    Mode:         0,
    ModeExplicit: true,
    Data:         []byte("payload"),
}
```

`hfsplus.Entry` uses the same fields. `Mode` uses Go's `os.FileMode` layout:
write `os.ModeSetuid | 0755`, not the numeric Unix mode `04755`. Select directories
and symlinks with `os.ModeDir` and `os.ModeSymlink`. `ModeExplicit` controls
permissions only; it does not change the type or follow links. Hard-link names
share the first entry's inode metadata, as before.

## Defaults and captured modes

| Input | Written permissions |
| --- | --- |
| `ModeExplicit: true` | Exact permission and special bits, including zero |
| `ModeExplicit: false`, nonzero low permission bits | Supplied permissions and special bits |
| `ModeExplicit: false`, zero low permission bits | Legacy `0644` for files or `0755` for directories/symlinks, plus supplied special bits |
| APFS root with nonzero `Mode` | Exact permissions, preserving the existing root API |

The APFS root's zero mode still defaults to `0755` unless explicitly supplied.
HFS+ roots use the general table. The host walker still synthesizes a root with default metadata; acquiring its
actual metadata remains transport work. Both `EntryTreeFromDir` adapters mark captured
modes explicit. APFS snapshot rebuilding does so for captured child entries as
well. This does not complete root/security transport in the snapshot command.

Existing default images retain their byte layout. Images whose entries supply
special bits now contain those bits; images selecting explicit zero permissions
contain zero instead of a fallback. These inode/catalog mode changes and their
checksums are intentional. Payloads, attributes, ownership and link identity are
unchanged.

## Qualification

The portable gate exhaustively checks all 4,096 permission combinations and
replays **656 native observations across 16 images**: APFS in both case modes,
HFSX and HFS+. The fixtures cover all eight special-bit combinations with zero,
owner-only, all-user and legacy-default permissions, across files, directories,
symlinks and hard links, plus explicit-zero and special-bit roots.

Every platform must recreate the archived native image SHA-256 hashes. Tests
also check numeric security metadata, `FileInfo.Mode`, payloads, unrelated
attributes and shared hard-link inode identity. Snapshot rebuilding and host
walker conversion have separate regressions. The three focused production files
must each exceed 95% coverage, and no focused test may skip.

The native harness checks public `lstatx_np` against the complete unchanged
`statx1` implementation from pinned Apple Libc, retaining the source hashes and
arm64/x86_64 Clang ASTs described in [image security capture](appledouble-image-security.md).
It mounts every image read-only with ownership enabled, compares native `lstat`
and the Go reader, runs the native filesystem checker, and verifies that mounting
did not change the image hash. HFS checking uses an attached device and requires
the completed clean-volume verdict, matching the existing HFS acceptance tests.

Of 512 native payload/link reads, 384 succeed and 128 return `EACCES` for explicit
zero read permissions. Those refusals are required observations, not skips.
The offline reader still returns stored bytes: it does not emulate authorization
by the mounted filesystem.

```sh
CGO_ENABLED=0 go run scripts/verify-mode-security-coverage.go
CGO_ENABLED=0 go run scripts/verify-root-layout.go
# On macOS, as an ordinary user:
CGO_ENABLED=0 go run scripts/verify-image-security.go -modes
```

`-capture` records unapproved native evidence. Normal qualification requires the
checked-in corpus and compares fresh observations, normalizing only host account
IDs and run provenance. This is a prerequisite for image security application;
it does not add an ACL write backend or claim native authorization parity.
All [five AppleDouble completion gates](../pkg/appledouble/README.md#roadmap)
remain open. Package PR #72 stays draft; codesign stays paused.
