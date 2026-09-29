# Independent image timestamps

APFS and HFS+ writers can retain birth, modification, metadata-change and access
times independently. This is required before an ordered metadata restore can
preserve access and modification times without overwriting birth/change history.
It also prevents a snapshot rebuild from replacing three timestamps with the
modification time. The implementation is pure Go and identical on Linux, macOS
and Windows; native tools are used only for qualification.

## Use

Both writer `Entry` types accept `Times *hostmeta.FileTimes`:

```go
times, err := sourceVolume.FileTimes("Payload/file")
if err != nil {
    return err
}
entry.Times = &times
```

`FileTimes` is available on both APFS and HFS+ volumes. It reads inode/catalog
metadata, resolves hard links, and does not follow the final symlink or load
payloads and xattrs. Names use `fs.ValidPath`; `"."` selects the root. Lookup and
I/O failures remain errors. Acquisition bypasses general file-size calculation,\nso compressed-file attributes are not loaded just to read timestamps. Keep the\nsource image immutable during acquisition.

A non-nil `Times` selects **all four fields**: `Birth`, `Modify`, `Change`, and
`Access`. They override the entry's legacy `ModTime`. Unix epoch zero is a real
value. The Go zero `time.Time` is the literal year 1, outside the supported image
ranges, and fails validation; it does not mean an omitted field. Writer input is
not modified. Hard-link groups retain the first entry's shared inode timestamps.

When `Times` is nil, existing `ModTime`/deterministic-default behavior remains.
The APFS child-inode epoch bug is fixed: an explicitly supplied `ModTime` at Unix
epoch zero is no longer replaced by the default. Synthetic roots and private
inodes still use their established defaults.

With `ClampModTimes`, an explicit `Times.Modify` is limited to `FixedTime` while
the other three explicit fields remain unchanged. Legacy `ModTime` still supplies
all four fields after its existing clamp. APFS snapshot rebuilding now captures
the root and every child's four timestamps before serialization. This does not
change the snapshot command's separate hard-link, attribute or ownership limits.

## Format limits

| Format | Explicit storage | Bounds and conversion |
| --- | --- | --- |
| APFS | Four nanosecond fields | Signed Unix-nanosecond values carried as the inode's 64-bit bit patterns; dates that cannot round-trip through signed nanoseconds fail |
| HFS+/HFSX | Four unsigned second fields | 1904-01-01 through 2040-02-06 06:28:15 UTC; subseconds truncate to whole seconds; out-of-range values fail |

These limits apply to explicitly supplied `Times`, before output writes. The
legacy `ModTime`/`FixedTime` conversion policy is unchanged. HFS readers return
raw catalog dates, including the 1904 epoch; this API does not apply a mounted
host driver's special-value conversions. It is a preservation view of stored
metadata, not a claim that all raw dates have identical native stat semantics.
The native comparison corpus covers Unix epoch zero through HFS's final second;
unit tests additionally check each encoder boundary and refusal.

HFS+ hard-link stubs retain the private metadata directory's creation date as
required by the format. The independently supplied timestamps belong to the
resolved indirect inode. APFS keeps one inode for all names in a hard-link group.

## Qualification

- `go run scripts/verify-image-security.go -times` builds eight deterministic
  images: APFS, case-sensitive APFS, HFSX and HFS+, each with and without clamping.
- **296 native observations** cover roots, files, directories, symlinks, hard
  links and nested entries. Profiles include independent fields, explicit and
  legacy epoch zero, nanoseconds, future modification time and HFS's final second.
- Read-only mounted macOS `lstatx_np` observes all four times. The existing helper
  also compares public security capture with complete unchanged pinned Libc
  `statx1`; arm64/x86_64 Clang ASTs, source hashes, native commands and readback
  remain in the artifact. See the [source-capture qualification](appledouble-image-security.md)
  for pinned Apple source provenance.
- `fsck_apfs`/`fsck_hfs` validate all eight images. APFS fixtures contain a snapshot.
  Payloads, link targets, inode identity and unchanged image hashes are checked.
  Snapshot rebuild unit tests independently preserve every root/child timestamp
  across two writes. This does not claim a separate native snapshot-mount test.
- `go run scripts/verify-image-times-coverage.go` replays the corpus on all three
  OSes, checks the eight image hashes and rejects skipped focused tests. Each new
  production file must exceed 95% coverage; the current gate covers **48/48
  statements (100%)**. Existing layout controls and codec/security gates remain.

The source references for the storage formats are Apple's
[HFS+ format specification](https://developer.apple.com/library/archive/technotes/tn/tn1150.html)
and [APFS reference](https://developer.apple.com/support/apple-file-system/Apple-File-System-Reference.pdf).

## Remaining integration

This is image metadata storage/acquisition, not a live-host timestamp setter or
an implementation of `copyfile_stat`. Host acquisition, permission-sensitive
writes, BSD flags, creation inheritance, quarantine/xattrs, deferred AppleDouble
ACL replacement and cleanup must still be bound in native order. Host directory
walking still supplies its existing metadata; it does not automatically opt into
capturing all four timestamps.

All five AppleDouble completion gates remain open. Package PR72 stays draft on
the published APFS dependency; codesign remains paused until qualification,
release and downstream adoption.
