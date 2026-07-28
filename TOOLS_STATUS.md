# Implementation status

A snapshot of what is implemented. See [`README.md`](README.md) for usage and
[`TOOLS_ROADMAP.md`](TOOLS_ROADMAP.md) for what is planned.

Legend: ✅ implemented · 🟡 partial · ⬜ not yet

## File systems

| Area | APFS | HFS+ / HFSX |
| --- | :---: | :---: |
| Read (containers, volumes, file-system tree, extents) | ✅ | ✅ |
| Transparent compression (zlib / LZVN / LZFSE) | ✅³ | ✅⁵ |
| Symlinks, hardlinks | ✅ | ✅ |
| Extended attributes (read) | ✅ | ✅⁶ |
| Snapshots (read / list) | ✅ | — |
| Snapshots (create, revert) | ✅¹ | — |
| FileVault / encryption unlock | ✅ | — |
| `io/fs.FS` adapter | ✅ | ✅ |
| Create empty volume | ✅ | ✅ |
| Populate a volume with files | ✅ | ✅ |
| Reproducible output (`SOURCE_DATE_EPOCH`, fixed UUIDs) | ✅ | ✅ |
| Volume roles and volume groups (read + write) | ✅² | — |
| Write-fidelity reporting (`--strict`) | ✅ | ✅ |
| Resource forks (write) | ✅⁴ | ✅ |
| Extended attributes (write) | ✅⁴ | ✅⁷ |
| Hard links (write) | ✅ | ✅⁸ |

¹ One snapshot per image (single static checkpoint); multiple snapshots need
distinct xids and incremental checkpoints.

² Roles read and written in full. A volume group can only be written on a
system volume: a group is a system/data pair and the writer emits one volume
per container, so the resulting group has no data half.

⁴ Attributes of any size, including resource forks: small values are stored
inline and larger ones get a data stream. `com.apple.decmpfs` is refused,
because it declares content this writer does not produce, and is reported as
dropped.

³ decmpfs types 3/4 (zlib), 5, 7/8 (LZVN) and 11/12 (LZFSE), stored inline in
the attribute or in a resource fork. Types 9/10 (uncompressed) and 13/14
(LZBITMAP) are recognized and reported as unsupported rather than decoded.
Coverage is mostly by synthesized fixtures, because producing a real LZFSE file
needs macOS plus `afsctool`. One real one is committed: `compressed.txt` in
`testdata/cli/basic.dmg` is type 8 — LZVN in a resource fork — written by
`ditto --hfsCompression`.

⁵ Decoding is shared with APFS (`internal/decmpfs`), so the same types are
covered. Both storage shapes are read: data held inline in the attribute, and
data held in the file's resource fork in 64 KiB chunks. A compressed file's
size is taken from its decmpfs header, since its data fork is empty.

⁸ Several names for one file share a single copy of the content, through an
indirect node in the volume's private metadata directory, as macOS does it. The
content's extended attributes live on the indirect node, so a reader resolving
any name reports them.

⁷ Values of any size: a small one lives inside its attribute record and a
larger one gets an allocation extent of its own. `com.apple.decmpfs` is refused,
because it would declare content this writer does not produce, and is reported
as dropped. A volume with no attributes carries no attributes file at all.

⁶ All three attribute record shapes are read on HFS+ — a value stored inside its
record, one given a fork of its own, and a fork whose extents spill past the
eight it can hold inline. A file's resource fork is reported as
`com.apple.ResourceFork`, matching what macOS presents, although HFS+ stores it
as a fork of the catalog record rather than in the attributes file.

The APFS writer lives in `pkg/apfswrite` (pure Go, MIT).

## Disk images (`pkg/disk`)

| Feature | Status |
| --- | :---: |
| DMG read: zlib, bzip2, ADC, LZFSE, LZMA chunks | ✅ |
| GPT and Apple Partition Map location | ✅ |
| Raw images, containers without a partition map (content sniffing) | ✅ |
| DMG write / lossless repack | ✅ |
| Decompressed-chunk LRU cache | ✅ |
| hdiutil-mountable created DMG wrappers | 🟡 |

## CLI commands

| Command | Status | Notes |
| --- | :---: | --- |
| `info` | ✅ | text/JSON; APFS forensic report flags |
| `list` | ✅ | recursive; JSON lines |
| `cat` | ✅ | multi-file to stdout |
| `extract` | ✅ | metadata, verify, symlink policy, name sanitization |
| `inspect` | ✅ | APFS only (walk / block / fstree) |
| `mount` | ✅ | APFS only; Linux/macOS FUSE |
| `pack` | ✅ | directory→HFS+ or APFS DMG (`--fs`), or lossless DMG repack |
| `create` | ✅ | empty HFS+ or APFS volume (`--fs`) |

## Quality gates

| Gate | Where |
| --- | --- |
| Unit + fixture acceptance tests | all OSes in CI |
| Real vendor-DMG acceptance (Firefox HFS+, Zed APFS) | all OSes in CI |
| `fsck_hfs` + `hdiutil` on created HFS+ | macOS in CI |
| `fsck_apfs` on created APFS | macOS in CI |
| `apfsck` (pinned version) on created APFS | Linux in CI |
| Byte-for-byte extraction vs `hdiutil` mount | macOS in CI |
