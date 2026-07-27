# Implementation status

A snapshot of what is implemented. See [`README.md`](README.md) for usage and
[`TOOLS_ROADMAP.md`](TOOLS_ROADMAP.md) for what is planned.

Legend: ✅ implemented · 🟡 partial · ⬜ not yet

## File systems

| Area | APFS | HFS+ / HFSX |
| --- | :---: | :---: |
| Read (containers, volumes, file-system tree, extents) | ✅ | ✅ |
| Transparent compression (zlib / LZVN / LZFSE) | ✅³ | ✅ |
| Symlinks, hardlinks | ✅ | ✅ |
| Extended attributes (read) | ✅ | 🟡 |
| Snapshots (read / list) | ✅ | — |
| Snapshots (create, revert) | ✅¹ | — |
| FileVault / encryption unlock | ✅ | — |
| `io/fs.FS` adapter | ✅ | ✅ |
| Create empty volume | ✅ | ✅ |
| Populate a volume with files | ✅ | ✅ |
| Reproducible output (`SOURCE_DATE_EPOCH`, fixed UUIDs) | ✅ | ✅ |
| Volume roles and volume groups (read + write) | ✅² | — |
| Write-fidelity reporting (`--strict`) | ✅ | ✅ |
| Extended attributes (write) | ⬜ | ⬜ |
| Hard links (write) | ⬜ | ⬜ |

¹ One snapshot per image (single static checkpoint); multiple snapshots need
distinct xids and incremental checkpoints.

² Roles read and written in full. A volume group can only be written on a
system volume: a group is a system/data pair and the writer emits one volume
per container, so the resulting group has no data half.

³ decmpfs types 3/4 (zlib), 5, 7/8 (LZVN) and 11/12 (LZFSE), stored inline in
the attribute or in a resource fork. Types 9/10 (uncompressed) and 13/14
(LZBITMAP) are recognized and reported as unsupported rather than decoded.
Coverage is by synthesized fixtures: no image available to the project contains
a decmpfs-compressed file, and producing a real LZFSE one needs macOS plus
`afsctool`.

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
