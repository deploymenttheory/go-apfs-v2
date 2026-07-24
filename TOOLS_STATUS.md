# Implementation status

A snapshot of what is implemented. See [`README.md`](README.md) for usage and
[`TOOLS_ROADMAP.md`](TOOLS_ROADMAP.md) for what is planned.

Legend: ✅ implemented · 🟡 partial · ⬜ not yet

## Filesystems

| Area | APFS | HFS+ / HFSX |
| --- | :---: | :---: |
| Read (containers, volumes, catalog, extents) | ✅ | ✅ |
| Transparent compression (zlib / LZVN / LZFSE) | ✅ | ✅ |
| Symlinks, hardlinks | ✅ | ✅ |
| Extended attributes (read) | ✅ | 🟡 |
| Snapshots (read) | 🟡 | ⬜ |
| FileVault / encryption unlock | ✅ | — |
| `io/fs.FS` adapter | ✅ | ✅ |
| Create empty volume | ✅ | ✅ |
| Populate a volume with files | ✅ | ✅ |

The APFS writer lives in `pkg/apfswrite` (pure Go, MIT).

## Disk images (`pkg/disk`)

| Feature | Status |
| --- | :---: |
| DMG read: zlib, bzip2, ADC, LZFSE, LZMA chunks | ✅ |
| GPT and Apple Partition Map location | ✅ |
| Raw images, bare containers (content sniffing) | ✅ |
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
| `inspect` | ✅ | APFS only (walk / block / btree) |
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
