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
| FileVault / encryption unlock | ✅¹⁰ | — |
| `io/fs.FS` adapter | ✅ | ✅ |
| Create empty volume | ✅ | ✅ |
| Case-insensitive volumes (write) | ✅ | 🟡⁹ |
| Populate a volume with files | ✅ | ✅ |
| Reproducible output (`SOURCE_DATE_EPOCH`, fixed UUIDs) | ✅ | ✅ |
| Volume roles and volume groups (read + write) | ✅² | — |
| Write-fidelity reporting (`--strict`) | ✅ | ✅ |
| Resource forks (write) | ✅⁴ | ✅ |
| Extended attributes (write) | ✅⁴ | ✅⁷ |
| Hard links (write) | ✅ | ✅⁸ |

¹ Several snapshots per volume and per container, each at its own transaction
id, with the live state one past the newest. Transaction ids come from a single
container-wide sequence, since two volumes' snapshots are two points in the same
history. The live state is one past the newest. macOS refuses to mount a container whose only
checkpoint sits at a raised id with nothing before it, so a predecessor
checkpoint is written alongside the live one describing the same objects. The
cap is the snapshot-metadata tree, built here as a single node.

¹⁰ Unlocking a volume with a password supplied by the caller, using the keybag
layout and key wrapping the format documents. An encrypted volume is detected
from the volume superblock's `APFS_FS_UNENCRYPTED` flag whether or not a
password is given, and one that cannot be unlocked is reported as locked rather
than read as ciphertext. Both AES-128-XTS and AES-256-XTS volume keys are
handled. The object map is not encrypted even on a FileVault volume; the
file-system tree and file contents are. Writing an encrypted volume is not
supported and is not planned.

² Roles read and written in full. Several volumes per container are written
through `CreateOptions.Volumes`, one per 512 MiB as the format allows, and a
volume group is written as the system/data pair it is — `create --volume-group`
makes both halves. The two halves share one inode-number space split at
`UNIFIED_ID_SPACE_MARK`: the system half numbers above it, the data half below.
Firmlinks, sealing and bootability are out of scope. A grouped system
volume numbers its inodes from `UNIFIED_ID_SPACE_MARK` upward, which is the
obligation `APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE` takes on; the reserved
numbers below `MIN_USER_INO_NUM` stay where they are, which is where the spec
and `fsck_apfs` disagree (see `inoBaseFor` in `pkg/apfswrite/writer.go`).

⁴ Attributes of any size, including resource forks: small values are stored
inline and larger ones get a data stream. `com.apple.decmpfs` is carried through
unchanged, with `UF_COMPRESSED` set to match; a file whose parts disagree with
the attribute is refused rather than written. `pack` preserves a source file's
transparent compression by default on both file systems, and `--decompress`
writes those files out in full instead.

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

⁹ `H+` version 4 with the case-folding catalog compare, alongside the
case-sensitive HFSX default, through `hfsplus.CreateOptions.CaseInsensitive`.
The fold table was derived by observing macOS (`scripts/derive-casefold.sh`)
rather than transcribed, because HFS+ froze its fold around Unicode 3.2 and
current data disagrees.

Two known limitations, both found by auditing the claims in this table rather
than by a bug report. **A case-insensitive volume carrying hard links is
ordered wrongly**: macOS sorts the private metadata directory (whose name
begins with four NULs) after every other name in the root, which matches
neither comparing those NULs as U+0000 nor ignoring them, so `fsck_hfs` reports
"b-tree key for HFS+ Private Data directory is out of order" and the links do
not resolve. Until that is understood, the CLI cannot offer case-insensitive
HFS+ volumes, so **`create --case-sensitive` is accepted and ignored on
`--fs hfs+`**, which always produces the case-sensitive HFSX default. APFS
honours the flag.

⁸ Several names for one file share a single copy of the content, through an
indirect node in the volume's private metadata directory, as macOS does it. The
content's extended attributes live on the indirect node, so a reader resolving
any name reports them.

⁷ Values of any size: a small one lives inside its attribute record and a
larger one gets an allocation extent of its own. `com.apple.decmpfs` is carried
through unchanged, with `UF_COMPRESSED` set in the catalog record's BSD flags to
match; a file whose parts disagree with the attribute is refused rather than
written. A volume with no attributes carries no attributes file at all.

⁶ All three attribute record shapes are read on HFS+ — a value stored inside its
record, one given a fork of its own, and a fork whose extents spill past the
eight it can hold inline. A file's resource fork is reported as
`com.apple.ResourceFork`, matching what macOS presents, although HFS+ stores it
as a fork of the catalog record rather than in the attributes file.

The APFS writer lives in `pkg/apfswrite` (pure Go, MIT).

## Disk images (`pkg/disk`)

| Feature | Status |
| --- | :---: |
| DMG read: zlib, bzip2, ADC, LZFSE, LZMA chunks | ✅¹² |
| GPT and Apple Partition Map location | ✅¹¹ |
| Raw images, containers without a partition map (content sniffing) | ✅ |
| DMG write / lossless repack | ✅ |
| Decompressed-chunk LRU cache | ✅ |
| hdiutil-mountable created DMG wrappers | ✅ |

## CLI commands

| Command | Status | Notes |
| --- | :---: | --- |
| `info` | ✅ | text/JSON; APFS forensic report flags |
| `list` | ✅ | recursive; JSON lines |
| `cat` | ✅ | multi-file to stdout |
| `extract` | ✅ | metadata, verify, symlink policy, name sanitization |
| `inspect` | ✅ | structural walk for both; `block` and `fstree` are APFS only |
| `mount` | ✅ | APFS and HFS+; Linux/macOS FUSE; serves extended attributes |
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

¹¹ Both schemes, in a DMG or in a raw whole-disk image. A DMG carrying an Apple
Partition Map is located through its blkx partition names; a raw image has the
map itself parsed at block 1.

¹² Each codec has a fixture of the same volume compressed that way, and they are
checked against each other rather than against a recorded hash, so a decoder
that is wrong but self-consistent shows up.
