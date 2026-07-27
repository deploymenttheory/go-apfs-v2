# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **decmpfs LZFSE (types 11 and 12) now decompresses** (`pkg/apfs`). It was
  listed as supported in the README and TOOLS_STATUS, but was blocked in three
  places: `internalCompressionMethod` returned "not supported yet",
  `NewCompressedDataHandle` rejected the method, and the resource-fork
  block-offset table was never parsed for it. The leaf decompressor already
  existed and was simply unreachable. Real vendor applications ship
  LZFSE-compressed files, so extraction could hard-fail on exactly the images
  the tool exists for.

  The per-chunk raw escape is signalled by the *absence* of the LZFSE block
  magic (`'b'`, the first byte of `bvx1`/`bvx2`/`bvxn`), which macOS writes
  behind a `0xff` marker — not by LZVN's `0x06` sentinel. Reusing that sentinel
  would misread any raw chunk whose first byte differed.

- **Inline decmpfs never worked, for any method** (`pkg/apfs`). Data stored in
  the `com.apple.decmpfs` attribute rather than a resource fork — types 3
  (zlib), 7 (LZVN) and 11 (LZFSE) — was handed to the block-offset loader with
  its 16-byte header already stripped, but that loader identifies inline
  storage by finding the `fpmc` magic at offset zero and skips the header
  itself. The value is now passed whole, and the magic is verified so a
  regression fails loudly instead of misparsing compressed bytes as an offset
  table.

- **A resource fork with more than ~8159 zlib blocks (about 510 MB) faulted**
  (`pkg/apfs`) with a slice-bounds panic instead of returning an error: the
  descriptor table was read into a fixed 65537-byte scratch buffer that only
  holds so many 8-byte descriptors. It is now sized from the table.

- decmpfs types 9/10 (uncompressed) and 13/14 (LZBITMAP) are now named in the
  "not supported" error rather than reported as an unrecognized type.

### Added

- **Volume roles and volume groups** (`pkg/apfs`, `pkg/apfswrite`, CLI):
  `apfs_role` was parsed and then used nowhere, and `apfs_volume_group_id` was
  not parsed at all, so a macOS installer or system image was illegible — N
  similarly-named volumes with no indication which held the OS. `apfs info` now
  reports each volume's role and volume group in both text and JSON (`role`,
  `roleName`, `roleValue`, `volumeGroupId`; omitted when unset, so the existing
  schema is unchanged for role-less volumes), and `-v/--volume` accepts a role
  token (`-v system`, or `-v role:system` to match only on role), erroring with
  the candidates listed when a role matches several volumes. `create --fs apfs`
  gains `--role` and `--volume-group`.

  Roles are a **single value, not a bit field**: Apple writes the low six as
  `0x0001`, `0x0002`, `0x0004` … but a checker matches `apfs_role` exactly, so
  `SYSTEM|DATA` is not a role. Decoding by exact match also makes the shifted
  encoding unambiguous: `APFS_VOL_ROLE_UPDATE` is `3 << 6` = `0x00c0`, which a
  bitwise decode would report as "Data, Baseband".

- **Reproducible output** (`pkg/apfswrite`, `pkg/hfsplus`, CLI): `create`,
  `pack` and `snapshot create` now produce byte-identical images for identical
  input, making a built image content-addressable, "did the vendor change
  anything?" hash-decidable, and attestation over the output meaningful.
  `--source-date-epoch` (and the standard bare `SOURCE_DATE_EPOCH`) pins the
  build timestamp and clamps source modification times newer than it, per the
  reproducible-builds convention; `--uuid`, `--volume-uuid` and
  `--container-uuid` pin the volume and container identity, with the APFS
  container UUID derived from the volume UUID as an RFC 4122 v5 UUID when only
  the latter is given. `SOURCE_DATE_EPOCH` resolves as flag > bare variable >
  `APFS_SOURCE_DATE_EPOCH` > config file — the one deliberate exception to the
  tool's usual precedence, because build systems set the unprefixed name. See
  [`docs/reproducible-output.md`](docs/reproducible-output.md).

- **APFS snapshots** (`pkg/apfswrite`, `pkg/apfs`, CLI): spec-compliant snapshot
  creation recognized by macOS (`diskutil apfs listSnapshots`) and validated
  with `fsck_apfs`/`apfsck`. `apfs snapshot {list,create,revert,verify}` plus a
  `--snapshot NAME` flag on `create`/`pack`. Create rebuilds an image with an
  added snapshot; revert marks the volume's `revert_to_xid` for roll-back on
  next mount. One snapshot per image today (single static checkpoint).

- **HFS+/HFSX reader** (`pkg/hfsplus`): catalog and extents-overflow B-trees,
  fork data reading, symlinks, hardlink resolution, transparent compression
  detection, and an `io/fs.FS` adapter.
- **HFS+ writer** (`pkg/hfsplus`): build a valid HFS+/HFSX volume from a
  directory tree (`apfs pack <dir>`); validated with `fsck_hfs` and `hdiutil`.
- **APFS container writer** (`pkg/apfswrite`, MIT): a pure-Go writer that builds
  a single-volume APFS container from scratch — empty, or populated with a
  directory tree of files, symlinks and nested directories. Validated against
  `fsck_apfs`/`hdiutil` (macOS) and `apfsck` (Linux). Exposed via
  `apfs create --fs apfs` and `apfs pack <dir> --fs apfs`.
- **DMG/UDIF writer** (`pkg/disk`): `apfs pack` repacks a DMG losslessly
  (raw file system image preserved bit-for-bit); LZMA (ULMO) chunk support and
  Apple Partition Map handling on the read side.
- **CLI**: `info`, `list`, `cat`, `extract`, `inspect`, `mount`, `pack`,
  `create` — all behind cobra/viper with `--output json`, `APFS_*` environment
  variables, an optional config file, and documented exit codes.
- Cross-platform CI (Linux/macOS/Windows) with fixture and real-world vendor-DMG
  acceptance tests and native-checker validation.

### Changed

- **Image bytes for a given input have moved once, and are stable from here.**
  `pkg/apfswrite` and `pkg/hfsplus` no longer call `time.Now()`;
  `CreateOptions.FixedTime` defaults to an exported `DefaultTime`
  (2024-01-01T00:00:00Z). Previously the wall clock reached the APFS volume
  superblock's formatted-by field and every directory entry's date-added, and
  the HFS+ volume header dates and volume identifier, so output differed on
  every run and nothing could depend on it.
- Complete rearchitecture from the initial libfsapfs port: public `pkg/apfs`
  and `pkg/disk` libraries, `Volume` implements `io/fs.FS`, and all commands
  route through a single content-sniffing image opener.

### Fixed

- Partition-offset handling, multi-leaf B-tree traversal, DMG chunk caching,
  and decmpfs size/handle wiring in the APFS reader (see git history for the
  detailed fixes).

## Historical

Earlier `1.x` entries in this file predated the rearchitecture and referred to
the repository template; they have been removed.
