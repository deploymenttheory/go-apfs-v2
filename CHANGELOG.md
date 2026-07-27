# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The APFS writer carries extended attributes** (`pkg/apfswrite`, CLI). They
  were dropped entirely before, so `extract` → `pack` could never round-trip a
  real macOS tree; now an ordinary attribute survives it. Attributes are stored
  inline, up to the format's 3804-byte embedded limit.

  The inode flags that must agree with which attributes are present —
  `INODE_HAS_SECURITY_EA`, `INODE_HAS_FINDER_INFO` and `INODE_NO_RSRC_FORK` —
  are set accordingly; a checker compares each against its attribute and
  complains either way.

  Attributes of any size are carried: a small value lives inside its record, and
  a larger one — along with any resource fork, however small — gets a data
  stream of its own. A resource fork has no size threshold because `fsck_apfs`
  requires one to be stream based whatever its size. An attribute's stream
  carries no `DSTREAM_ID` record, unlike a file's, because it cannot be cloned
  and so has no reference count to keep.

  `com.apple.decmpfs` is refused rather than written wrong, and reported as
  dropped: it declares content this writer does not produce. See
  [`docs/write-fidelity.md`](docs/write-fidelity.md).

- **Building an image no longer holds it in memory** (`internal/imagefile`,
  `pkg/disk`, CLI). The DMG encoder can now read its source lazily through
  `SourceBlock.Reader`, and `create`, `pack <dir>` and `snapshot create` build
  into a temporary file rather than a `bytes.Buffer`. Creating a 2 GiB image
  went from 2551 MB of peak resident memory to 16 MB.

  The scratch file goes beside the output rather than in the system temporary
  directory, which is often small and on many Linux images is RAM-backed —
  putting it there would reproduce the problem being fixed. `--temp-dir`
  overrides. Output is byte-identical to before.

  `pack SRC.dmg OUT.dmg` no longer materialises the source image either.
  `reconstructBlocks` describes each blkx block as a lazy reader that
  decompresses chunks on demand, so `RepackDMG` re-chunks on the fly. Repacking
  a 500 MB vendor DMG went from 924 MB of peak resident memory to 33 MB.
  `ReconstructRawImageTo` is the streaming counterpart of
  `ReconstructRawImage`, and `snapshot revert` uses it, so nothing in the
  command line assembles a whole image any more.

  `pkg/hfsplus` writes its image region by region rather than assembling it in
  a single `[]byte` — which mattered most, HFS+ being the default `--fs`.
  Creating a 2 GiB HFS+ image went from 1449 MB of peak resident memory to
  17 MB. `pkg/apfswrite` writes each file's content in fixed windows rather
  than allocating a buffer the size of the file, so one large file inside an
  otherwise small tree no longer costs its own size in memory.

- **Write-fidelity reporting and `--strict`** (`pkg/fidelity`, `pkg/apfswrite`,
  `pkg/hfsplus`, CLI): packing a directory is lossy, and until now it was
  silently so. `pack <dir>` and `snapshot create` now count and report every
  thing the volume cannot carry — special files skipped, extended attributes,
  resource forks and ACLs dropped, hard links collapsed into copies, BSD flags
  lost, and (for a volume rebuild) the volume's role and group membership.
  Counts appear as `Note:` lines and, under `--output json`, as stable keys with
  every key always present. `--strict` refuses to write anything at all when
  something would be lost, failing before the destination is created.

  Exit codes: entries omitted from the volume give 6, the same "some things
  could not be handled" meaning `extract` already has; metadata loss alone gives
  0. That distinction is deliberate — macOS attaches `com.apple.provenance` to
  files as they are written, so treating a dropped attribute as failure would
  make almost every pack of a macOS tree exit non-zero. See
  [`docs/write-fidelity.md`](docs/write-fidelity.md).

- **`extract --xattrs`** now restores extended attributes onto the extracted
  files. It was previously a reserved flag that did nothing, which meant
  extract-then-pack discarded every attribute however capable the writer was.
  Transparent-compression metadata is deliberately not restored: extraction
  decompresses as it reads, so restoring `com.apple.decmpfs` would leave the
  file describing content it no longer holds.

- Both writers expose `EntryTreeFromDir`, returning the entry tree alongside the
  account of what the conversion dropped, so a program can inspect it before
  deciding to write. `CreateContainerFromDir` and `CreateImageFromDir` remain as
  wrappers that discard the report.


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

- **`pack <dir>` no longer hangs on a device node, FIFO or socket**
  (`pkg/apfswrite`, `pkg/hfsplus`). Both directory walks fell through to reading
  such a file as though it were regular, and none of the three failure modes was
  clean: opening a FIFO blocks until a writer appears, so the command never
  returned; a character device such as `/dev/zero` reads until memory runs out;
  a socket errors and aborts the whole pack. They are now skipped and counted.
  This applied to both `--fs apfs` and `--fs hfs+`, the latter being the default.

  `CreateContainer` also now rejects an `Entry` whose mode carries an
  unsupported type bit, rather than stamping it `S_IFREG` and writing a device
  node as a regular file. The walk skips these; a caller assembling a tree by
  hand is told.

- **A DMG whose chunks were all zero-fill could not be read back**
  (`pkg/disk`). Such an image writes no data fork, so its plist starts at offset
  zero — which the reader took for "no plist at all" and rejected. It went
  unnoticed because building a fully sparse image previously needed as much
  memory as the image was nominally large; it is exactly what a large repack
  produces.

- **Reading an extended attribute could loop forever** (`pkg/apfs`).
  `ExtendedAttribute.Read` relied on the underlying stream to report `io.EOF`,
  so a stream that signalled its end by returning `(0, nil)` turned any
  `io.Reader` loop over the attribute — `io.ReadAll` inside `Volume.Xattrs`, for
  instance — into an endless one. The reader now bounds itself by the
  attribute's own size. Nothing reached this path until `extract --xattrs`
  existed.

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

- Partition-offset handling, multi-leaf B-tree traversal, DMG chunk caching,
  and decmpfs size/handle wiring in the APFS reader (see git history for the
  detailed fixes).

## Historical

Earlier `1.x` entries in this file predated the rearchitecture and referred to
the repository template; they have been removed.
