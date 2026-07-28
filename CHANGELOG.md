# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`mount` and `inspect` work on HFS+** (`internal/tools`, `internal/cli`).
  Both were APFS-only: `mount` was built directly on `*apfs.FileEntry`, and
  `inspect` had nothing to say about a volume with no container.

  The FUSE layer is now written against `VolumeFS` — the same interface `list`,
  `cat` and `extract` already share — so it serves whichever file system the
  image turned out to hold. Extended attributes are served too, so `xattr` and
  `ls -l@` work against a mount. `mount` also goes through the shared opener,
  which means it honours `--volume`, `--offset` and the password flags exactly
  as the other commands do, rather than reimplementing them.

  That deleted about 1300 lines of APFS-specific mount code, which existed only
  because the FUSE layer reached past the file-system abstraction.

  `inspect` gained a structural walk for HFS+: the volume header, each special
  file with its fork and extents, and each B-tree's header record — node size,
  depth, record count and key comparison. The `block` and `fstree` modes stay
  APFS-only, since HFS+ has no container, checkpoints or object map, and now say
  which mode is unavailable rather than reporting the image as unreadable.

- **The HFS+ writer can emit case-insensitive volumes** (`pkg/hfsplus`).
  `CreateOptions.CaseInsensitive` produces plain HFS+ (`H+`, version 4, catalog
  `keyCompareType` 0xCF) instead of the case-sensitive HFSX default, which
  matches what `hdiutil create -fs HFS+` produces.

  The fold table this needs was **derived by observing macOS**
  (`scripts/derive-casefold.sh`) rather than transcribed: a case-insensitive
  volume is created, one file per BMP code point is written to it, and the
  catalog B-tree's leaf order — which is fold order — is read back. The derived
  table is then required to reproduce that observed order exactly before it is
  written out.

  That mattered. HFS+ froze its fold around Unicode 3.2, so a table built from
  current Unicode data is wrong in 38 places: modern data maps the Georgian
  block `U+10A0`–`U+10C5` to Nuskhuri at `U+2D00`+, while HFS+ maps it to
  Mkhedruli at `U+10D0`+, so every Georgian name would sort and resolve
  incorrectly. `U+1E9E`, added in Unicode 5.1, is another — it folds to itself
  here rather than to `ß`.

- **The HFS+ writer represents hard links** (`pkg/hfsplus`, CLI). Several names
  for one file became independent copies; they now share one copy of the
  content, so `hardLinksCollapsed` is zero where it counted every extra name.

  HFS+ does this indirectly: the content lives in an `iNodeNNNN` file inside a
  private directory at the volume root, and each visible name is a catalog
  record carrying the `hlnk` type, the `hfs+` creator and that node's catalog id.
  The shape follows a volume macOS created rather than the prose — the private
  directory is invisible and name-locked with a mode carrying no permission
  bits, and the indirect node holds the file's extended attributes as well as
  its content, which is where a reader resolving a link expects to find them.

  Verified through the kernel rather than only the checker: macOS mounts the
  image and reports one inode with three names and a link count of three, and
  the private directory does not appear in a listing.

- **The HFS+ writer carries extended attributes** (`pkg/hfsplus`, CLI). It
  emitted no attributes file at all, so every attribute was dropped. Packing the
  committed HFS+ fixture now reports **every fidelity counter at zero**, and
  `extract --xattrs` → `pack --fs hfs+` → `extract --xattrs` returns all
  fourteen attributes, including a 6000-byte one.

  Values of any size are carried: a small one lives inside its record, and a
  larger one gets an allocation extent of its own with a fork-data record
  pointing at it. `com.apple.decmpfs` is refused rather than written wrong — the
  data is written plain, so the header would describe bytes that are not there —
  and is reported as dropped.

  `HFSHasAttributesMask` is set on exactly the catalog records that have
  attributes, because `fsck_hfs` checks the flag against the attributes file in
  both directions. A volume with no attributes carries no attributes file at
  all, so images this writer produced before stay byte-identical.

  The tree's header constants were read off a volume macOS created rather than
  guessed: `maxKeyLength` 266, `attributes` 0x06, and `keyCompareType` 0 — the
  last notably not one of the catalog's compare types, because attribute names
  are ordered as plain UTF-16 code units.

- **The HFS+ writer carries resource forks** (`pkg/hfsplus`, CLI). They were
  dropped entirely, so a resource fork could be read off an HFS+ image and not
  written back to one. A file's fork now survives `extract --xattrs` → `pack
  --fs hfs+` byte-identically, and `resourceForksDropped` is zero where it used
  to count every one.

  A resource fork is a fork of the catalog record on HFS+, not an
  attributes-file record, so this needs no attributes file: the fork gets its
  own extent alongside the data fork, and the allocation bitmap and free-block
  count account for it. A file without one keeps an all-zero fork descriptor
  rather than a zero-length extent, which is what `fsck_hfs` expects.

  Verified by `fsck_hfs -n` reporting the volume clean and by `hdiutil`
  mounting it, with the fork readable both as `..namedfork/rsrc` and as
  `com.apple.ResourceFork`.

- **HFS+ transparent compression is read** (`pkg/hfsplus`, CLI). A file carrying
  `UF_COMPRESSED` returned an error instead of its contents; it now decodes.
  Both storage shapes work: data held inline in the `com.apple.decmpfs`
  attribute, and data held in the file's resource fork in 64 KiB chunks — which
  is what `ditto --hfsCompression` produces and what nothing in this package
  read before, `forkTypeResource` having been declared and never used.

  `Stat` reports the size from the decmpfs header rather than the data fork's,
  which is empty for a compressed file — so such a file listed as zero bytes
  even once it could be read. Where a file's compression metadata is broken it
  still lists at its data fork's size and then fails on read, because
  `fs.DirEntry.Info` has no error path worth failing into.

  No decoding was added: `internal/decmpfs` already had it, and this supplies
  only the two things HFS+ does differently — where the attribute comes from and
  where the resource fork is.

- **The fixture generator produces the HFS+ set too** (`scripts/gen-fixtures.sh`).
  `testdata/cli/hfs-basic.dmg` and its manifest were committed with no script
  that could rebuild them, while a test hard-failed without them: load-bearing
  and unreproducible at once. Both file systems now get the same tree from one
  shared function, so the two can be compared against each other, and the script
  takes an optional `apfs`/`hfs+` argument.

  The tree gained what the attribute and compression work needs to be tested
  against bytes macOS wrote rather than bytes we synthesized: a large attribute
  that cannot fit in an inline record, a real resource fork, and a
  `ditto --hfsCompression` file on both volumes. `random.bin` is now generated
  deterministically rather than from `/dev/urandom`, so regenerating twice
  produces the same fixture — which is the point of committing one.

  The manifest records each file's extended attributes and whether it is
  compressed. It is not exhaustive: macOS hides `com.apple.decmpfs` and the
  resource fork of a compressed file from a normal listing, so tests assert that
  the recorded attributes are present rather than that they are all there is.

- **HFS+ extended attributes are read** (`pkg/hfsplus`, CLI). The attributes
  file — the third of the volume's B-trees — was not parsed at all, so no
  attribute reached the `io/fs` adapter. `extract --xattrs` was therefore a
  silent no-op on every HFS+ image: `internal/tools` asks the volume for
  attributes through an interface `*hfsplus.Volume` did not satisfy, so it
  returned without doing anything. Extracting the committed HFS+ fixture with
  `--xattrs` now restores seven attributes where it restored none.

  All three record shapes are handled: a value stored inside its own record, a
  value given a fork of its own, and a fork whose extents spill past the eight
  it holds inline. Those spilled extents live in the attributes tree itself,
  keyed by the same file and attribute name with a non-zero start block — not in
  the extents overflow file, whose keys only ever name a data or resource fork.

  A file's resource fork is reported as `com.apple.ResourceFork`, matching what
  macOS presents, even though HFS+ stores it as a fork of the catalog record
  rather than as an attribute. `com.apple.decmpfs` is returned like any other
  attribute rather than filtered out, as on APFS; `extract` already drops
  compression metadata when writing files back out, because it decompresses as
  it reads.

  Attributes of a hard link come from its target's catalog record, which is
  where HFS+ keeps them.

- **The APFS writer represents hard links** (`pkg/apfswrite`, CLI). Several
  names for one file previously became independent copies; they now share one
  inode and one copy of the content, so six names for a 512 KiB file cost
  512 KiB rather than three megabytes.

  A file with several names gets `nlink` set, a sibling-link record per name, a
  sibling-map record per sibling id, and a sibling-id extended field on each of
  its directory entries. Sibling ids come from the same pool as inode numbers,
  so the volume's next object id accounts for them. HFS+ has no way to
  represent a link and still reports each extra name as collapsed.

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

- **decmpfs decoding moved to `internal/decmpfs`**, shared rather than owned by
  `pkg/apfs`. Transparent compression is a property of the file, not of the file
  system: the `com.apple.decmpfs` header, the 64 KiB block table and the codecs
  are identical on HFS+ and APFS, and HFS+ is where it started. Keeping the
  decoder inside the APFS reader would have meant either making `pkg/hfsplus`
  depend on the whole APFS engine, or writing the block-table parser a second
  time — and the block table is the part that has cost the most to get right.

  `pkg/apfs`'s published names are unchanged, kept as type aliases:
  `CompressedDataHandle`, `CompressedDataHeader`, `DecompressData`,
  `NewCompressedDataHandle`, `ParseCompressedDataHeader`, `CompressionMethod*`,
  `CompressedDataHandleBlockSize`, `CompressedDataHeaderSize` and
  `CompressedDataHeaderSignature`. One field changes type:
  `CompressedDataHandle.CompressedDataStream` is now a `CompressedDataSource`
  (an `io.ReaderAt` that knows its size) rather than a `*DataStream`. Passing a
  `*DataStream` still compiles, since it satisfies the interface.

  Two dead parameters went with the move: `loadCompressedBlockOffsets` and
  `ReadSegmentData` each took an `io.ReaderAt` they never read from.

- **The APFS writer now accepts only a 4096-byte block** (`pkg/apfswrite`).
  `CreateOptions.BlockSize` previously took any power of two from 4096 to 65536,
  as the format allows, and the writer's arithmetic is parameterised by it
  throughout — so the larger sizes looked supported. They were not. Measured
  against the checkers:

  | block size | `fsck_apfs -n` | `apfsck -cw` |
  | --- | --- | --- |
  | 4096 | clean | clean |
  | 8192 | clean | clean |
  | 16384 | `invalid btn_table_space`, no valid checkpoint | `Omap record: bad alignment for key or value` |
  | 65536 | spins without reaching a verdict | clean |

  Every non-4096 container was also unreadable by this project's own reader:
  `pkg/apfs` reads a fixed 4096-byte container superblock and so verifies the
  Fletcher-64 over a different span than the writer sealed it over, which fails
  as a checksum mismatch before any block-size check is reached. Writing an
  image that neither Apple's checker nor our own reader accepts is worse than
  refusing to write it.

  `CreateOptions.BlockSize` is deprecated rather than removed, since it is
  public API, and nothing in the command line ever set it — so no existing
  invocation changes behaviour. Supporting larger blocks again means a two-phase
  superblock read on the reader side and a corrected layout on the writer side,
  neither of which is a deletion of a check.

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

- **HFS+ names are normalized, so macOS can find them** (`pkg/hfsplus`). HFS+
  stores names decomposed; the writer stored them as given. A name containing a
  precomposed character such as `ü` was therefore written in a form macOS does
  not look for — the file was on the volume, listed by `ls`, and could not be
  opened by name. It affected HFSX and `H+` alike.

  Names are now decomposed on write, and a lookup normalizes its query, so
  either spelling resolves. A listing reports what is on disk, as macOS does,
  which means `ReadDir` returns the decomposed form.

  The decomposition is NFD with an exclusion list, derived by observing macOS
  (`scripts/derive-normalization.sh`): of the 12665 decomposing BMP code points,
  523 are stored intact and the rest match NFD exactly, with none differing in
  any other way. The exclusions are the CJK compatibility ideographs at `U+F900`+
  and part of `U+2000`–`U+2FFF`, which HFS+ leaves alone deliberately, plus a
  few whose decompositions postdate the behaviour Apple froze — the same reason
  `U+1E9E` folds to itself.

- **decmpfs type 5 is no longer decoded as sparse and answered with zeros.**
  It was mapped to a "compression method" that filled the caller's buffer with
  zeros, and documented as "uncompressed, stored inline". Both are wrong: per
  Apple's `copyfile.c`, type 5 marks de-duplication within the generation store,
  so the attribute does not describe the file's content at all. A file using it
  therefore read back as the right length of nothing, with no error — the worst
  failure mode available to a reader. It is now refused by name, alongside the
  other recognized-but-undecoded types.

  `CompressionMethodUnknown5` is deprecated and unreachable: nothing maps to it,
  and `NewCompressedDataHandle` rejects it.

- **The documented HFS+ capabilities now match the code.** Three claims were
  wrong, and each of them would have sent someone down a path that could not
  work:

  `README.md` and `TOOLS_STATUS.md` marked transparent compression as
  implemented for HFS+. It is not: a file with the `UF_COMPRESSED` flag returns
  an error instead of its contents, and the resource fork that decmpfs stores
  compressed data in is never read.

  `TOOLS_STATUS.md` marked HFS+ extended-attribute reading as partial. There is
  no partial support — the attributes file is not parsed at all, so no attribute
  is visible through the `io/fs` adapter and `extract --xattrs` silently carries
  nothing off an HFS+ image. The `extract` synopsis in `README.md` also omitted
  `--xattrs` entirely, and did not say that both it and transparent
  decompression apply only to APFS.

  Finally, the decmpfs note in `TOOLS_STATUS.md` and the preamble to
  `pkg/apfs/decmpfs_test.go` both said no image available to this project
  contains a decmpfs-compressed file. One does, and always has:
  `compressed.txt` in `testdata/cli/basic.dmg` is type 8 — LZVN in a resource
  fork, written by `ditto --hfsCompression` — so that path is covered against
  bytes macOS produced rather than only against synthesized fixtures.

  Both HFS+ gaps are now listed under "Near term" in `TOOLS_ROADMAP.md`.

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
