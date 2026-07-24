# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  (raw filesystem image preserved bit-for-bit); LZMA (ULMO) chunk support and
  Apple Partition Map handling on the read side.
- **CLI**: `info`, `list`, `cat`, `extract`, `inspect`, `mount`, `pack`,
  `create` — all behind cobra/viper with `--output json`, `APFS_*` environment
  variables, an optional config file, and documented exit codes.
- Cross-platform CI (Linux/macOS/Windows) with fixture and real-world vendor-DMG
  acceptance tests and native-checker validation.

### Changed

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
