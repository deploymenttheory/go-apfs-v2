# Roadmap

Current capabilities are described in [`README.md`](README.md) and their
implementation state in [`TOOLS_STATUS.md`](TOOLS_STATUS.md). This file lists
what is planned or under consideration, roughly in priority order.

## Recently completed

- **APFS file population** — `pack <dir> --fs apfs` now builds a populated APFS
  volume (files of any size, symlinks, nested directories) and `create --fs
  apfs` formats an empty one, in pure Go. Validated against `fsck_apfs`,
  `hdiutil` and `apfsck`.

## Near term

- **Case-insensitive HFS+ (`H+` v4)** — the writer currently emits
  case-sensitive HFSX (`HX`). Case-insensitive volumes need the Unicode
  case-folding comparison for catalog key ordering.
- **HFS+ `inspect` and `mount`** — these commands are APFS-only today.

## Medium term

- **Extended attributes / decmpfs on write** (both filesystems).
- **Hard links** in the HFS+ writer.
- **Multi-volume and snapshot** handling on the write side.
- **hdiutil-mountable created DMGs** — created images are read by this tool and
  their raw filesystem is `fsck`-clean and hdiutil-mountable; the DMG *wrapper*
  of a partition-map-less image is not yet directly mountable by hdiutil.

## Under consideration

- **FileVault / encrypted APFS validation** with committed encrypted fixtures.
- **`goreleaser`** packaging and signed release archives.
- **HFS+ classic / HFS wrapper** and **LZMA-only DMG** edge cases seen in the
  wild.

Contributions and priority feedback are welcome via GitHub issues.
