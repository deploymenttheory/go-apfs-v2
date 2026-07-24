# Roadmap

Current capabilities are described in [`README.md`](README.md) and their
implementation state in [`TOOLS_STATUS.md`](TOOLS_STATUS.md). This file lists
what is planned or under consideration, roughly in priority order.

## Near term

- **APFS file population** — the biggest gap. `create --fs apfs` currently
  formats an *empty* container (the `mkapfs` equivalent). Writing user files
  into an APFS volume requires copy-on-write catalog B-tree insertion, extent
  allocation and space-manager updates. This would bring `pack <dir>` to APFS,
  matching what already works for HFS+.
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
