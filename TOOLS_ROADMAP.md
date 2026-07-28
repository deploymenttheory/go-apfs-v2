# Roadmap

Current capabilities are described in [`README.md`](README.md) and their
implementation state in [`TOOLS_STATUS.md`](TOOLS_STATUS.md). This file lists
what is planned or under consideration, roughly in priority order.

## Recently completed

- **APFS file population** — `pack <dir> --fs apfs` now builds a populated APFS
  volume (files of any size, symlinks, nested directories) and `create --fs
  apfs` formats an empty one, in pure Go. Validated against `fsck_apfs`,
  `hdiutil` and `apfsck`.
- **Multi-volume containers and volume groups** — `CreateOptions.Volumes`
  writes several volumes per container, and `create --volume-group` writes a
  complete system/data pair, with snapshots on any volume. Validated against
  `apfsck`'s volume-group checks, which a lone system volume could never
  exercise.
- **APFS snapshots** — `apfs snapshot {create,list,revert,verify}` and the
  `--snapshot` flag on `create`/`pack`. Spec-compliant snapshots recognized by
  macOS (`diskutil apfs listSnapshots`); revert marks `revert_to_xid` for
  roll-back on next mount. Several snapshots per image, each at its own
  transaction id.

## Near term

- **Case-insensitive HFS+ with hard links.** The private metadata directory
  sorts differently from anything this writer produces: on a volume macOS
  wrote, it comes after every other name in the root, which is neither the
  order given by comparing its four leading NULs as U+0000 nor the order given
  by ignoring them. Until the rule is known, `create --case-sensitive` cannot
  be honoured on `--fs hfs+`. See `TOOLS_STATUS.md` note 9.



## Medium term

- **decmpfs on write** — needs the compression machinery and the inode's
  BSD flags, not just the attribute.

## Under consideration

- **FileVault / encrypted APFS validation** with committed encrypted fixtures.
- **`goreleaser`** packaging and signed release archives.
- **HFS+ classic / HFS wrapper** and **LZMA-only DMG** edge cases seen in the
  wild.

Contributions and priority feedback are welcome via GitHub issues.
