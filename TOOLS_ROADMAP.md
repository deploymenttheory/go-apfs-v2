# Roadmap

Current capabilities are described in [`README.md`](README.md) and their
implementation state in [`TOOLS_STATUS.md`](TOOLS_STATUS.md). This file lists
what is planned or under consideration, roughly in priority order.

## Recently completed

- **Multi-volume containers and volume groups** — `CreateOptions.Volumes`
  writes several volumes per container, and `create --volume-group` writes a
  complete system/data pair, with snapshots on any volume. Validated against
  `apfsck`'s volume-group checks, which a lone system volume could never
  exercise.
- **Several APFS snapshots per volume** — each at its own transaction id, from
  a single container-wide sequence, with a predecessor checkpoint so macOS will
  mount a container whose live state is past its newest snapshot.
- **Transparent compression on write** — a compressed file's `com.apple.decmpfs`
  is carried through unchanged on both file systems, with `UF_COMPRESSED` set to
  match. `pack` preserves it by default; `--decompress` writes such files out in
  full.
- **FileVault unlock** — a volume encrypted with a supplied password is detected,
  unlocked and read. An encrypted volume that cannot be unlocked is reported as
  locked rather than read as ciphertext.
- **APFS file population** — `pack <dir> --fs apfs` builds a populated APFS
  volume and `create --fs apfs` formats an empty one, in pure Go. Validated
  against `fsck_apfs`, `hdiutil` and `apfsck`.

## Near term

- **`goreleaser`** packaging and signed release archives.

- **Case-insensitive HFS+ with hard links.** The private metadata directory
  sorts differently from anything this writer produces: on a volume macOS wrote,
  it comes after every other name in the root, which is neither the order given
  by comparing its four leading NULs as U+0000 nor the order given by ignoring
  them. Until the rule is known, `create --case-sensitive` cannot be honoured on
  `--fs hfs+`. See `TOOLS_STATUS.md` note 9.

## Under consideration

- **`extract --keep-compressed`** — rebuilding a compressed file on the host, so
  a round trip through `extract` preserves compression the way `pack` does.
  macOS rejects most orderings of the create/setxattr/chflags sequence, and it
  is macOS-only.
- **HFS+ classic / HFS wrapper** — an HFS volume embedding an HFS+ one, which
  `hfsplus.New` currently rejects outright.
- **Writing LZMA-chunked DMGs.** They are read, but the encoder emits zlib or
  raw, so repacking an LZMA image normalises it to zlib. The file system round-
  trips bit-for-bit either way.
- **Firmlinks, volume sealing and bootability.** None of the three checkers
  examines them, and they lead toward building a bootable installer rather than
  a volume group.

Contributions and priority feedback are welcome via GitHub issues.
