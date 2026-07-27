# Reproducible output

`create`, `pack` and `snapshot create` produce **byte-identical images for
identical input**. Running any of them twice gives two files with the same
SHA-256.

That makes several things possible that were not before:

- **Content-addressed caching** — an image's hash is a function of its input,
  so a build system can skip work it has already done.
- **"Did the vendor change anything?" becomes hash-decidable** — repack two
  downloads of the same DMG and compare one number, instead of diffing trees.
- **Attestation over the output** — a signature over the image hash means
  something, because the hash is reproducible by anyone with the same input.
- **Proving a refactor changed nothing** — see
  [CONTRIBUTING.md](../CONTRIBUTING.md).

## How it works

Two wall-clock reads used to reach every image: `pkg/apfswrite` seeded its
timestamp from `time.Now()`, and `pkg/hfsplus` fell back to `time.Now()` when
given no options. In APFS that timestamp reached the volume superblock's
formatted-by field *and every directory entry's date-added*, so it perturbed the
whole file-system tree leaf payload — roughly 31–46 bytes per 64 MB image,
scattered.

Both writers now default to a fixed `DefaultTime` (2024-01-01T00:00:00Z) rather
than the wall clock. No flag is needed for reproducibility; the flags below
control *which* timestamp and identity are used.

The DMG/UDIF encoder was already deterministic — its `koly` footer carries no
timestamp and no UUID — so the file system writers were the only source of
drift. That is why `pack SRC.dmg OUT.dmg` (repack) was always reproducible.

## `SOURCE_DATE_EPOCH`

Set it to pin the build timestamp explicitly, as decimal seconds since
1970 UTC:

```sh
apfs pack ./tree out.dmg --source-date-epoch 1700000000
SOURCE_DATE_EPOCH=1700000000 apfs pack ./tree out.dmg
```

It does two things:

1. **Sets the timestamp** written to every clock-derived on-disk field.
2. **Clamps source modification times** — a source file whose mtime is *newer*
   than the epoch is written as the epoch; older files keep their own time.
   This is the rule the [reproducible-builds
   specification](https://reproducible-builds.org/docs/source-date-epoch/)
   prescribes, and it is what makes a fresh `git clone` or CI checkout — where
   every mtime is "now" — pack identically on any machine.

Clamping rather than overwriting is deliberate: a file's modification time is
the user's data, and blanket-overwriting it would make `pack` lossy in a way
`extract` cannot undo.

### Precedence

```
--source-date-epoch  >  SOURCE_DATE_EPOCH  >  APFS_SOURCE_DATE_EPOCH  >  config file
```

This is the **one deliberate exception** to the tool's usual
flag > `APFS_<FLAG>` > config order. The bare, unprefixed variable is the
ecosystem standard that build systems set, so a stale `APFS_SOURCE_DATE_EPOCH`
left in a shell profile must not defeat it.

Only decimal seconds are accepted — no RFC 3339 convenience form — so the flag
and the variable can never disagree about what a value means. A malformed value
is a usage error (exit 2), not a silent fallback: an image that looks pinned but
is not would be worse than a clear failure.

## UUID flags

Without these, the writers use fixed built-in default UUIDs, which is
reproducible but means every image the tool produces shares an identity. Pin
them per build when identity matters:

| Flag | Applies to | Effect |
|---|---|---|
| `--uuid` | APFS, HFS+ | Volume UUID. For APFS the container UUID is *derived* from it. |
| `--volume-uuid` | APFS, HFS+ | Volume UUID, overriding `--uuid`. |
| `--container-uuid` | APFS only | Container UUID, overriding the derivation. |

```sh
apfs create data.dmg --fs apfs --uuid 11111111-2222-3333-4444-555555555555
```

The container UUID is derived as an RFC 4122 version 5 (SHA-1) UUID with the
volume UUID as its namespace. Deriving rather than defaulting means pinning one
half does not silently leave the other at the built-in default, which would be
surprising — and the derivation is itself deterministic.

For HFS+ only the first eight bytes reach disk, because the HFS+ volume
identifier is the 64-bit `FinderInfo[6]`/`FinderInfo[7]` pair. `--container-uuid`
is rejected for HFS+, which has no container.

The all-zero UUID is rejected: the writers read zero as "use the built-in
default", so accepting it would silently ignore the flag. The UUID flags are
also rejected on the repack path (`pack SRC.dmg OUT.dmg`), which copies the
source file system through unchanged and has no writer to hand a UUID to.

These are per-command flags, so unlike the root persistent flags they have no
`APFS_*` environment or config-file binding.

## Residual variance

Two images built on different machines can still differ. Be honest about this
rather than overclaiming:

- **Ownership.** `pack <dir>` copies each source file's uid and gid into the
  inode, so packing the same tree as two different users gives two different
  images. `SOURCE_DATE_EPOCH` deliberately does not touch this — rewriting
  ownership under a variable named "date" would be surprising, and it would
  break installer DMGs that need specific ownership.
- **Source modification times older than the epoch.** Clamping only lowers
  times, so a tree whose files carry genuinely different old mtimes on two
  machines will pack differently. Checkouts do not usually have this problem;
  restored backups can.
- **Anything the writer cannot represent.** A source tree containing extended
  attributes, hard links or device nodes packs to something less than itself,
  and how much less can vary by platform.

## Verifying

```sh
apfs pack ./tree /tmp/a.dmg --source-date-epoch 1700000000
apfs pack ./tree /tmp/b.dmg --source-date-epoch 1700000000
shasum -a 256 /tmp/a.dmg /tmp/b.dmg   # the two hashes must match
```

The property is covered by unit tests in `pkg/apfswrite` and `pkg/hfsplus`
(`writer_repro_test.go`) and end-to-end in `acceptance/reproducible_test.go`.
