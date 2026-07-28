# apfs

A cross-platform, self-contained **pure-Go toolkit for Apple disk images**. It
reads **APFS** and **HFS+** file systems directly from `.dmg` files, raw images
and containers without a partition map — without mounting, without kernel extensions, and without
macOS — and can also **build and repack** disk images.

It parses on-disk structures directly, which makes it useful for data recovery,
forensic analysis, backup verification, security auditing, and CI pipelines
that need to inspect or produce `.dmg` payloads on Linux, macOS or Windows.

```console
$ apfs info Firefox.dmg
HFS+ volume:
  UUID               2bc924f8-...
  Size               500.6 MB (525378560 bytes)
  Volumes            1
Volume 0: Firefox
  Contents           116 files, 54 directories, 1 symlinks

$ apfs list -R Firefox.dmg | head -3
.DS_Store
Firefox.app
Firefox.app/Contents

$ apfs extract Firefox.dmg -C ./out --verify
```

## Features

| Capability | APFS | HFS+ / HFSX |
| --- | :---: | :---: |
| Read: info, list, cat, extract, inspect | ✅ | ✅ |
| Mount read-only (FUSE, Linux/macOS) | ✅ | ✅ |
| FileVault (AES-128-XTS) unlock | ✅ | — |
| Transparent compression (zlib / LZVN / LZFSE) | ✅ | ✅ |
| Repack a DMG losslessly (`pack`) | ✅ | ✅ |
| Build a DMG from a directory (`pack <dir>`) | ✅ | ✅ |
| Create a formatted volume (`create`) | ✅ | ✅ |
| APFS snapshots: create, list, revert (`snapshot`) | ✅ | — |
| Reproducible (byte-identical) output | ✅ | ✅ |

Both file systems can be written as well as read: `pack <dir>` builds a populated
volume (files, symlinks, nested directories) and `create` formats an empty one.
The APFS writer is a pure-Go, MIT-licensed package (`pkg/apfswrite`); created
containers are validated against Apple's `fsck_apfs`/`hdiutil` and Linux
`apfsck`.

Every write command is **reproducible**: run it twice on the same input and you
get two byte-identical images. That makes an image content-addressable, makes
"did the vendor change anything?" a hash comparison, and lets an attestation
over the output mean something. `--source-date-epoch` (or the standard
`SOURCE_DATE_EPOCH`) pins the build timestamp and clamps source modification
times to it; `--uuid` pins the volume identity. See
[docs/reproducible-output.md](docs/reproducible-output.md).

**Image formats read:** UDIF DMGs compressed with zlib (UDZO), bzip2 (UDBZ),
ADC, LZFSE (ULFO) or LZMA (ULMO); GPT-partitioned and Apple-Partition-Map
layouts; and raw file system images. Images are detected by content, not by
file extension.

## Install

```console
go install github.com/deploymenttheory/go-apfs-v2/cmd/apfs@latest

# From a clone
git clone https://github.com/deploymenttheory/go-apfs-v2
cd go-apfs-v2
go build -o apfs ./cmd/apfs
```

The binary is MIT-licensed and includes the full read and write feature set
(APFS and HFS+). No cgo is required; the toolkit is pure Go and cross-compiles
to Linux, macOS and Windows on `amd64` and `arm64`.

## Command reference

Every command takes the image path as its first argument. Global flags (below)
apply to all commands.

### `info` — container and volume summary

```
apfs info IMAGE [--hierarchy] [--bodyfile FILE] [--md5] [--entry ID] [--file-path PATH]
```

Prints the file system type (APFS or HFS+), container/volume UUIDs, sizes,
file/directory/symlink counts, and — for APFS — each volume's **role** and
volume group. With `-o json`, emits a single document including a `fileSystem`
field.

```console
apfs info image.dmg
apfs info -o json image.dmg | jq -r '.volumes[0].name'
apfs info -v "Macintosh HD" image.dmg          # select a volume by name/UUID
apfs info -v system image.dmg                  # ...or by role
apfs info --hierarchy image.dmg                # full tree (APFS, text)
apfs info --bodyfile out.body image.dmg        # Sleuth Kit bodyfile
```

The forensic flags (`--hierarchy`, `--bodyfile`, `--md5`, `--entry`,
`--file-path`) are APFS-only and text-only.

#### Volume roles

A volume's role (`apfs_role`) says what it is for — `system`, `data`,
`recovery`, `preboot`, `update` and so on. Without it a macOS installer or
system image is illegible: several similarly-named volumes with no indication
which one holds the OS.

`-v/--volume` accepts a role token anywhere it accepts an index, name or UUID,
so `-v system` finds the OS volume without knowing its name. Name and UUID are
matched first, so a volume literally named `system` still wins; `-v role:system`
skips that and matches only on role. A role matching several volumes is an
error naming the candidates rather than an arbitrary pick.

In JSON, `role` is the lowercase token, `roleName` the display name, and
`roleValue` the raw `apfs_role` — always present, so a value this build does not
recognize is visible rather than silently dropped. `volumeGroupId` is the
volume group (`apfs_volume_group_id`), the system/data pairing macOS has used
since Catalina. All three are omitted when unset.

Note that roles are a **single value**, never a combination: `0x00c0` is
`update`, not `data|baseband`.

### `list` — list directory contents

```
apfs list IMAGE [PATH] [-l|--long] [-R|--recursive]
```

Lists a directory (default: the volume root), sorted by name. With `-o json`,
emits **one JSON object per line** (path, name, type, size, mode, mtime, inode,
symlink target) for streaming with `jq`.

```console
apfs list image.dmg
apfs list image.dmg /Applications --long
apfs list -R image.dmg | wc -l
apfs list -o json -R image.dmg | jq -r 'select(.type=="symlink") | "\(.path) -> \(.target)"'
```

### `cat` — write file contents to stdout

```
apfs cat IMAGE PATH...
```

Streams one or more files to stdout, for pipelines.

```console
apfs cat image.dmg /etc/hosts
apfs cat image.dmg /App.app/Contents/Info.plist | plutil -p -
```

### `extract` — extract files to the local file system

```
apfs extract IMAGE [PATH] -C DIR [-r|--recursive] [--pattern REGEX]
                   [--preserve-meta] [--xattrs] [--verify]
                   [--symlinks auto|real|file]
```

Extracts the whole volume (or a subtree given `PATH`) to `DIR`, preserving
symlinks, decompressing transparently-compressed files, and
optionally restoring permissions/timestamps (`--preserve-meta`), restoring
extended attributes (`--xattrs`) and verifying content against source checksums
(`--verify`).

**Symlink handling** (`--symlinks`): `auto` (default) creates a real symlink
where the OS allows it and otherwise writes the link target into a regular file
(useful on Windows without the symlink privilege); `real` always creates a
symlink and fails if refused; `file` always writes the target as a file. Names
the destination OS cannot store (e.g. trailing spaces on Windows) are sanitized
and reported. Exit code **6** signals a partial extraction.

```console
apfs extract image.dmg -C ./out
apfs extract image.dmg /Applications/Some.app -C ./out --recursive
apfs extract image.dmg -C ./out --pattern '\.plist$'
apfs extract image.dmg -C ./out --preserve-meta --verify
```

### `inspect` — low-level structural inspection

```
apfs inspect IMAGE                 # structural walk (superblock, checkpoints, object maps, volumes)
apfs inspect IMAGE block N         # decode one block by physical address (decimal or 0x hex)
apfs inspect IMAGE fstree          # interactively explore the file-system tree
```

Debugging/forensics view of the on-disk structures. Text output only.

```console
apfs inspect image.dmg
apfs inspect image.dmg block 0
apfs inspect image.dmg block 0x1b0c1
apfs inspect image.dmg fstree
```

### `mount` — mount read-only via FUSE

```
apfs mount IMAGE MOUNTPOINT
```

Mounts an APFS image read-only using FUSE (Linux and macOS with macFUSE). On
Windows it exits with code 5; use `extract` instead. Press Ctrl+C to unmount.

```console
apfs mount image.dmg /mnt/apfs
```

### `pack` — build a DMG from a directory, or repack a DMG

```
apfs pack SOURCE OUT.dmg [--fs hfs+|apfs] [--volname NAME] [--compression zlib|none] [--chunk-size KiB]
```

Two modes, chosen by what `SOURCE` is:

- **`SOURCE` is a directory** → its contents are written into a new volume and
  wrapped in a DMG (the inverse of `extract`). `--fs` chooses the file system:
  `hfs+` (default) or `apfs`.
- **`SOURCE` is a DMG** → it is **repacked** losslessly: the exact block layout
  is preserved and the chunks recompressed. The result is not byte-identical to
  the original (different compressors produce different container bytes), but
  the **raw file system image round-trips bit-for-bit** and mounts under both
  this tool and macOS. Repacking the *same* input twice is byte-identical.

```console
apfs pack ./mytree out.dmg --volname "My Data"          # directory -> HFS+ DMG
apfs pack ./mytree out.dmg --fs apfs --volname "My Data" # directory -> APFS DMG
apfs pack original.dmg repacked.dmg                     # repack a DMG
apfs pack original.dmg smaller.dmg --compression none
```

### `create` — format an empty volume

```
apfs create OUT.dmg --fs hfs+|apfs [--volname NAME] [--size MiB] [--case-sensitive]
                    [--role ROLE] [--volume-group UUID]
```

Creates a new DMG containing a freshly formatted, **empty** volume (the format
operation). Both `--fs hfs+` and `--fs apfs` are supported.

```console
apfs create blank.dmg --fs hfs+ --volname Scratch --size 16
apfs create blank.dmg --fs apfs --volname Data
apfs create system.dmg --fs apfs --volname "Macintosh HD" --role system
```

`--role` and `--volume-group` are APFS-only. `--volume-group` requires
`--role system`: a volume group is a system/data pair, and this writer emits one
volume per container, so the data half cannot accompany it (multi-volume
containers are on the roadmap).

A snapshot capturing the new volume can be created at the same time with
`--snapshot NAME` (APFS only). This applies to `pack` too.

### Reproducible output

`create`, `pack` and `snapshot create` produce byte-identical images for
identical input, with no flags required.

```
[--source-date-epoch SECONDS] [--uuid UUID] [--volume-uuid UUID] [--container-uuid UUID]
```

```console
apfs pack ./tree a.dmg --source-date-epoch 1700000000
SOURCE_DATE_EPOCH=1700000000 apfs pack ./tree b.dmg
shasum -a 256 a.dmg b.dmg   # identical
```

`--source-date-epoch` pins the build timestamp and clamps source modification
times newer than it, per the reproducible-builds convention. It resolves as
`--source-date-epoch` > `SOURCE_DATE_EPOCH` > `APFS_SOURCE_DATE_EPOCH` > config
file — the bare variable outranks the `APFS_` form, the one deliberate exception
to this tool's usual precedence, because build systems set the standard name.

Images are built into a temporary file beside the output rather than in memory,
so image size is not bounded by RAM. `--temp-dir` puts that scratch file
somewhere else; the system temporary directory is deliberately not the default,
because it is often small and on many Linux systems is RAM-backed. `create` and
`pack` check there is room before they start, rather than failing part-way
through.

`--uuid` pins the volume UUID; for APFS the container UUID is derived from it.
Full detail, including the residual sources of variance, is in
[docs/reproducible-output.md](docs/reproducible-output.md).

### `snapshot` — create, list and revert APFS snapshots

```
apfs snapshot list   IMAGE
apfs snapshot create IMAGE --name NAME [-O OUT.dmg] [--force]
apfs snapshot revert IMAGE --name NAME [-O OUT.dmg] [--force]
apfs snapshot verify IMAGE
```

Real, spec-compliant APFS snapshots — recognized by macOS (`diskutil apfs
listSnapshots`), validated with `fsck_apfs`/`apfsck`. Snapshots are an APFS
concept (HFS+ has none). A snapshot captures a volume at a point in time, for
data-forensics and backup-verification workflows.

- **list** — show each APFS volume's snapshots (name, xid, creation time). With
  `-o json`, one record per snapshot.
- **create** — rebuild the image with an added snapshot of the current state.
  The writer rebuilds the volume from its contents (so the result is not a
  byte-for-byte copy of the source). To protect evidence, the result goes to
  `-O/--output` by default; overwriting the source in place requires `--force`.
- **revert** — mark the volume to roll back to a snapshot on next mount (the
  spec's `revert_to_xid` mechanism, patched in place with a resealed checksum).
  Same output safety.
- **verify** — confirm every snapshot's frozen superblock and metadata read back.

```console
apfs snapshot create evidence.dmg --name baseline -O evidence-snap.dmg
apfs snapshot list   evidence-snap.dmg
apfs snapshot revert evidence-snap.dmg --name baseline -O reverted.dmg
```

One snapshot per image is supported today; multiple snapshots require distinct
transaction ids and incremental checkpoints (planned).

## Global flags

| Flag | Description |
| --- | --- |
| `-o, --output` | Output format: `text` or `json` (default `text`). |
| `-v, --volume STR` | Select a volume by index, name or UUID (default: first). |
| `-p, --password STR` | Password for encrypted (FileVault) volumes. |
| `--password-stdin` | Read the password from standard input. |
| `--recovery-password STR` | Recovery password for encrypted volumes. |
| `--offset N` | Byte offset of the container in the image (expert; overrides detection). |
| `-q, --quiet` | Suppress progress and non-essential messages. |
| `--verbose` | Verbose diagnostics on stderr. |

**Configuration precedence:** command-line flag > `APFS_<FLAG>` environment
variable (e.g. `APFS_OUTPUT=json`, `APFS_PASSWORD=…`) > optional config file at
`~/.config/apfs/config.yaml`.

Data is written to **stdout**; progress and diagnostics go to **stderr**, so
pipelines stay clean.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Generic runtime error |
| 2 | Usage error (bad flags or arguments) |
| 3 | Image not found or not a recognizable APFS/HFS+ image |
| 4 | Authentication required or failed |
| 5 | Feature not supported on this platform / build |
| 6 | Partial result (e.g. some files skipped during extraction) |

## Using it as a library

The read side is exposed as MIT-licensed packages. Volumes implement
`io/fs.FS`, so they plug into any code that consumes a file system:

```go
import (
	"io/fs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

container, closer, _ := apfs.OpenImage("image.dmg", nil)
defer closer.Close()
defer container.Free()

vol, _ := container.VolumeBySelector("0")
data, _ := fs.ReadFile(vol, "Applications/Some.app/Contents/Info.plist")
```

Key packages: `pkg/apfs` (APFS reader), `pkg/hfsplus` (HFS+ reader and writer),
`pkg/disk` (DMG/UDIF reader and writer, partition tables), and `pkg/apfswrite`
(APFS container writer).

## Licensing

This repository is **MIT-licensed** in full, including `pkg/apfswrite` (the APFS
writer). That package began as a study of
[`mkapfs`](https://github.com/linux-apfs/apfsprogs) (GPL-2.0), used as a
reference for the format's behaviour, and was then reimplemented independently
from Apple's *Apple File System Reference*; it shares none of mkapfs's source
expression. See `NOTICE` and `pkg/apfswrite/README.md` for the full provenance.

## Development

```console
go build ./...            # build everything
go test ./pkg/... ./internal/...   # unit tests
go test -v ./acceptance/  # acceptance suite against the committed fixtures
```

The acceptance tests live in their own root package, `acceptance/`, which holds
no production code. A test goes there if something outside our own code decides
whether it passed — the real `apfs` command run as a subprocess, or a tool that
ships with the OS such as `fsck_apfs`, `apfsck` or `hdiutil`. Tests that only
check our code against itself stay in the package they test. Some of them run
against a published application DMG and are skipped unless
`APFS_ACCEPTANCE_DMG` is set; see `go doc ./acceptance`.

CI runs the build matrix and the test suite on
Linux, macOS and Windows. Correctness is cross-checked against the platforms'
own tools: created HFS+ volumes are validated with `fsck_hfs` and mounted with
`hdiutil`; created APFS containers with `fsck_apfs` (macOS) and `apfsck`
(Linux). Real-world acceptance runs against published vendor DMGs (Firefox for
HFS+, Zed for APFS), and on macOS every extraction is compared byte-for-byte
against an `hdiutil` mount of the same image.

## Acknowledgements

The design and on-disk handling draw on
[libfsapfs](https://github.com/libyal/libfsapfs),
[blacktop/go-apfs](https://github.com/blacktop/go-apfs),
[apfsprogs](https://github.com/linux-apfs/apfsprogs) and Apple's
*Apple File System Reference*. See `NOTICE` for details and licenses.
