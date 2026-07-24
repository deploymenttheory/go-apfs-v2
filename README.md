# apfs

A cross-platform, self-contained **pure-Go toolkit for Apple disk images**. It
reads **APFS** and **HFS+** filesystems directly from `.dmg` files, raw images
and bare containers — without mounting, without kernel extensions, and without
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
| Mount read-only (FUSE, Linux/macOS) | ✅ | — |
| FileVault (AES-128-XTS) unlock | ✅ | — |
| Transparent compression (zlib / LZVN / LZFSE) | ✅ | ✅ |
| Repack a DMG losslessly (`pack`) | ✅ | ✅ |
| Build a DMG from a directory (`pack <dir>`) | ✅ | ✅ |
| Create a formatted volume (`create`) | ✅ | ✅ |

Both filesystems can be written as well as read: `pack <dir>` builds a populated
volume (files, symlinks, nested directories) and `create` formats an empty one.
The APFS writer is a pure-Go, MIT-licensed package (`pkg/apfswrite`); created
containers are validated against Apple's `fsck_apfs`/`hdiutil` and Linux
`apfsck`.

**Image formats read:** UDIF DMGs compressed with zlib (UDZO), bzip2 (UDBZ),
ADC, LZFSE (ULFO) or LZMA (ULMO); GPT-partitioned and Apple-Partition-Map
layouts; and bare raw filesystem images. Images are detected by content, not by
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

Prints the filesystem type (APFS or HFS+), container/volume UUIDs, sizes, and
file/directory/symlink counts. With `-o json`, emits a single document
including a `filesystem` field.

```console
apfs info image.dmg
apfs info -o json image.dmg | jq -r '.volumes[0].name'
apfs info -v "Macintosh HD" image.dmg          # select a volume by name/UUID
apfs info --hierarchy image.dmg                # full tree (APFS, text)
apfs info --bodyfile out.body image.dmg        # Sleuth Kit bodyfile
```

The forensic flags (`--hierarchy`, `--bodyfile`, `--md5`, `--entry`,
`--file-path`) are APFS-only and text-only.

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

### `extract` — extract files to the local filesystem

```
apfs extract IMAGE [PATH] -C DIR [-r|--recursive] [--pattern REGEX]
                   [--preserve-meta] [--verify] [--symlinks auto|real|file]
```

Extracts the whole volume (or a subtree given `PATH`) to `DIR`, preserving
symlinks, decompressing transparently-compressed files, and optionally
restoring permissions/timestamps (`--preserve-meta`) and verifying content
against source checksums (`--verify`).

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
apfs inspect IMAGE                 # structural walk (superblock, checkpoints, omaps, volumes)
apfs inspect IMAGE block N         # decode one block by physical address (decimal or 0x hex)
apfs inspect IMAGE btree           # interactively explore the file-system B-tree
```

Debugging/forensics view of the on-disk structures. Text output only.

```console
apfs inspect image.dmg
apfs inspect image.dmg block 0
apfs inspect image.dmg block 0x1b0c1
apfs inspect image.dmg btree
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
  wrapped in a DMG (the inverse of `extract`). `--fs` chooses the filesystem:
  `hfs+` (default) or `apfs`.
- **`SOURCE` is a DMG** → it is **repacked** losslessly: the exact block layout
  is preserved and the chunks recompressed. The result is not byte-identical to
  the original (different compressors produce different container bytes), but
  the **raw filesystem image round-trips bit-for-bit** and mounts under both
  this tool and macOS.

```console
apfs pack ./mytree out.dmg --volname "My Data"          # directory -> HFS+ DMG
apfs pack ./mytree out.dmg --fs apfs --volname "My Data" # directory -> APFS DMG
apfs pack original.dmg repacked.dmg                     # repack a DMG
apfs pack original.dmg smaller.dmg --compression none
```

### `create` — format an empty volume

```
apfs create OUT.dmg --fs hfs+|apfs [--volname NAME] [--size MiB] [--case-sensitive]
```

Creates a new DMG containing a freshly formatted, **empty** volume (the mkfs
operation). Both `--fs hfs+` and `--fs apfs` are supported.

```console
apfs create blank.dmg --fs hfs+ --volname Scratch --size 16
apfs create blank.dmg --fs apfs --volname Data
```

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
`io/fs.FS`, so they plug into any code that consumes a filesystem:

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
go test ./...      # unit + fixture acceptance tests
go build ./...     # build everything
```

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
