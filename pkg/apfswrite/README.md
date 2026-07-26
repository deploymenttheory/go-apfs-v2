# pkg/apfswrite — APFS file system writer

A pure-Go writer that builds a complete APFS container from scratch: an empty
single-volume container, or one populated with a directory tree of files,
symbolic links and nested directories. The whole container is written as one
static checkpoint (transaction id 1), so every object is laid out in its final
position up front — no copy-on-write mutation.

This package is MIT-licensed, like the rest of the repository (`pkg/apfs`,
`pkg/hfsplus`, `pkg/disk`).

## Provenance and licensing

This writer began as a study of **mkapfs**, part of
[apfsprogs](https://github.com/linux-apfs/apfsprogs) by Ernesto A. Fernández
(GPL-2.0), which was used as a reference and a springboard for understanding
how APFS lays a container out. It has since been reimplemented independently
from Apple's *Apple File System Reference* — with its own code structure,
checkpoint-area sizing and space manager layout — and shares none of mkapfs's
source expression. It is therefore original work under the MIT license.

Where a container must carry values that Apple's APFS implementation validates
when it mounts a volume (for example the space manager free-queue node limits),
those values are reproduced as functional interoperability requirements of the
format, verified against Apple's `fsck_apfs`/`hdiutil` and the Linux `apfsck`.

## Validation

Created containers are checked against three oracles: our own reader in
`pkg/apfs`, Apple's `fsck_apfs` and `hdiutil` (macOS), and `apfsck` (Linux).
