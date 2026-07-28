# Write fidelity

Building a volume from a directory is **lossy**. This page is the canonical
list of what survives and what does not, so the answer lives in one place rather
than drifting across four.

The commands affected are `pack <dir>` and `snapshot create`. Repacking an
existing DMG (`pack SRC.dmg OUT.dmg`) loses nothing: the file system image is
copied through bit-for-bit.

## What is carried

| | |
|---|---|
| Regular files | content, mode, owner, group, modification time |
| Directories | mode, owner, group, modification time |
| Symbolic links | target, mode, owner, group, modification time |
| Extended attributes | both, any size |
| Resource forks | both: on APFS as an attribute stream, on HFS+ as the catalog record's resource fork |
| Hard links | both: several names share one inode and one copy of the content |

## What is not

| | What happens | Reported as |
|---|---|---|
| Device nodes, FIFOs, sockets | **skipped entirely** | `specialFilesSkipped` |
| `com.apple.decmpfs` when packing a host tree | dropped: the walker cannot see it yet (see below) | `xattrsDropped` |
| ACLs on HFS+ | dropped | `aclsDropped` |
| BSD flags (`uchg`, `hidden`, …) | dropped | `bsdFlagsDropped` |
| Volume role and group (`snapshot create` only) | not carried | `volumeIdentityDropped` |

Creation, change and access times are also lost: all four inode timestamps are
written from the entry's modification time. That is a per-entry, always-true
loss, so counting it would produce a number equal to the entry count and tell
you nothing; it is documented here instead.

Resource forks and ACLs are counted separately from ordinary extended
attributes deliberately. A dropped `com.apple.quarantine` is metadata; a dropped
resource fork is *file content*, and "ACLs were dropped" is a materially
different statement to a forensic reader than "3 attributes were dropped".

### How attributes are stored, and what decmpfs needs

A small value lives inside its attribute record. A larger one — and **any**
resource fork, however small — gets a data stream of its own: an object with its
own id, extent and place in the extent-reference tree.

Resource forks have no size threshold because `fsck_apfs` requires one to be
stream based whatever its size: *"com.apple.ResourceFork is expected to be
stream based"*. `apfsck` accepts the embedded form, so this is a case where only
Apple's own checker objects.

An attribute's stream carries no `DSTREAM_ID` record, unlike a file's data
stream. That record holds a reference count, and an attribute's stream cannot be
cloned, so there is no count to keep. `apfsck` reports one as *"xattrs can't be
cloned"*.

`com.apple.decmpfs` is carried through as it stands — the APFS writer does not
compress or decompress anything, it copies the attribute the source had. What it
must add is `UF_COMPRESSED` in the inode's `bsd_flags`, and it refuses a file
whose parts disagree: the data fork must be empty, and a resource fork must be
present exactly when the compression type puts the payload there.

That flag is the whole of the difficulty, because almost nothing notices when it
is missing. With the attribute written and the flag clear, `fsck_apfs` reports
the volume clean and this toolkit's own reader returns the right bytes, because
it dispatches on the attribute rather than the flag. macOS dispatches on the
flag and reports the file as **0 bytes and empty**. Only `apfsck` — *"Inode: is
not compressed but has decmpfs xattr"* — and a real mount catch it, which is why
both gate this behaviour in CI.

Note what this does and does not change for `pack`. A compressed file's
attributes are invisible to an ordinary `listxattr`: reading them needs
`XATTR_SHOWCOMPRESSION`, which the directory walker does not yet pass. So
packing a host tree still stores those files decompressed. The writer is ready
for them; the walker is the remaining half.

One checker limitation is worth recording, because it looks like a bug in the
image rather than in the tool. macOS compresses system files with decmpfs type 8
(LZVN in a resource fork) almost exclusively, and `apfsck` v0.2.1 parses every
resource-fork type except zlib's as though it used zlib's layout. Handing it a
file copied byte for byte from `/bin/ls` — one macOS itself reads back
identically — produces *"Resource compressed file: block metadata is too big"*.
Fork-based types therefore cannot be gated on `apfsck`; they are checked against
a real mount instead.

## How losses are reported

As they are found, one note per occurrence on stderr, capped at ten per
category so a tree with an attribute on every file cannot bury the summary:

```
Note: sub/b.txt: resource fork not carried across (com.apple.ResourceFork)
Note: pipe: special file not carried across (named pipe (FIFO))
```

Then a summary after the write:

```
Note: 1 special file skipped: device nodes, FIFOs and sockets cannot be represented
Note: 6 extended attributes not written
Note: 1 resource fork not written; that is file content, not metadata
```

`--quiet` suppresses the summary but **not** the individual notes: a lossy write
must never be silent. `--output json` adds every count to the report document,
with every key always present so a consumer can rely on the shape:

```json
{
  "destination": "out.dmg",
  "specialFilesSkipped": 1,
  "xattrsDropped": 6,
  "resourceForksDropped": 1,
  "aclsDropped": 0,
  "hardLinksCollapsed": 1,
  "bsdFlagsDropped": 0,
  "volumeIdentityDropped": 0,
  "lossless": false
}
```

## Exit codes

| Situation | Exit |
|---|---|
| Everything carried, or only metadata lost | 0 |
| Entries omitted from the volume entirely | 6 (partial) |
| `--strict` and anything at all was lost | 5 (unsupported), nothing written |

**Metadata loss alone does not change the exit code, and that is deliberate.**
macOS attaches `com.apple.provenance` to files as they are written, so an
ordinary macOS tree *always* has extended attributes. Treating a dropped
attribute as failure would make almost every pack exit non-zero and break every
script that checks. Entries missing from the volume are different: that is the
same "some things could not be handled" meaning `extract` already gives exit 6.

`--strict` is how a caller asks for the stricter contract.

## `--strict`

```console
apfs pack ./tree out.dmg --fs apfs --strict
```

Refuses to write anything when the source contains something the volume cannot
carry, and **fails before creating the destination** — in a pipeline, a
half-faithful image that exists is worse than no image at all. The walk runs to
completion first, so the error names everything that was wrong, not just the
first thing found.

Available on `pack <dir>` and `snapshot create`. Accepted on a repack, where it
passes trivially. Not offered on `create`, which formats an empty volume and has
nothing to lose.

Note that on macOS `--strict` will refuse most real trees, because of
`com.apple.provenance`. That is the flag working as intended: it is asking
"is this image a faithful copy?", and the honest answer is usually no.

## Round-tripping

Extraction discards extended attributes unless asked to keep them:

```console
apfs extract image.dmg -C ./out --xattrs
```

Without `--xattrs`, extract-then-pack loses every attribute regardless of what
the writer can do. With it, attributes are restored onto the extracted files;
any the kernel reserves or the destination file system rejects are counted and
reported rather than failing the extraction.

Transparent-compression metadata (`com.apple.decmpfs` and the resource fork
holding the compressed copy) is deliberately **not** restored. Extraction
decompresses as it reads, so the extracted file holds its content in the data
fork; restoring that metadata would leave the file describing content it no
longer has, and would render it unreadable if anything later set
`UF_COMPRESSED`. A resource fork without `decmpfs` is a genuine one and is
restored.

## Using this from Go

Both writers expose the walk, so a program can inspect the account before
deciding to write:

```go
root, report, err := apfswrite.EntryTreeFromDir(dir, &apfswrite.WalkOptions{Xattrs: true})
if err != nil {
    return err
}
if !report.Lossless() {
    return fmt.Errorf("refusing to write a lossy image: %v", report.JSON())
}
err = apfswrite.CreateContainer(w, 0, &apfswrite.CreateOptions{Root: root})
```

`CreateContainerFromDir` and `CreateImageFromDir` remain as convenience wrappers
that discard the report. The report type is [`pkg/fidelity`](../pkg/fidelity),
public so that a consumer of the writer libraries can name what it is handed.

## Roadmap

Extended attributes and hard links are planned for the APFS writer; see
[`TOOLS_ROADMAP.md`](../TOOLS_ROADMAP.md). Until then, the counts above are the
honest account of what a packed image is missing.
