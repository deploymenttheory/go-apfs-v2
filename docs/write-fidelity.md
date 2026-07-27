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

## What is not

| | What happens | Reported as |
|---|---|---|
| Device nodes, FIFOs, sockets | **skipped entirely** | `specialFilesSkipped` |
| Extended attributes | dropped | `xattrsDropped` |
| Resource forks | dropped | `resourceForksDropped` |
| ACLs | dropped | `aclsDropped` |
| Hard links | each name becomes an independent copy | `hardLinksCollapsed` |
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
