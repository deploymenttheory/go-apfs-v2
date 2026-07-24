# APFS file population — milestone plan

`pkg/apfswrite` currently formats an *empty* APFS container (the `mkapfs`
equivalent). This effort adds the ability to write **user files** into the
volume, bringing `pack <dir>` to APFS.

## Key architectural decision

`mkapfs` builds the whole container in a **single checkpoint** (transaction
`XID = 1`), writing the final on-disk state directly. We keep that model:
populating files means **building the final populated state statically**, not
performing copy-on-write mutation of an existing volume. This sidesteps the
hardest part of a general APFS writer (COW B-tree rewrites, multi-transaction
checkpoints) and is exactly what creating a volume from a directory tree needs.

The APFS *reader* (`pkg/apfs`) already parses every record type we must write
(inode, dir-record, file-extent, dstream-id, physical-extent-reference), so it
is a precise oracle: if our reader reads a file back with the right content and
`fsck_apfs`/`apfsck` are clean, the records are valid.

Licensing: `pkg/apfswrite` is pure-Go, MIT-licensed original work (see its
README for provenance); it is part of the default build.

## Records involved (for one file "f" of content C in directory D)

Catalog B-tree (sorted by key = obj-id, then type):
- `(D, DIR_REC, hash(f))` → dir-record pointing to the file's CNID
- `(f, INODE)` → the file inode (mode S_IFREG, sizes, name xfield, dstream)
- `(f, FILE_EXTENT, 0)` → maps logical offset 0 → physical block + length
- update `(D, INODE)`: `nchildren++`

Extent-reference B-tree:
- `(phys_block, EXTENT)` → records the physical extent is owned (refcnt 1)

Plus: allocate the data block(s) in the space-manager bitmap, write content,
bump `apfs_num_files`/`apfs_total_blocks_alloced` in the volume superblock, and
keep the object-map / checkpoint accounting consistent (roots keep their block
numbers; only their contents grow).

## Milestone ladder (each gated on our reader + fsck_apfs + apfsck)

- **M1 — single small file.** One regular file (≤ one block, single extent) in
  the volume root, with content. Reader lists + cats it with the correct
  sha256; `fsck_apfs -n` and `apfsck` clean. *(in progress)*
- **M2 — trees.** Nested directories and multiple files; per-directory child
  counts; catalog records correctly sorted; grow the catalog to multiple
  B-tree nodes when one leaf overflows.
- **M3 — large files.** Multi-extent files (multiple `FILE_EXTENT` and extent-
  reference records); multi-block space-manager allocation.
- **M4 — metadata + wiring.** Modes, uid/gid, timestamps (inode xfields) and
  symlinks; an `Entry` tree input mirroring `pkg/hfsplus`; then wire
  `apfs pack <dir> --fs apfs` and extend the add-files/byte-delta test to APFS.
