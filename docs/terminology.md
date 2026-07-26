# APFS terminology

Naming in this repository follows the [Apple File System
Reference](../spec/Apple-File-System-Reference.md) (2020-06-22), vendored at
`spec/Apple-File-System-Reference.md`. This file is the reference the codebase is
graded against.

Occurrence counts quoted below are `grep -oc` against that document. They are
given because they settle spelling questions that are otherwise a matter of
taste — they are not.

## Why this file exists

`pkg/apfs` began as a transliteration of [libfsapfs][libfsapfs] and
`pkg/apfswrite` as a port of [apfsprogs/mkapfs][apfsprogs]. Both inherited their
donor project's vocabulary rather than Apple's, and the two disagreed with each
other about what to call the same on-disk structure. Worse, several names came
from **HFS+**, a different filesystem: "catalog" and "CNID" appear **zero** times
in Apple's APFS reference.

[libfsapfs]: https://github.com/libyal/libfsapfs
[apfsprogs]: https://github.com/eafer/apfsprogs

## Two naming registers

**Prose register** — used for everything except byte-for-byte struct mirrors.
PascalCase of Apple's English name, as Apple writes it in the prose of the
reference:

| Apple prose | Apple C type | Go name |
|---|---|---|
| container superblock | `nx_superblock_t` | `ContainerSuperblock` |
| volume superblock | `apfs_superblock_t` | `VolumeSuperblock` |
| object map | `omap_phys_t` | `ObjectMap` |
| object map key / value | `omap_key_t` / `omap_val_t` | `ObjectMapKey` / `ObjectMapValue` |
| object's header | `obj_phys_t` | `ObjectHeader` |
| checkpoint mapping | `checkpoint_mapping_t` | `CheckpointMapping` |
| checkpoint map | `checkpoint_map_phys_t` | `CheckpointMap` |
| space manager | `spaceman_phys_t` | `SpaceManager` |
| chunk-info block | `chunk_info_block_t` | `ChunkInfoBlock` |
| CIB address block | `cib_addr_block_t` | `CIBAddressBlock` |
| reaper | `nx_reaper_phys_t` | `Reaper` |
| B-tree node | `btree_node_phys_t` | `BTreeNode` |
| B-tree info | `btree_info_t` | `BTreeInfo` |
| location within a B-tree node | `nloc_t` | `NLoc` |
| location of a key and value | `kvloc_t` | `KVLoc` |
| location of a fixed-size key and value | `kvoff_t` | `KVOff` |
| keybag | `kb_locker_t` | `Keybag` |
| keybag entry | `keybag_entry_t` | `KeybagEntry` |
| key encryption key (KEK) | — | `KeyEncryptionKey` |
| volume encryption key (VEK) | — | `VolumeEncryptionKey` |
| file-system tree | `OBJECT_TYPE_FSTREE` | `FileSystemTree` |
| extentref tree | `apfs_extentref_tree_oid` | `ExtentrefTree` |
| snapshot metadata tree | `apfs_snap_meta_tree_oid` | `SnapshotMetadataTree` |
| file extent tree | `fext_tree_key_t` | `FileExtentTree` |
| Fusion middle tree | `fusion_mt_key_t` | `FusionMiddleTree` |
| write-back cache | `fusion_wbc_phys_t` | `WriteBackCache` |
| inode record | `j_inode_key_t` / `j_inode_val_t` | `Inode` |
| directory entry record | `j_drec_key_t` / `j_drec_val_t` | `DirectoryEntryRecord` |
| extended attribute record | `j_xattr_key_t` / `j_xattr_val_t` | `ExtendedAttribute` |
| file extent record | `j_file_extent_key_t` / `_val_t` | `FileExtent` |
| physical extent record | `j_phys_ext_key_t` / `_val_t` | `PhysicalExtent` |
| data stream | `j_dstream_t` | `DataStream` |
| extended field | `x_field_t` | `ExtendedField` |
| snapshot metadata | `j_snap_metadata_val_t` | `SnapshotMetadata` |
| integrity metadata | `integrity_meta_phys_t` | `IntegrityMetadata` |
| range of physical addresses | `prange_t` | `PhysicalRange` |

**C register** — used *only* by `pkg/apfswrite/structs.go`, whose types exist to
mirror an Apple `_t` field-for-field so they can be marshalled straight to disk.
These keep the C typedef's shape (`objPhys`, `nxSuperblock`, `apfsSuperblock`,
`omapPhys`, `nxReaperPhys`, `apfsModifiedBy`) and carry a doc comment naming the
typedef. Every *other* identifier in that package uses the prose register.

## Identifier conventions

| Concept | Apple | Go | Never |
|---|---|---|---|
| object identifier | `oid_t` | `OID` | `Oid`, `ObjectID`, `ObjectIdentifier`, `…BlockNumber` |
| transaction identifier | `xid_t` | `XID` | `Xid`, `TransactionID`, `TransactionIdentifier` |
| universally unique identifier | `uuid_t` | `UUID` | `Identifier` |
| physical address of a block | `paddr_t` | `Paddr` (`PhysicalAddress` in prose-facing API) | `BlockNumber`, `bno`, `lba` |
| block count | `nx_block_count` | `BlockCount` | `blkcnt` |
| checkpoint descriptor/data area | `nx_xp_desc_*` / `nx_xp_data_*` | `XPDesc*` / `XPData*` | `cpDesc*`, `cpData*` |

`OID`, `XID` and `UUID` are initialisms and stay fully capitalised in the middle
of a name (`OmapOID`, `RevertToXID`), per Go convention.

`…BlockNumber` is reserved for values that genuinely are a `paddr_t`. Several
fields in this repo were named that way while holding an `oid_t`, which is why
the rule is stated so bluntly.

## Prose spellings

Apply in comments, documentation, CLI help and CLI output alike.

| Write | Not | Spec evidence |
|---|---|---|
| B-tree | btree, Btree, BTree, B-Tree | "B-tree" ×82 in prose; `btree_*` only inside identifiers |
| file system (noun) | filesystem | "file system" ×18; "filesystem" ×1, and that one is a typo |
| file-system (attributive) | file system tree | "file-system tree" ×6, "file-system object" ×6, "file-system record" ×3 |
| keybag | key bag, Key Bag | "keybag" ×60; "key bag" ×0 |
| object map | omap, objectmap | "object map" ×22; `omap_*` only inside identifiers |
| space manager | space-manager | "space manager" ×4 (unhyphenated) |
| extentref tree | extref, extent-reference tree | "extentref" ×8; "extref" ×0 |
| chunk-info block | chunk information block | "chunk-info" ×2 |
| checkpoint descriptor area | checkpoint description area | ×4; the doc's own Container bullet says "description" once — prefer "descriptor" |
| nonleaf, nonroot | non-leaf, non-root | ×10 and ×3, always closed |
| Fletcher 64 | Fletcher-64 | ×3, never hyphenated |
| Tier2 | tier 2 | ×21, never spaced |
| Fusion (capitalised in prose) | fusion | Lowercase only inside identifiers |
| write-back cache | writeback cache | ×13 |
| sealed volume | Sealed Volume | ×5, lowercase in prose |
| format | mkfs, mkapfs | Apple's verb is "format"; `newfs_apfs` is the tool |
| physical address | logical block address | "physical address" ×8; LBA is a GPT/UDIF term, not APFS |

Apple's reference never uses the words **sector**, **run**, **block range**, or
**j-key**. Use *block*, *extent*, `prange_t`/"range of physical addresses", and
*file-system key* respectively.

## Terms that are wrong for APFS

These come from HFS+ or from a donor C project. They must not appear in APFS
code or documentation. They *are* correct inside `pkg/hfsplus` and in HFS+
sections of the changelog and roadmap.

| Banned in APFS context | Origin | Use instead |
|---|---|---|
| catalog, catalog B-tree, `cat*` | HFS+ Catalog File | file-system tree, `fsTree*` |
| CNID, catalog node ID | HFS+ | object identifier (`OID`) or inode number (`ino`) |
| allocation file | HFS+ | space manager, allocation bitmap |
| extents overflow | HFS+ | extentref tree |
| resource fork | HFS+ | — (but `INODE_NO_RSRC_FORK` is a genuine Apple constant; keep it) |
| data block, `libfdata` vector | libfsapfs / libfdata | extent, data stream |
| file entry, `*DataHandle`, `FileIOHandle` | libfsapfs / libbfio | — |
| `bno`, `blkcnt` | mkapfs / BSD | `paddr`, `BlockCount` |
| `extref` | apfsprogs | `extentref` |
| internal pool (as prose) | apfsprogs | Apple only has the `sm_ip_*` field prefix; the spec heading is "Internal-Pool Bitmap" |

## Checking

```sh
grep -rin 'catalog\|cnid\|key bag\|filesystem\|\bextref\|\bbno\b' \
  --include='*.go' --include='*.md' . \
  | grep -v '^./pkg/hfsplus/' | grep -v '^./spec/'
```

Hits outside `pkg/hfsplus` and genuine HFS+ documentation rows are regressions.
