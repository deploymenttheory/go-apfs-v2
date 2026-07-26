// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// snapBuild is a resolved snapshot to write: its name, transaction id, timestamp
// and the block holding its frozen volume superblock.
type snapBuild struct {
	name      string
	xid       uint64
	mtime     uint64
	inum      uint64
	sblockBno uint64 // frozen volume superblock
	extrefBno uint64 // the snapshot's own extentref tree
}

// snapNameObjID is the object-id field used in every snapshot-name key. The
// format uses an all-ones id (the 60-bit object-id mask) so name records sort
// after the metadata records within the snapshot-metadata tree.
const snapNameObjID = 0x0fffffffffffffff

// maxSnapshots caps how many snapshots one volume may carry. The writer builds a
// single static checkpoint at one transaction id, which macOS requires to mount
// the container (it rejects a lone higher-xid checkpoint with no predecessor).
// A snapshot and the live volume therefore share that transaction id, so exactly
// one snapshot is supported for now; more would need distinct transaction ids
// and the matching incremental checkpoints.
const maxSnapshots = 1

// setSnapshots resolves opts.Snapshots into the builder. It validates the names,
// assigns each snapshot a transaction id (1..N in request order), sets the live
// xid one past the last snapshot, and counts the snapshot object blocks. With no
// snapshots the live xid stays at mkfsXID, preserving the single-state layout.
func (b *builder) setSnapshots(opts *CreateOptions) error {
	b.liveXID = mkfsXID
	if len(opts.Snapshots) == 0 {
		return nil
	}
	if len(opts.Snapshots) > maxSnapshots {
		return fmt.Errorf("apfswrite: %d snapshots requested; at most %d are supported", len(opts.Snapshots), maxSnapshots)
	}
	// Each snapshot copies the extentref tree; only the single-leaf shape
	// is supported for now, which covers volumes up to a few thousand extents.
	if b.extrefTwoLevel {
		return fmt.Errorf("apfswrite: snapshots are not yet supported for volumes with a 2-level extentref tree")
	}
	defaultTime := uint64(defaultInodeTime.UnixNano())
	// Each snapshot is associated with a distinct inode number reserved past the
	// highest user inode; fsck_apfs rejects a zero inum.
	inumBase := b.nextObjID()
	seen := make(map[string]bool, len(opts.Snapshots))
	for i, s := range opts.Snapshots {
		if s.Name == "" {
			return fmt.Errorf("apfswrite: snapshot %d has an empty name", i)
		}
		if strings.ContainsRune(s.Name, 0) {
			return fmt.Errorf("apfswrite: snapshot name %q contains a NUL", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("apfswrite: duplicate snapshot name %q", s.Name)
		}
		seen[s.Name] = true
		mtime := defaultTime
		if !s.ModTime.IsZero() {
			mtime = uint64(s.ModTime.UnixNano())
		}
		b.snapshots = append(b.snapshots, &snapBuild{
			name: s.Name, xid: uint64(i) + 1, mtime: mtime, inum: inumBase + uint64(i),
		})
	}
	// The snapshot and the live volume share the single static checkpoint's
	// transaction id, so the live xid stays at the base xid.
	b.liveXID = mkfsXID
	// One shared omap snapshot tree, plus a frozen superblock and an
	// extentref tree copy per snapshot.
	b.snapBlocks = 1 + 2*uint64(len(b.snapshots))
	return nil
}

// placeSnapshots assigns block numbers to the snapshot objects starting at base:
// the volume omap's snapshot tree first, then one frozen superblock per snapshot.
func (b *builder) placeSnapshots(base uint64) {
	if len(b.snapshots) == 0 {
		return
	}
	b.snapBase = base
	b.volSnapTreeBno = base
	for i := range b.snapshots {
		b.snapshots[i].sblockBno = base + 1 + uint64(i)*2
		b.snapshots[i].extrefBno = base + 2 + uint64(i)*2
	}
}

// extentRefcount is the reference count stamped on every physical-extent record.
// It is one: each volume state (the live volume and each snapshot) accounts its
// own single reference to the extent through its own view of the extent-
// reference tree, so the count within any one tree is one.
func (b *builder) extentRefcount() uint32 {
	return 1
}

// writeSnapMetaTree writes the volume's snapshot-metadata tree: an empty
// root-leaf when there are no snapshots, otherwise a root-leaf holding a
// j_snap_metadata + j_snap_name record pair per snapshot.
func (b *builder) writeSnapMetaTree(bno uint64) error {
	if len(b.snapshots) == 0 {
		return b.writeEmptyTree(bno, bno, objectTypeSnapMetaTree)
	}
	return b.writeSnapMetaNode(bno, b.snapMetaRecords())
}

// snapMetaRecords builds the (key, value) records for the snapshot-metadata
// tree: per snapshot a j_snap_metadata record (keyed by xid) and a j_snap_name
// record (keyed by name), sorted by the tree's key order.
func (b *builder) snapMetaRecords() []catRecord {
	recs := make([]catRecord, 0, 2*len(b.snapshots))
	for _, s := range b.snapshots {
		name := append([]byte(s.name), 0) // NUL-terminated

		// j_snap_metadata: key (xid, TYPE_SNAP_METADATA) -> j_snap_metadata_val.
		mkey := make([]byte, sizeofInodeKey)
		setKeyHeader(mkey, 0, s.xid, typeSnapMetadata)
		mval := make([]byte, sizeofSnapMetadataVal+len(name))
		binary.LittleEndian.PutUint64(mval[0:], s.extrefBno)                  // extentref_tree_oid
		binary.LittleEndian.PutUint64(mval[8:], s.sblockBno)                  // sblock_oid (physical)
		binary.LittleEndian.PutUint64(mval[16:], s.mtime)                     // create_time
		binary.LittleEndian.PutUint64(mval[24:], s.mtime)                     // change_time
		binary.LittleEndian.PutUint64(mval[32:], s.inum)                      // inum
		binary.LittleEndian.PutUint32(mval[40:], objPhysical|objectTypeBtree) // extentref_tree_type
		binary.LittleEndian.PutUint32(mval[44:], 0)                           // flags
		binary.LittleEndian.PutUint16(mval[48:], uint16(len(name)))           // name_len
		copy(mval[sizeofSnapMetadataVal:], name)
		recs = append(recs, catRecord{id: s.xid, typ: typeSnapMetadata, key: mkey, val: mval})

		// j_snap_name: key (~0, TYPE_SNAP_NAME) + name -> j_snap_name_val (xid).
		nkey := make([]byte, sizeofInodeKey+2+len(name))
		setKeyHeader(nkey, 0, snapNameObjID, typeSnapName)
		binary.LittleEndian.PutUint16(nkey[sizeofInodeKey:], uint16(len(name)))
		copy(nkey[sizeofInodeKey+2:], name)
		nval := make([]byte, 8)
		binary.LittleEndian.PutUint64(nval[0:], s.xid)
		recs = append(recs, catRecord{id: snapNameObjID, typ: typeSnapName, name: s.name, key: nkey, val: nval})
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].id != recs[j].id {
			return recs[i].id < recs[j].id
		}
		if recs[i].typ != recs[j].typ {
			return recs[i].typ < recs[j].typ
		}
		return recs[i].name < recs[j].name
	})
	return recs
}

// writeSnapMetaNode writes the snapshot-metadata tree as a single physical
// root-leaf holding variable-size records.
func (b *builder) writeSnapMetaNode(bno uint64, recs []catRecord) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(block[btnOffFlags:], btnodeRoot|btnodeLeaf)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(recs)))

	tocLen := tocBytesFor(len(recs))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &catCursor{
		b: b, block: block, tocOff: headLen,
		keyArea: headLen + tocLen, keyOff: headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen, valEnd: int(b.blocksize) - infoLen,
	}
	longestKey, longestVal := 0, 0
	for _, r := range recs {
		cur.putRecord(r.key, r.val)
		if len(r.key) > longestKey {
			longestKey = len(r.key)
		}
		if len(r.val) > longestVal {
			longestVal = len(r.val)
		}
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	info := block[int(b.blocksize)-infoLen:]
	binary.LittleEndian.PutUint32(info[0:], btreePhysical|btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)                     // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(longestKey))             // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(longestVal))             // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(len(recs)))              // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)                              // bt_node_count

	setObjectHeader(block, int(b.blocksize), bno, objectTypeBtree|objPhysical, objectTypeSnapMetaTree)
	return b.writeBlock(block, bno)
}

// writeSnapshots writes each snapshot's frozen volume superblock and the volume
// omap's snapshot tree.
func (b *builder) writeSnapshots() error {
	if len(b.snapshots) == 0 {
		return nil
	}
	for _, s := range b.snapshots {
		// Each snapshot owns a copy of the extentref tree so its extent
		// refcounts are checked against its own frozen fsroot, independent of the
		// live volume's tree.
		if err := b.makeExtrefRoot(s.extrefBno, s.extrefBno); err != nil {
			return err
		}
		if err := b.writeFrozenSblock(s); err != nil {
			return err
		}
	}
	return b.writeOmapSnapshotTree(b.volSnapTreeBno)
}

// writeFrozenSblock writes a snapshot's frozen volume superblock: a physical copy
// of the volume superblock as it stood at the snapshot's xid, referenced by the
// snapshot record's sblock_oid.
func (b *builder) writeFrozenSblock(s *snapBuild) error {
	vsb := b.volumeSuperblock()
	vsb.NumSnapshots = 0               // the state before this snapshot existed
	vsb.ExtentrefTreeOID = s.extrefBno // the snapshot's own extentref tree
	block := b.zeroedBlock()
	marshalInto(block, vsb)
	setObjectHeaderXID(block, int(b.blocksize), s.sblockBno,
		objPhysical|objectTypeFS, objectTypeInvalid, s.xid)
	return b.writeBlock(block, s.sblockBno)
}

// writeOmapSnapshotTree writes the volume omap's snapshot tree: a physical,
// fixed-layout root-leaf keyed by snapshot xid, each value an omap_snapshot_t
// (flags, pad, oid — all zero for a plain snapshot).
func (b *builder) writeOmapSnapshotTree(bno uint64) error {
	const keySz, valSz = 8, sizeofOmapSnapshot
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo
	n := len(b.snapshots)

	capacity := (int(b.blocksize) - headLen) / (keySz + valSz + sizeofKvoff)
	tocLen := capacity * sizeofKvoff
	keyArea := headLen + tocLen
	valAreaEnd := int(b.blocksize) - infoLen

	for i, s := range b.snapshots {
		toc := headLen + i*sizeofKvoff
		keyOff := keyArea + i*keySz
		valOff := valAreaEnd - (i+1)*valSz
		binary.LittleEndian.PutUint16(block[toc:], uint16(keyOff-keyArea))
		binary.LittleEndian.PutUint16(block[toc+2:], uint16(valAreaEnd-valOff))
		binary.LittleEndian.PutUint64(block[keyOff:], s.xid) // key: snapshot xid
		// value omap_snapshot_t {flags, pad, oid} is left zero.
	}

	usedKeys := n * keySz
	usedVals := n * valSz
	freeLen := int(b.blocksize) - headLen - tocLen - usedKeys - usedVals - infoLen
	writeLeafHeader(block, btnodeRoot|btnodeLeaf|btnodeFixedKVSize, n, tocLen, usedKeys, freeLen)

	info := block[int(b.blocksize)-infoLen:]
	binary.LittleEndian.PutUint32(info[0:], btreePhysical) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)   // bt_node_size
	binary.LittleEndian.PutUint32(info[8:], keySz)         // bt_key_size
	binary.LittleEndian.PutUint32(info[12:], valSz)        // bt_val_size
	binary.LittleEndian.PutUint32(info[16:], keySz)        // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], valSz)        // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(n))    // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)            // bt_node_count

	setObjectHeader(block, int(b.blocksize), bno, objectTypeBtree|objPhysical, objectTypeOmapSnapshot)
	return b.writeBlock(block, bno)
}
