// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"sort"
)

// Offsets within an apfs_btree_node_phys header.
const (
	btnOffFlags       = sizeofObjPhys      // 0x20
	btnOffLevel       = sizeofObjPhys + 2  // 0x22
	btnOffNkeys       = sizeofObjPhys + 4  // 0x24
	btnOffTableSpace  = sizeofObjPhys + 8  // 0x28 (nloc)
	btnOffFreeSpace   = sizeofObjPhys + 12 // 0x2C (nloc)
	btnOffKeyFreeList = sizeofObjPhys + 16 // 0x30 (nloc)
	btnOffValFreeList = sizeofObjPhys + 20 // 0x34 (nloc)
)

// Table-of-contents entries grow in fixed increments; a node reserves at least
// this many entries even when it holds fewer records.
const (
	btreeTOCEntryIncrement = 8
	btreeTOCEntryMaxUnused = 2 * btreeTOCEntryIncrement
)

// putNloc writes an apfs_nloc {off, len} pair at the given block offset.
func putNloc(block []byte, off int, nlocOff, nlocLen uint16) {
	binary.LittleEndian.PutUint16(block[off:], nlocOff)
	binary.LittleEndian.PutUint16(block[off+2:], nlocLen)
}

// writeLeafHeader fills the apfs_btree_node_phys header shared by the leaf nodes
// this file builds. level stays 0 (all nodes here are leaves; the file-system tree index
// node is built in file-system tree.go). tocLen sizes the table-of-contents extent that
// starts right after the header; keyEnd/freeLen describe the free-space extent
// that follows the packed keys. Both freelists are marked invalid — a freshly
// built node has no reclaimed fragments.
func writeLeafHeader(block []byte, flags uint16, nkeys, tocLen, keyEnd, freeLen int) {
	binary.LittleEndian.PutUint16(block[btnOffFlags:], flags)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(nkeys))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))
	putNloc(block, btnOffFreeSpace, uint16(keyEnd), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)
}

// fixedKVSizes reports the key and value sizes for a fixed-layout B-tree of the
// given subtype, and whether the subtype is fixed-layout at all. Free-queue
// values are eight bytes because the queues written here hold no ghost entries.
// Variable-layout trees (the file-system tree) return ok=false.
func fixedKVSizes(subtype uint32) (keySize, valSize int, ok bool) {
	switch subtype {
	case objectTypeOmap:
		return sizeofOmapKey, sizeofOmapVal, true
	case objectTypeSpacemanFreeQueue:
		return sizeofSpacemanFreeQueueKey, 8, true
	case objectTypeFusionMiddleTree:
		return sizeofFusionMtKey, sizeofFusionMtVal, true
	default:
		return 0, 0, false
	}
}

// treeFlags returns the bt_info flags for a tree of the given subtype and
// whether its nodes are fixed-key-size. Free queues are ephemeral and permit
// ghosts; the physical trees do not.
func treeFlags(subtype uint32) (btInfoFlags uint32, fixedNode bool) {
	switch subtype {
	case objectTypeSpacemanFreeQueue:
		return btreeEphemeral | btreeAllowGhosts, true
	case objectTypeFusionMiddleTree:
		return btreePhysical, true
	default:
		return btreePhysical | btreeKVNonaligned, false
	}
}

// tocAreaBytes returns how many bytes to reserve for a fixed-layout node's table
// of contents. It is sized to index as many records as the node body could hold
// if packed solid: the body is everything past the header (the info footer is
// intentionally not deducted, which yields the record ceiling), and each record
// costs its key, its value and one TOC entry. Variable-layout nodes fall back to
// the small-node minimum.
func (b *builder) tocAreaBytes(subtype uint32) int {
	keySize, valSize, ok := fixedKVSizes(subtype)
	if !ok {
		return sizeofKvloc * btreeTOCEntryMaxUnused
	}
	body := int(b.blocksize) - sizeofBtreeNodePhys
	perRecord := keySize + valSize + sizeofKvoff
	return (body / perRecord) * sizeofKvoff
}

// writeEmptyTreeFooter fills the bt_info footer of an empty single-node tree:
// the layout flags, the node size, the key/value sizes for fixed-layout trees,
// and a node count of one (the tree is just its root).
func (b *builder) writeEmptyTreeFooter(info []byte, subtype uint32) {
	flags, _ := treeFlags(subtype)
	binary.LittleEndian.PutUint32(info[0:], flags)       // bt_fixed.bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize) // bt_fixed.bt_node_size

	if keySize, valSize, ok := fixedKVSizes(subtype); ok {
		binary.LittleEndian.PutUint32(info[8:], uint32(keySize))  // bt_key_size
		binary.LittleEndian.PutUint32(info[12:], uint32(valSize)) // bt_val_size
		binary.LittleEndian.PutUint32(info[16:], uint32(keySize)) // bt_longest_key
		binary.LittleEndian.PutUint32(info[20:], uint32(valSize)) // bt_longest_val
	}
	binary.LittleEndian.PutUint64(info[32:], 1) // bt_node_count
}

// writeEmptyTree writes a tree that is one empty root-leaf. The free queues,
// the snapshot-metadata tree and the extentref tree (via file.go) all
// begin this way. subtype selects the fixed/variable layout and the storage
// class (free queues are ephemeral, the rest physical).
func (b *builder) writeEmptyTree(paddr, oid uint64, subtype uint32) error {
	root := b.zeroedBlock()
	infoLen := sizeofBtreeInfo

	flags := uint16(btnodeRoot | btnodeLeaf)
	if _, fixed := treeFlags(subtype); fixed {
		flags |= btnodeFixedKVSize
	}

	tocLen := b.tocAreaBytes(subtype)
	freeLen := int(b.blocksize) - sizeofBtreeNodePhys - tocLen - infoLen
	writeLeafHeader(root, flags, 0, tocLen, 0, freeLen)

	b.writeEmptyTreeFooter(root[int(b.blocksize)-infoLen:], subtype)

	typ := uint32(objectTypeBtree)
	if subtype == objectTypeSpacemanFreeQueue {
		typ |= objEphemeral
	} else {
		typ |= objPhysical
	}
	setObjectHeader(root, int(b.blocksize), oid, typ, subtype)
	return b.writeBlock(root, paddr)
}

// omapEntry is one (oid -> physical block) mapping stored in an object map, at a
// given transaction id. A lookup at xid X resolves to the entry with the largest
// xid <= X, which is what keeps a snapshot's older object versions resolvable.
type omapEntry struct {
	oid   uint64
	paddr uint64
	xid   uint64
	flags uint32
}

// writeOmapFooter fills the bt_info footer of an object-map root node.
func (b *builder) writeOmapFooter(info []byte, nkeys int) {
	binary.LittleEndian.PutUint32(info[0:], btreePhysical)  // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)    // bt_node_size
	binary.LittleEndian.PutUint32(info[8:], sizeofOmapKey)  // bt_key_size
	binary.LittleEndian.PutUint32(info[12:], sizeofOmapVal) // bt_val_size
	binary.LittleEndian.PutUint32(info[16:], sizeofOmapKey) // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], sizeofOmapVal) // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(nkeys)) // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)             // bt_node_count
}

// omapEntries returns the mappings an object map must hold. The container omap
// maps only the volume superblock's virtual oid — at the live xid, since the
// live superblock is the current one. The volume omap maps the file-system tree root
// and, when the file-system tree spans two levels, every file-system tree leaf node, all at the
// base xid (the format state a snapshot captures).
func (b *builder) omapEntries(isVol bool) []omapEntry {
	if !isVol {
		return []omapEntry{{firstVolOID, b.firstVolPaddr, b.liveXID, 0}}
	}
	// The file-system tree root (and any leaves) are shared by the live volume and the
	// snapshots, so they carry no OMAP_VAL_SAVED flag (that would mark them as
	// superseded in the live volume, which is not the case here).
	entries := []omapEntry{{firstVolFSTreeRootOID, b.firstVolFSTreeRootPaddr, formatXID, 0}}
	if b.fsTreeTwoLevel {
		for i := uint64(0); i < b.numFSTreeLeaves; i++ {
			entries = append(entries, omapEntry{fsTreeLeafOIDBase + i, b.fsTreeLeafBase + i, formatXID, 0})
		}
	}
	return entries
}

// writeObjectMapRoot writes the root node of an object map. Records are fixed-size
// (omap_key, omap_val) pairs sorted by oid; keys pack forward from the end of
// the table of contents and values pack backward from the start of the footer.
func (b *builder) writeObjectMapRoot(paddr uint64, isVol bool) error {
	entries := b.omapEntries(isVol)
	sort.Slice(entries, func(i, j int) bool { return entries[i].oid < entries[j].oid })

	root := b.zeroedBlock()
	infoLen := sizeofBtreeInfo
	nkeys := len(entries)

	tocLen := b.tocAreaBytes(objectTypeOmap)
	keyArea := sizeofBtreeNodePhys + tocLen
	valAreaEnd := int(b.blocksize) - infoLen

	for i, e := range entries {
		toc := sizeofBtreeNodePhys + i*sizeofKvoff
		keyOff := keyArea + i*sizeofOmapKey
		valOff := valAreaEnd - (i+1)*sizeofOmapVal
		binary.LittleEndian.PutUint16(root[toc:], uint16(keyOff-keyArea))
		binary.LittleEndian.PutUint16(root[toc+2:], uint16(valAreaEnd-valOff))

		binary.LittleEndian.PutUint64(root[keyOff:], e.oid)         // ok_oid
		binary.LittleEndian.PutUint64(root[keyOff+8:], e.xid)       // ok_xid
		binary.LittleEndian.PutUint32(root[valOff:], e.flags)       // ov_flags
		binary.LittleEndian.PutUint32(root[valOff+4:], b.blocksize) // ov_size
		binary.LittleEndian.PutUint64(root[valOff+8:], e.paddr)     // ov_paddr
	}

	usedKeys := nkeys * sizeofOmapKey
	usedVals := nkeys * sizeofOmapVal
	freeLen := int(b.blocksize) - sizeofBtreeNodePhys - tocLen - usedKeys - usedVals - infoLen
	writeLeafHeader(root, btnodeRoot|btnodeLeaf|btnodeFixedKVSize, nkeys, tocLen, usedKeys, freeLen)

	b.writeOmapFooter(root[int(b.blocksize)-infoLen:], nkeys)
	setObjectHeader(root, int(b.blocksize), paddr, objectTypeBtree|objPhysical, objectTypeOmap)
	return b.writeBlock(root, paddr)
}

// writeObjectMap writes an object map: the omap_phys object that points at its
// root plus the root node itself. The container omap is manually managed; the
// volume omap is not.
func (b *builder) writeObjectMap(paddr uint64, isVol bool) error {
	omap := &omapPhys{}
	if !isVol {
		omap.Flags = omapManuallyManaged
	}
	omap.TreeType = objectTypeBtree | objPhysical
	omap.SnapshotTreeType = objectTypeBtree | objPhysical

	// The volume omap records its snapshots: the snapshot tree (keyed by xid),
	// the snapshot count and the most recent snapshot xid.
	if isVol && len(b.snapshots) > 0 {
		omap.SnapCount = uint32(len(b.snapshots))
		omap.SnapshotTreeOID = b.volSnapTreePaddr
		omap.MostRecentSnap = b.snapshots[len(b.snapshots)-1].xid
	}

	rootPaddr := b.mainOmapRootPaddr
	if isVol {
		rootPaddr = b.firstVolOmapRootPaddr
	}
	omap.TreeOID = rootPaddr
	if err := b.writeObjectMapRoot(rootPaddr, isVol); err != nil {
		return err
	}

	block := b.zeroedBlock()
	marshalInto(block, omap)
	setObjectHeader(block, int(b.blocksize), paddr, objPhysical|objectTypeOmap, objectTypeInvalid)
	return b.writeBlock(block, paddr)
}
