// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "encoding/binary"

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

// Table-of-contents sizing constants (btree.c).
const (
	btreeTOCEntryIncrement = 8
	btreeTOCEntryMaxUnused = 2 * btreeTOCEntryIncrement
)

// putNloc writes an apfs_nloc {off, len} at the given block offset.
func putNloc(block []byte, off int, nloc_off, nloc_len uint16) {
	binary.LittleEndian.PutUint16(block[off:], nloc_off)
	binary.LittleEndian.PutUint16(block[off+2:], nloc_len)
}

// minTableSize returns the minimum size of the table of contents for a leaf,
// mirroring btree.c:min_table_size.
func (b *builder) minTableSize(typ uint32) int {
	var keySize, valSize, tocSize int
	switch typ {
	case objectTypeOmap:
		keySize = sizeofOmapKey
		valSize = sizeofOmapVal
		tocSize = sizeofKvoff
	case objectTypeSpacemanFreeQueue:
		keySize = sizeofSpacemanFreeQueueKey
		valSize = 8 // no ghosts here
		tocSize = sizeofKvoff
	case objectTypeFusionMiddleTree:
		keySize = sizeofFusionMtKey
		valSize = sizeofFusionMtVal
		tocSize = sizeofKvoff
	default:
		// It should at least have room for one record.
		return sizeofKvloc * btreeTOCEntryMaxUnused
	}
	// The footer of root nodes is ignored for some reason.
	space := int(b.blocksize) - sizeofBtreeNodePhys
	count := space / (keySize + valSize + tocSize)
	return count * tocSize
}

// setEmptyBtreeInfo sets the info footer for an empty b-tree node, mirroring
// btree.c:set_empty_btree_info. info is a slice starting at the footer.
func (b *builder) setEmptyBtreeInfo(info []byte, subtype uint32) {
	var flags uint32
	switch subtype {
	case objectTypeSpacemanFreeQueue:
		flags = btreeEphemeral | btreeAllowGhosts
	case objectTypeFusionMiddleTree:
		flags = btreePhysical
	default:
		flags = btreePhysical | btreeKVNonaligned
	}

	binary.LittleEndian.PutUint32(info[0:], flags)       // bt_fixed.bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize) // bt_fixed.bt_node_size

	if subtype == objectTypeSpacemanFreeQueue {
		binary.LittleEndian.PutUint32(info[8:], sizeofSpacemanFreeQueueKey)  // bt_key_size
		binary.LittleEndian.PutUint32(info[12:], 8)                          // bt_val_size
		binary.LittleEndian.PutUint32(info[16:], sizeofSpacemanFreeQueueKey) // bt_longest_key
		binary.LittleEndian.PutUint32(info[20:], 8)                          // bt_longest_val
	}
	if subtype == objectTypeFusionMiddleTree {
		binary.LittleEndian.PutUint32(info[8:], sizeofFusionMtKey)
		binary.LittleEndian.PutUint32(info[12:], sizeofFusionMtVal)
		binary.LittleEndian.PutUint32(info[16:], sizeofFusionMtKey)
		binary.LittleEndian.PutUint32(info[20:], sizeofFusionMtVal)
	}
	binary.LittleEndian.PutUint64(info[32:], 1) // bt_node_count: only the root
}

// makeEmptyBtreeRoot makes an empty root for a b-tree, mirroring
// btree.c:make_empty_btree_root. Used for the free queues, snapshot metadata
// tree and extent reference tree.
func (b *builder) makeEmptyBtreeRoot(bno, oid uint64, subtype uint32) error {
	root := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	flags := uint16(btnodeRoot | btnodeLeaf)
	if subtype == objectTypeSpacemanFreeQueue || subtype == objectTypeFusionMiddleTree {
		flags |= btnodeFixedKVSize
	}
	binary.LittleEndian.PutUint16(root[btnOffFlags:], flags)

	tocLen := b.minTableSize(subtype)

	// No keys and no values.
	binary.LittleEndian.PutUint32(root[btnOffNkeys:], 0)
	freeLen := int(b.blocksize) - headLen - tocLen - infoLen
	putNloc(root, btnOffTableSpace, 0, uint16(tocLen))
	putNloc(root, btnOffFreeSpace, 0, uint16(freeLen))
	putNloc(root, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(root, btnOffValFreeList, btoffInvalid, 0)

	b.setEmptyBtreeInfo(root[int(b.blocksize)-infoLen:], subtype)

	typ := uint32(objectTypeBtree)
	if subtype == objectTypeSpacemanFreeQueue {
		typ |= objEphemeral
	} else {
		typ |= objPhysical
	}
	setObjectHeader(root, int(b.blocksize), oid, typ, subtype)
	return b.writeBlock(root, bno)
}

// setOmapInfo sets the info footer for an object map node, mirroring
// btree.c:set_omap_info.
func (b *builder) setOmapInfo(info []byte, nkeys int) {
	binary.LittleEndian.PutUint32(info[0:], btreePhysical)  // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)    // bt_node_size
	binary.LittleEndian.PutUint32(info[8:], sizeofOmapKey)  // bt_key_size
	binary.LittleEndian.PutUint32(info[12:], sizeofOmapVal) // bt_val_size
	binary.LittleEndian.PutUint32(info[16:], sizeofOmapKey) // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], sizeofOmapVal) // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(nkeys)) // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)             // bt_node_count
}

// makeOmapRoot makes the root node of an object map, mirroring
// btree.c:make_omap_root.
func (b *builder) makeOmapRoot(bno uint64, isVol bool) error {
	root := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(root[btnOffFlags:], btnodeRoot|btnodeLeaf|btnodeFixedKVSize)

	binary.LittleEndian.PutUint32(root[btnOffNkeys:], 1)
	tocLen := b.minTableSize(objectTypeOmap)
	keyLen := sizeofOmapKey
	valLen := sizeofOmapVal

	// Location of the one record.
	keyOff := headLen + tocLen
	valOff := int(b.blocksize) - infoLen - valLen
	// kvoff at head_len: k = 0, v = val_len.
	binary.LittleEndian.PutUint16(root[headLen:], 0)
	binary.LittleEndian.PutUint16(root[headLen+2:], uint16(valLen))

	// Set the key and value for the one record.
	if isVol {
		binary.LittleEndian.PutUint64(root[keyOff:], firstVolCatRootOID)     // ok_oid
		binary.LittleEndian.PutUint64(root[valOff+8:], b.firstVolCatRootBno) // ov_paddr
	} else {
		binary.LittleEndian.PutUint64(root[keyOff:], firstVolOID)
		binary.LittleEndian.PutUint64(root[valOff+8:], b.firstVolBno)
	}
	binary.LittleEndian.PutUint64(root[keyOff+8:], mkfsXID)     // ok_xid
	binary.LittleEndian.PutUint32(root[valOff+4:], b.blocksize) // ov_size

	putNloc(root, btnOffTableSpace, 0, uint16(tocLen))
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(root, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(root, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(root, btnOffValFreeList, btoffInvalid, 0)

	b.setOmapInfo(root[int(b.blocksize)-infoLen:], 1)
	setObjectHeader(root, int(b.blocksize), bno,
		objectTypeBtree|objPhysical, objectTypeOmap)
	return b.writeBlock(root, bno)
}

// makeOmapBtree makes an object map, mirroring btree.c:make_omap_btree.
func (b *builder) makeOmapBtree(bno uint64, isVol bool) error {
	omap := &omapPhys{}
	if !isVol {
		omap.Flags = omapManuallyManaged
	}
	omap.TreeType = objectTypeBtree | objPhysical
	omap.SnapshotTreeType = objectTypeBtree | objPhysical

	var rootBno uint64
	if isVol {
		rootBno = b.firstVolOmapRootBno
	} else {
		rootBno = b.mainOmapRootBno
	}
	omap.TreeOID = rootBno
	if err := b.makeOmapRoot(rootBno, isVol); err != nil {
		return err
	}

	block := b.zeroedBlock()
	marshalInto(block, omap)
	setObjectHeader(block, int(b.blocksize), bno,
		objPhysical|objectTypeOmap, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// setCatInfo sets the info footer for a catalog root node, mirroring
// btree.c:set_cat_info.
func (b *builder) setCatInfo(info []byte) {
	drecKeysz := sizeofDrecHashedKeyFixed
	if b.normSensitive {
		drecKeysz = sizeofDrecKeyFixed
	}
	maxkey := drecKeysz + len("private-dir") + 1
	maxval := sizeofInodeVal + sizeofXfBlob + sizeofXField + int(roundUp(uint64(len("private-dir")+1), 8))

	binary.LittleEndian.PutUint32(info[0:], btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)       // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(maxkey))   // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(maxval))   // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], 4)                // bt_key_count (two per dir)
	binary.LittleEndian.PutUint64(info[32:], 1)                // bt_node_count
}

// makeCatRoot makes the root node of a catalog tree with two records: the root
// and private directories. Mirrors btree.c:make_cat_root.
func (b *builder) makeCatRoot(bno, oid uint64) error {
	root := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(root[btnOffFlags:], btnodeRoot|btnodeLeaf)

	// The two dentry records and their inodes.
	binary.LittleEndian.PutUint32(root[btnOffNkeys:], 4)
	tocLen := b.minTableSize(objectTypeFSTree)
	putNloc(root, btnOffTableSpace, 0, uint16(tocLen))

	cur := &catCursor{
		b:          b,
		block:      root,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}

	cur.makeSpecialDirDentry(privDirInoNum, "private-dir")
	cur.makeSpecialDirDentry(rootDirInoNum, "root")
	cur.makeSpecialDirInode(rootDirInoNum, "root")
	cur.makeSpecialDirInode(privDirInoNum, "private-dir")

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(root, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(root, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(root, btnOffValFreeList, btoffInvalid, 0)

	b.setCatInfo(root[int(b.blocksize)-infoLen:])
	setObjectHeader(root, int(b.blocksize), oid,
		objectTypeBtree|objVirtual, objectTypeFSTree)
	return b.writeBlock(root, bno)
}
