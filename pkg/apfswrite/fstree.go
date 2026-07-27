// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "encoding/binary"

// makeFSTree builds the volume's file-system tree (file-system) B-tree. When every
// record fits in one node the tree is a single root-leaf. When the records
// overflow one leaf the tree grows to two levels: an index root at (paddr, oid)
// plus one leaf per group of records,
// each leaf a virtual object mapped by the volume object map. Child-node
// pointers in the index are virtual oids, which the reader and fsck resolve
// through that object map.
func (b *builder) makeFSTree(paddr, oid uint64) error {
	recs := b.buildFSTreeRecords()

	longestKey, longestVal := 0, 0
	for _, r := range recs {
		if len(r.key) > longestKey {
			longestKey = len(r.key)
		}
		if len(r.val) > longestVal {
			longestVal = len(r.val)
		}
	}
	// The empty-volume special records set a floor for the longest key/value.
	if longestKey < sizeofDrecHashedKeyFixed+len("private-dir")+1 {
		longestKey = sizeofDrecHashedKeyFixed + len("private-dir") + 1
	}

	if !b.fsTreeTwoLevel {
		return b.writeFSTreeNode(paddr, oid, recs, true /* root */, 0, /* level */
			&fsTreeInfo{longestKey: longestKey, longestVal: longestVal, keyCount: len(recs), nodeCount: 1})
	}

	leaves := packFSTreeLeaves(recs, int(b.blocksize), 0)
	idx := make([]fsTreeRecord, 0, len(leaves))
	for i, leaf := range leaves {
		leafOID := fsTreeLeafOIDBase + uint64(i)
		leafPaddr := b.fsTreeLeafBase + uint64(i)
		if err := b.writeFSTreeNode(leafPaddr, leafOID, leaf, false /* not root */, 0 /* level */, nil); err != nil {
			return err
		}
		// Index record: the leaf's first key -> the leaf's virtual oid.
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, leafOID)
		idx = append(idx, fsTreeRecord{key: leaf[0].key, val: val})
	}

	nodeCount := 1 + len(leaves)
	return b.writeFSTreeIndex(paddr, oid, idx, &fsTreeInfo{
		longestKey: longestKey, longestVal: longestVal, keyCount: len(recs), nodeCount: nodeCount,
	})
}

// fsTreeInfo holds the values written into a file-system tree root node's btree_info.
type fsTreeInfo struct {
	longestKey int
	longestVal int
	keyCount   int
	nodeCount  int
}

// writeFSTreeNode writes a file-system tree leaf node (level 0) holding recs. isRoot marks a
// single-node tree (root+leaf), which carries the btree_info footer; a plain
// leaf of a taller tree has no footer and its values are counted from the end
// of the block.
func (b *builder) writeFSTreeNode(paddr, oid uint64, recs []fsTreeRecord, isRoot bool, level uint16, footer *fsTreeInfo) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := 0
	flags := uint16(btnodeLeaf)
	if isRoot {
		flags |= btnodeRoot
		infoLen = sizeofBtreeInfo
	}
	binary.LittleEndian.PutUint16(block[btnOffFlags:], flags)
	binary.LittleEndian.PutUint16(block[btnOffLevel:], level)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(recs)))

	tocLen := tocBytesFor(len(recs))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b:          b,
		block:      block,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}
	for _, r := range recs {
		cur.putRecord(r.key, r.val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	objType := uint32(objectTypeBtreeNode) | objVirtual
	if isRoot {
		objType = objectTypeBtree | objVirtual
		b.setFSTreeInfo(block[int(b.blocksize)-infoLen:], footer)
	}
	setObjectHeader(block, int(b.blocksize), oid, objType, objectTypeFSTree)
	return b.writeBlock(block, paddr)
}

// writeFSTreeIndex writes the file-system tree index root (level 1). Its records map the
// first key of each child leaf to that leaf's virtual oid (an 8-byte value).
func (b *builder) writeFSTreeIndex(paddr, oid uint64, idx []fsTreeRecord, footer *fsTreeInfo) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(block[btnOffFlags:], btnodeRoot) // root, not leaf
	binary.LittleEndian.PutUint16(block[btnOffLevel:], 1)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(idx)))

	tocLen := tocBytesFor(len(idx))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b:          b,
		block:      block,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}
	for _, r := range idx {
		cur.putRecord(r.key, r.val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	b.setFSTreeInfo(block[int(b.blocksize)-infoLen:], footer)
	setObjectHeader(block, int(b.blocksize), oid,
		objectTypeBtree|objVirtual, objectTypeFSTree)
	return b.writeBlock(block, paddr)
}

// setFSTreeInfo writes a file-system tree root node's btree_info trailer.
func (b *builder) setFSTreeInfo(info []byte, f *fsTreeInfo) {
	binary.LittleEndian.PutUint32(info[0:], btreeKVNonaligned)     // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)           // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(f.longestKey)) // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(f.longestVal)) // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(f.keyCount))   // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], uint64(f.nodeCount))  // bt_node_count
}

// putRecord lays out one variable-size (key, value) pair in a file-system tree node:
// the key grows forward from the key area, the value backward from the value
// area, and a kvloc TOC entry records their offsets and lengths.
func (c *fsTreeCursor) putRecord(key, val []byte) {
	kStart := c.keyOff
	copy(c.block[c.keyOff:], key)
	c.keyOff += len(key)

	valOff := c.valEnd - len(val)
	copy(c.block[valOff:], val)
	vOff := c.valAreaEnd - c.valEnd + len(val)
	c.valEnd -= len(val)

	c.putKvloc(uint16(kStart-c.keyArea), uint16(len(key)), uint16(vOff), uint16(len(val)))
	c.tocOff += sizeofKvloc
}
