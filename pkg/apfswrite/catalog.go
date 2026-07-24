// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "encoding/binary"

// makeCatTree builds the volume's catalog (file-system) B-tree. When every
// record fits in one node the tree is a single root-leaf, exactly like
// mkapfs's make_cat_root. When the records overflow one leaf the tree grows to
// two levels: an index root at (bno, oid) plus one leaf per group of records,
// each leaf a virtual object mapped by the volume object map. Child-node
// pointers in the index are virtual oids, which the reader and fsck resolve
// through that object map.
func (b *builder) makeCatTree(bno, oid uint64) error {
	recs := b.buildCatRecords()

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

	if !b.catTwoLevel {
		return b.writeCatNode(bno, oid, recs, true /* root */, 0, /* level */
			&catFooter{longestKey: longestKey, longestVal: longestVal, keyCount: len(recs), nodeCount: 1})
	}

	leaves := packCatLeaves(recs, int(b.blocksize), 0)
	idx := make([]catRecord, 0, len(leaves))
	for i, leaf := range leaves {
		leafOID := catLeafOIDBase + uint64(i)
		leafBno := b.catLeafBase + uint64(i)
		if err := b.writeCatNode(leafBno, leafOID, leaf, false /* not root */, 0 /* level */, nil); err != nil {
			return err
		}
		// Index record: the leaf's first key -> the leaf's virtual oid.
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, leafOID)
		idx = append(idx, catRecord{key: leaf[0].key, val: val})
	}

	nodeCount := 1 + len(leaves)
	return b.writeCatIndex(bno, oid, idx, &catFooter{
		longestKey: longestKey, longestVal: longestVal, keyCount: len(recs), nodeCount: nodeCount,
	})
}

// catFooter holds the values written into a catalog root node's btree_info.
type catFooter struct {
	longestKey int
	longestVal int
	keyCount   int
	nodeCount  int
}

// writeCatNode writes a catalog leaf node (level 0) holding recs. isRoot marks a
// single-node tree (root+leaf), which carries the btree_info footer; a plain
// leaf of a taller tree has no footer and its values are counted from the end
// of the block.
func (b *builder) writeCatNode(bno, oid uint64, recs []catRecord, isRoot bool, level uint16, footer *catFooter) error {
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

	cur := &catCursor{
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
		b.setCatFooter(block[int(b.blocksize)-infoLen:], footer)
	}
	setObjectHeader(block, int(b.blocksize), oid, objType, objectTypeFSTree)
	return b.writeBlock(block, bno)
}

// writeCatIndex writes the catalog index root (level 1). Its records map the
// first key of each child leaf to that leaf's virtual oid (an 8-byte value).
func (b *builder) writeCatIndex(bno, oid uint64, idx []catRecord, footer *catFooter) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(block[btnOffFlags:], btnodeRoot) // root, not leaf
	binary.LittleEndian.PutUint16(block[btnOffLevel:], 1)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(idx)))

	tocLen := tocBytesFor(len(idx))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &catCursor{
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

	b.setCatFooter(block[int(b.blocksize)-infoLen:], footer)
	setObjectHeader(block, int(b.blocksize), oid,
		objectTypeBtree|objVirtual, objectTypeFSTree)
	return b.writeBlock(block, bno)
}

// setCatFooter writes a catalog root node's btree_info trailer.
func (b *builder) setCatFooter(info []byte, f *catFooter) {
	binary.LittleEndian.PutUint32(info[0:], btreeKVNonaligned)     // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)           // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(f.longestKey)) // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(f.longestVal)) // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(f.keyCount))   // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], uint64(f.nodeCount))  // bt_node_count
}

// putRecord lays out one variable-size (key, value) pair in a catalog node:
// the key grows forward from the key area, the value backward from the value
// area, and a kvloc TOC entry records their offsets and lengths.
func (c *catCursor) putRecord(key, val []byte) {
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
