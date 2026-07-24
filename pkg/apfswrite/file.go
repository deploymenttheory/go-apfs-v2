// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// setTree resolves the caller's directory tree (Root plus the RootFiles
// convenience) into a flat list of catalog entries with assigned cnids, then
// decides the catalog B-tree shape (single leaf vs a 2-level index+leaves
// tree). Physical block numbers are assigned later, in the space manager.
func (b *builder) setTree(opts *CreateOptions) error {
	// Build the effective root directory: Root's children plus any RootFiles.
	var topLevel []*Entry
	if opts.Root != nil {
		topLevel = append(topLevel, opts.Root.Children...)
	}
	for _, f := range opts.RootFiles {
		topLevel = append(topLevel, &Entry{Name: f.Name, Data: f.Data})
	}
	if len(topLevel) == 0 {
		return nil // empty volume
	}

	// Deterministic order: sort siblings by name at every level.
	nextCNID := uint64(minUserInoNum)
	var walk func(parent uint64, children []*Entry) (uint32, error)
	walk = func(parent uint64, children []*Entry) (uint32, error) {
		sorted := make([]*Entry, len(children))
		copy(sorted, children)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

		seen := make(map[string]bool, len(sorted))
		for _, e := range sorted {
			if err := validateName(e.Name); err != nil {
				return 0, err
			}
			if seen[e.Name] {
				return 0, fmt.Errorf("apfswrite: duplicate name %q in one directory", e.Name)
			}
			seen[e.Name] = true

			be := &builderEntry{
				name:   e.Name,
				isDir:  e.IsDir,
				cnid:   nextCNID,
				parent: parent,
			}
			nextCNID++
			b.entries = append(b.entries, be)

			if e.IsDir {
				n, err := walk(be.cnid, e.Children)
				if err != nil {
					return 0, err
				}
				be.nchildren = n
				b.numDirs++
			} else {
				// Every regular file carries a data stream (a DSTREAM xfield and a
				// DSTREAM_ID record), even a 0-byte one. A non-empty file also owns
				// a physical extent of ceil(size/blocksize) contiguous blocks; an
				// empty file has size 0, alloced_size 0 and no extent at all.
				be.data = e.Data
				be.hasStream = true
				be.blocks = divRoundUp(uint64(len(e.Data)), uint64(b.blocksize))
				be.allocedSize = be.blocks * uint64(b.blocksize)
				b.streamFiles = append(b.streamFiles, be)
				b.numFiles++
			}
		}
		return uint32(len(sorted)), nil
	}

	if _, err := walk(rootDirInoNum, topLevel); err != nil {
		return err
	}

	b.fileDataBlocks = 0
	for _, f := range b.streamFiles {
		b.fileDataBlocks += f.blocks
	}

	// Decide the catalog shape from the record sizes. Block numbers are not yet
	// known but do not affect record sizes, so the packing decided here matches
	// the one recomputed at write time.
	recs := b.buildCatRecords()
	leaves := packCatLeaves(recs, int(b.blocksize), sizeofBtreeInfo)
	if len(leaves) > 1 {
		b.catTwoLevel = true
		// Repack leaves without the root footer (only the index root carries it).
		leaves = packCatLeaves(recs, int(b.blocksize), 0)
		b.numCatLeaves = uint64(len(leaves))
		if b.numCatLeaves > maxCatLeaves {
			return fmt.Errorf("apfswrite: catalog needs %d leaf nodes; only a 2-level tree up to %d leaves is supported", b.numCatLeaves, maxCatLeaves)
		}
	}

	// Decide the extent-reference tree shape. One physical-extent record per file
	// that owns a physical extent (empty files own none). When they overflow a
	// single leaf the tree grows to two physical levels (an index root plus
	// leaves), the same way the catalog grows.
	nExtents := len(b.physFiles())
	if perLeaf := extrefRecordsPerLeaf(int(b.blocksize)); nExtents > perLeaf {
		b.extrefTwoLevel = true
		b.numExtrefLeaves = uint64(divRoundUp(uint64(nExtents), uint64(perLeaf)))
		if b.numExtrefLeaves > maxExtrefLeaves {
			return fmt.Errorf("apfswrite: extent-reference tree needs %d leaf nodes; only a 2-level tree up to %d leaves is supported", b.numExtrefLeaves, maxExtrefLeaves)
		}
	}
	return nil
}

// maxCatLeaves caps the 2-level catalog: L leaves need L index records in one
// root node and L omap entries in one omap leaf; both fit comfortably here.
const maxCatLeaves = 64

// maxExtrefLeaves caps the 2-level extent-reference tree: its L index records
// must fit in the single index root node.
const maxExtrefLeaves = 100

// physFiles returns the stream files that own a physical extent (blocks > 0),
// i.e. every regular file except the 0-byte ones.
func (b *builder) physFiles() []*builderEntry {
	out := make([]*builderEntry, 0, len(b.streamFiles))
	for _, f := range b.streamFiles {
		if f.blocks > 0 {
			out = append(out, f)
		}
	}
	return out
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("apfswrite: entry has an empty name")
	}
	if strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("apfswrite: name %q contains a path separator or NUL", name)
	}
	if len(name)+1 > int(drecLenMask) {
		return fmt.Errorf("apfswrite: name %q too long", name)
	}
	return nil
}

// hasFiles reports whether any user entries are being written.
func (b *builder) hasFiles() bool { return len(b.entries) > 0 }

// nextObjID returns the volume's next free object id: one past the highest user
// cnid in use (APFS_MIN_USER_INO_NUM when there are no entries).
func (b *builder) nextObjID() uint64 {
	next := uint64(minUserInoNum)
	for _, e := range b.entries {
		if e.cnid+1 > next {
			next = e.cnid + 1
		}
	}
	return next
}

// writeFileData writes each stream file's content into its data block,
// zero-padded to a full allocation block.
func (b *builder) writeFileData() error {
	for _, f := range b.streamFiles {
		if f.blocks == 0 {
			continue // 0-byte file: no data block
		}
		block := b.zeroedBlocks(int(f.blocks))
		copy(block, f.data)
		if err := b.writeBlocks(block, f.dataBlock); err != nil {
			return err
		}
	}
	return nil
}

// --- catalog record generation ---
//
// Each record is materialized as (key, value) byte slices plus the fields the
// catalog key comparator needs. buildCatRecords returns the whole catalog in
// globally sorted order.

type catRecord struct {
	id      uint64 // object id (low 60 bits of the key header)
	typ     uint8  // record type (APFS_TYPE_*)
	hash    uint32 // DIR_REC: name_len_and_hash, for ordering
	name    string // DIR_REC: name, for ordering tie-break
	logical uint64 // FILE_EXTENT: logical address, for ordering
	key     []byte
	val     []byte
}

// buildCatRecords generates every catalog record — the special root and
// private-dir records plus one dentry+inode (and, for files, dstream-id and
// file-extent) per user entry — and returns them sorted by the catalog key
// comparator.
func (b *builder) buildCatRecords() []catRecord {
	recs := make([]catRecord, 0, 4+4*len(b.entries))

	// Special directory dentries live under the virtual root parent (id 1).
	recs = append(recs, b.dentryRecord(rootDirParent, "root", rootDirInoNum, dtDir))
	recs = append(recs, b.dentryRecord(rootDirParent, "private-dir", privDirInoNum, dtDir))
	// Root inode (id 2): nchildren = number of top-level entries.
	recs = append(recs, b.inodeRecord(&builderEntry{
		name: "root", isDir: true, cnid: rootDirInoNum, parent: rootDirParent,
		nchildren: b.rootChildCount(),
	}))
	// Private-dir inode (id 3).
	recs = append(recs, b.inodeRecord(&builderEntry{
		name: "private-dir", isDir: true, cnid: privDirInoNum, parent: rootDirParent,
	}))

	for _, e := range b.entries {
		dt := dtDir
		if !e.isDir {
			dt = dtReg
		}
		recs = append(recs, b.dentryRecord(e.parent, e.name, e.cnid, uint16(dt)))
		recs = append(recs, b.inodeRecord(e))
		if e.hasStream {
			recs = append(recs, b.dstreamIDRecord(e))
			// A 0-byte file has a data stream but no physical extent, so no
			// file-extent record.
			if e.blocks > 0 {
				recs = append(recs, b.fileExtentRecord(e))
			}
		}
	}

	sort.SliceStable(recs, func(i, j int) bool { return catLess(recs[i], recs[j]) })
	return recs
}

// rootChildCount counts the direct children of the volume root (cnid 2).
func (b *builder) rootChildCount() uint32 {
	n := uint32(0)
	for _, e := range b.entries {
		if e.parent == rootDirInoNum {
			n++
		}
	}
	return n
}

// catLess is the catalog key comparator: object id ascending, then record type
// ascending, then the type-specific key (DIR_REC by name hash then name;
// FILE_EXTENT by logical address).
func catLess(a, b catRecord) bool {
	if a.id != b.id {
		return a.id < b.id
	}
	if a.typ != b.typ {
		return a.typ < b.typ
	}
	switch a.typ {
	case typeDirRec:
		if a.hash != b.hash {
			return a.hash < b.hash
		}
		return a.name < b.name
	case typeFileExtent:
		return a.logical < b.logical
	}
	return false
}

// dentryRecord builds a hashed dentry record: key (parent, DIR_REC, hash(name)),
// value j_drec_hashed_val pointing at childID with directory-entry type dt.
func (b *builder) dentryRecord(parent uint64, name string, childID uint64, dt uint16) catRecord {
	key, hash := buildHashedDrecKey(parent, name)
	val := make([]byte, sizeofDrecVal)
	binary.LittleEndian.PutUint64(val[0:], childID)     // file_id
	binary.LittleEndian.PutUint64(val[8:], b.timestamp) // date_added
	binary.LittleEndian.PutUint16(val[16:], dt)         // flags (dir-entry type)
	return catRecord{id: parent, typ: typeDirRec, hash: hash, name: name, key: key, val: val}
}

// inodeRecord builds an inode record: key (cnid, INODE), value j_inode_val with
// a NAME xfield and, for stream files, a DSTREAM xfield.
func (b *builder) inodeRecord(e *builderEntry) catRecord {
	key := make([]byte, sizeofInodeKey)
	setKeyHeader(key, 0, e.cnid, typeInode)
	val := b.inodeValue(e)
	return catRecord{id: e.cnid, typ: typeInode, key: key, val: val}
}

// inodeValue serializes a j_inode_val for a directory or regular file.
func (b *builder) inodeValue(e *builderEntry) []byte {
	nameLen := len(e.name) + 1
	paddedNameLen := int(roundUp(uint64(nameLen), 8))

	numXF := 1
	extra := paddedNameLen
	if e.hasStream {
		numXF = 2
		extra += sizeofDstream
	}
	valLen := sizeofInodeVal + sizeofXfBlob + numXF*sizeofXField + extra
	val := make([]byte, valLen)

	binary.LittleEndian.PutUint64(val[0:], e.parent) // parent_id
	binary.LittleEndian.PutUint64(val[8:], e.cnid)   // private_id

	binary.LittleEndian.PutUint64(val[16:], b.timestamp) // create_time
	binary.LittleEndian.PutUint64(val[24:], b.timestamp) // mod_time
	binary.LittleEndian.PutUint64(val[32:], b.timestamp) // change_time
	binary.LittleEndian.PutUint64(val[40:], b.timestamp) // access_time

	binary.LittleEndian.PutUint64(val[48:], inodeNoRsrcFork) // internal_flags

	if e.isDir {
		binary.LittleEndian.PutUint32(val[56:], e.nchildren)            // nchildren
		binary.LittleEndian.PutUint32(val[60:], protectionClassDirNone) // default_protection_class
		binary.LittleEndian.PutUint16(val[80:], 0o755|sIFDIR)           // mode
	} else {
		binary.LittleEndian.PutUint32(val[56:], 1)            // nlink
		binary.LittleEndian.PutUint16(val[80:], sIFREG|0o644) // mode
	}

	// xf_blob header.
	xblob := sizeofInodeVal
	binary.LittleEndian.PutUint16(val[xblob:], uint16(numXF))   // xf_num_exts
	binary.LittleEndian.PutUint16(val[xblob+2:], uint16(extra)) // xf_used_data

	// x_field[0]: NAME.
	xf0 := xblob + sizeofXfBlob
	val[xf0+0] = inoExtTypeName
	val[xf0+1] = xfDoNotCopy
	binary.LittleEndian.PutUint16(val[xf0+2:], uint16(nameLen))

	if e.hasStream {
		// x_field[1]: DSTREAM.
		xf1 := xf0 + sizeofXField
		val[xf1+0] = inoExtTypeDstream
		val[xf1+1] = xfSystemField
		binary.LittleEndian.PutUint16(val[xf1+2:], uint16(sizeofDstream))

		nameVal := xf1 + sizeofXField
		copy(val[nameVal:], e.name)
		dsVal := nameVal + paddedNameLen
		binary.LittleEndian.PutUint64(val[dsVal+0:], uint64(len(e.data))) // size
		binary.LittleEndian.PutUint64(val[dsVal+8:], e.allocedSize)       // alloced_size
		// default_crypto_id (16) = 0 on an unencrypted volume.
		binary.LittleEndian.PutUint64(val[dsVal+24:], uint64(len(e.data))) // total_bytes_written
	} else {
		nameVal := xf0 + sizeofXField
		copy(val[nameVal:], e.name)
	}
	return val
}

// dstreamIDRecord builds the data-stream id record: key (cnid, DSTREAM_ID),
// value j_dstream_id_val (refcnt).
func (b *builder) dstreamIDRecord(e *builderEntry) catRecord {
	key := make([]byte, sizeofInodeKey)
	setKeyHeader(key, 0, e.cnid, typeDstreamID)
	val := make([]byte, sizeofDstreamIDVal)
	binary.LittleEndian.PutUint32(val[0:], 1) // refcnt = 1
	return catRecord{id: e.cnid, typ: typeDstreamID, key: key, val: val}
}

// fileExtentRecord builds the file-extent record mapping logical offset 0 to
// the file's physical data block: key (cnid, FILE_EXTENT, 0), value
// j_file_extent_val.
func (b *builder) fileExtentRecord(e *builderEntry) catRecord {
	key := make([]byte, sizeofFileExtentKey)
	setKeyHeader(key, 0, e.cnid, typeFileExtent)
	binary.LittleEndian.PutUint64(key[8:], 0) // logical_addr = 0
	val := make([]byte, sizeofFileExtentVal)
	binary.LittleEndian.PutUint64(val[0:], e.allocedSize) // len_and_flags (block-aligned length)
	binary.LittleEndian.PutUint64(val[8:], e.dataBlock)   // phys_block_num
	// crypto_id (16) = 0.
	return catRecord{id: e.cnid, typ: typeFileExtent, logical: 0, key: key, val: val}
}

// buildHashedDrecKey builds a hashed dentry key and returns the key bytes and
// the name_len_and_hash field used for ordering. Mirrors makeHashedDentryKey.
func buildHashedDrecKey(parent uint64, name string) ([]byte, uint32) {
	nameLen := uint32(len(name) + 1)
	key := make([]byte, sizeofDrecHashedKeyFixed+int(nameLen))
	setKeyHeader(key, 0, parent, typeDirRec)
	copy(key[12:], name)
	// key[12+len(name)] = 0 already (zeroed).

	hash := uint32(0xFFFFFFFF)
	var buf [4]byte
	for _, c := range []byte(name) {
		binary.LittleEndian.PutUint32(buf[:], uint32(c))
		hash = crc32c(hash, buf[:])
	}
	hash = (hash & 0x3FFFFF) << 10
	nameLenAndHash := hash | nameLen
	binary.LittleEndian.PutUint32(key[8:], nameLenAndHash)
	return key, nameLenAndHash
}

// packCatLeaves greedily packs sorted records into leaf nodes of blocksize,
// reserving footer bytes at the end of each node (sizeofBtreeInfo for a node
// that also serves as the tree root, 0 for a plain leaf). Each record costs its
// key + value bytes plus one kvloc table entry.
func packCatLeaves(recs []catRecord, blocksize, footer int) [][]catRecord {
	var leaves [][]catRecord
	var cur []catRecord
	keys, vals := 0, 0

	flush := func() {
		if len(cur) > 0 {
			leaves = append(leaves, cur)
			cur, keys, vals = nil, 0, 0
		}
	}

	for _, r := range recs {
		n := len(cur) + 1
		toc := tocBytesFor(n)
		used := sizeofBtreeNodePhys + toc + keys + len(r.key) + vals + len(r.val) + footer
		if used > blocksize && len(cur) > 0 {
			flush()
		}
		cur = append(cur, r)
		keys += len(r.key)
		vals += len(r.val)
	}
	flush()
	return leaves
}

// tocBytesFor returns the table-of-contents size (bytes) for a node holding
// nkeys records: room for nkeys kvloc entries, rounded up to whole increments
// of btreeTOCEntryIncrement, never below btreeTOCEntryMaxUnused entries. This
// matches btree.c's minimum-table-size behaviour for small nodes.
func tocBytesFor(nkeys int) int {
	entries := roundUpInt(nkeys, btreeTOCEntryIncrement)
	if entries < btreeTOCEntryMaxUnused {
		entries = btreeTOCEntryMaxUnused
	}
	return entries * sizeofKvloc
}

func roundUpInt(x, y int) int {
	if x <= 0 {
		return 0
	}
	return ((x + y - 1) / y) * y
}

// extrefRecordsPerLeaf returns how many physical-extent records fit in one
// plain (non-root) blockref leaf of blocksize bytes.
func extrefRecordsPerLeaf(blocksize int) int {
	n := 0
	for {
		used := sizeofBtreeNodePhys + tocBytesFor(n+1) + (n+1)*(sizeofPhysExtKey+sizeofPhysExtVal)
		if used > blocksize {
			break
		}
		n++
	}
	return n
}

// makeExtrefRoot builds the volume's extent-reference (blockref) tree. Each
// file that owns a physical extent contributes one record: key (phys_block,
// EXTENT), value j_phys_ext_val (len_and_kind = KIND_NEW|blocks, owning_obj_id
// = file cnid, refcnt = 1). Records sort by physical block address, which our
// contiguous layout already produces in stream-file order. When they fit in one
// node the tree is a single root-leaf; when they overflow it grows to two
// physical levels: an index root plus one leaf per group of records. All nodes
// are physical objects whose oid equals their block number.
func (b *builder) makeExtrefRoot(bno, oid uint64) error {
	phys := b.physFiles()
	if len(phys) == 0 {
		return b.makeEmptyBtreeRoot(bno, oid, objectTypeBlockrefTree)
	}

	extents := make([]*builderEntry, len(phys))
	copy(extents, phys)
	sort.Slice(extents, func(i, j int) bool { return extents[i].dataBlock < extents[j].dataBlock })

	if !b.extrefTwoLevel {
		return b.writeExtrefNode(bno, extents, true /* root */, 0 /* level */, 1 /* nodeCount */)
	}

	// Two levels: split the records into leaves, then build an index root whose
	// records map each leaf's first key to that leaf's physical block number.
	perLeaf := extrefRecordsPerLeaf(int(b.blocksize))
	idx := make([]catRecord, 0, b.numExtrefLeaves)
	for i := 0; i < len(extents); i += perLeaf {
		end := i + perLeaf
		if end > len(extents) {
			end = len(extents)
		}
		leaf := extents[i:end]
		leafBno := b.extrefLeafBase + uint64(i/perLeaf)
		if err := b.writeExtrefNode(leafBno, leaf, false /* leaf */, 0 /* level */, 0); err != nil {
			return err
		}
		key := make([]byte, sizeofPhysExtKey)
		setKeyHeader(key, 0, leaf[0].dataBlock, typeExtent)
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, leafBno)
		idx = append(idx, catRecord{key: key, val: val})
	}
	nodeCount := 1 + len(idx)
	return b.writeExtrefIndex(bno, idx, len(extents), nodeCount)
}

// writeExtrefNode writes one blockref leaf holding the given physical extents.
// isRoot marks a single-node tree, which carries the btree_info footer.
func (b *builder) writeExtrefNode(bno uint64, extents []*builderEntry, isRoot bool, level uint16, nodeCount int) error {
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

	nkeys := len(extents)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(nkeys))
	tocLen := tocBytesFor(nkeys)
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
	for _, f := range extents {
		key := make([]byte, sizeofPhysExtKey)
		setKeyHeader(key, 0, f.dataBlock, typeExtent)
		val := make([]byte, sizeofPhysExtVal)
		lenAndKind := (uint64(pextKindNew) << pextKindShift) | f.blocks
		binary.LittleEndian.PutUint64(val[0:], lenAndKind)
		binary.LittleEndian.PutUint64(val[8:], f.cnid) // owning_obj_id
		binary.LittleEndian.PutUint32(val[16:], 1)     // refcnt
		cur.putRecord(key, val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	objType := uint32(objectTypeBtreeNode) | objPhysical
	if isRoot {
		objType = objectTypeBtree | objPhysical
		b.setExtrefInfo(block[int(b.blocksize)-infoLen:], nkeys, nodeCount)
	}
	setObjectHeader(block, int(b.blocksize), bno, objType, objectTypeBlockrefTree)
	return b.writeBlock(block, bno)
}

// writeExtrefIndex writes the blockref index root (level 1). Each record maps a
// child leaf's first key (phys_block, EXTENT) to that leaf's physical block
// number (an 8-byte value). Being a physical tree, child pointers are block
// numbers resolved directly, without an object map.
func (b *builder) writeExtrefIndex(bno uint64, idx []catRecord, keyCount, nodeCount int) error {
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

	b.setExtrefInfo(block[int(b.blocksize)-infoLen:], keyCount, nodeCount)
	setObjectHeader(block, int(b.blocksize), bno,
		objectTypeBtree|objPhysical, objectTypeBlockrefTree)
	return b.writeBlock(block, bno)
}

// setExtrefInfo sets the info footer for a populated blockref-tree root.
func (b *builder) setExtrefInfo(info []byte, keyCount, nodeCount int) {
	binary.LittleEndian.PutUint32(info[0:], btreePhysical|btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)                     // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], sizeofPhysExtKey)               // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], sizeofPhysExtVal)               // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(keyCount))               // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], uint64(nodeCount))              // bt_node_count
}
