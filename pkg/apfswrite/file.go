// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// setFiles validates the caller's RootFiles and resolves them into builderFile
// entries. Milestone 1 supports at most one non-empty file that fits in a
// single allocation block; anything else is rejected with a clear error so the
// (still-supported) empty-container path stays unchanged.
func (b *builder) setFiles(files []RootFile) error {
	if len(files) == 0 {
		return nil
	}
	if len(files) > 1 {
		return fmt.Errorf("apfswrite: milestone 1 supports at most one root file, got %d", len(files))
	}

	f := files[0]
	if f.Name == "" {
		return fmt.Errorf("apfswrite: root file has empty name")
	}
	if strings.ContainsAny(f.Name, "/\x00") {
		return fmt.Errorf("apfswrite: root file name %q contains a path separator or NUL", f.Name)
	}
	// The name plus its null terminator must fit the catalog key limit.
	if len(f.Name)+1 > int(drecLenMask) {
		return fmt.Errorf("apfswrite: root file name too long")
	}
	if len(f.Data) == 0 {
		return fmt.Errorf("apfswrite: milestone 1 requires non-empty file content")
	}
	if uint64(len(f.Data)) > uint64(b.blocksize) {
		return fmt.Errorf("apfswrite: milestone 1 supports files up to one block (%d bytes), got %d", b.blocksize, len(f.Data))
	}

	bf := &builderFile{
		name:        f.Name,
		data:        f.Data,
		cnid:        minUserInoNum,
		blocks:      1,
		allocedSize: uint64(b.blocksize),
	}
	b.files = append(b.files, bf)
	b.fileDataBlocks += bf.blocks
	return nil
}

// hasFiles reports whether any user files are being written.
func (b *builder) hasFiles() bool { return len(b.files) > 0 }

// nextObjID returns the volume's next free object id: one past the highest
// user cnid in use (APFS_MIN_USER_INO_NUM when there are no files).
func (b *builder) nextObjID() uint64 {
	next := uint64(minUserInoNum)
	for _, f := range b.files {
		if f.cnid+1 > next {
			next = f.cnid + 1
		}
	}
	return next
}

// writeFileData writes each file's content into its data block, zero-padded to
// a full allocation block.
func (b *builder) writeFileData() error {
	for _, f := range b.files {
		block := b.zeroedBlocks(int(f.blocks))
		copy(block, f.data)
		if err := b.writeBlocks(block, f.dataBlock); err != nil {
			return err
		}
	}
	return nil
}

// --- catalog record builders for regular files ---
//
// These extend dir.go's catCursor. Records must be appended in ascending key
// order (obj-id, then type, then the type-specific key), matching the order
// makeCatRoot calls them in.

// makeFileDentry writes a hashed dentry record for a regular file: key
// (parentIno, DIR_REC, hash(name)), value j_drec_hashed_val pointing at the
// file's cnid with directory-entry type DT_REG.
func (c *catCursor) makeFileDentry(parentIno uint64, f *builderFile) {
	kStart := c.keyOff
	kLen := makeHashedDentryKey(c.block, c.keyOff, parentIno, f.name)
	c.keyOff += kLen

	valOff := c.valEnd - sizeofDrecVal
	binary.LittleEndian.PutUint64(c.block[valOff:], f.cnid)          // file_id
	binary.LittleEndian.PutUint64(c.block[valOff+8:], c.b.timestamp) // date_added
	binary.LittleEndian.PutUint16(c.block[valOff+16:], dtReg)        // flags (dir-entry type)
	vLen := sizeofDrecVal
	vOff := c.valAreaEnd - c.valEnd + vLen
	c.valEnd -= vLen

	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
	c.tocOff += sizeofKvloc
}

// makeFileInode writes the inode record for a regular file: key (cnid, INODE),
// value j_inode_val with an INO_EXT_TYPE_NAME xfield (the filename) and an
// INO_EXT_TYPE_DSTREAM xfield (the j_dstream describing the file's content).
func (c *catCursor) makeFileInode(parentIno uint64, f *builderFile) {
	kStart := c.keyOff
	setKeyHeader(c.block, c.keyOff, f.cnid, typeInode)
	kLen := sizeofInodeKey
	c.keyOff += kLen

	nameLen := len(f.name) + 1 // includes null terminator
	paddedNameLen := int(roundUp(uint64(nameLen), 8))
	// value = inode_val + xf_blob + 2*x_field + name(padded) + dstream(40)
	iLen := sizeofInodeVal + sizeofXfBlob + 2*sizeofXField + paddedNameLen + sizeofDstream
	valOff := c.valEnd - iLen

	binary.LittleEndian.PutUint64(c.block[valOff+0:], parentIno) // parent_id
	binary.LittleEndian.PutUint64(c.block[valOff+8:], f.cnid)    // private_id == dstream id

	binary.LittleEndian.PutUint64(c.block[valOff+16:], c.b.timestamp) // create_time
	binary.LittleEndian.PutUint64(c.block[valOff+24:], c.b.timestamp) // mod_time
	binary.LittleEndian.PutUint64(c.block[valOff+32:], c.b.timestamp) // change_time
	binary.LittleEndian.PutUint64(c.block[valOff+40:], c.b.timestamp) // access_time

	// internal_flags (48): mirror the special inodes' NO_RSRC_FORK marker. The
	// file has no resource-fork xattr, so this is consistent.
	binary.LittleEndian.PutUint64(c.block[valOff+48:], inodeNoRsrcFork)
	binary.LittleEndian.PutUint32(c.block[valOff+56:], 1) // nlink = 1
	// default_protection_class (60), write_gen (64), bsd_flags (68) = 0.
	// owner/group (72,76) = 0 (root) for cross-platform determinism.
	binary.LittleEndian.PutUint16(c.block[valOff+80:], sIFREG|0o644) // mode
	// pad1 (82) and uncompressed_size (84) stay 0.

	// xf_blob at offset 92 (sizeofInodeVal).
	xblob := valOff + sizeofInodeVal
	usedData := paddedNameLen + sizeofDstream
	binary.LittleEndian.PutUint16(c.block[xblob+0:], 2)                // xf_num_exts
	binary.LittleEndian.PutUint16(c.block[xblob+2:], uint16(usedData)) // xf_used_data

	// x_field[0]: NAME (must carry DO_NOT_COPY).
	xf0 := xblob + sizeofXfBlob
	c.block[xf0+0] = inoExtTypeName
	c.block[xf0+1] = xfDoNotCopy
	binary.LittleEndian.PutUint16(c.block[xf0+2:], uint16(nameLen))
	// x_field[1]: DSTREAM (must carry SYSTEM_FIELD).
	xf1 := xf0 + sizeofXField
	c.block[xf1+0] = inoExtTypeDstream
	c.block[xf1+1] = xfSystemField
	binary.LittleEndian.PutUint16(c.block[xf1+2:], uint16(sizeofDstream))

	// Values follow the x_field array, in the same order, each 8-byte padded.
	nameVal := xf1 + sizeofXField
	copy(c.block[nameVal:], f.name) // trailing bytes already zero (padding)
	dsVal := nameVal + paddedNameLen
	binary.LittleEndian.PutUint64(c.block[dsVal+0:], uint64(len(f.data))) // size
	binary.LittleEndian.PutUint64(c.block[dsVal+8:], f.allocedSize)       // alloced_size
	// default_crypto_id (16): 0 on an unencrypted volume. fsck_apfs rejects
	// APFS_CRYPTO_SW_ID here when apfs_fs_flags has APFS_FS_UNENCRYPTED set.
	binary.LittleEndian.PutUint64(c.block[dsVal+16:], 0)
	binary.LittleEndian.PutUint64(c.block[dsVal+24:], uint64(len(f.data))) // total_bytes_written
	// total_bytes_read (32) = 0.

	vOff := c.valAreaEnd - c.valEnd + iLen
	c.valEnd -= iLen
	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(iLen))
	c.tocOff += sizeofKvloc
}

// makeDstreamID writes the data-stream id record: key (cnid, DSTREAM_ID),
// value j_dstream_id_val (refcnt). fsck requires this to accompany a file's
// data stream (its absence is reported as a missing reference count).
func (c *catCursor) makeDstreamID(f *builderFile) {
	kStart := c.keyOff
	setKeyHeader(c.block, c.keyOff, f.cnid, typeDstreamID)
	kLen := sizeofInodeKey // bare key header, 8 bytes
	c.keyOff += kLen

	valOff := c.valEnd - sizeofDstreamIDVal
	binary.LittleEndian.PutUint32(c.block[valOff:], 1) // refcnt = 1
	vLen := sizeofDstreamIDVal
	vOff := c.valAreaEnd - c.valEnd + vLen
	c.valEnd -= vLen

	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
	c.tocOff += sizeofKvloc
}

// makeFileExtent writes the file-extent record mapping logical offset 0 to the
// file's physical data block: key (cnid, FILE_EXTENT, 0), value
// j_file_extent_val (block-aligned length, physical block, crypto id 0).
func (c *catCursor) makeFileExtent(f *builderFile) {
	kStart := c.keyOff
	setKeyHeader(c.block, c.keyOff, f.cnid, typeFileExtent)
	binary.LittleEndian.PutUint64(c.block[c.keyOff+8:], 0) // logical_addr = 0
	kLen := sizeofFileExtentKey
	c.keyOff += kLen

	valOff := c.valEnd - sizeofFileExtentVal
	// len_and_flags: block-aligned length in the low 56 bits, no flags.
	binary.LittleEndian.PutUint64(c.block[valOff+0:], f.allocedSize)
	binary.LittleEndian.PutUint64(c.block[valOff+8:], f.dataBlock) // phys_block_num
	// crypto_id (16) = 0.
	vLen := sizeofFileExtentVal
	vOff := c.valAreaEnd - c.valEnd + vLen
	c.valEnd -= vLen

	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
	c.tocOff += sizeofKvloc
}

// makeExtrefRoot builds the volume's extent-reference (blockref) tree root. It
// mirrors make_empty_btree_root but populates one physical-extent record per
// file data extent: key (phys_block, EXTENT), value j_phys_ext_val
// (len_and_kind = KIND_NEW|blocks, owning_obj_id = file cnid, refcnt = 1).
func (b *builder) makeExtrefRoot(bno, oid uint64) error {
	if !b.hasFiles() {
		return b.makeEmptyBtreeRoot(bno, oid, objectTypeBlockrefTree)
	}

	root := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(root[btnOffFlags:], btnodeRoot|btnodeLeaf)

	nkeys := len(b.files)
	binary.LittleEndian.PutUint32(root[btnOffNkeys:], uint32(nkeys))
	tocLen := b.minTableSize(objectTypeBlockrefTree)
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

	// Records are sorted by physical block number, which our contiguous
	// layout already guarantees in file order.
	for _, f := range b.files {
		kStart := cur.keyOff
		setKeyHeader(cur.block, cur.keyOff, f.dataBlock, typeExtent)
		kLen := sizeofPhysExtKey
		cur.keyOff += kLen

		valOff := cur.valEnd - sizeofPhysExtVal
		lenAndKind := (uint64(pextKindNew) << pextKindShift) | f.blocks
		binary.LittleEndian.PutUint64(cur.block[valOff+0:], lenAndKind)
		binary.LittleEndian.PutUint64(cur.block[valOff+8:], f.cnid) // owning_obj_id
		binary.LittleEndian.PutUint32(cur.block[valOff+16:], 1)     // refcnt
		vLen := sizeofPhysExtVal
		vOff := cur.valAreaEnd - cur.valEnd + vLen
		cur.valEnd -= vLen

		cur.putKvloc(uint16(kStart-cur.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
		cur.tocOff += sizeofKvloc
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(root, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(root, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(root, btnOffValFreeList, btoffInvalid, 0)

	b.setExtrefInfo(root[int(b.blocksize)-infoLen:], nkeys)
	setObjectHeader(root, int(b.blocksize), oid,
		objectTypeBtree|objPhysical, objectTypeBlockrefTree)
	return b.writeBlock(root, bno)
}

// setExtrefInfo sets the info footer for a populated blockref-tree root.
func (b *builder) setExtrefInfo(info []byte, nkeys int) {
	binary.LittleEndian.PutUint32(info[0:], btreePhysical|btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)                     // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], sizeofPhysExtKey)               // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], sizeofPhysExtVal)               // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(nkeys))                  // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)                              // bt_node_count
}
