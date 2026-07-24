// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "encoding/binary"

// catCursor tracks the free positions inside a catalog leaf node while its
// records are laid out. Keys grow forward from keyArea; values grow backward
// from valAreaEnd. It corresponds to the running pointers passed around
// between dir.c's make_special_dir_* helpers.
type catCursor struct {
	b          *builder
	block      []byte
	tocOff     int // byte offset of the next kvloc entry
	keyArea    int // start of the key area
	keyOff     int // next free position in the key area
	valAreaEnd int // end of the value area
	valEnd     int // current end of the free value area
}

// setKeyHeader sets the cnid and type on a catalog key, mirroring
// dir.c:set_key_header. keyOff points at the apfs_key_header.
func setKeyHeader(block []byte, keyOff int, ino, typ uint64) {
	objIDAndType := (typ << objTypeShift) | ino
	binary.LittleEndian.PutUint64(block[keyOff:], objIDAndType)
}

// makeUnhashedDentryKey writes an unhashed dentry key, mirroring
// dir.c:make_unhashed_dentry_key. Returns the key length.
func makeUnhashedDentryKey(block []byte, keyOff int, ino uint64, name string) int {
	nameLen := len(name) + 1 // count the null termination
	setKeyHeader(block, keyOff, ino, typeDirRec)
	copy(block[keyOff+10:], name) // name[] after hdr(8)+name_len(2)
	block[keyOff+10+len(name)] = 0
	binary.LittleEndian.PutUint16(block[keyOff+8:], uint16(nameLen))
	return sizeofDrecKeyFixed + nameLen
}

// makeHashedDentryKey writes a hashed dentry key, mirroring
// dir.c:make_hashed_dentry_key. Returns the key length.
func makeHashedDentryKey(block []byte, keyOff int, ino uint64, name string) int {
	setKeyHeader(block, keyOff, ino, typeDirRec)
	copy(block[keyOff+12:], name) // name[] after hdr(8)+name_len_and_hash(4)
	block[keyOff+12+len(name)] = 0

	nameLen := uint32(len(name) + 1) // count the null termination

	// Special directories don't have unicode characters in their names, so the
	// UTF-32 code point of each ASCII byte is just its value.
	hash := uint32(0xFFFFFFFF)
	var buf [4]byte
	for _, c := range []byte(name) {
		binary.LittleEndian.PutUint32(buf[:], uint32(c))
		hash = crc32c(hash, buf[:])
	}
	hash = (hash & 0x3FFFFF) << 10

	binary.LittleEndian.PutUint32(block[keyOff+8:], hash|nameLen)
	return sizeofDrecHashedKeyFixed + int(nameLen)
}

// makeSpecialDentryKey writes the dentry key for a special directory.
func (c *catCursor) makeSpecialDentryKey(ino uint64, name string) int {
	if c.b.normSensitive {
		return makeUnhashedDentryKey(c.block, c.keyOff, ino, name)
	}
	return makeHashedDentryKey(c.block, c.keyOff, ino, name)
}

// makeSpecialDentryVal writes the dentry value for a special directory ending
// at valEnd, mirroring dir.c:make_special_dentry_val. Returns the value length.
func (c *catCursor) makeSpecialDentryVal(ino uint64) int {
	valOff := c.valEnd - sizeofDrecVal
	binary.LittleEndian.PutUint64(c.block[valOff:], ino)             // file_id
	binary.LittleEndian.PutUint64(c.block[valOff+8:], c.b.timestamp) // date_added
	binary.LittleEndian.PutUint16(c.block[valOff+16:], sIFDIR>>12)   // flags
	return sizeofDrecVal
}

// makeSpecialInodeKey writes the inode key for a special directory, mirroring
// dir.c:make_special_inode_key. Returns the key length.
func (c *catCursor) makeSpecialInodeKey(ino uint64) int {
	setKeyHeader(c.block, c.keyOff, ino, typeInode)
	return sizeofInodeKey
}

// makeSpecialInodeVal writes the inode value for a special directory ending at
// valEnd, mirroring dir.c:make_special_inode_val. Returns the value length.
func (c *catCursor) makeSpecialInodeVal(ino uint64, name string) int {
	nameLen := len(name) + 1
	paddedNameLen := int(roundUp(uint64(nameLen), 8))
	iLen := sizeofInodeVal + sizeofXfBlob + sizeofXField + paddedNameLen
	valOff := c.valEnd - iLen

	binary.LittleEndian.PutUint64(c.block[valOff+0:], rootDirParent) // parent_id
	binary.LittleEndian.PutUint64(c.block[valOff+8:], ino)           // private_id

	// create/mod/change/access all share the format timestamp.
	binary.LittleEndian.PutUint64(c.block[valOff+16:], c.b.timestamp) // create_time
	binary.LittleEndian.PutUint64(c.block[valOff+24:], c.b.timestamp) // mod_time
	binary.LittleEndian.PutUint64(c.block[valOff+32:], c.b.timestamp) // change_time
	binary.LittleEndian.PutUint64(c.block[valOff+40:], c.b.timestamp) // access_time

	// internal_flags (48): newer fsck_apfs expects APFS_INODE_NO_RSRC_FORK on
	// these special directory inodes. nchildren (56) left 0 (empty dir).
	binary.LittleEndian.PutUint64(c.block[valOff+48:], inodeNoRsrcFork)
	binary.LittleEndian.PutUint32(c.block[valOff+60:], protectionClassDirNone)

	// owner/group left as 0 (root) for cross-platform determinism.
	binary.LittleEndian.PutUint16(c.block[valOff+80:], 0o755|sIFDIR) // mode

	// xf_blob at xfields (offset 92).
	xblob := valOff + sizeofInodeVal
	binary.LittleEndian.PutUint16(c.block[xblob+0:], 1)                     // xf_num_exts
	binary.LittleEndian.PutUint16(c.block[xblob+2:], uint16(paddedNameLen)) // xf_used_data

	// x_field at xf_data (offset 96).
	xfield := xblob + sizeofXfBlob
	c.block[xfield+0] = inoExtTypeName                                 // x_type
	c.block[xfield+1] = xfDoNotCopy                                    // x_flags
	binary.LittleEndian.PutUint16(c.block[xfield+2:], uint16(nameLen)) // x_size

	// The name value goes at the very end of this record.
	copy(c.block[c.valEnd-paddedNameLen:], name)
	return iLen
}

// putKvloc writes an apfs_kvloc entry at c.tocOff.
func (c *catCursor) putKvloc(kOff, kLen, vOff, vLen uint16) {
	binary.LittleEndian.PutUint16(c.block[c.tocOff+0:], kOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+2:], kLen)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+4:], vOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+6:], vLen)
}

// makeSpecialDirDentry makes a dentry record for an empty special dir,
// mirroring dir.c:make_special_dir_dentry.
func (c *catCursor) makeSpecialDirDentry(ino uint64, name string) {
	kStart := c.keyOff
	kLen := c.makeSpecialDentryKey(rootDirParent, name)
	c.keyOff += kLen

	vLen := c.makeSpecialDentryVal(ino)
	vOff := c.valAreaEnd - c.valEnd + vLen
	c.valEnd -= vLen

	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
	c.tocOff += sizeofKvloc
}

// makeSpecialDirInode makes an inode record for an empty special dir, mirroring
// dir.c:make_special_dir_inode.
func (c *catCursor) makeSpecialDirInode(ino uint64, name string) {
	kStart := c.keyOff
	kLen := c.makeSpecialInodeKey(ino)
	c.keyOff += kLen

	vLen := c.makeSpecialInodeVal(ino, name)
	vOff := c.valAreaEnd - c.valEnd + vLen
	c.valEnd -= vLen

	c.putKvloc(uint16(kStart-c.keyArea), uint16(kLen), uint16(vOff), uint16(vLen))
	c.tocOff += sizeofKvloc
}
