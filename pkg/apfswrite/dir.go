// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "encoding/binary"

// catCursor tracks the free positions inside a B-tree leaf/index node while its
// records are laid out. Keys grow forward from keyArea; values grow backward
// from valAreaEnd. It corresponds to the running pointers passed around between
// btree.c's node-building helpers.
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

// putKvloc writes an apfs_kvloc entry at c.tocOff.
func (c *catCursor) putKvloc(kOff, kLen, vOff, vLen uint16) {
	binary.LittleEndian.PutUint16(c.block[c.tocOff+0:], kOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+2:], kLen)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+4:], vOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+6:], vLen)
}
