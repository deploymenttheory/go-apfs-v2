// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import (
	"encoding/binary"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// Offsets within an apfs_obj_phys header.
const (
	objOffCksum   = 0
	objOffOID     = 8
	objOffXID     = 16
	objOffType    = 24
	objOffSubtype = 28
)

// setObjectHeader sets the header for a filesystem object and computes its
// Fletcher-64 checksum. It mirrors mkapfs object.c:set_object_header. All other
// fields of the object must already be set by the caller, otherwise the
// checksum will not be correct.
//
// block is the full object buffer; size is the object size in bytes (the block
// size for single-block objects, or the total size for the space manager).
func setObjectHeader(block []byte, size int, oid uint64, typ, subtype uint32) {
	binary.LittleEndian.PutUint64(block[objOffOID:], oid)
	binary.LittleEndian.PutUint64(block[objOffXID:], mkfsXID)
	binary.LittleEndian.PutUint32(block[objOffType:], typ)
	binary.LittleEndian.PutUint32(block[objOffSubtype:], subtype)

	// Fletcher-64 over everything after the 8-byte checksum field. Reuse the
	// MIT pkg/apfs implementation as required by the port's licensing note.
	cksum, err := apfs.CalculateFletcher64(block[objOffCksum+8:size], 0)
	if err != nil {
		// The only error paths are a nil buffer or a non-multiple-of-4 length;
		// neither can happen here because object sizes are block-size multiples.
		panic("apfswrite: fletcher64: " + err.Error())
	}
	binary.LittleEndian.PutUint64(block[objOffCksum:], cksum)
}

// crc32c computes the CRC-32C (Castagnoli) checksum used for hashed directory
// entry keys, mirroring apfsprogs lib/checksum.c:crc32c. It reuses the MIT
// pkg/apfs table-driven implementation.
func crc32c(crc uint32, buf []byte) uint32 {
	out, err := apfs.CalculateWeakCRC32(buf, crc)
	if err != nil {
		panic("apfswrite: crc32c: " + err.Error())
	}
	return out
}
