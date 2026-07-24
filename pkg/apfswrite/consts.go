// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

// Package apfswrite is a pure-Go port of mkapfs (apfsprogs). It writes a
// complete, empty, single-volume APFS container — the equivalent of
// newfs_apfs formatting a fresh volume with just the root directory and the
// standard special inodes, no user files.
//
// This package is GPL-2.0-only (see LICENSE in this directory). It is a direct
// translation of mkapfs, and a translation is a derivative work. It MAY import
// the MIT-licensed pkg/apfs (for the Fletcher-64 / CRC32C checksums); the MIT
// packages MUST NOT import this one.
package apfswrite

// On-disk constants, mirrored from apfsprogs include/apfs/raw.h.

// Object identifier constants.
const (
	oidNXSuperblock  = 1
	oidReservedCount = 1024
)

// Object type masks and flags.
const (
	objStoragetypeMask = 0xc0000000

	objVirtual   = 0x00000000
	objEphemeral = 0x80000000
	objPhysical  = 0x40000000
)

// Object types.
const (
	objectTypeNXSuperblock      = 0x00000001
	objectTypeBtree             = 0x00000002
	objectTypeBtreeNode         = 0x00000003
	objectTypeSpaceman          = 0x00000005
	objectTypeSpacemanCAB       = 0x00000006
	objectTypeSpacemanCIB       = 0x00000007
	objectTypeSpacemanBitmap    = 0x00000008
	objectTypeSpacemanFreeQueue = 0x00000009
	objectTypeOmap              = 0x0000000b
	objectTypeCheckpointMap     = 0x0000000c
	objectTypeFS                = 0x0000000d
	objectTypeFSTree            = 0x0000000e
	objectTypeBlockrefTree      = 0x0000000f
	objectTypeSnapMetaTree      = 0x00000010
	objectTypeNXReaper          = 0x00000011
	objectTypeFusionMiddleTree  = 0x00000015
	objectTypeNXFusionWBC       = 0x00000016
	objectTypeInvalid           = 0x00000000
)

// Fixed transaction id used by the mkfs.
const mkfsXID = 1

// B-tree node flags.
const (
	btnodeRoot        = 0x0001
	btnodeLeaf        = 0x0002
	btnodeFixedKVSize = 0x0004
)

// B-tree location constant.
const btoffInvalid = 0xffff

// B-tree info flags.
const (
	btreeAllowGhosts  = 0x00000004
	btreeEphemeral    = 0x00000008
	btreePhysical     = 0x00000010
	btreeKVNonaligned = 0x00000040
)

// Object map flags.
const omapManuallyManaged = 0x00000001

// Inode numbers for special inodes.
const (
	rootDirParent = 1
	rootDirInoNum = 2
	privDirInoNum = 3
	minUserInoNum = 16
)

// Catalog record types (APFS_TYPE_*).
const (
	typeExtent     = 2
	typeInode      = 3
	typeDstreamID  = 6
	typeFileExtent = 8
	typeDirRec     = 9
)

// Key header field shift.
const objTypeShift = 60

// Directory entry name/hash masks.
const drecLenMask = 0x000003ff

// Inode internal flag: no resource fork (newer fsck_apfs expects this on the
// special directory inodes created by the mkfs).
const inodeNoRsrcFork = 0x00008000

// Extended field types for inodes.
const (
	inoExtTypeName    = 4
	inoExtTypeDstream = 8
)

// Extended field flags.
const (
	xfDoNotCopy   = 0x02
	xfSystemField = 0x20
)

// S_IFREG from <sys/stat.h>, used for regular-file mode bits.
const sIFREG = 0o100000

// Directory entry type (drec val flags & APFS_DREC_TYPE_MASK) for a regular
// file: the file-type nibble of the mode. DT_REG == S_IFREG >> 12.
const dtReg = sIFREG >> 12

// Physical-extent record kinds and the shift of the kind field within
// len_and_kind (APFS_PEXT_KIND_*, APFS_PEXT_KIND_SHIFT).
const (
	pextKindNew   = 1
	pextKindShift = 60
)

// Constant for extended fields.
const minDocID = 3

// Container constants.
const (
	nxMagic          = 0x4253584e
	nxBlockNum       = 0
	nxMaxFileSystems = 100

	nxEphMinBlockCount        = 8
	nxMaxFileSystemEphStructs = 4
	nxEphInfoVersion1         = 1

	nxDefaultBlockSize = 4096
	nxMinimumBlockSize = 4096
	nxMaximumBlockSize = 65536
)

// Container incompatible feature flags.
const (
	nxIncompatVersion2 = 0x0000000000000002
	nxIncompatFusion   = 0x0000000000000100
)

// Checkpoint flags.
const checkpointMapLast = 0x00000001

// Volume constants.
const (
	apfsMagic  = 0x42535041
	volnameLen = 256
)

// Volume feature / flag constants.
const (
	featureHardlinkMapRecords = 0x00000002

	fsUnencrypted = 0x00000001

	incompatCaseInsensitive          = 0x00000001
	incompatNormalizationInsensitive = 0x00000008
)

// Wrapped meta crypto state versions and protection classes.
const (
	wmcsMajorVersion = 5
	wmcsMinorVersion = 0

	protectionClassDirNone = 0
	protectionClassF       = 6
)

// Reaper flags.
const nrBHMFlag = 0x00000001

// Space manager device and free-queue array indexes.
const (
	sdMain  = 0
	sdTier2 = 1
	sdCount = 2

	sfqIP    = 0
	sfqMain  = 1
	sfqTier2 = 2
	sfqCount = 3
)

// Internal-pool bitmap constants.
const (
	spacemanIPBMTxMultiplier = 16
	spacemanIPBMIndexInvalid = 0xffff
)

// Sizes of on-disk structures (bytes), matching the __packed C layouts.
const (
	sizeofObjPhys              = 32
	sizeofBtreeNodePhys        = 56 // obj(32)+flags(2)+level(2)+nkeys(4)+4*nloc(16)
	sizeofBtreeInfo            = 40
	sizeofKvloc                = 8
	sizeofKvoff                = 4
	sizeofOmapKey              = 16
	sizeofOmapVal              = 16
	sizeofCheckpointMapping    = 40
	sizeofChunkInfo            = 32
	sizeofChunkInfoBlockHdr    = 40 // obj(32)+cib_index(4)+cib_chunk_info_count(4)
	sizeofCibAddrBlockHdr      = 40 // obj(32)+cab_index(4)+cab_cib_count(4)
	sizeofSpacemanFreeQueueKey = 16
	sizeofFusionMtKey          = 8
	sizeofFusionMtVal          = 16
	sizeofNXReaperPhys         = 112
	sizeofDrecVal              = 18 // file_id(8)+date_added(8)+flags(2)
	sizeofInodeVal             = 92 // ends at 0x5C (xfields)
	sizeofXfBlob               = 4
	sizeofXField               = 4
	sizeofInodeKey             = 8
	sizeofDrecKeyFixed         = 10 // hdr(8)+name_len(2)
	sizeofDrecHashedKeyFixed   = 12 // hdr(8)+name_len_and_hash(4)

	sizeofDstream       = 40 // size(8)+alloced_size(8)+default_crypto_id(8)+total_bytes_written(8)+total_bytes_read(8)
	sizeofDstreamIDVal  = 4  // refcnt(4)
	sizeofFileExtentKey = 16 // hdr(8)+logical_addr(8)
	sizeofFileExtentVal = 24 // len_and_flags(8)+phys_block_num(8)+crypto_id(8)
	sizeofPhysExtKey    = 8  // hdr(8)
	sizeofPhysExtVal    = 20 // len_and_kind(8)+owning_obj_id(8)+refcnt(4)
)

// S_IFDIR from <sys/stat.h>, used for directory mode bits.
const sIFDIR = 0o040000
