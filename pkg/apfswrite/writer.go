// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import (
	"fmt"
	"io"
	"time"
)

// CreateOptions configures CreateContainer. The zero value is valid: it formats
// a 4096-byte-block, normalization-sensitive-by-default, case-insensitive
// volume named "untitled" with deterministic default UUIDs.
type CreateOptions struct {
	// BlockSize is the container block size in bytes. Zero means 4096. Must be
	// a power of two between 4096 and 65536.
	BlockSize uint32

	// VolumeName is the volume label. Empty means "untitled".
	VolumeName string

	// CaseSensitive selects a case-sensitive, normalization-insensitive volume
	// (like APFS "Case-sensitive"). When false, the volume is case-insensitive.
	CaseSensitive bool

	// ContainerUUID is the container UUID. The zero value selects a fixed
	// deterministic default (useful for reproducible tests).
	ContainerUUID [16]byte

	// VolumeUUID is the volume UUID. The zero value selects a fixed
	// deterministic default.
	VolumeUUID [16]byte

	// RootFiles are regular files to create in the volume root directory.
	// It is a convenience shorthand for a flat set of root-level files; each
	// becomes a top-level child of Root. When Root is also set, RootFiles are
	// appended as additional top-level entries.
	//
	// Files may be of any size (multi-block, spanning many allocation blocks)
	// and may be empty (0 bytes).
	RootFiles []RootFile

	// Root is a directory tree to populate the volume with: nested directories
	// and regular files of arbitrary depth and size (including empty files). A
	// nil Root (and empty RootFiles) formats an empty volume, exactly as before.
	//
	// Root itself represents the volume root directory; only its Children are
	// used (any Name/Data on Root is ignored).
	Root *Entry
}

// Entry is one node of the directory tree written into the volume. A directory
// has IsDir set and carries its Children; a regular file carries its bytes in
// Data. It mirrors pkg/hfsplus's Entry in shape.
type Entry struct {
	// Name is the entry's file name (no path separators, no NUL).
	Name string
	// IsDir marks the entry as a directory. Directories have no Data.
	IsDir bool
	// Data is the file content for a regular file (any size, may be empty).
	Data []byte
	// Children are the entries contained in a directory.
	Children []*Entry
}

// RootFile is a regular file to be created in the volume root directory.
type RootFile struct {
	// Name is the file name (no path separators).
	Name string
	// Data is the file content (any size, may be empty).
	Data []byte
}

// builderEntry holds the resolved on-disk placement for a single catalog
// entry (a directory or a regular file).
type builderEntry struct {
	name      string
	isDir     bool
	cnid      uint64 // catalog node id / inode number
	parent    uint64 // parent directory cnid
	nchildren uint32 // directories: number of direct children

	// Regular files with content (non-empty streams).
	data        []byte
	hasStream   bool   // true for every regular file (has a DSTREAM xfield + DSTREAM_ID record)
	dataBlock   uint64 // physical block number of the first content block (0 if empty)
	blocks      uint64 // number of allocation blocks in the file's extent (0 for a 0-byte file)
	allocedSize uint64 // block-aligned allocated size in bytes (0 for a 0-byte file)
}

// Deterministic default UUIDs used when the caller leaves a UUID zero.
var (
	defaultContainerUUID = [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	defaultVolumeUUID    = [16]byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x49, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
)

// CreateContainer writes a complete, empty, single-volume APFS container of
// sizeBytes (rounded down to a whole number of blocks) to w. The volume has
// only its root directory and the standard special inodes — no user files.
//
// If sizeBytes is 0, a sane minimum (512 KiB, mkapfs's smallest supported
// container) is used.
func CreateContainer(w io.WriterAt, sizeBytes int64, opts *CreateOptions) error {
	if opts == nil {
		opts = &CreateOptions{}
	}

	b := &builder{w: w}

	b.blocksize = opts.BlockSize
	if b.blocksize == 0 {
		b.blocksize = nxDefaultBlockSize
	}
	if b.blocksize < nxMinimumBlockSize || b.blocksize > nxMaximumBlockSize || b.blocksize&(b.blocksize-1) != 0 {
		return fmt.Errorf("apfswrite: unsupported block size %d", b.blocksize)
	}

	b.label = opts.VolumeName
	if b.label == "" {
		b.label = "untitled"
	}
	if len(b.label)+1 > volnameLen {
		return fmt.Errorf("apfswrite: volume label too long")
	}

	b.mainUUID = opts.ContainerUUID
	if b.mainUUID == ([16]byte{}) {
		b.mainUUID = defaultContainerUUID
	}
	b.volUUID = opts.VolumeUUID
	if b.volUUID == ([16]byte{}) {
		b.volUUID = defaultVolumeUUID
	}

	// Case-sensitivity handling mirrors mkapfs (see below); resolve the tree now
	// so its data requirements can size the image when the caller passes 0.
	b.caseSensitive = opts.CaseSensitive
	b.normSensitive = false

	// Resolve the user directory tree (nested dirs + regular files of any size).
	if err := b.setTree(opts); err != nil {
		return err
	}

	// mkapfs enforces a 512 KiB minimum for the main device.
	const minBytes = 512 * 1024
	if sizeBytes == 0 {
		// Size the image to comfortably hold the post-internal-pool payload
		// (catalog leaves, extref leaves, file data) plus the fixed format
		// metadata, block-aligned, with headroom for the checkpoint areas.
		payload := b.numCatLeaves + b.numExtrefLeaves + b.fileDataBlocks
		needBlocks := payload + payload/8 + 2048
		sizeBytes = int64(needBlocks) * int64(b.blocksize)
		if sizeBytes < minBytes {
			sizeBytes = minBytes
		}
	}
	b.mainBlkcnt = uint64(sizeBytes) / uint64(b.blocksize)
	b.blockCount = b.mainBlkcnt
	if b.mainBlkcnt*uint64(b.blocksize) < minBytes {
		return fmt.Errorf("apfswrite: container too small (%d bytes); minimum is %d", sizeBytes, minBytes)
	}

	// Case-sensitivity handling mirrors mkapfs. mkapfs defaults to
	// normalization-sensitive off (i.e. a case-insensitive volume). The public
	// API exposes only the common CaseSensitive toggle (resolved above).

	b.computeCheckpointLayout()

	if err := b.makeContainer(); err != nil {
		return err
	}

	// Ensure the underlying image is exactly sizeBytes: mkfs only writes the
	// blocks it uses, so extend the file/buffer by writing its final byte.
	total := b.mainBlkcnt * uint64(b.blocksize)
	if total > 0 {
		if _, err := w.WriteAt([]byte{0}, int64(total)-1); err != nil {
			return fmt.Errorf("apfswrite: sizing image: %w", err)
		}
	}
	return nil
}

// builder holds all filesystem parameters and the fixed block layout while the
// container is being written. It corresponds to mkapfs's global `param` plus
// `eph_info` and the checkpoint-area macros.
type builder struct {
	w io.WriterAt

	// Parameters.
	blocksize     uint32
	blockCount    uint64
	mainBlkcnt    uint64
	label         string
	mainUUID      [16]byte
	volUUID       [16]byte
	caseSensitive bool
	normSensitive bool

	// Checkpoint areas (mkapfs.h macros, resolved for this block_count).
	cpDescBase   uint64
	cpDescBlocks uint32
	cpDataBase   uint64
	cpDataBlocks uint32
	cpEnd        uint64

	// Fixed block numbers derived from the checkpoint areas.
	cpMapBno              uint64
	cpSbBno               uint64
	mainOmapBno           uint64
	mainOmapRootBno       uint64
	firstVolBno           uint64
	firstVolOmapBno       uint64
	firstVolOmapRootBno   uint64
	firstVolCatRootBno    uint64
	firstVolExtrefRootBno uint64
	firstVolSnapRootBno   uint64
	ipBmapBase            uint64

	// Ephemeral objects (eph_info).
	reaperBno        uint64
	spacemanBno      uint64
	spacemanSz       uint32
	spacemanBlkcnt   uint32
	ipFreeQueueBno   uint64
	mainFreeQueueBno uint64
	totalBlkcnt      uint32

	// Space manager info (sm_info), populated by setSpacemanInfo.
	sm smInfo

	// The user directory tree, flattened into catalog entries in cnid order,
	// plus the subset that are regular files with a data extent.
	entries     []*builderEntry
	streamFiles []*builderEntry
	numFiles    uint64 // regular files (user)
	numDirs     uint64 // directories (user, excludes root and private-dir)

	// Catalog B-tree shape, decided in setTree from the record sizes.
	numCatLeaves uint64 // extra leaf nodes when the catalog is a 2-level tree
	catTwoLevel  bool   // true when the catalog needs an index root + leaves

	// Extent-reference B-tree shape, decided in setTree from the extent count.
	numExtrefLeaves uint64 // leaf nodes when the extref tree is a 2-level tree
	extrefTwoLevel  bool   // true when the extref tree needs an index root + leaves

	// Post-internal-pool allocation region. All blocks the volume owns beyond
	// the fixed metadata are laid out contiguously starting at postIPBase, in
	// order: extra catalog leaf nodes, extra extent-reference leaf nodes, then
	// file data. This region may span several space-manager chunks.
	postIPBase   uint64
	postIPBlocks uint64

	// Physical-block bases within the post-internal-pool region. catLeafBase is
	// the first extra catalog leaf; extrefLeafBase the first extra extref leaf;
	// fileDataBase the first block of file content.
	catLeafBase    uint64
	extrefLeafBase uint64
	fileDataBase   uint64
	fileDataBlocks uint64

	timestamp uint64
}

// catLeafOIDBase is the first virtual object id handed to extra catalog leaf
// nodes (2-level catalog). It sits just past the named reserved object ids and
// below the container's NextOID reservation.
const catLeafOIDBase = mainFreeQueueOID + 1 // 1030

// Fixed object ids, derived from oidReservedCount (mkapfs.h).
const (
	spacemanOID        = oidReservedCount       // 1024
	reaperOID          = spacemanOID + 1        // 1025
	firstVolOID        = reaperOID + 1          // 1026
	firstVolCatRootOID = firstVolOID + 1        // 1027
	ipFreeQueueOID     = firstVolCatRootOID + 1 // 1028
	mainFreeQueueOID   = ipFreeQueueOID + 1     // 1029
)

// computeCheckpointLayout resolves the checkpoint-area macros and every fixed
// block number that depends on them.
func (b *builder) computeCheckpointLayout() {
	b.cpDescBase = nxBlockNum + 1
	b.cpDescBlocks = cpointDescBlocks(b.blockCount)
	b.cpDataBase = b.cpDescBase + uint64(b.cpDescBlocks)
	b.cpDataBlocks = cpointDataBlocks(b.blockCount)
	b.cpEnd = b.cpDataBase + uint64(b.cpDataBlocks)

	b.cpMapBno = b.cpDescBase
	b.cpSbBno = b.cpDescBase + 1
	b.mainOmapBno = b.cpEnd
	b.mainOmapRootBno = b.cpEnd + 1
	b.firstVolBno = b.cpEnd + 2
	b.firstVolOmapBno = b.cpEnd + 3
	b.firstVolOmapRootBno = b.cpEnd + 4
	b.firstVolCatRootBno = b.cpEnd + 5
	b.firstVolExtrefRootBno = b.cpEnd + 6
	b.firstVolSnapRootBno = b.cpEnd + 7
	// cpEnd+8 (fusion mt) and cpEnd+9 (fusion wbc) are skipped: no Fusion.
	b.ipBmapBase = b.cpEnd + 10

	b.timestamp = uint64(time.Now().UnixNano())
}

// writeBlocks writes count blocks of data starting at block number bno.
func (b *builder) writeBlocks(data []byte, bno uint64) error {
	off := int64(bno) * int64(b.blocksize)
	if _, err := b.w.WriteAt(data, off); err != nil {
		return fmt.Errorf("apfswrite: write at block %d: %w", bno, err)
	}
	return nil
}

// writeBlock writes a single block of data at block number bno.
func (b *builder) writeBlock(data []byte, bno uint64) error {
	return b.writeBlocks(data, bno)
}

// zeroedBlock returns a zeroed buffer of count blocks.
func (b *builder) zeroedBlocks(count int) []byte {
	return make([]byte, count*int(b.blocksize))
}

func (b *builder) zeroedBlock() []byte {
	return b.zeroedBlocks(1)
}

// cpointDescBlocks calculates the number of checkpoint descriptor blocks,
// mirroring mkapfs.h:cpoint_desc_blocks.
func cpointDescBlocks(blockCount uint64) uint32 {
	if blockCount < 512*1024/4 { // Up to 512M
		return 8
	}
	if blockCount < 1024*1024/4 { // Up to 1G
		return 12
	}
	if blockCount < 50*1024*1024/4 { // Up to 50G
		off512M := (blockCount - 1024*1024/4) / (512 * 1024 / 4)
		return uint32(20 + 60*off512M/23)
	}
	return 280
}

// cpointDataBlocks calculates the number of checkpoint data blocks, mirroring
// mkapfs.h:cpoint_data_blocks.
func cpointDataBlocks(blockCount uint64) uint32 {
	switch {
	case blockCount < 4545:
		return 52
	case blockCount < 13633:
		return 124
	case blockCount < 36353:
		return uint32(160 + 36*((blockCount-13633)/4544))
	case blockCount < 131777:
		return uint32(308 + 4*((blockCount-36353)/4544))
	case blockCount < 262144:
		return uint32(648 + 4*((blockCount-131777)/4544))
	case blockCount == 262144: // 1G is a special case
		return 992
	case blockCount < 1048576: // Up to 4G
		off512M := int64((blockCount - 262144) / 131072)
		return uint32(1248 + 488*off512M + 4*((int64(blockCount)-(261280+off512M*131776))/2272))
	case blockCount < 4063232: // Up to 10G
		off512M := (blockCount - 1048576) / 131072
		return uint32(4112 + 256*off512M)
	case blockCount < 13107200: // Up to 50G
		off512M := (blockCount - 4063232) / 131072
		return uint32(10000 + 256*off512M)
	default:
		return 27672
	}
}

// ipFQNodeLimit mirrors lib/parameters.c:ip_fq_node_limit.
func ipFQNodeLimit(chunks uint64) uint16 {
	ret := uint16(3*(chunks+751)/1127 - 1)
	if ret == 2 {
		ret = 3
	}
	return ret
}

// mainFQNodeLimit mirrors lib/parameters.c:main_fq_node_limit.
func mainFQNodeLimit(blocks uint64) uint16 {
	const blks1gb = 0x40000
	const blks4gb = 0x100000
	var ret uint16
	switch {
	case blocks < blks1gb:
		ret = uint16(1 + (blocks-1)/4544)
	case blocks < blks4gb:
		ret = uint16(116 + (blocks-261281)/2272)
	default:
		ret = 512
	}
	if ret == 2 {
		ret = 3
	}
	return ret
}

// divRoundUp computes ceil(n/d).
func divRoundUp(n, d uint64) uint64 { return (n + d - 1) / d }

// roundUp rounds x up to the next multiple of y.
func roundUp(x, y uint64) uint64 { return ((x - 1) | (y - 1)) + 1 }
