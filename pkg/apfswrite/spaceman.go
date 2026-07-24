// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "encoding/binary"

// Fixed field offsets within an apfs_spaceman_phys block.
const (
	smOffBlockSize       = 0x20
	smOffBlocksPerChunk  = 0x24
	smOffChunksPerCib    = 0x28
	smOffCibsPerCab      = 0x2c
	smOffDev             = 0x30 // sm_dev[APFS_SD_COUNT], 48 bytes each
	smOffFlags           = 0x90
	smOffIPBMTxMult      = 0x94
	smOffIPBlockCount    = 0x98
	smOffIPBMSizeBlocks  = 0xa0
	smOffIPBMBlockCount  = 0xa4
	smOffIPBMBase        = 0xa8
	smOffIPBase          = 0xb0
	smOffFQ              = 0xc8 // sm_fq[APFS_SFQ_COUNT], 40 bytes each
	smOffIPBMFreeHead    = 0x140
	smOffIPBMFreeTail    = 0x142
	smOffIPBMXidOffset   = 0x144
	smOffIPBitmapOffset  = 0x148
	smOffIPBMFreeNextOff = 0x14c

	// Transaction id for the ip bitmap; borrowed from a test image (spaceman.c).
	bitmapXidOff = 0x150

	sizeofSpacemanDevice    = 48
	sizeofSpacemanFreeQueue = 40
)

// devInfo mirrors spaceman.c:struct device_info.
type devInfo struct {
	blockCount uint64
	chunkCount uint64
	cibCount   uint32
	cabCount   uint32

	cibAddrBaseOff uint32 // offset of the cib/cab address array in the spaceman

	firstCib uint64
	firstCab uint64

	usedBlocksEnd uint64
	usedChunksEnd uint64

	firstChunkBmap uint64
}

// smInfo mirrors spaceman.c:struct spaceman_info.
type smInfo struct {
	dev [sdCount]devInfo

	totalChunkCount uint64
	totalCibCount   uint32
	totalCabCount   uint32

	ipBlocks      uint64
	ipBmSize      uint32
	ipBmapBlocks  uint32
	ipBase        uint64
	bmAddrOff     uint32
	bmFreeNextOff uint32
}

func (b *builder) blocksPerChunk() uint64 { return 8 * uint64(b.blocksize) }

func (b *builder) chunksPerCib() uint64 {
	return (uint64(b.blocksize) - sizeofChunkInfoBlockHdr) / sizeofChunkInfo
}

func (b *builder) cibsPerCab() uint64 {
	return (uint64(b.blocksize) - sizeofCibAddrBlockHdr) / 8
}

// spacemanSize calculates the size of the spaceman object in bytes, mirroring
// spaceman.c:spaceman_size.
func (b *builder) spacemanSize() uint32 {
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]

	entryCount := uint64(0)
	if main.cabCount > 1 {
		entryCount += uint64(main.cabCount)
	} else {
		entryCount += uint64(main.cibCount)
	}
	if tier2.cabCount > 1 {
		entryCount += uint64(tier2.cabCount)
	} else {
		entryCount += uint64(tier2.cibCount)
	}

	return uint32(divRoundUp(entryCount*8+uint64(main.cibAddrBaseOff), uint64(b.blocksize)) * uint64(b.blocksize))
}

// countUsedBlocksInChunk mirrors spaceman.c:count_used_blocks_in_chunk.
func (b *builder) countUsedBlocksInChunk(dev *devInfo, chunkno uint64) uint32 {
	if chunkno >= dev.usedChunksEnd {
		return 0
	}
	// The tier 2 device only has a superblock (not used in the non-Fusion path).
	if dev.usedBlocksEnd == 1 {
		return 1
	}

	firstChunkIPBlocks := b.sm.ipBlocks
	if avail := b.blocksPerChunk() - b.sm.ipBase; avail < firstChunkIPBlocks {
		firstChunkIPBlocks = avail
	}

	if chunkno == 0 {
		blocks := uint32(0)
		blocks += 1                 // Block zero
		blocks += b.cpDescBlocks    // Checkpoint descriptor blocks
		blocks += b.cpDataBlocks    // Checkpoint data blocks
		blocks += 2                 // Container object map and its root
		blocks += 6                 // Volume superblock and its trees
		blocks += b.sm.ipBmapBlocks // Internal pool bitmap blocks
		blocks += uint32(firstChunkIPBlocks)
		blocks += uint32(b.fileDataBlocks) // User file data blocks
		return blocks
	}

	if chunkno != dev.usedChunksEnd-1 {
		return uint32(b.blocksPerChunk())
	}
	// Last chunk.
	return uint32((b.sm.ipBlocks - firstChunkIPBlocks) % b.blocksPerChunk())
}

// countUsedBlocks mirrors spaceman.c:count_used_blocks.
func (b *builder) countUsedBlocks(dev *devInfo) uint32 {
	blocks := uint32(0)
	for chunkno := uint64(0); chunkno < dev.usedChunksEnd; chunkno++ {
		blocks += b.countUsedBlocksInChunk(dev, chunkno)
	}
	return blocks
}

// bmapMarkAsUsed marks a range as used in an allocation bitmap.
func bmapMarkAsUsed(bitmap []byte, paddr, length uint64) {
	for i := paddr; i < paddr+length; i++ {
		bitmap[i/8] |= 1 << (i % 8)
	}
}

// makeMainAllocBitmap mirrors spaceman.c:make_main_alloc_bitmap.
func (b *builder) makeMainAllocBitmap() error {
	dev := &b.sm.dev[sdMain]
	bmap := b.zeroedBlocks(int(dev.usedChunksEnd))

	bmapMarkAsUsed(bmap, 0, 1)                                    // Block zero
	bmapMarkAsUsed(bmap, b.cpDescBase, uint64(b.cpDescBlocks))    // Checkpoint descriptor
	bmapMarkAsUsed(bmap, b.cpDataBase, uint64(b.cpDataBlocks))    // Checkpoint data
	bmapMarkAsUsed(bmap, b.mainOmapBno, 2)                        // Container omap + root
	bmapMarkAsUsed(bmap, b.firstVolBno, 6)                        // Volume sb + its trees
	bmapMarkAsUsed(bmap, b.ipBmapBase, uint64(b.sm.ipBmapBlocks)) // IP bitmap blocks
	bmapMarkAsUsed(bmap, b.sm.ipBase, b.sm.ipBlocks)              // Internal pool blocks
	if b.fileDataBlocks > 0 {
		bmapMarkAsUsed(bmap, b.fileDataBase, b.fileDataBlocks) // User file data blocks
	}

	return b.writeBlocks(bmap, dev.firstChunkBmap)
}

// makeChunkInfo writes a chunk info structure at chunk (a slice into the cib),
// mirroring spaceman.c:make_chunk_info. Returns the next chunk's first block.
func (b *builder) makeChunkInfo(dev *devInfo, chunk []byte, start uint64) uint64 {
	remaining := dev.blockCount - start
	chunkno := start / b.blocksPerChunk()

	binary.LittleEndian.PutUint64(chunk[0:], mkfsXID) // ci_xid
	binary.LittleEndian.PutUint64(chunk[8:], start)   // ci_addr

	if start < dev.usedBlocksEnd {
		binary.LittleEndian.PutUint64(chunk[24:], dev.firstChunkBmap+chunkno) // ci_bitmap_addr
	}

	blockCount := b.blocksPerChunk()
	if remaining < blockCount {
		blockCount = remaining
	}
	binary.LittleEndian.PutUint32(chunk[16:], uint32(blockCount)) // ci_block_count

	freeCount := uint32(blockCount) - b.countUsedBlocksInChunk(dev, chunkno)
	binary.LittleEndian.PutUint32(chunk[20:], freeCount) // ci_free_count

	return start + blockCount
}

// makeChunkInfoBlock mirrors spaceman.c:make_chunk_info_block.
func (b *builder) makeChunkInfoBlock(dev *devInfo, bno uint64, index int, start uint64) (uint64, error) {
	cib := b.zeroedBlock()
	binary.LittleEndian.PutUint32(cib[32:], uint32(index)) // cib_index

	i := 0
	for ; uint64(i) < b.chunksPerCib(); i++ {
		if start == dev.blockCount {
			break
		}
		chunk := cib[sizeofChunkInfoBlockHdr+i*sizeofChunkInfo:]
		start = b.makeChunkInfo(dev, chunk, start)
	}
	binary.LittleEndian.PutUint32(cib[36:], uint32(i)) // cib_chunk_info_count

	setObjectHeader(cib, int(b.blocksize), bno,
		objPhysical|objectTypeSpacemanCIB, objectTypeInvalid)
	if err := b.writeBlock(cib, bno); err != nil {
		return 0, err
	}
	return start, nil
}

// makeSingleDevice mirrors spaceman.c:make_single_device. It writes the device
// structure at smOffDev+which*sizeofSpacemanDevice inside sm and lays out that
// device's chunk-info blocks.
func (b *builder) makeSingleDevice(sm []byte, which int) error {
	devInfoP := &b.sm.dev[which]
	dev := sm[smOffDev+which*sizeofSpacemanDevice:]

	binary.LittleEndian.PutUint64(dev[0:], devInfoP.blockCount)                                      // sm_block_count
	binary.LittleEndian.PutUint64(dev[8:], devInfoP.chunkCount)                                      // sm_chunk_count
	binary.LittleEndian.PutUint32(dev[16:], devInfoP.cibCount)                                       // sm_cib_count
	binary.LittleEndian.PutUint32(dev[20:], devInfoP.cabCount)                                       // sm_cab_count
	binary.LittleEndian.PutUint64(dev[24:], devInfoP.blockCount-uint64(b.countUsedBlocks(devInfoP))) // sm_free_count
	binary.LittleEndian.PutUint32(dev[32:], devInfoP.cibAddrBaseOff)                                 // sm_addr_offset

	start := uint64(0)
	if devInfoP.cabCount == 0 {
		// Only cib addresses (no cab layer). We omit the cab path entirely
		// because it is only reachable for very large / Fusion devices.
		for i := uint32(0); i < devInfoP.cibCount; i++ {
			binary.LittleEndian.PutUint64(sm[uint64(devInfoP.cibAddrBaseOff)+uint64(i)*8:], devInfoP.firstCib+uint64(i))
			var err error
			start, err = b.makeChunkInfoBlock(devInfoP, devInfoP.firstCib+uint64(i), int(i), start)
			if err != nil {
				return err
			}
		}
	} else {
		return errCabUnsupported
	}
	return nil
}

// makeDevices mirrors spaceman.c:make_devices (tier 2 is empty here).
func (b *builder) makeDevices(sm []byte) error {
	if err := b.makeSingleDevice(sm, sdMain); err != nil {
		return err
	}
	return b.makeSingleDevice(sm, sdTier2)
}

// makeIPFreeQueue mirrors spaceman.c:make_ip_free_queue. fq is a slice into sm.
func (b *builder) makeIPFreeQueue(fq []byte) error {
	binary.LittleEndian.PutUint64(fq[8:], ipFreeQueueOID) // sfq_tree_oid
	if err := b.makeEmptyBtreeRoot(b.ipFreeQueueBno, ipFreeQueueOID, objectTypeSpacemanFreeQueue); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(fq[24:], ipFQNodeLimit(b.sm.totalChunkCount)) // sfq_tree_node_limit
	return nil
}

// makeMainFreeQueue mirrors spaceman.c:make_main_free_queue.
func (b *builder) makeMainFreeQueue(fq []byte) error {
	binary.LittleEndian.PutUint64(fq[8:], mainFreeQueueOID)
	if err := b.makeEmptyBtreeRoot(b.mainFreeQueueBno, mainFreeQueueOID, objectTypeSpacemanFreeQueue); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(fq[24:], mainFQNodeLimit(b.mainBlkcnt))
	return nil
}

// makeIPBitmap mirrors spaceman.c:make_ip_bitmap.
func (b *builder) makeIPBitmap() error {
	bmap := b.zeroedBlocks(int(b.sm.ipBmSize))
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]

	// Cib address blocks.
	bmapMarkAsUsed(bmap, main.firstCab-b.sm.ipBase, uint64(main.cabCount))
	bmapMarkAsUsed(bmap, tier2.firstCab-b.sm.ipBase, uint64(tier2.cabCount))
	// Chunk-info blocks.
	bmapMarkAsUsed(bmap, main.firstCib-b.sm.ipBase, uint64(main.cibCount))
	bmapMarkAsUsed(bmap, tier2.firstCib-b.sm.ipBase, uint64(tier2.cibCount))
	// Allocation bitmap block.
	bmapMarkAsUsed(bmap, main.firstChunkBmap-b.sm.ipBase, main.usedChunksEnd)
	bmapMarkAsUsed(bmap, tier2.firstChunkBmap-b.sm.ipBase, tier2.usedChunksEnd)

	return b.writeBlocks(bmap, b.ipBmapBase)
}

// makeIPBMFreeNext mirrors spaceman.c:make_ip_bm_free_next. addr is a slice
// into sm at bm_free_next_off.
func (b *builder) makeIPBMFreeNext(addr []byte) {
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		binary.LittleEndian.PutUint16(addr[i*2:], spacemanIPBMIndexInvalid)
	}
	for i := b.sm.ipBmSize; i < b.sm.ipBmapBlocks-1; i++ {
		binary.LittleEndian.PutUint16(addr[i*2:], uint16(i+1))
	}
	binary.LittleEndian.PutUint16(addr[(b.sm.ipBmapBlocks-1)*2:], spacemanIPBMIndexInvalid)
}

// makeInternalPool mirrors spaceman.c:make_internal_pool.
func (b *builder) makeInternalPool(sm []byte) error {
	binary.LittleEndian.PutUint32(sm[smOffIPBMTxMult:], spacemanIPBMTxMultiplier)
	binary.LittleEndian.PutUint64(sm[smOffIPBlockCount:], b.sm.ipBlocks)
	binary.LittleEndian.PutUint64(sm[smOffIPBase:], b.sm.ipBase)
	binary.LittleEndian.PutUint32(sm[smOffIPBMSizeBlocks:], b.sm.ipBmSize)

	binary.LittleEndian.PutUint32(sm[smOffIPBMBlockCount:], b.sm.ipBmapBlocks)
	binary.LittleEndian.PutUint64(sm[smOffIPBMBase:], b.ipBmapBase)
	zero := b.zeroedBlock()
	for i := uint32(0); i < b.sm.ipBmapBlocks; i++ {
		if err := b.writeBlock(zero, b.ipBmapBase+uint64(i)); err != nil {
			return err
		}
	}

	// The current bitmaps are the first in the ring.
	binary.LittleEndian.PutUint32(sm[smOffIPBitmapOffset:], b.sm.bmAddrOff)
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		binary.LittleEndian.PutUint16(sm[uint64(b.sm.bmAddrOff)+uint64(i)*2:], uint16(i))
	}
	binary.LittleEndian.PutUint16(sm[smOffIPBMFreeHead:], uint16(b.sm.ipBmSize))
	binary.LittleEndian.PutUint16(sm[smOffIPBMFreeTail:], uint16(b.sm.ipBmapBlocks-1))

	binary.LittleEndian.PutUint32(sm[smOffIPBMXidOffset:], bitmapXidOff)
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		binary.LittleEndian.PutUint64(sm[bitmapXidOff+uint64(i)*8:], mkfsXID)
	}

	binary.LittleEndian.PutUint32(sm[smOffIPBMFreeNextOff:], b.sm.bmFreeNextOff)
	b.makeIPBMFreeNext(sm[b.sm.bmFreeNextOff:])

	return b.makeIPBitmap()
}

// calculateDevInfo mirrors spaceman.c:calculate_dev_info.
func (b *builder) calculateDevInfo(dev *devInfo, which int) error {
	if which == sdMain {
		dev.blockCount = b.mainBlkcnt
	} else {
		dev.blockCount = 0 // no tier 2
	}
	dev.chunkCount = divRoundUp(dev.blockCount, b.blocksPerChunk())
	dev.cibCount = uint32(divRoundUp(dev.chunkCount, b.chunksPerCib()))
	dev.cabCount = uint32(divRoundUp(uint64(dev.cibCount), b.cibsPerCab()))
	if dev.cabCount == 1 {
		dev.cabCount = 0
	}
	if dev.cabCount > 1000 {
		return errDeviceTooBig
	}
	return nil
}

// setSpacemanInfo mirrors spaceman.c:set_spaceman_info.
func (b *builder) setSpacemanInfo() error {
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]
	if err := b.calculateDevInfo(main, sdMain); err != nil {
		return err
	}
	if err := b.calculateDevInfo(tier2, sdTier2); err != nil {
		return err
	}
	b.sm.totalChunkCount = main.chunkCount + tier2.chunkCount
	b.sm.totalCibCount = main.cibCount + tier2.cibCount
	b.sm.totalCabCount = main.cabCount + tier2.cabCount
	b.sm.ipBlocks = (b.sm.totalChunkCount + uint64(b.sm.totalCibCount) + uint64(b.sm.totalCabCount)) * 3
	if b.sm.ipBlocks > b.mainBlkcnt/2 {
		return errIPPoolTooBig
	}

	// We have 16 ip bitmaps; each maps the whole ip and may span blocks.
	b.sm.ipBmSize = uint32(divRoundUp(b.sm.ipBlocks, b.blocksPerChunk()))
	b.sm.ipBmapBlocks = 16 * b.sm.ipBmSize
	b.sm.ipBase = b.ipBmapBase + uint64(b.sm.ipBmapBlocks)

	// One xid for each of the ip bitmaps.
	b.sm.bmAddrOff = bitmapXidOff + 8*b.sm.ipBmSize
	b.sm.bmFreeNextOff = b.sm.bmAddrOff + uint32(roundUp(uint64(2*b.sm.ipBmSize), 8))
	main.cibAddrBaseOff = b.sm.bmFreeNextOff + b.sm.ipBmapBlocks*2
	if main.cabCount != 0 {
		tier2.cibAddrBaseOff = main.cibAddrBaseOff + main.cabCount*8
	} else {
		tier2.cibAddrBaseOff = main.cibAddrBaseOff + main.cibCount*8
	}

	// Only the ip size matters; all other used blocks come before it.
	main.usedBlocksEnd = b.sm.ipBase + b.sm.ipBlocks
	main.usedChunksEnd = divRoundUp(main.usedBlocksEnd, b.blocksPerChunk())
	tier2.usedBlocksEnd = 0
	tier2.usedChunksEnd = 0

	main.firstChunkBmap = b.sm.ipBase
	main.firstCib = main.firstChunkBmap + main.usedChunksEnd
	main.firstCab = main.firstCib + uint64(main.cibCount)
	tier2.firstChunkBmap = main.firstCab + uint64(main.cabCount)
	tier2.firstCib = tier2.firstChunkBmap + tier2.usedChunksEnd
	tier2.firstCab = tier2.firstCib + uint64(tier2.cibCount)

	// File data blocks are laid out contiguously right after the internal pool,
	// i.e. at the first otherwise-free block. Milestone 1 keeps them within the
	// first chunk so the fixed chunk-0 used-block accounting stays valid.
	b.fileDataBase = main.usedBlocksEnd
	if b.fileDataBlocks > 0 {
		if b.fileDataBase+b.fileDataBlocks > b.blocksPerChunk() {
			return errFileDataTooBig
		}
		if b.fileDataBase+b.fileDataBlocks > b.mainBlkcnt {
			return errFileDataTooBig
		}
		blk := b.fileDataBase
		for _, f := range b.files {
			f.dataBlock = blk
			blk += f.blocks
		}
	}
	return nil
}

// makeSpaceman mirrors spaceman.c:make_spaceman.
func (b *builder) makeSpaceman(bno, oid uint64) error {
	size := b.spacemanSize()
	sm := b.zeroedBlocks(int(size) / int(b.blocksize))

	binary.LittleEndian.PutUint32(sm[smOffBlockSize:], b.blocksize)
	binary.LittleEndian.PutUint32(sm[smOffBlocksPerChunk:], uint32(b.blocksPerChunk()))
	binary.LittleEndian.PutUint32(sm[smOffChunksPerCib:], uint32(b.chunksPerCib()))
	binary.LittleEndian.PutUint32(sm[smOffCibsPerCab:], uint32(b.cibsPerCab()))

	if err := b.makeDevices(sm); err != nil {
		return err
	}
	if err := b.makeIPFreeQueue(sm[smOffFQ+sfqIP*sizeofSpacemanFreeQueue:]); err != nil {
		return err
	}
	if err := b.makeMainFreeQueue(sm[smOffFQ+sfqMain*sizeofSpacemanFreeQueue:]); err != nil {
		return err
	}
	if err := b.makeInternalPool(sm); err != nil {
		return err
	}
	if err := b.makeMainAllocBitmap(); err != nil {
		return err
	}

	setObjectHeader(sm, int(size), oid,
		objEphemeral|objectTypeSpaceman, objectTypeInvalid)
	return b.writeBlocks(sm, bno)
}
