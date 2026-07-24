// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
)

// mkfsIDString identifies the formatting program in the volume superblock.
const mkfsIDString = "mkapfs go port (apfswrite)"

// makeContainer builds the whole filesystem, mirroring super.c:make_container.
func (b *builder) makeContainer() error {
	sb := &nxSuperblock{}
	size := b.blockCount * uint64(b.blocksize)

	sb.Magic = nxMagic
	sb.BlockSize = b.blocksize
	sb.BlockCount = b.blockCount

	// We only support version 2 of APFS. No Fusion.
	sb.IncompatibleFeatures |= nxIncompatVersion2

	sb.UUID = b.mainUUID

	// Leave some room for the objects created by the mkfs.
	sb.NextOID = oidReservedCount + 100
	sb.NextXID = mkfsXID + 1

	// We need to know the spaceman size before we can decide the location of
	// the other ephemeral objects.
	if err := b.setSpacemanInfo(); err != nil {
		return err
	}
	b.setEphemeralBnos()

	sb.SpacemanOID = spacemanOID
	if err := b.makeSpaceman(b.spacemanBno, spacemanOID); err != nil {
		return err
	}
	sb.ReaperOID = reaperOID
	if err := b.makeEmptyReaper(b.reaperBno, reaperOID); err != nil {
		return err
	}
	sb.OmapOID = b.mainOmapBno
	if err := b.makeOmapBtree(b.mainOmapBno, false /* is_vol */); err != nil {
		return err
	}

	b.setCheckpointAreas(sb)

	sb.MaxFileSystems = getMaxVolumes(size)
	sb.FsOID[0] = firstVolOID
	if err := b.makeVolume(b.firstVolBno, firstVolOID); err != nil {
		return err
	}

	b.setEphemeralInfo(&sb.EphemeralInfo[0])

	// Serialize the superblock and finalize its object header/checksum.
	block := b.zeroedBlock()
	marshalInto(block, sb)
	setObjectHeader(block, int(b.blocksize), oidNXSuperblock,
		objEphemeral|objectTypeNXSuperblock, objectTypeInvalid)

	// If the disk was ever formatted as APFS, valid checkpoint superblocks may
	// still remain. Wipe the descriptor area to avoid mounting them by mistake.
	if err := b.zeroArea(b.cpDescBase, uint64(b.cpDescBlocks)); err != nil {
		return err
	}
	if err := b.makeCpointMapBlock(b.cpMapBno); err != nil {
		return err
	}
	if err := b.makeCpointSuperblock(b.cpSbBno, block); err != nil {
		return err
	}

	// The primary superblock lives at block zero.
	return b.writeBlock(block, nxBlockNum)
}

// zeroArea wipes an area on disk, mirroring super.c:zero_area.
func (b *builder) zeroArea(start, blocks uint64) error {
	zero := b.zeroedBlock()
	for bno := start; bno < start+blocks; bno++ {
		if err := b.writeBlock(zero, bno); err != nil {
			return err
		}
	}
	return nil
}

// setCheckpointAreas sets all superblock fields describing the checkpoint
// areas, mirroring super.c:set_checkpoint_areas.
func (b *builder) setCheckpointAreas(sb *nxSuperblock) {
	sb.XpDescBase = b.cpDescBase
	sb.XpDescBlocks = b.cpDescBlocks
	// The first two blocks hold the superblock and the mappings.
	sb.XpDescLen = 2
	sb.XpDescNext = 2
	sb.XpDescIndex = 0

	sb.XpDataBase = b.cpDataBase
	sb.XpDataBlocks = b.cpDataBlocks
	sb.XpDataLen = b.totalBlkcnt
	sb.XpDataNext = b.totalBlkcnt
	sb.XpDataIndex = 0
}

// getMaxVolumes calculates the maximum number of volumes for the container,
// mirroring super.c:get_max_volumes.
func getMaxVolumes(size uint64) uint32 {
	maxVols := divRoundUp(size, 512*1024*1024)
	if maxVols > nxMaxFileSystems {
		maxVols = nxMaxFileSystems
	}
	return uint32(maxVols)
}

// setEphemeralInfo sets the container's first ephemeral-info entry, mirroring
// super.c:set_ephemeral_info.
func (b *builder) setEphemeralInfo(info *uint64) {
	containerSize := b.blockCount * uint64(b.blocksize)
	var minBlockCount uint64
	if containerSize < 128*1024*1024 {
		minBlockCount = uint64(mainFQNodeLimit(b.blockCount))
	} else {
		minBlockCount = nxEphMinBlockCount
	}
	*info = (minBlockCount << 32) |
		(nxMaxFileSystemEphStructs << 16) |
		nxEphInfoVersion1
}

// setMetaCrypto sets a volume's meta_crypto field, mirroring
// super.c:set_meta_crypto.
func setMetaCrypto(wmcs *wrappedMetaCryptoState) {
	wmcs.MajorVersion = wmcsMajorVersion
	wmcs.MinorVersion = wmcsMinorVersion
	wmcs.Cpflags = 0
	wmcs.PersistentClass = protectionClassF
	wmcs.KeyOSVersion = 0
	wmcs.KeyRevision = 1
}

// makeVolume makes a volume, mirroring super.c:make_volume.
func (b *builder) makeVolume(bno, oid uint64) error {
	vsb := &apfsSuperblock{}

	vsb.Magic = apfsMagic
	vsb.Features = featureHardlinkMapRecords

	switch {
	case b.normSensitive:
		vsb.IncompatibleFeatures = 0
	case b.caseSensitive:
		vsb.IncompatibleFeatures = incompatNormalizationInsensitive
	default:
		vsb.IncompatibleFeatures = incompatCaseInsensitive
	}

	setMetaCrypto(&vsb.MetaCrypto)

	// We won't create any user inodes.
	vsb.NextObjID = minUserInoNum

	vsb.VolUUID = b.volUUID
	vsb.FsFlags = fsUnencrypted

	copy(vsb.FormattedBy.ID[:], mkfsIDString)
	vsb.FormattedBy.Timestamp = b.timestamp
	vsb.FormattedBy.LastXID = mkfsXID

	copy(vsb.Volname[:], b.label)
	vsb.NextDocID = minDocID

	vsb.RootTreeType = objVirtual | objectTypeBtree
	vsb.ExtentrefTreeType = objPhysical | objectTypeBtree
	vsb.SnapMetaTreeType = objPhysical | objectTypeBtree

	vsb.OmapOID = b.firstVolOmapBno
	if err := b.makeOmapBtree(b.firstVolOmapBno, true /* is_vol */); err != nil {
		return err
	}
	vsb.RootTreeOID = firstVolCatRootOID
	if err := b.makeCatRoot(b.firstVolCatRootBno, firstVolCatRootOID); err != nil {
		return err
	}

	// The snapshot metadata and extent reference trees are empty.
	vsb.ExtentrefTreeOID = b.firstVolExtrefRootBno
	if err := b.makeEmptyBtreeRoot(b.firstVolExtrefRootBno, b.firstVolExtrefRootBno, objectTypeBlockrefTree); err != nil {
		return err
	}
	vsb.SnapMetaTreeOID = b.firstVolSnapRootBno
	if err := b.makeEmptyBtreeRoot(b.firstVolSnapRootBno, b.firstVolSnapRootBno, objectTypeSnapMetaTree); err != nil {
		return err
	}

	// The root nodes of all four trees, plus the object map structure.
	vsb.FsAllocCount = 5

	block := b.zeroedBlock()
	marshalInto(block, vsb)
	setObjectHeader(block, int(b.blocksize), oid,
		objVirtual|objectTypeFS, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// makeCpointMapBlock makes the mapping block for the one checkpoint, mirroring
// super.c:make_cpoint_map_block.
func (b *builder) makeCpointMapBlock(bno uint64) error {
	block := b.zeroedBlock()

	// cpm_flags at offset sizeofObjPhys; cpm_count next; then the mappings.
	off := sizeofObjPhys
	binary.LittleEndian.PutUint32(block[off:], checkpointMapLast) // cpm_flags
	// cpm_count filled at the end.
	mapBase := sizeofObjPhys + 8 // header (obj + flags + count)

	idx := 0
	putMapping := func(typ, subtype, mapSize uint32, oid, paddr uint64) {
		m := block[mapBase+idx*sizeofCheckpointMapping:]
		binary.LittleEndian.PutUint32(m[0:], typ)     // cpm_type
		binary.LittleEndian.PutUint32(m[4:], subtype) // cpm_subtype
		binary.LittleEndian.PutUint32(m[8:], mapSize) // cpm_size
		// m[12:] cpm_pad = 0
		// m[16:] cpm_fs_oid = 0
		binary.LittleEndian.PutUint64(m[24:], oid)   // cpm_oid
		binary.LittleEndian.PutUint64(m[32:], paddr) // cpm_paddr
		idx++
	}

	// Reaper.
	putMapping(objEphemeral|objectTypeNXReaper, objectTypeInvalid, b.blocksize, reaperOID, b.reaperBno)
	// Space manager.
	putMapping(objEphemeral|objectTypeSpaceman, objectTypeInvalid, b.spacemanSz, spacemanOID, b.spacemanBno)
	// Internal-pool free queue root.
	putMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, ipFreeQueueOID, b.ipFreeQueueBno)
	// Main device free queue root.
	putMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, mainFreeQueueOID, b.mainFreeQueueBno)

	binary.LittleEndian.PutUint32(block[off+4:], uint32(idx)) // cpm_count

	setObjectHeader(block, int(b.blocksize), bno,
		objPhysical|objectTypeCheckpointMap, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// makeCpointSuperblock makes the one checkpoint superblock, mirroring
// super.c:make_cpoint_superblock (it is just a copy of the block-zero sb).
func (b *builder) makeCpointSuperblock(bno uint64, sbCopy []byte) error {
	block := b.zeroedBlock()
	copy(block, sbCopy)
	return b.writeBlock(block, bno)
}

// makeEmptyReaper makes an empty reaper, mirroring super.c:make_empty_reaper.
func (b *builder) makeEmptyReaper(bno, oid uint64) error {
	reaper := &nxReaperPhys{}
	reaper.NextReapID = 1
	reaper.Flags = nrBHMFlag
	reaper.StateBufferSize = b.blocksize - sizeofNXReaperPhys

	block := b.zeroedBlock()
	marshalInto(block, reaper)
	setObjectHeader(block, int(b.blocksize), oid,
		objEphemeral|objectTypeNXReaper, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// setEphemeralBnos decides the block numbers for the ephemeral objects,
// mirroring super.c:set_ephemeral_bnos.
func (b *builder) setEphemeralBnos() {
	b.reaperBno = b.cpDataBase
	b.spacemanBno = b.reaperBno + 1
	b.spacemanSz = b.spacemanSize()
	b.spacemanBlkcnt = b.spacemanSz / b.blocksize
	b.ipFreeQueueBno = b.spacemanBno + uint64(b.spacemanBlkcnt)
	b.mainFreeQueueBno = b.ipFreeQueueBno + 1
	b.totalBlkcnt = uint32(b.mainFreeQueueBno - b.reaperBno + 1)
}
