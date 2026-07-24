// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
)

// formatterID identifies this tool in the volume superblock's "formatted by"
// field, the way newfs_apfs records itself.
const formatterID = "go-apfs (apfswrite)"

// nextContainerOID returns nx_next_oid: one past the highest virtual object id
// the container assigns. The fixed container objects occupy ids up to
// mainFreeQueueOID; a two-level catalog additionally consumes one virtual id per
// leaf starting at catLeafOIDBase, which then becomes the high-water mark.
func (b *builder) nextContainerOID() uint64 {
	next := uint64(mainFreeQueueOID + 1)
	if b.catTwoLevel {
		next = catLeafOIDBase + b.numCatLeaves
	}
	return next
}

// assemble writes the whole container. By the time it runs every block position
// and all space-manager geometry are fixed, so it works in three phases: write
// the container's objects (the ephemeral objects, the container object map and
// the volume with its trees), populate the container superblock that references
// them, and finally lay down the checkpoint and the primary superblock at block
// zero.
func (b *builder) assemble() error {
	// Phase 1: write the objects the container superblock will point at. The
	// order among these is immaterial — each lands at its own fixed block.
	if err := b.writeSpaceman(b.spacemanBno, spacemanOID); err != nil {
		return err
	}
	if err := b.writeReaper(b.reaperBno, reaperOID); err != nil {
		return err
	}
	if err := b.writeObjectMap(b.mainOmapBno, false /* container omap */); err != nil {
		return err
	}
	if err := b.writeVolume(b.firstVolBno, firstVolOID); err != nil {
		return err
	}

	// Phase 2: populate the container superblock, field by field.
	sb := &nxSuperblock{}
	sb.Magic = nxMagic
	sb.BlockSize = b.blocksize
	sb.BlockCount = b.blockCount
	sb.IncompatibleFeatures = nxIncompatVersion2 // APFS version 2, no Fusion
	sb.UUID = b.mainUUID
	sb.NextOID = b.nextContainerOID()
	sb.NextXID = mkfsXID + 1
	b.fillCheckpointAreas(sb)
	sb.SpacemanOID = spacemanOID
	sb.OmapOID = b.mainOmapBno
	sb.ReaperOID = reaperOID
	sb.MaxFileSystems = maxVolumes(b.blockCount * uint64(b.blocksize))
	sb.FsOID[0] = firstVolOID
	b.fillEphemeralInfo(&sb.EphemeralInfo[0])

	block := b.zeroedBlock()
	marshalInto(block, sb)
	setObjectHeader(block, int(b.blocksize), oidNXSuperblock,
		objEphemeral|objectTypeNXSuperblock, objectTypeInvalid)

	// Phase 3: the descriptor area is wiped first so no stale checkpoint
	// superblock from a prior format can be mounted by mistake, then this
	// checkpoint's mapping block and superblock copy go into it. The primary
	// superblock lands at block zero last.
	if err := b.wipeArea(b.cpDescBase, uint64(b.cpDescBlocks)); err != nil {
		return err
	}
	if err := b.writeCheckpointMap(b.cpMapBno); err != nil {
		return err
	}
	if err := b.writeCheckpointSuper(b.cpSbBno, block); err != nil {
		return err
	}
	return b.writeBlock(block, nxBlockNum)
}

// wipeArea zeroes blocks blocks starting at start.
func (b *builder) wipeArea(start, blocks uint64) error {
	zero := b.zeroedBlock()
	for bno := start; bno < start+blocks; bno++ {
		if err := b.writeBlock(zero, bno); err != nil {
			return err
		}
	}
	return nil
}

// fillCheckpointAreas records the checkpoint areas in the superblock. The one
// checkpoint occupies the first two descriptor blocks (the mapping block and
// this superblock copy) and totalBlkcnt data blocks (the ephemeral objects).
func (b *builder) fillCheckpointAreas(sb *nxSuperblock) {
	sb.XpDescBase = b.cpDescBase
	sb.XpDescBlocks = b.cpDescBlocks
	sb.XpDescLen = 2
	sb.XpDescNext = 2
	sb.XpDescIndex = 0

	sb.XpDataBase = b.cpDataBase
	sb.XpDataBlocks = b.cpDataBlocks
	sb.XpDataLen = b.totalBlkcnt
	sb.XpDataNext = b.totalBlkcnt
	sb.XpDataIndex = 0
}

// maxVolumes returns the container's maximum volume count: one per 512 MiB,
// capped at the format maximum.
func maxVolumes(size uint64) uint32 {
	return uint32(min(divRoundUp(size, 512*1024*1024), nxMaxFileSystems))
}

// fillEphemeralInfo sets the container's first ephemeral-info word, which encodes
// the minimum ephemeral block count, the maximum ephemeral structure count and
// the info version. Small containers use the main free queue's node limit as the
// minimum; larger ones use the format's fixed minimum.
func (b *builder) fillEphemeralInfo(info *uint64) {
	containerSize := b.blockCount * uint64(b.blocksize)
	minBlockCount := uint64(nxEphMinBlockCount)
	if containerSize < 128*1024*1024 {
		minBlockCount = uint64(b.mainFreeQueueNodeLimit())
	}
	*info = (minBlockCount << 32) |
		(nxMaxFileSystemEphStructs << 16) |
		nxEphInfoVersion1
}

// fillMetaCrypto fills a volume's wrapped-meta-crypto-state field. On an
// unencrypted volume this carries only the version and a no-protection class.
func fillMetaCrypto(wmcs *wrappedMetaCryptoState) {
	wmcs.MajorVersion = wmcsMajorVersion
	wmcs.MinorVersion = wmcsMinorVersion
	wmcs.Cpflags = 0
	wmcs.PersistentClass = protectionClassF
	wmcs.KeyOSVersion = 0
	wmcs.KeyRevision = 1
}

// volIncompatFeatures returns the volume's incompatible-feature flags, which
// encode the case- and normalization-sensitivity of the name comparison.
func (b *builder) volIncompatFeatures() uint64 {
	switch {
	case b.normSensitive:
		return 0
	case b.caseSensitive:
		return incompatNormalizationInsensitive
	default:
		return incompatCaseInsensitive
	}
}

// writeVolume writes the volume: its four trees (object map, catalog,
// extent-reference and snapshot-metadata) and its file content, then the volume
// superblock that references them.
func (b *builder) writeVolume(bno, oid uint64) error {
	// Write the trees and file data first; the superblock fields below only
	// record where each landed.
	if err := b.writeObjectMap(b.firstVolOmapBno, true /* volume omap */); err != nil {
		return err
	}
	if err := b.makeCatTree(b.firstVolCatRootBno, firstVolCatRootOID); err != nil {
		return err
	}
	// The extent-reference tree holds one physical-extent record per file data
	// extent; the snapshot-metadata tree stays empty.
	if err := b.makeExtrefRoot(b.firstVolExtrefRootBno, b.firstVolExtrefRootBno); err != nil {
		return err
	}
	if err := b.writeEmptyTree(b.firstVolSnapRootBno, b.firstVolSnapRootBno, objectTypeSnapMetaTree); err != nil {
		return err
	}
	if err := b.writeFileData(); err != nil {
		return err
	}

	// Populate the volume superblock field by field.
	//
	// FsAllocCount is what fsck_apfs cross-checks: the blocks the volume owns are
	// the five of an empty volume (its four tree roots plus the omap structure)
	// plus every extra catalog leaf, extref leaf and file-data block in the
	// post-pool region. The root and private directories are not counted as
	// directories.
	vsb := &apfsSuperblock{}
	vsb.Magic = apfsMagic
	vsb.Features = featureHardlinkMapRecords
	vsb.IncompatibleFeatures = b.volIncompatFeatures()
	vsb.FsAllocCount = 5 + b.postIPBlocks
	fillMetaCrypto(&vsb.MetaCrypto)
	vsb.RootTreeType = objVirtual | objectTypeBtree
	vsb.ExtentrefTreeType = objPhysical | objectTypeBtree
	vsb.SnapMetaTreeType = objPhysical | objectTypeBtree
	vsb.OmapOID = b.firstVolOmapBno
	vsb.RootTreeOID = firstVolCatRootOID
	vsb.ExtentrefTreeOID = b.firstVolExtrefRootBno
	vsb.SnapMetaTreeOID = b.firstVolSnapRootBno
	vsb.NextObjID = b.nextObjID()
	vsb.NumFiles = b.numFiles
	vsb.NumDirectories = b.numDirs
	vsb.NumSymlinks = b.numSymlinks
	vsb.TotalBlocksAlloced = b.postIPBlocks
	vsb.VolUUID = b.volUUID
	vsb.FsFlags = fsUnencrypted
	copy(vsb.FormattedBy.ID[:], formatterID)
	vsb.FormattedBy.Timestamp = b.timestamp
	vsb.FormattedBy.LastXID = mkfsXID
	copy(vsb.Volname[:], b.label)
	vsb.NextDocID = minDocID

	block := b.zeroedBlock()
	marshalInto(block, vsb)
	setObjectHeader(block, int(b.blocksize), oid, objVirtual|objectTypeFS, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// writeCheckpointMap writes the checkpoint's mapping block, which records where
// each ephemeral object of this checkpoint lives on disk.
func (b *builder) writeCheckpointMap(bno uint64) error {
	block := b.zeroedBlock()

	off := sizeofObjPhys
	binary.LittleEndian.PutUint32(block[off:], checkpointMapLast) // cpm_flags
	mapBase := sizeofObjPhys + 8                                  // header: obj + flags + count

	idx := 0
	addMapping := func(typ, subtype, mapSize uint32, oid, paddr uint64) {
		m := block[mapBase+idx*sizeofCheckpointMapping:]
		binary.LittleEndian.PutUint32(m[0:], typ)     // cpm_type
		binary.LittleEndian.PutUint32(m[4:], subtype) // cpm_subtype
		binary.LittleEndian.PutUint32(m[8:], mapSize) // cpm_size
		binary.LittleEndian.PutUint64(m[24:], oid)    // cpm_oid
		binary.LittleEndian.PutUint64(m[32:], paddr)  // cpm_paddr
		idx++
	}

	addMapping(objEphemeral|objectTypeNXReaper, objectTypeInvalid, b.blocksize, reaperOID, b.reaperBno)
	addMapping(objEphemeral|objectTypeSpaceman, objectTypeInvalid, b.spacemanSz, spacemanOID, b.spacemanBno)
	addMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, ipFreeQueueOID, b.ipFreeQueueBno)
	addMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, mainFreeQueueOID, b.mainFreeQueueBno)

	binary.LittleEndian.PutUint32(block[off+4:], uint32(idx)) // cpm_count

	setObjectHeader(block, int(b.blocksize), bno, objPhysical|objectTypeCheckpointMap, objectTypeInvalid)
	return b.writeBlock(block, bno)
}

// writeCheckpointSuper writes the checkpoint's superblock copy — a duplicate of
// the primary superblock placed in the descriptor area.
func (b *builder) writeCheckpointSuper(bno uint64, sbCopy []byte) error {
	block := b.zeroedBlock()
	copy(block, sbCopy)
	return b.writeBlock(block, bno)
}

// writeReaper writes an empty reaper object (no objects are pending reclaim in a
// freshly formatted container).
func (b *builder) writeReaper(bno, oid uint64) error {
	reaper := &nxReaperPhys{}
	reaper.NextReapID = 1
	reaper.Flags = nrBHMFlag
	reaper.StateBufferSize = b.blocksize - sizeofNXReaperPhys

	block := b.zeroedBlock()
	marshalInto(block, reaper)
	setObjectHeader(block, int(b.blocksize), oid, objEphemeral|objectTypeNXReaper, objectTypeInvalid)
	return b.writeBlock(block, bno)
}
