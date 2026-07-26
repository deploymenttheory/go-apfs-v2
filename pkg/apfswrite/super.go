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
// mainFreeQueueOID; a two-level file-system tree additionally consumes one virtual id per
// leaf starting at fsTreeLeafOIDBase, which then becomes the high-water mark.
func (b *builder) nextContainerOID() uint64 {
	next := uint64(mainFreeQueueOID + 1)
	if b.fsTreeTwoLevel {
		next = fsTreeLeafOIDBase + b.numFSTreeLeaves
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
	if err := b.writeSpaceman(b.spacemanPaddr, spacemanOID); err != nil {
		return err
	}
	if err := b.writeReaper(b.reaperPaddr, reaperOID); err != nil {
		return err
	}
	if err := b.writeObjectMap(b.mainOmapPaddr, false /* container omap */); err != nil {
		return err
	}
	if err := b.writeVolume(b.firstVolPaddr, firstVolOID); err != nil {
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
	sb.NextXID = b.liveXID + 1
	b.fillCheckpointAreas(sb)
	sb.SpacemanOID = spacemanOID
	sb.OmapOID = b.mainOmapPaddr
	sb.ReaperOID = reaperOID
	sb.MaxFileSystems = maxVolumes(b.blockCount * uint64(b.blocksize))
	sb.FsOID[0] = firstVolOID
	b.fillEphemeralInfo(&sb.EphemeralInfo[0])

	// The container superblock (and its checkpoint copy) is the latest
	// checkpoint, stamped at the live xid.
	block := b.zeroedBlock()
	marshalInto(block, sb)
	setObjectHeaderXID(block, int(b.blocksize), oidNXSuperblock,
		objEphemeral|objectTypeNXSuperblock, objectTypeInvalid, b.liveXID)

	// Phase 3: the descriptor area is wiped first so no stale checkpoint
	// superblock from a prior format can be mounted by mistake, then this
	// checkpoint's mapping block and superblock copy go into it. The primary
	// superblock lands at block zero last.
	if err := b.wipeArea(b.xpDescBase, uint64(b.xpDescBlocks)); err != nil {
		return err
	}
	if err := b.writeCheckpointMap(b.xpMapPaddr); err != nil {
		return err
	}
	if err := b.writeCheckpointSuperblockCopy(b.xpSuperPaddr, block); err != nil {
		return err
	}
	return b.writeBlock(block, nxBlockNum)
}

// wipeArea zeroes blocks blocks starting at start.
func (b *builder) wipeArea(start, blocks uint64) error {
	zero := b.zeroedBlock()
	for paddr := start; paddr < start+blocks; paddr++ {
		if err := b.writeBlock(zero, paddr); err != nil {
			return err
		}
	}
	return nil
}

// fillCheckpointAreas records the checkpoint areas in the superblock. The one
// checkpoint occupies the first two descriptor blocks (the mapping block and
// this superblock copy) and totalBlockCount data blocks (the ephemeral objects).
func (b *builder) fillCheckpointAreas(sb *nxSuperblock) {
	sb.XpDescBase = b.xpDescBase
	sb.XpDescBlocks = b.xpDescBlocks
	sb.XpDescLen = 2
	sb.XpDescNext = 2
	sb.XpDescIndex = 0

	sb.XpDataBase = b.xpDataBase
	sb.XpDataBlocks = b.xpDataBlocks
	sb.XpDataLen = b.totalBlockCount
	sb.XpDataNext = b.totalBlockCount
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
		return apfsIncompatNormalizationInsensitive
	default:
		return apfsIncompatCaseInsensitive
	}
}

// volumeSuperblock builds the on-disk volume superblock fields shared by the
// live volume and every snapshot copy (they reference the same trees and
// carry the same accounting). The caller sets the xid-, oid- and
// snapshot-specific fields (NumSnapshots, object header) afterwards.
//
// FsAllocCount is what fsck_apfs cross-checks: the blocks the volume owns are the
// five of an empty volume (its four tree roots plus the omap structure) plus
// every extra file-system tree leaf, extentref leaf and file-data block in the post-pool
// region. The root and private directories are not counted as directories.
func (b *builder) volumeSuperblock() *apfsSuperblock {
	vsb := &apfsSuperblock{}
	vsb.Magic = apfsMagic
	vsb.Features = apfsFeatureHardlinkMapRecords
	vsb.IncompatibleFeatures = b.volIncompatFeatures()
	// The snapshot volume superblocks are superblocks, not fs-allocated blocks,
	// so they are excluded from the allocation count.
	vsb.FsAllocCount = 5 + b.postIPBlocks - uint64(len(b.snapshots))
	fillMetaCrypto(&vsb.MetaCrypto)
	vsb.RootTreeType = objVirtual | objectTypeBtree
	vsb.ExtentrefTreeType = objPhysical | objectTypeBtree
	vsb.SnapMetaTreeType = objPhysical | objectTypeBtree
	vsb.OmapOID = b.firstVolOmapPaddr
	vsb.RootTreeOID = firstVolFSTreeRootOID
	vsb.ExtentrefTreeOID = b.firstVolExtentrefRootPaddr
	vsb.SnapMetaTreeOID = b.firstVolSnapRootPaddr
	// Snapshots reserve an inode each past the highest user inode.
	vsb.NextObjID = b.nextObjID() + uint64(len(b.snapshots))
	vsb.NumFiles = b.numFiles
	vsb.NumDirectories = b.numDirs
	vsb.NumSymlinks = b.numSymlinks
	vsb.TotalBlocksAlloced = b.postIPBlocks
	vsb.VolUUID = b.volUUID
	vsb.FsFlags = apfsFSUnencrypted
	copy(vsb.FormattedBy.ID[:], formatterID)
	vsb.FormattedBy.Timestamp = b.timestamp
	vsb.FormattedBy.LastXID = formatXID
	copy(vsb.Volname[:], b.label)
	vsb.NextDocID = minDocID
	return vsb
}

// writeVolume writes the volume: its four trees (object map, file-system tree,
// extent-reference and snapshot-metadata) and its file content, then the live
// volume superblock referencing them, then any snapshots (snapshot volume superblocks +
// the object-map snapshot tree).
func (b *builder) writeVolume(paddr, oid uint64) error {
	// Write the trees and file data first; the superblock fields below only
	// record where each landed.
	if err := b.writeObjectMap(b.firstVolOmapPaddr, true /* volume omap */); err != nil {
		return err
	}
	if err := b.makeFSTree(b.firstVolFSTreeRootPaddr, firstVolFSTreeRootOID); err != nil {
		return err
	}
	// The extentref tree holds one physical-extent record per file data
	// extent. With snapshots the extents were created at (and are owned by) the
	// snapshot's transaction, so the live tree — which has no changes since the
	// last snapshot — is empty and each snapshot carries its own copy instead.
	if len(b.snapshots) > 0 {
		if err := b.writeEmptyTree(b.firstVolExtentrefRootPaddr, b.firstVolExtentrefRootPaddr, objectTypeBlockrefTree); err != nil {
			return err
		}
	} else if err := b.makeExtentrefRoot(b.firstVolExtentrefRootPaddr, b.firstVolExtentrefRootPaddr); err != nil {
		return err
	}
	if err := b.writeSnapMetaTree(b.firstVolSnapRootPaddr); err != nil {
		return err
	}
	if err := b.writeFileData(); err != nil {
		return err
	}

	// The live volume superblock, stamped at the live xid (past every snapshot).
	vsb := b.volumeSuperblock()
	vsb.NumSnapshots = uint64(len(b.snapshots))
	block := b.zeroedBlock()
	marshalInto(block, vsb)
	setObjectHeaderXID(block, int(b.blocksize), oid, objVirtual|objectTypeFS, objectTypeInvalid, b.liveXID)
	if err := b.writeBlock(block, paddr); err != nil {
		return err
	}

	// The per-snapshot snapshot volume superblocks and the volume's object-map snapshot
	// tree.
	return b.writeSnapshots()
}

// writeCheckpointMap writes the checkpoint's mapping block, which records where
// each ephemeral object of this checkpoint lives on disk.
func (b *builder) writeCheckpointMap(paddr uint64) error {
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

	addMapping(objEphemeral|objectTypeNXReaper, objectTypeInvalid, b.blocksize, reaperOID, b.reaperPaddr)
	addMapping(objEphemeral|objectTypeSpaceman, objectTypeInvalid, b.spacemanSz, spacemanOID, b.spacemanPaddr)
	addMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, ipFreeQueueOID, b.ipFreeQueuePaddr)
	addMapping(objEphemeral|objectTypeBtree, objectTypeSpacemanFreeQueue, b.blocksize, mainFreeQueueOID, b.mainFreeQueuePaddr)

	binary.LittleEndian.PutUint32(block[off+4:], uint32(idx)) // cpm_count

	// The checkpoint map belongs to this checkpoint, so it carries the same xid
	// as the checkpoint superblock (the live xid).
	setObjectHeaderXID(block, int(b.blocksize), paddr, objPhysical|objectTypeCheckpointMap, objectTypeInvalid, b.liveXID)
	return b.writeBlock(block, paddr)
}

// writeCheckpointSuperblockCopy writes the checkpoint's superblock copy — a duplicate of
// the primary superblock placed in the descriptor area.
func (b *builder) writeCheckpointSuperblockCopy(paddr uint64, sbCopy []byte) error {
	block := b.zeroedBlock()
	copy(block, sbCopy)
	return b.writeBlock(block, paddr)
}

// writeReaper writes an empty reaper object (no objects are pending reclaim in a
// freshly formatted container).
func (b *builder) writeReaper(paddr, oid uint64) error {
	reaper := &nxReaperPhys{}
	reaper.NextReapID = 1
	reaper.Flags = nrBHMFlag
	reaper.StateBufferSize = b.blocksize - sizeofNXReaperPhys

	block := b.zeroedBlock()
	marshalInto(block, reaper)
	setObjectHeader(block, int(b.blocksize), oid, objEphemeral|objectTypeNXReaper, objectTypeInvalid)
	return b.writeBlock(block, paddr)
}
