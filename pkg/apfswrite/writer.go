// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// CreateOptions configures CreateContainer. The zero value is valid: it formats
// a 4096-byte-block, normalization-sensitive-by-default, case-insensitive
// volume named "untitled" with deterministic default UUIDs.
type CreateOptions struct {
	// BlockSize is the container block size in bytes. Zero means 4096, and 4096
	// is the only accepted value.
	//
	// Deprecated: the format permits any power of two from NX_MINIMUM_BLOCK_SIZE
	// to NX_MAXIMUM_BLOCK_SIZE, but this writer does not produce a sound
	// container at any of them, so the field no longer selects anything. It is
	// kept because it is public API; see the error returned by CreateContainer
	// for the evidence.
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

	// Snapshots are APFS snapshots to create on the volume, each capturing the
	// built state (the volume's contents at creation time). They are written as
	// spec-compliant snapshots — a snapshot-metadata record pair, a physical copy of the
	// physical volume superblock, an object-map snapshot entry and pinned extent
	// refcounts — recognized by macOS. Names must be unique and non-empty.
	Snapshots []SnapshotSpec

	// FixedTime is the timestamp written to every clock-derived on-disk field —
	// the volume superblock's formatted-by and last-modified times and every
	// directory entry's date-added — and the default for entries and snapshots
	// that carry no ModTime. The zero value selects DefaultTime, so a container
	// is byte-identical for identical input without the caller doing anything.
	FixedTime time.Time

	// ClampModTimes applies the SOURCE_DATE_EPOCH rule to entry modification
	// times: an Entry.ModTime later than the resolved FixedTime is written as
	// FixedTime, while earlier times are preserved. It has no effect on entries
	// that supply no ModTime.
	ClampModTimes bool

	// Role is the volume's role (apfs_role): what the volume is for, such as
	// the system or data volume of a macOS install. Use the apfs.VolumeRole*
	// constants. Zero means no role, which is what a plain data image wants.
	Role uint16

	// VolumeGroupID identifies the volume group this volume belongs to
	// (apfs_volume_group_id) — the system/data pairing macOS has used since
	// Catalina. The zero value means the volume belongs to no group.
	//
	// Setting it requires Role to be apfs.VolumeRoleSystem, and also sets the
	// APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE feature flag, which is what actually
	// declares membership. The resulting group is incomplete — it has no data
	// volume — because this writer emits one volume per container.
	//
	// That flag makes the group's two members share one inode-number space, so
	// a grouped system volume numbers its inodes from UNIFIED_ID_SPACE_MARK
	// upward rather than from MIN_USER_INO_NUM. See inoBaseFor.
	VolumeGroupID [16]byte
}

// SnapshotSpec describes one APFS snapshot to create at build time.
type SnapshotSpec struct {
	// Name is the snapshot name (unique, non-empty, no NUL).
	Name string
	// ModTime is the snapshot's create/change time. Zero means a deterministic
	// default.
	ModTime time.Time
}

// Entry is one node of the directory tree written into the volume. It mirrors
// pkg/hfsplus's Entry in shape. The Mode's type bits select the kind of entry:
// a directory (os.ModeDir) carries its Children; a symbolic link
// (os.ModeSymlink) carries its target path in Data; otherwise it is a regular
// file carrying its bytes in Data. When Mode is zero, an Entry with Children is
// treated as a directory and any other Entry as a regular file (0644).
type Entry struct {
	// Name is the entry's file name (no path separators, no NUL).
	Name string
	// Mode carries the entry type (dir/symlink) and permission bits. When zero,
	// sensible defaults are applied (0755 dirs, 0644 files).
	Mode os.FileMode
	// ModTime is written to the inode's create/mod/change/access times. When
	// zero, a fixed deterministic timestamp is used.
	ModTime time.Time
	// UID and GID are the inode's owner and group ids.
	UID, GID uint32
	// Data is the file content for a regular file (any size, may be empty), or
	// the target path for a symbolic link.
	Data []byte
	// Xattrs are the entry's extended attributes. Small values are stored
	// inside their attribute record; larger ones, and any resource fork, get a
	// data stream of their own.
	//
	// The com.apple.fs.symlink name is reserved: it is how APFS stores a
	// symbolic link's target, and the writer emits it itself.
	Xattrs map[string][]byte
	// Children are the entries contained in a directory.
	Children []*Entry

	// LinkGroup marks entries that are names for one and the same file. Two
	// regular files sharing a non-zero LinkGroup are written as hard links: one
	// inode, one copy of the content, and a directory entry each. The value is
	// an opaque grouping key, not an inode number — the writer assigns its own.
	//
	// It is ignored on directories and symbolic links, which cannot be linked.
	LinkGroup uint64
}

// isDirEntry reports whether e should be written as a directory. A zero Mode
// with Children present is treated as a directory (backwards compatible with
// callers that built trees before Mode existed).
func (e *Entry) isDirEntry() bool {
	if e.isSymlinkEntry() {
		return false
	}
	if e.Mode == 0 {
		return len(e.Children) > 0
	}
	return e.Mode.IsDir()
}

// isSymlinkEntry reports whether e is a symbolic link.
func (e *Entry) isSymlinkEntry() bool { return e.Mode&os.ModeSymlink != 0 }

// resolvedMode returns the on-disk inode mode (S_IFMT | perm) for e, applying
// default permission bits when Mode carries none.
func (e *Entry) resolvedMode() uint16 {
	perm := uint16(e.Mode.Perm())
	switch {
	case e.isSymlinkEntry():
		if perm == 0 {
			perm = 0o755
		}
		return sIFLNK | perm
	case e.isDirEntry():
		if perm == 0 {
			perm = 0o755
		}
		return sIFDIR | perm
	default:
		if perm == 0 {
			perm = 0o644
		}
		return sIFREG | perm
	}
}

// RootFile is a regular file to be created in the volume root directory.
type RootFile struct {
	// Name is the file name (no path separators).
	Name string
	// Data is the file content (any size, may be empty).
	Data []byte
}

// builderEntry holds the resolved on-disk placement for a single file-system tree
// entry (a directory or a regular file).
type builderEntry struct {
	name      string
	isDir     bool
	isSymlink bool   // true for a symbolic link (target stored in a symlink xattr)
	oid       uint64 // object identifier / inode number
	parent    uint64 // parent directory oid
	nchildren uint32 // directories: number of direct children

	// Inode metadata.
	mode  uint16 // S_IFMT | permission bits
	uid   uint32 // owner id
	gid   uint32 // group id
	mtime uint64 // create/mod/change/access time (ns since 1970 UTC)

	// Symbolic links: the target path bytes (stored in a com.apple.fs.symlink
	// extended attribute, not in a data stream).
	linkTarget []byte

	// Hard links. primary is the entry holding the inode when this one is a
	// second or later name for it, and nil when this entry is that holder.
	// siblings lists every name for the file, and is populated on the holder
	// only; nlink is its length.
	primary  *builderEntry
	siblings []siblingName
	nlink    uint32
	// siblingID is this name's own sibling record, referenced from its
	// directory entry. Zero when the file has only one name.
	siblingID uint64

	// Extended attributes small enough to store inside their record.
	xattrs map[string][]byte
	// Extended attributes too large to embed, or required by the format to be
	// stream based. Each owns a synthetic stream entry holding its content.
	streamedXattrs map[string]*builderEntry
	// xattrFlags are the inode internal_flags the attributes require. Several
	// flags must agree exactly with whether a particular attribute is present.
	xattrFlags uint64
	// bsdFlags are the chflags(2) flags for the inode's bsd_flags field.
	// UF_COMPRESSED is the one that matters here, and like xattrFlags it has to
	// agree with the attribute it describes.
	bsdFlags uint32

	// Regular files with content (non-empty streams).
	data        []byte
	hasStream   bool   // true for every regular file (has a DSTREAM xfield + DSTREAM_ID record)
	dataBlock   uint64 // physical block number of the first content block (0 if empty)
	blocks      uint64 // number of allocation blocks in the file's extent (0 for a 0-byte file)
	allocedSize uint64 // block-aligned allocated size in bytes (0 for a 0-byte file)
}

// siblingName is one name for a file that has several, as recorded in a
// sibling-link record.
type siblingName struct {
	id     uint64 // the sibling's own object id
	parent uint64 // the directory holding this name
	name   string
}

// Deterministic default UUIDs used when the caller leaves a UUID zero.
var (
	defaultContainerUUID = [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	defaultVolumeUUID    = [16]byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x49, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
)

// CreateContainer writes a complete, single-volume APFS container of sizeBytes
// (rounded down to a whole number of blocks) to w. The volume is either empty
// (just its root directory and the standard special inodes) or populated from
// opts.Root / opts.RootFiles with a directory tree of files, symbolic links and
// nested directories.
//
// If sizeBytes is 0 the image is sized automatically to fit its contents, with a
// floor of 512 KiB (the smallest container this writer produces).
func CreateContainer(w io.WriterAt, sizeBytes int64, opts *CreateOptions) error {
	if opts == nil {
		opts = &CreateOptions{}
	}

	b := &builder{w: w}

	// The format allows any power of two in [nxMinimumBlockSize,
	// nxMaximumBlockSize], and this writer's arithmetic is parameterised by
	// b.blocksize throughout, so larger sizes look supported. They are not, and
	// the containers produced are unsound rather than merely unreadable:
	//
	//	 8192   fsck_apfs and apfsck -cw both clean
	//	16384   fsck_apfs: "invalid btn_table_space (0, 1812)", no valid
	//	        checkpoint; apfsck: "Omap record: bad alignment for key or value"
	//	65536   fsck_apfs spins indefinitely rather than reaching a verdict
	//
	// Every one of them is also unreadable by pkg/apfs, which reads a fixed
	// 4096-byte container superblock and so checksums a different span than the
	// writer sealed (see the note in pkg/apfs/container_superblock.go). Emitting
	// an image that neither Apple's checker nor our own reader accepts is worse
	// than refusing, so refuse.
	b.blocksize = opts.BlockSize
	if b.blocksize == 0 {
		b.blocksize = nxDefaultBlockSize
	}
	if b.blocksize != nxDefaultBlockSize {
		return fmt.Errorf("apfswrite: unsupported block size %d: only %d is supported, "+
			"because this writer does not lay out a sound container at any other size",
			b.blocksize, nxDefaultBlockSize)
	}

	b.mainUUID = opts.ContainerUUID
	if b.mainUUID == ([16]byte{}) {
		b.mainUUID = defaultContainerUUID
	}

	// The container's single volume. Everything the caller asked for about a
	// volume rather than about the container lands here.
	v := &volBuild{index: 0}
	b.vols = []*volBuild{v}

	v.label = opts.VolumeName
	if v.label == "" {
		v.label = "untitled"
	}
	if len(v.label)+1 > volnameLen {
		return fmt.Errorf("apfswrite: volume label too long")
	}

	v.volUUID = opts.VolumeUUID
	if v.volUUID == ([16]byte{}) {
		v.volUUID = defaultVolumeUUID
	}

	v.role = opts.Role
	v.volumeGroupID = opts.VolumeGroupID
	if err := validateRole(v.role, v.volumeGroupID); err != nil {
		return err
	}
	v.inoBase = inoBaseFor(v.role, v.volumeGroupID)

	// A normalization-insensitive, case-insensitive volume is the default; the
	// public API exposes only the CaseSensitive toggle.
	v.caseSensitive = opts.CaseSensitive
	v.normSensitive = false

	// The volume bound to its container, for the volume-scoped work below.
	vc := volCtx{b, v}

	// Resolve the timestamp before the tree and the snapshots, both of which
	// stamp it into records.
	fixed := opts.FixedTime
	if fixed.IsZero() {
		fixed = DefaultTime
	}
	b.timestamp = uint64(fixed.UnixNano())
	b.clampTime = opts.ClampModTimes

	// Resolve the user directory tree (nested dirs + regular files of any size)
	// so its space requirements can size the image when the caller passes 0.
	if err := vc.setTree(opts); err != nil {
		return err
	}

	// Resolve the requested snapshots (xids, live xid, block count).
	if err := vc.setSnapshots(opts); err != nil {
		return err
	}

	// The container has a floor of 512 KiB.
	const minBytes = 512 * 1024
	if sizeBytes == 0 {
		// Size the image to comfortably hold the post-pool payload (extra
		// file-system tree leaves, extentref leaves, file data, snapshot objects) plus the
		// fixed metadata, block-aligned, with headroom for the pool and
		// checkpoint areas.
		payload := vc.numFSTreeLeaves + vc.numExtentrefLeaves + vc.fileDataBlocks + vc.snapBlocks
		needBlocks := payload + payload/8 + 2048
		sizeBytes = max(int64(needBlocks)*int64(b.blocksize), minBytes)
	}
	b.mainBlockCount = uint64(sizeBytes) / uint64(b.blocksize)
	b.blockCount = b.mainBlockCount
	if b.mainBlockCount*uint64(b.blocksize) < minBytes {
		return fmt.Errorf("apfswrite: container too small (%d bytes); minimum is %d", sizeBytes, minBytes)
	}

	// Lay the container out, then write it. Geometry comes first (device counts,
	// the internal pool and the spaceman extent); knowing the spaceman extent
	// lets the checkpoint data area be sized to exactly the ephemeral objects it
	// must hold. Then the fixed block positions, then the placement that depends
	// on them, then the write.
	if err := b.spacemanGeometry(); err != nil {
		return err
	}
	b.sizeCheckpointAreas()
	vc.layoutFixedBlocks()
	if err := vc.spacemanPlacement(); err != nil {
		return err
	}
	if err := b.assemble(); err != nil {
		return err
	}

	// Only the blocks actually used are written, so grow the image to its full
	// size by writing its final byte.
	total := b.mainBlockCount * uint64(b.blocksize)
	if total > 0 {
		if _, err := w.WriteAt([]byte{0}, int64(total)-1); err != nil {
			return fmt.Errorf("apfswrite: sizing image: %w", err)
		}
	}
	return nil
}

// CreateContainerFromDir walks srcDir into an Entry tree — regular files,
// directories and symbolic links, preserving each entry's mode, uid/gid and
// modification time — and writes a populated APFS container of sizeBytes to w
// via CreateContainer. It mirrors hfsplus.CreateImageFromDir. srcDir's own name
// is not used; its contents become the volume root's children. When sizeBytes
// is 0 the image is sized automatically to fit the tree.
//
// The conversion is lossy: device nodes, FIFOs and sockets are skipped, and
// extended attributes, resource forks, ACLs, BSD flags and hard links are not
// carried across. This function discards the account of what was lost; call
// EntryTreeFromDir directly to see it.
func CreateContainerFromDir(w io.WriterAt, sizeBytes int64, srcDir string, opts *CreateOptions) error {
	root, _, err := EntryTreeFromDir(srcDir, nil)
	if err != nil {
		return err
	}
	var o CreateOptions
	if opts != nil {
		o = *opts
	}
	o.Root = root
	return CreateContainer(w, sizeBytes, &o)
}

// builder holds all file system parameters and the fixed block layout while the
// container is being written: the requested geometry, the resolved directory
// tree, and every block position derived from them.
type builder struct {
	w io.WriterAt

	// Parameters.
	blocksize      uint32
	blockCount     uint64
	mainBlockCount uint64
	mainUUID       [16]byte

	// Checkpoint areas, sized and positioned for this container.
	xpDescBase   uint64
	xpDescBlocks uint32
	xpDataBase   uint64
	xpDataBlocks uint32
	xpEnd        uint64

	// Fixed block numbers derived from the checkpoint areas.
	xpMapPaddr        uint64
	xpSuperPaddr      uint64
	mainOmapPaddr     uint64
	mainOmapRootPaddr uint64
	ipBmapBase        uint64

	// Ephemeral objects (eph_info).
	reaperPaddr        uint64
	spacemanPaddr      uint64
	spacemanSz         uint32
	spacemanBlockCount uint32
	ipFreeQueuePaddr   uint64
	mainFreeQueuePaddr uint64
	totalBlockCount    uint32

	// Space-manager geometry, populated by spacemanGeometry/spacemanPlacement.
	sm spacemanLayout

	// vols are the container's volumes, in the order their object ids and
	// FsOID slots are assigned.
	vols []*volBuild

	// Post-internal-pool allocation region. All blocks the volumes own beyond
	// the fixed metadata are laid out contiguously starting at postIPBase.
	postIPBase   uint64
	postIPBlocks uint64

	// liveXID is the container's live transaction id, one past the newest
	// snapshot on any volume. Transaction ids are the container's, not a
	// volume's.
	liveXID uint64

	// timestamp is the resolved CreateOptions.FixedTime in nanoseconds since
	// 1970 UTC. It is written to every clock-derived on-disk field and is the
	// default for entries and snapshots that carry no time of their own.
	timestamp uint64
	// clampTime carries CreateOptions.ClampModTimes into entryTime.
	clampTime bool
}

// volBuild is everything that belongs to one volume rather than to the
// container: what the caller asked for, the tree it resolved to, and every
// block position derived from it.
//
// It is separate from builder so a container can hold more than one. The fields
// were deliberately removed from builder rather than left in place: with volCtx
// promoting both, a leftover would still compile and would silently shadow the
// volume's own copy.
type volBuild struct {
	// Parameters.
	label         string
	volUUID       [16]byte
	role          uint16   // apfs_role
	volumeGroupID [16]byte // apfs_volume_group_id
	inoBase       uint64   // added to the user inode numbers; see inoBaseFor
	caseSensitive bool
	normSensitive bool

	// index is the volume's position in the container, which fixes its object
	// ids and its slot in the superblock's FsOID table.
	index uint64

	// Fixed block numbers for this volume's own objects.
	volPaddr           uint64
	omapPaddr          uint64
	omapRootPaddr      uint64
	fsTreeRootPaddr    uint64
	extentrefRootPaddr uint64
	snapRootPaddr      uint64

	// The user directory tree, flattened into file-system tree entries in oid order,
	// plus the subset that are regular files with a data extent.
	entries     []*builderEntry
	streamFiles []*builderEntry
	// xattrStreams are the synthetic stream entries backing extended
	// attributes too large to embed. They are also in streamFiles, which is
	// what gets them blocks, an extent and a place in the extentref tree; this
	// list exists so their object ids can be accounted for separately.
	xattrStreams []*builderEntry
	symlinks     []*builderEntry
	numFiles     uint64 // regular files (user)
	numDirs      uint64 // directories (user, excludes root and private-dir)
	numSymlinks  uint64 // symbolic links (user)

	// file-system tree shape, decided in setTree from the record sizes.
	numFSTreeLeaves uint64 // extra leaf nodes when the file-system tree is a 2-level tree
	fsTreeTwoLevel  bool   // true when the file-system tree needs an index root + leaves

	// Extent-reference B-tree shape, decided in setTree from the extent count.
	numExtentrefLeaves uint64 // leaf nodes when the extentref tree is a 2-level tree
	extentrefTwoLevel  bool   // true when the extentref tree needs an index root + leaves

	// Physical-block bases within the post-internal-pool region. fsTreeLeafBase is
	// the first extra file-system tree leaf; extentrefLeafBase the first extra extentref leaf;
	// fileDataBase the first block of file content.
	fsTreeLeafBase    uint64
	extentrefLeafBase uint64
	fileDataBase      uint64
	fileDataBlocks    uint64

	// Snapshots. Each captures the built state (snapshot == live). The snapshot
	// objects (a per-snapshot snapshot volume superblock + snap_meta_ext, and one shared
	// object-map snapshot tree) live at the end of the post-internal-pool region.
	snapshots        []*snapBuild
	snapBase         uint64 // first block of the snapshot object region
	snapBlocks       uint64 // total blocks in the snapshot object region
	volSnapTreePaddr uint64 // the volume omap's snapshot tree (0 when no snapshots)

}

// volCtx is a builder together with one of its volumes. Volume-scoped methods
// take it as their receiver, and field promotion means their bodies read the
// same whether a name belongs to the container or to the volume.
type volCtx struct {
	*builder
	*volBuild
}

// vol returns the container's i'th volume bound to the builder.
func (b *builder) vol(i uint64) volCtx { return volCtx{b, b.vols[i]} }

// only returns the container's single volume. It marks the places that still
// assume one volume, so they are easy to find when there can be several.
func (b *builder) only() volCtx { return b.vol(0) }

// DefaultTime is the timestamp used when CreateOptions.FixedTime is unset. It is
// a fixed value rather than the wall clock so that identical input produces
// identical bytes: a container built twice is byte-for-byte the same.
var DefaultTime = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

// validateRole rejects role and volume-group combinations that produce an image
// a checker will reject, so the caller gets an error rather than a container
// that only fails later under apfsck or macOS.
//
// A volume's role is a single value, never a combination: every checker matches
// apfs_role against the defined values exactly.
//
// A volume group is a system/data pair, and this writer emits one volume per
// container, so a complete group cannot be represented yet (multi-volume
// containers are a roadmap item). The system volume is the half that stands
// alone: apfsck treats a group whose data volume is absent as an oddity rather
// than corruption, but a group whose *system* volume is absent is a hard error.
// So a grouped volume must be the system one.
func validateRole(role uint16, groupID [16]byte) error {
	if !apfs.IsValidVolumeRole(role) {
		return fmt.Errorf("apfswrite: invalid volume role %#04x: a volume has exactly one role, and roles are not combined", role)
	}
	if groupID == ([16]byte{}) {
		return nil
	}
	if role != apfs.VolumeRoleSystem {
		return fmt.Errorf("apfswrite: a volume in a volume group must have the system role, not %q: "+
			"a group is a system/data pair, and this writer emits a single volume per container, "+
			"so the data half cannot be written alongside it", apfs.VolumeRoleString(role))
	}
	return nil
}

// inoBaseFor returns the amount added to the user inode numbers this volume
// allocates.
//
// A volume group shares one inode-number space across its two members, which is
// what APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE declares. The space is divided at
// UNIFIED_ID_SPACE_MARK: the data volume numbers below it, the system volume at
// or above it, so an inode number identifies a file across the pair. The flag
// is set on both members, so it alone does not say which half a volume is; the
// role does, and only the system volume shifts.
//
// The reserved numbers below MIN_USER_INO_NUM do not shift, which is where the
// spec and Apple's own tools disagree. The spec (Inode Numbers) says the system
// volume "reserves each of the inode numbers listed above but with
// UNIFIED_ID_SPACE_MARK added to them", giving 0x0800000000000002 for its root
// directory. fsck_apfs rejects exactly that: writing the root at the shifted
// number makes it count the root and private directories as ordinary ones
// ("apfs_num_directories is not valid (expected 3, actual 1)"), and shifting
// ROOT_DIR_PARENT alongside it produces "orphan directory record" for both
// special dentries. Its reserved-inode test is plainly oid < MIN_USER_INO_NUM
// against the unshifted numbers.
//
// So the reserved numbers stay put and the user inodes move. That is the only
// arrangement both fsck_apfs and the macOS driver accept: a volume written this
// way is fsck-clean and mounts, with the root reported as 2 and the user inodes
// as 0x0800000000000010 upward.
func inoBaseFor(role uint16, groupID [16]byte) uint64 {
	if groupID != ([16]byte{}) && role == apfs.VolumeRoleSystem {
		return unifiedIDSpaceMark
	}
	return 0
}

// firstUserIno is the lowest inode number this volume assigns to an entry:
// MIN_USER_INO_NUM in the volume's own half of the inode-number space.
func (b volCtx) firstUserIno() uint64 { return b.inoBase + minUserInoNum }

// entryTime resolves an entry's on-disk timestamp. A zero time means the
// builder's fixed default; otherwise the entry's own time is used, clamped down
// to that default when ClampModTimes is set (the SOURCE_DATE_EPOCH rule).
func (b *builder) entryTime(t time.Time) uint64 {
	if t.IsZero() {
		return b.timestamp
	}
	ns := uint64(t.UnixNano())
	if b.clampTime && ns > b.timestamp {
		return b.timestamp
	}
	return ns
}

// Object ids, assigned just past the format's reserved-oid range.
//
// The container's own objects come first and the volumes follow, each volume
// taking a fixed stride so a second one can be added without disturbing the
// first. The free queues used to sit between a volume's own ids, which left no
// room to grow: a volume's file-system tree leaves are numbered from its base,
// so the next volume would have had to start after them.
const (
	spacemanOID      = oidReservedCount     // 1024
	reaperOID        = spacemanOID + 1      // 1025
	ipFreeQueueOID   = reaperOID + 1        // 1026
	mainFreeQueueOID = ipFreeQueueOID + 1   // 1027
	firstVolOIDBase  = mainFreeQueueOID + 1 // 1028
)

// volOIDStride is how many object ids each volume reserves: its superblock, its
// file-system tree root, and one per leaf a 2-level tree may hold.
const volOIDStride = 2 + maxFSTreeLeaves

// volOID returns a volume's superblock object id, volFSTreeRootOID its
// file-system tree root, and volFSTreeLeafOID the id of one of its leaves.
func volOID(vol uint64) uint64                 { return firstVolOIDBase + vol*volOIDStride }
func volFSTreeRootOID(vol uint64) uint64       { return volOID(vol) + 1 }
func volFSTreeLeafOID(vol, leaf uint64) uint64 { return volOID(vol) + 2 + leaf }

// The first volume's ids, which is all this writer emits today.
const (
	firstVolOID           = firstVolOIDBase     // 1028
	firstVolFSTreeRootOID = firstVolOIDBase + 1 // 1029
	fsTreeLeafOIDBase     = firstVolOIDBase + 2 // 1030
)

// Checkpoint-area floors. fsck_apfs rejects a container whose checkpoint areas
// are smaller than eight blocks each, so both areas are reserved at no less than
// that even when the single static checkpoint uses fewer.
const (
	minCheckpointDescBlocks = 8
	minCheckpointDataBlocks = 8
)

// sizeCheckpointAreas sizes the two checkpoint areas. Because the whole
// container is one static checkpoint, each area is sized to exactly what that
// checkpoint writes, then raised to the format floor: the descriptor area holds
// the mapping block and the superblock copy (two blocks), and the data area
// holds the ephemeral objects — the reaper, the spaceman and the two free-queue
// roots — whose count spacemanGeometry recorded in totalBlockCount.
func (b *builder) sizeCheckpointAreas() {
	b.xpDescBlocks = minCheckpointDescBlocks
	b.xpDataBlocks = uint32(max(uint64(b.totalBlockCount), minCheckpointDataBlocks))
}

// layoutFixedBlocks assigns every fixed block position, given the sized
// checkpoint areas. The descriptor area starts right after block zero; the data
// area follows it; the container object map, the volume superblock and its trees
// follow the data area in a fixed order, and the internal-pool bitmap begins ten
// blocks past the data area (two of which — the Fusion middle-tree and
// write-back-cache slots — are intentionally left unused).
func (b volCtx) layoutFixedBlocks() {
	b.xpDescBase = nxBlockNum + 1
	b.xpDataBase = b.xpDescBase + uint64(b.xpDescBlocks)
	b.xpEnd = b.xpDataBase + uint64(b.xpDataBlocks)

	b.xpMapPaddr = b.xpDescBase + b.liveCheckpointIndex()
	b.xpSuperPaddr = b.xpMapPaddr + 1
	b.mainOmapPaddr = b.xpEnd
	b.mainOmapRootPaddr = b.xpEnd + 1
	b.volPaddr = b.xpEnd + 2
	b.omapPaddr = b.xpEnd + 3
	b.omapRootPaddr = b.xpEnd + 4
	b.fsTreeRootPaddr = b.xpEnd + 5
	b.extentrefRootPaddr = b.xpEnd + 6
	b.snapRootPaddr = b.xpEnd + 7
	b.ipBmapBase = b.xpEnd + 10 // +8 and +9 are the unused Fusion slots
}

// writeBlocks writes count blocks of data starting at block number paddr.
func (b *builder) writeBlocks(data []byte, paddr uint64) error {
	off := int64(paddr) * int64(b.blocksize)
	if _, err := b.w.WriteAt(data, off); err != nil {
		return fmt.Errorf("apfswrite: write at block %d: %w", paddr, err)
	}
	return nil
}

// writeBlock writes a single block of data at block number paddr.
func (b *builder) writeBlock(data []byte, paddr uint64) error {
	return b.writeBlocks(data, paddr)
}

// zeroedBlock returns a zeroed buffer of count blocks.
func (b *builder) zeroedBlocks(count int) []byte {
	return make([]byte, count*int(b.blocksize))
}

func (b *builder) zeroedBlock() []byte {
	return b.zeroedBlocks(1)
}

// The space-manager free-queue node limits (sfq_tree_node_limit) are an
// interoperability requirement, not a free choice: Apple's APFS implementation
// validates them when it mounts a volume and refuses to mount one whose limits
// differ from what its own formatter would have written — verified here against
// hdiutil, which rejects any other value. They are therefore reproduced as
// functional constants of the format. The internal-pool queue scales with the
// pool's chunk count and the main-device queue with the device's block count;
// both avoid the value 2, which Apple's implementation treats as invalid.

// avoidNodeLimit2 substitutes 3 for a computed limit of 2, which the format
// rejects.
func avoidNodeLimit2(n uint16) uint16 {
	if n == 2 {
		return 3
	}
	return n
}

// ipFreeQueueNodeLimit is the internal-pool free queue's node cap.
func (b *builder) ipFreeQueueNodeLimit() uint16 {
	chunks := b.sm.totalChunkCount
	return avoidNodeLimit2(uint16(3*(chunks+751)/1127 - 1))
}

// mainFreeQueueNodeLimit is the main device's free queue node cap.
func (b *builder) mainFreeQueueNodeLimit() uint16 {
	const blocks1G, blocks4G = 0x40000, 0x100000
	blocks := b.mainBlockCount
	var n uint16
	switch {
	case blocks < blocks1G:
		n = uint16(1 + (blocks-1)/4544)
	case blocks < blocks4G:
		n = uint16(116 + (blocks-261281)/2272)
	default:
		n = 512
	}
	return avoidNodeLimit2(n)
}

// divRoundUp computes ceil(n/d).
func divRoundUp(n, d uint64) uint64 { return (n + d - 1) / d }

// roundUp rounds x up to the next multiple of y.
func roundUp(x, y uint64) uint64 { return ((x - 1) | (y - 1)) + 1 }
