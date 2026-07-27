// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// Children are the entries contained in a directory.
	Children []*Entry
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

	// A normalization-insensitive, case-insensitive volume is the default; the
	// public API exposes only the CaseSensitive toggle.
	b.caseSensitive = opts.CaseSensitive
	b.normSensitive = false

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
	if err := b.setTree(opts); err != nil {
		return err
	}

	// Resolve the requested snapshots (xids, live xid, block count).
	if err := b.setSnapshots(opts); err != nil {
		return err
	}

	// The container has a floor of 512 KiB.
	const minBytes = 512 * 1024
	if sizeBytes == 0 {
		// Size the image to comfortably hold the post-pool payload (extra
		// file-system tree leaves, extentref leaves, file data, snapshot objects) plus the
		// fixed metadata, block-aligned, with headroom for the pool and
		// checkpoint areas.
		payload := b.numFSTreeLeaves + b.numExtentrefLeaves + b.fileDataBlocks + b.snapBlocks
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
	b.layoutFixedBlocks()
	if err := b.spacemanPlacement(); err != nil {
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
func CreateContainerFromDir(w io.WriterAt, sizeBytes int64, srcDir string, opts *CreateOptions) error {
	root, err := entryFromDir(srcDir)
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

// entryFromDir builds an Entry tree rooted at dir (dir's own name is dropped;
// its children become the returned root's children).
func entryFromDir(dir string) (*Entry, error) {
	children, err := readDirEntries(dir)
	if err != nil {
		return nil, err
	}
	return &Entry{Children: children}, nil
}

// readDirEntries reads one directory level into Entry nodes, recursing into
// subdirectories. Symlinks are captured as their target path; regular files as
// their bytes. Mode, mtime and (where the OS exposes them) uid/gid are copied.
func readDirEntries(dir string) ([]*Entry, error) {
	fis, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, fi := range fis {
		full := filepath.Join(dir, fi.Name())
		info, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		e := &Entry{Name: fi.Name(), Mode: info.Mode(), ModTime: info.ModTime()}
		if st, ok := info.Sys().(interface {
			Uid() uint32
			Gid() uint32
		}); ok {
			e.UID, e.GID = st.Uid(), st.Gid()
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err != nil {
				return nil, err
			}
			e.Data = []byte(target)
		case info.IsDir():
			kids, err := readDirEntries(full)
			if err != nil {
				return nil, err
			}
			e.Children = kids
		default:
			data, err := os.ReadFile(full)
			if err != nil {
				return nil, err
			}
			e.Data = data
		}
		out = append(out, e)
	}
	return out, nil
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
	label          string
	mainUUID       [16]byte
	volUUID        [16]byte
	caseSensitive  bool
	normSensitive  bool

	// Checkpoint areas, sized and positioned for this container.
	xpDescBase   uint64
	xpDescBlocks uint32
	xpDataBase   uint64
	xpDataBlocks uint32
	xpEnd        uint64

	// Fixed block numbers derived from the checkpoint areas.
	xpMapPaddr                 uint64
	xpSuperPaddr               uint64
	mainOmapPaddr              uint64
	mainOmapRootPaddr          uint64
	firstVolPaddr              uint64
	firstVolOmapPaddr          uint64
	firstVolOmapRootPaddr      uint64
	firstVolFSTreeRootPaddr    uint64
	firstVolExtentrefRootPaddr uint64
	firstVolSnapRootPaddr      uint64
	ipBmapBase                 uint64

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

	// The user directory tree, flattened into file-system tree entries in oid order,
	// plus the subset that are regular files with a data extent.
	entries     []*builderEntry
	streamFiles []*builderEntry
	symlinks    []*builderEntry
	numFiles    uint64 // regular files (user)
	numDirs     uint64 // directories (user, excludes root and private-dir)
	numSymlinks uint64 // symbolic links (user)

	// file-system tree shape, decided in setTree from the record sizes.
	numFSTreeLeaves uint64 // extra leaf nodes when the file-system tree is a 2-level tree
	fsTreeTwoLevel  bool   // true when the file-system tree needs an index root + leaves

	// Extent-reference B-tree shape, decided in setTree from the extent count.
	numExtentrefLeaves uint64 // leaf nodes when the extentref tree is a 2-level tree
	extentrefTwoLevel  bool   // true when the extentref tree needs an index root + leaves

	// Post-internal-pool allocation region. All blocks the volume owns beyond
	// the fixed metadata are laid out contiguously starting at postIPBase, in
	// order: extra file-system tree leaf nodes, extra extent-reference leaf nodes, then
	// file data. This region may span several space-manager chunks.
	postIPBase   uint64
	postIPBlocks uint64

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
	liveXID          uint64 // the live volume's transaction id (> snapshot xids)
	snapBase         uint64 // first block of the snapshot object region
	snapBlocks       uint64 // total blocks in the snapshot object region
	volSnapTreePaddr uint64 // the volume omap's snapshot tree (0 when no snapshots)

	// timestamp is the resolved CreateOptions.FixedTime in nanoseconds since
	// 1970 UTC. It is written to every clock-derived on-disk field and is the
	// default for entries and snapshots that carry no time of their own.
	timestamp uint64
	// clampTime carries CreateOptions.ClampModTimes into entryTime.
	clampTime bool
}

// DefaultTime is the timestamp used when CreateOptions.FixedTime is unset. It is
// a fixed value rather than the wall clock so that identical input produces
// identical bytes: a container built twice is byte-for-byte the same.
var DefaultTime = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

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

// fsTreeLeafOIDBase is the first virtual object id handed to extra file-system tree leaf
// nodes (2-level file-system tree). It sits just past the named reserved object ids and
// below the container's NextOID reservation.
const fsTreeLeafOIDBase = mainFreeQueueOID + 1 // 1030

// Fixed object ids, assigned just past the format's reserved-oid range.
const (
	spacemanOID           = oidReservedCount          // 1024
	reaperOID             = spacemanOID + 1           // 1025
	firstVolOID           = reaperOID + 1             // 1026
	firstVolFSTreeRootOID = firstVolOID + 1           // 1027
	ipFreeQueueOID        = firstVolFSTreeRootOID + 1 // 1028
	mainFreeQueueOID      = ipFreeQueueOID + 1        // 1029
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
func (b *builder) layoutFixedBlocks() {
	b.xpDescBase = nxBlockNum + 1
	b.xpDataBase = b.xpDescBase + uint64(b.xpDescBlocks)
	b.xpEnd = b.xpDataBase + uint64(b.xpDataBlocks)

	b.xpMapPaddr = b.xpDescBase
	b.xpSuperPaddr = b.xpDescBase + 1
	b.mainOmapPaddr = b.xpEnd
	b.mainOmapRootPaddr = b.xpEnd + 1
	b.firstVolPaddr = b.xpEnd + 2
	b.firstVolOmapPaddr = b.xpEnd + 3
	b.firstVolOmapRootPaddr = b.xpEnd + 4
	b.firstVolFSTreeRootPaddr = b.xpEnd + 5
	b.firstVolExtentrefRootPaddr = b.xpEnd + 6
	b.firstVolSnapRootPaddr = b.xpEnd + 7
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
