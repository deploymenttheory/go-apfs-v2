// HFS+ / HFSX volume writer: serialises an in-memory directory tree into a
// raw, mountable HFSX volume image (bytes).
//
// v1 produces a case-sensitive HFSX volume (signature "HX", version 5,
// catalog keyCompareType 0xBC / kHFSBinaryCompare), unjournaled, with no
// attributes (xattr) file. Binary key comparison means catalog ordering is a
// plain lexicographic compare of the big-endian UTF-16 name code units, so no
// Unicode case-folding table is needed.
//
// Extension point for a future case-insensitive "H+" v4 writer: switch the
// signature/version and set keyCompareType to 0xCF (kHFSCaseFolding); the
// catalog key comparison would then need Apple's FastUnicodeCompare fold
// table in place of compareCatalogKeys' binary compare. Everything else
// (layout, B-tree packing, forks, bitmap) is unchanged.
//
// All multi-byte on-disk fields are big-endian. Reuses the on-disk structs
// from types.go for serialisation.
package hfsplus

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Entry is one node of the directory tree to be written. A directory has
// Children; a regular file or symlink carries its bytes in Data (for a
// symlink, Data is the target path).
type Entry struct {
	Name     string
	Mode     os.FileMode // dir/symlink/perm bits
	ModTime  time.Time
	UID, GID uint32
	Data     []byte   // file content, or symlink target bytes
	Children []*Entry // directory children (writer sorts them)
}

// CreateOptions tunes image creation. The zero value is valid.
type CreateOptions struct {
	// BlockSize is the allocation block size in bytes (default 4096). Must be
	// a power of two >= 512.
	BlockSize uint32
	// FixedTime is the timestamp written to the volume header's create, modify
	// and checked dates, and the default for entries that carry no ModTime. The
	// zero value selects DefaultTime, so an image is byte-identical for
	// identical input without the caller doing anything.
	FixedTime time.Time
	// ClampModTimes applies the SOURCE_DATE_EPOCH rule to entry modification
	// times: an Entry.ModTime later than the resolved FixedTime is written as
	// FixedTime, while earlier times are preserved. It has no effect on entries
	// that supply no ModTime.
	ClampModTimes bool
	// VolumeUUID pins the volume's identifier. Only its first eight bytes reach
	// disk, because the HFS+ volume identifier is the 64-bit pair
	// FinderInfo[6]/FinderInfo[7]. The zero value derives a stable identifier
	// from the volume name and the resolved timestamp.
	VolumeUUID [16]byte
}

// DefaultTime is the timestamp used when CreateOptions.FixedTime is unset. It is
// a fixed value rather than the wall clock so that identical input produces
// identical bytes: an image built twice is byte-for-byte the same.
var DefaultTime = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

// internal per-node bookkeeping built from the Entry tree.
type fileNode struct {
	entry     *Entry
	name      string
	cnid      CatalogNodeID
	parent    CatalogNodeID
	isDir     bool
	isSymlink bool
	children  []*fileNode

	dataLen    int
	dataBlocks uint32
	dataStart  uint32 // first allocation block of the data fork
}

// layout describes where each metadata region and file data lives, in
// allocation blocks.
type layout struct {
	blockSize    int
	totalBlocks  uint32
	bitmapStart  uint32
	bitmapBlocks uint32
	extentsStart uint32
	extentBlocks uint32
	catalogStart uint32
	catalogBlks  uint32
	dataStart    uint32 // first file-data block
	firstFree    uint32 // first free block after all data
}

// CreateImage writes a raw HFSX volume image built from root into w. When
// sizeBytes is 0 a minimum size that fits all metadata and data is computed;
// otherwise sizeBytes (rounded down to a whole number of blocks) is used and
// must be large enough. volumeName becomes the root folder's catalog name.
func CreateImage(w io.WriterAt, sizeBytes int64, volumeName string, root *Entry, opts *CreateOptions) error {
	blockSize := 4096
	var o CreateOptions
	if opts != nil {
		o = *opts
		if o.BlockSize != 0 {
			blockSize = int(o.BlockSize)
		}
	}
	if blockSize < 512 || blockSize&(blockSize-1) != 0 {
		return fmt.Errorf("hfsplus: invalid block size %d", blockSize)
	}
	if root == nil {
		root = &Entry{}
	}
	defaultTime := o.FixedTime
	if defaultTime.IsZero() {
		defaultTime = DefaultTime
	}

	// 1. Flatten the tree, assign CNIDs, count files/folders.
	b := &builder{
		blockSize:   blockSize,
		defaultTime: defaultTime,
		clampTime:   o.ClampModTimes,
		volumeUUID:  o.VolumeUUID,
		nextCNID:    HFSFirstUserCatalogNodeID,
	}
	rootNode := b.flatten(root, volumeName)

	// 2. Determine catalog node count (independent of fork contents).
	tree0 := buildBTree(blockSize, b.catalogRecords(rootNode), HFSBinaryCompare, 0x00000006, 516, 0)
	catalogBlks := tree0.totalNodes

	// 3. Compute the layout (and total size).
	lay, err := b.computeLayout(sizeBytes, catalogBlks)
	if err != nil {
		return err
	}

	// 4. Assign each file's data extent now that dataStart is known.
	b.assignData(&lay)

	// 5. Build the final catalog and (empty) extents-overflow B-trees.
	catTree := buildBTree(blockSize, b.catalogRecords(rootNode), HFSBinaryCompare, 0x00000006, 516, 0)
	if catTree.totalNodes != catalogBlks {
		// Should never happen: node count is independent of fork values.
		return fmt.Errorf("hfsplus: catalog node count changed (%d -> %d)", catalogBlks, catTree.totalNodes)
	}
	extTree := buildBTree(blockSize, nil, 0, 0x00000002, 10, 0)

	// 6. Assemble the image.
	img := make([]byte, int64(lay.totalBlocks)*int64(blockSize))

	// Catalog nodes.
	for i, n := range catTree.nodes {
		copy(img[(int(lay.catalogStart)+i)*blockSize:], n)
	}
	// Extents-overflow nodes.
	for i, n := range extTree.nodes {
		copy(img[(int(lay.extentsStart)+i)*blockSize:], n)
	}
	// File data.
	b.writeFileData(img)

	// 7. Allocation bitmap.
	bitmap := b.buildBitmap(&lay)
	copy(img[int(lay.bitmapStart)*blockSize:], bitmap)

	// 8. Volume header (primary at 1024, alternate at end-1024).
	vh := b.volumeHeader(volumeName, &lay, catTree, extTree)
	vhBytes := marshalBE(&vh)
	copy(img[1024:], vhBytes)
	copy(img[len(img)-1024:], vhBytes)

	if _, err := w.WriteAt(img, 0); err != nil {
		return fmt.Errorf("hfsplus: writing image: %w", err)
	}
	return nil
}

// CreateImageFromDir walks srcDir into an Entry tree and writes it via
// CreateImage. Regular files, directories and symlinks are supported.
func CreateImageFromDir(w io.WriterAt, sizeBytes int64, volumeName, srcDir string, opts *CreateOptions) error {
	root, err := entryFromDir(srcDir)
	if err != nil {
		return err
	}
	return CreateImage(w, sizeBytes, volumeName, root, opts)
}

// entryFromDir builds an Entry tree rooted at dir (the directory's own name
// is not used; its children become the volume root's children).
func entryFromDir(dir string) (*Entry, error) {
	root := &Entry{}
	children, err := readDirEntries(dir)
	if err != nil {
		return nil, err
	}
	root.Children = children
	return root, nil
}

// isSpecialFile reports whether mode describes something this writer cannot
// model: a device node, FIFO or socket. os.ModeIrregular covers whatever else
// the platform may report that is neither a regular file, a directory nor a
// symbolic link.
func isSpecialFile(mode os.FileMode) bool {
	return mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeIrregular) != 0
}

// readDirEntries reads one directory level into Entry nodes, recursing into
// subdirectories. Device nodes, FIFOs and sockets are skipped: this writer
// cannot represent them, and reading one would hang or exhaust memory rather
// than fail cleanly.
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
		case isSpecialFile(info.Mode()):
			// This writer models regular files, directories and symbolic links.
			// Reading a special file as though it were regular does not merely
			// produce a wrong entry, it breaks the run: opening a FIFO blocks
			// until a writer appears, a character device such as /dev/zero
			// reads until memory runs out, and a socket fails outright. Skip it.
			continue
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

// builder holds writer state across the layout/build passes.
type builder struct {
	blockSize   int
	defaultTime time.Time
	clampTime   bool
	volumeUUID  [16]byte
	nextCNID    CatalogNodeID

	root      *fileNode
	allNodes  []*fileNode // every node including root
	fileNodes []*fileNode // files and symlinks (have data forks)

	fileCount   uint32
	folderCount uint32 // excludes the root folder
}

// flatten converts the Entry tree into fileNodes, assigning CNIDs depth-first
// with children sorted by name for determinism.
func (b *builder) flatten(rootEntry *Entry, volumeName string) *fileNode {
	root := &fileNode{
		entry:  rootEntry,
		name:   volumeName,
		cnid:   HFSRootFolderID,
		parent: HFSRootParentID,
		isDir:  true,
	}
	b.root = root
	b.allNodes = append(b.allNodes, root)
	b.addChildren(root, rootEntry.Children)
	return root
}

func (b *builder) addChildren(parent *fileNode, children []*Entry) {
	sorted := append([]*Entry(nil), children...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, ce := range sorted {
		n := &fileNode{
			entry:  ce,
			name:   ce.Name,
			cnid:   b.nextCNID,
			parent: parent.cnid,
		}
		b.nextCNID++
		switch {
		case ce.Mode&os.ModeSymlink != 0:
			n.isSymlink = true
			n.dataLen = len(ce.Data)
			b.fileCount++
			b.fileNodes = append(b.fileNodes, n)
		case ce.Mode.IsDir():
			n.isDir = true
			b.folderCount++
		default:
			n.dataLen = len(ce.Data)
			b.fileCount++
			b.fileNodes = append(b.fileNodes, n)
		}
		if n.dataLen > 0 {
			n.dataBlocks = uint32((n.dataLen + b.blockSize - 1) / b.blockSize)
		}
		parent.children = append(parent.children, n)
		b.allNodes = append(b.allNodes, n)
		if n.isDir {
			b.addChildren(n, ce.Children)
		}
	}
}

// computeLayout places metadata and file data in allocation blocks and
// determines the total block count.
func (b *builder) computeLayout(sizeBytes int64, catalogBlks uint32) (layout, error) {
	bs := b.blockSize
	var totalData uint32
	for _, f := range b.fileNodes {
		totalData += f.dataBlocks
	}

	// Metadata before data: block 0, bitmap, extents (1 node), catalog.
	// Data follows; the last block holds the alternate volume header.
	place := func(total uint32) layout {
		bitmapBytes := (total + 7) / 8
		bitmapBlks := (bitmapBytes + uint32(bs) - 1) / uint32(bs)
		lay := layout{blockSize: bs, totalBlocks: total}
		next := uint32(1) // block 0 reserved
		lay.bitmapStart, lay.bitmapBlocks = next, bitmapBlks
		next += bitmapBlks
		lay.extentsStart, lay.extentBlocks = next, 1
		next++
		lay.catalogStart, lay.catalogBlks = next, catalogBlks
		next += catalogBlks
		lay.dataStart = next
		next += totalData
		lay.firstFree = next
		return lay
	}

	var total uint32
	if sizeBytes > 0 {
		total = uint32(sizeBytes / int64(bs))
	} else {
		// Iterate to a stable total (bitmap size depends on total). Add two
		// trailing blocks so at least one free block and the alternate VH fit.
		total = 8
		for i := 0; i < 8; i++ {
			lay := place(total)
			want := lay.firstFree + 2
			if want <= total {
				break
			}
			total = want
		}
	}

	lay := place(total)
	if lay.firstFree > total-1 { // data must not overlap the alternate-VH block
		return layout{}, fmt.Errorf("hfsplus: image too small: need %d blocks, have %d", lay.firstFree+1, total)
	}
	if total < 4 {
		return layout{}, fmt.Errorf("hfsplus: image too small: %d blocks", total)
	}
	return lay, nil
}

// assignData assigns each file a contiguous data extent starting at dataStart.
func (b *builder) assignData(lay *layout) {
	next := lay.dataStart
	for _, f := range b.fileNodes {
		if f.dataBlocks == 0 {
			continue
		}
		f.dataStart = next
		next += f.dataBlocks
	}
}

// writeFileData copies every file's bytes into the image at its data extent.
func (b *builder) writeFileData(img []byte) {
	for _, f := range b.fileNodes {
		if f.dataLen == 0 {
			continue
		}
		off := int(f.dataStart) * b.blockSize
		copy(img[off:], f.entry.Data)
	}
}

// forkFor returns the data-fork descriptor for a file node.
func (b *builder) forkFor(f *fileNode) ForkData {
	fork := ForkData{
		LogicalSize: uint64(f.dataLen),
		ClumpSize:   65536,
		TotalBlocks: f.dataBlocks,
	}
	if f.dataBlocks > 0 {
		fork.Extents[0] = ExtentDescriptor{StartBlock: f.dataStart, BlockCount: f.dataBlocks}
	}
	return fork
}

// catalogRecords builds every catalog leaf record (folder/file + thread for
// each node), sorted in HFSX binary key order.
func (b *builder) catalogRecords(_ *fileNode) []btRecord {
	var recs []btRecord
	for _, n := range b.allNodes {
		recs = append(recs, b.normalRecord(n), b.threadRecord(n))
	}
	sort.Slice(recs, func(i, j int) bool { return compareCatalogKeys(recs[i].key, recs[j].key) < 0 })
	return recs
}

// nodeTime resolves a node's catalog timestamp. A node with no ModTime takes
// the builder's fixed default; otherwise its own time is used, clamped down to
// that default when ClampModTimes is set (the SOURCE_DATE_EPOCH rule).
func (b *builder) nodeTime(n *fileNode) hfsTime {
	t := n.entry.ModTime
	if t.IsZero() {
		t = b.defaultTime
	} else if b.clampTime && t.After(b.defaultTime) {
		t = b.defaultTime
	}
	return toHFSTime(t)
}

// normalRecord builds the folder or file record keyed by (parent, name).
func (b *builder) normalRecord(n *fileNode) btRecord {
	key := encodeCatalogKey(n.parent, n.name)
	ht := b.nodeTime(n)
	bsd := BSDInfo{
		OwnerID:  n.entry.UID,
		GroupID:  n.entry.GID,
		FileMode: hfsFileMode(n),
	}

	if n.isDir {
		var subFolders uint32
		for _, c := range n.children {
			if c.isDir {
				subFolders++
			}
		}
		// Directories must NOT set kHFSThreadExistsMask/kHFSFileLockedMask;
		// fsck_hfs treats those bits as reserved-must-be-zero on folders
		// (E_CatalogFlagsNotZero). Only the folder-count flag is set.
		folder := HFSPlusCatalogFolder{
			RecordType:       HFSPlusFolderRecord,
			Flags:            HFSHasFolderCountMask,
			Valence:          uint32(len(n.children)),
			FolderID:         n.cnid,
			CreateDate:       ht,
			ContentModDate:   ht,
			AttributeModDate: ht,
			AccessDate:       ht,
			BSDInfo:          bsd,
			FolderCount:      subFolders,
		}
		return btRecord{key: key, payload: marshalBE(&folder)}
	}

	file := HFSPlusCatalogFile{
		RecordType:       HFSPlusFileRecord,
		Flags:            HFSThreadExistsMask,
		FileID:           n.cnid,
		CreateDate:       ht,
		ContentModDate:   ht,
		AttributeModDate: ht,
		AccessDate:       ht,
		BSDInfo:          bsd,
		DataFork:         b.forkFor(n),
	}
	if n.isSymlink {
		file.UserInfo.FileType = SymLinkFileType
		file.UserInfo.FileCreator = SymLinkCreator
	}
	return btRecord{key: key, payload: marshalBE(&file)}
}

// threadRecord builds the thread record keyed by (cnid, emptyName) that
// points back to the object's real parent and name.
func (b *builder) threadRecord(n *fileNode) btRecord {
	key := encodeCatalogKey(n.cnid, "")
	recType := HFSPlusFileThreadRecord
	if n.isDir {
		recType = HFSPlusFolderThreadRecord
	}
	name := encodeUniStr(n.name)
	payload := make([]byte, 8+len(name))
	binary.BigEndian.PutUint16(payload[0:], uint16(recType))
	// payload[2:4] reserved = 0
	binary.BigEndian.PutUint32(payload[4:], uint32(n.parent))
	copy(payload[8:], name)
	return btRecord{key: key, payload: payload}
}

// encodeUniStr encodes a name as UniStr255: length(2) + UTF-16BE units.
func encodeUniStr(name string) []byte {
	units := encodeUTF16(name)
	out := make([]byte, 2+2*len(units))
	binary.BigEndian.PutUint16(out[0:], uint16(len(units)))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2+2*i:], u)
	}
	return out
}

// buildBitmap builds the allocation bitmap (1 bit/block, MSB-first, 1=used).
func (b *builder) buildBitmap(lay *layout) []byte {
	bitmap := make([]byte, lay.bitmapBlocks*uint32(b.blockSize))
	set := func(block uint32) { bitmap[block/8] |= 0x80 >> (block % 8) }
	setRange := func(start, count uint32) {
		for i := uint32(0); i < count; i++ {
			set(start + i)
		}
	}
	set(0) // volume header / boot blocks
	setRange(lay.bitmapStart, lay.bitmapBlocks)
	setRange(lay.extentsStart, lay.extentBlocks)
	setRange(lay.catalogStart, lay.catalogBlks)
	for _, f := range b.fileNodes {
		setRange(f.dataStart, f.dataBlocks)
	}
	set(lay.totalBlocks - 1) // alternate volume header
	return bitmap
}

// volumeHeader assembles the HFSX volume header.
func (b *builder) volumeHeader(volumeName string, lay *layout, _, _ builtTree) VolumeHeader {
	usedBlocks := b.countUsedBlocks(lay)
	now := toHFSTime(b.defaultTime)

	vh := VolumeHeader{
		Signature:        HFSXSigWord,
		Version:          HFSXVersion,
		Attributes:       0x80000100, // kHFSVolumeUnmountedMask + top bit, as newfs writes
		JournalInfoBlock: 0,
		CreateDate:       now,
		ModifyDate:       now,
		BackupDate:       0,
		CheckedDate:      now,
		FileCount:        b.fileCount,
		FolderCount:      b.folderCount,
		BlockSize:        uint32(b.blockSize),
		TotalBlocks:      lay.totalBlocks,
		FreeBlocks:       lay.totalBlocks - usedBlocks,
		NextAllocation:   lay.firstFree,
		RsrcClumpSize:    65536,
		DataClumpSize:    65536,
		NextCatalogID:    b.nextCNID,
		WriteCount:       0,
		EncodingsBitmap:  1,
	}
	copy(vh.LastMountedVersion[:], "10.0")

	// A stable, non-zero volume identifier: the caller's UUID when it supplied
	// one (its first eight bytes, big-endian, are the 64-bit HFS+ identifier),
	// otherwise one derived from the volume name and the fixed timestamp.
	if b.volumeUUID != ([16]byte{}) {
		vh.FinderInfo[6] = binary.BigEndian.Uint32(b.volumeUUID[0:4])
		vh.FinderInfo[7] = binary.BigEndian.Uint32(b.volumeUUID[4:8])
	} else {
		h := fnv.New64a()
		fmt.Fprintf(h, "%s-%d", volumeName, uint32(now))
		id := h.Sum64()
		vh.FinderInfo[6] = uint32(id >> 32)
		vh.FinderInfo[7] = uint32(id)
	}
	if vh.FinderInfo[6] == 0 && vh.FinderInfo[7] == 0 {
		vh.FinderInfo[7] = 1
	}

	// Allocation (bitmap) file.
	vh.AllocationFile = ForkData{
		LogicalSize: uint64(lay.bitmapBlocks) * uint64(b.blockSize),
		ClumpSize:   uint32(b.blockSize),
		TotalBlocks: lay.bitmapBlocks,
	}
	vh.AllocationFile.Extents[0] = ExtentDescriptor{StartBlock: lay.bitmapStart, BlockCount: lay.bitmapBlocks}

	// Extents overflow file (empty tree, one header node).
	vh.ExtentsFile = ForkData{
		LogicalSize: uint64(lay.extentBlocks) * uint64(b.blockSize),
		ClumpSize:   65536,
		TotalBlocks: lay.extentBlocks,
	}
	vh.ExtentsFile.Extents[0] = ExtentDescriptor{StartBlock: lay.extentsStart, BlockCount: lay.extentBlocks}

	// Catalog file.
	vh.CatalogFile = ForkData{
		LogicalSize: uint64(lay.catalogBlks) * uint64(b.blockSize),
		ClumpSize:   65536,
		TotalBlocks: lay.catalogBlks,
	}
	vh.CatalogFile.Extents[0] = ExtentDescriptor{StartBlock: lay.catalogStart, BlockCount: lay.catalogBlks}

	// Attributes and startup files are absent (all-zero forks).
	return vh
}

// countUsedBlocks counts the allocation blocks marked used in the bitmap.
func (b *builder) countUsedBlocks(lay *layout) uint32 {
	used := uint32(1) // block 0
	used += lay.bitmapBlocks
	used += lay.extentBlocks
	used += lay.catalogBlks
	for _, f := range b.fileNodes {
		used += f.dataBlocks
	}
	used++ // alternate volume header (last block, in the trailing free region)
	return used
}

// hfsFileMode maps a node to an HFS+ BSD file mode (S_IFMT | perms).
func hfsFileMode(n *fileNode) uint16 {
	perm := uint16(n.entry.Mode.Perm())
	switch {
	case n.isSymlink:
		if perm == 0 {
			perm = 0o755
		}
		return sIFLNK | perm
	case n.isDir:
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

// toHFSTime converts a time to seconds since the HFS+ epoch (1904-01-01 UTC).
func toHFSTime(t time.Time) hfsTime {
	epoch := time.Date(1904, time.January, 1, 0, 0, 0, 0, time.UTC)
	if t.Before(epoch) {
		return 0
	}
	return hfsTime(t.Sub(epoch) / time.Second)
}
