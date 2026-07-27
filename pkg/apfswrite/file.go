// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/hostmeta"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// setTree resolves the caller's directory tree (Root plus the RootFiles
// convenience) into a flat list of file-system tree entries with assigned oids, then
// decides the file-system tree shape (single leaf vs a 2-level index+leaves
// tree). Physical block numbers are assigned later, in the space manager.
func (b *builder) setTree(opts *CreateOptions) error {
	// Build the effective root directory: Root's children plus any RootFiles.
	var topLevel []*Entry
	if opts.Root != nil {
		topLevel = append(topLevel, opts.Root.Children...)
	}
	for _, f := range opts.RootFiles {
		topLevel = append(topLevel, &Entry{Name: f.Name, Data: f.Data})
	}
	if len(topLevel) == 0 {
		return nil // empty volume
	}

	// Deterministic order: sort siblings by name at every level.
	nextOID := uint64(minUserInoNum)
	// The first name seen for a link group holds the inode; later ones become
	// extra names for it. The walk is deterministic, so "first" is stable.
	linkGroups := map[uint64]*builderEntry{}
	var walk func(parent uint64, children []*Entry) (uint32, error)
	walk = func(parent uint64, children []*Entry) (uint32, error) {
		sorted := make([]*Entry, len(children))
		copy(sorted, children)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

		seen := make(map[string]bool, len(sorted))
		for _, e := range sorted {
			if err := validateName(e.Name); err != nil {
				return 0, err
			}
			if seen[e.Name] {
				return 0, fmt.Errorf("apfswrite: duplicate name %q in one directory", e.Name)
			}
			seen[e.Name] = true

			// resolvedMode would otherwise stamp anything that is not a
			// directory or a symbolic link as a regular file, so a device node
			// or FIFO handed in directly would be written with the wrong mode
			// and no sign anything was lost. EntryTreeFromDir skips these and
			// reports them; a caller building a tree by hand gets told.
			if hostmeta.IsSpecial(e.Mode) {
				return 0, fmt.Errorf("apfswrite: %q is a %s; this writer models only regular files, directories and symbolic links",
					e.Name, e.Mode.Type())
			}

			// A second or later name for a file already seen is written as a
			// hard link: a directory entry pointing at the existing inode, with
			// no inode, content or attributes of its own. Its attributes are
			// that same inode's, so there is nothing separate to validate.
			if primary := linkGroups[e.LinkGroup]; primary != nil && e.LinkGroup != 0 && e.Mode.IsRegular() {
				extra := &builderEntry{name: e.Name, parent: parent, primary: primary}
				b.entries = append(b.entries, extra)
				primary.siblings = append(primary.siblings, siblingName{parent: parent, name: e.Name})
				continue
			}

			mtime := b.entryTime(e.ModTime)
			xattrs, xattrFlags, err := validateXattrs(e)
			if err != nil {
				return 0, err
			}
			embedded, streamed := splitXattrs(xattrs)

			be := &builderEntry{
				name:       e.Name,
				oid:        nextOID,
				parent:     parent,
				mode:       e.resolvedMode(),
				uid:        e.UID,
				gid:        e.GID,
				mtime:      mtime,
				xattrs:     embedded,
				xattrFlags: xattrFlags,
			}
			nextOID++
			b.entries = append(b.entries, be)

			if e.LinkGroup != 0 && e.Mode.IsRegular() {
				linkGroups[e.LinkGroup] = be
				be.siblings = append(be.siblings, siblingName{parent: parent, name: e.Name})
			}

			// Each streamed attribute owns an object of its own: a data stream
			// with its own oid, extent and refcount, referenced by the
			// attribute record. It carries no inode and no directory entry —
			// it is not a file, only somewhere for the bytes to live.
			for _, name := range sortedNames(streamed) {
				value := streamed[name]
				stream := &builderEntry{
					name:        e.Name + ":" + name,
					oid:         nextOID,
					data:        value,
					hasStream:   true,
					blocks:      divRoundUp(uint64(len(value)), uint64(b.blocksize)),
					allocedSize: 0,
				}
				stream.allocedSize = stream.blocks * uint64(b.blocksize)
				nextOID++

				if be.streamedXattrs == nil {
					be.streamedXattrs = map[string]*builderEntry{}
				}
				be.streamedXattrs[name] = stream
				b.streamFiles = append(b.streamFiles, stream)
				b.xattrStreams = append(b.xattrStreams, stream)
			}

			switch {
			case e.isSymlinkEntry():
				// A symbolic link stores its target in a com.apple.fs.symlink
				// extended attribute (not a data stream): no DSTREAM xfield, no
				// DSTREAM_ID record and no file extent.
				be.isSymlink = true
				be.linkTarget = e.Data
				b.symlinks = append(b.symlinks, be)
				b.numSymlinks++
			case e.isDirEntry():
				be.isDir = true
				n, err := walk(be.oid, e.Children)
				if err != nil {
					return 0, err
				}
				be.nchildren = n
				b.numDirs++
			default:
				// Every regular file carries a data stream (a DSTREAM xfield and a
				// DSTREAM_ID record), even a 0-byte one. A non-empty file also owns
				// a physical extent of ceil(size/blocksize) contiguous blocks; an
				// empty file has size 0, alloced_size 0 and no extent at all.
				be.data = e.Data
				be.hasStream = true
				be.blocks = divRoundUp(uint64(len(e.Data)), uint64(b.blocksize))
				be.allocedSize = be.blocks * uint64(b.blocksize)
				b.streamFiles = append(b.streamFiles, be)
				b.numFiles++
			}
		}
		return uint32(len(sorted)), nil
	}

	if _, err := walk(rootDirInoNum, topLevel); err != nil {
		return err
	}

	// Sibling ids come from the same pool as inode numbers, and the volume's
	// next-id must end up past them, so they are allocated after the tree is
	// walked and before nextObjID is consulted.
	//
	// A file with a single name gets none: a checker accepts a lone sibling
	// record but does not require one, and omitting it keeps an ordinary tree's
	// records exactly as they were.
	for _, e := range b.entries {
		if e.primary != nil || len(e.siblings) < 2 {
			e.siblings = nil
			continue
		}
		e.nlink = uint32(len(e.siblings))
		for i := range e.siblings {
			e.siblings[i].id = nextOID
			nextOID++
		}
	}
	b.linkSiblingIDs()

	b.fileDataBlocks = 0
	for _, f := range b.streamFiles {
		b.fileDataBlocks += f.blocks
	}

	// Decide the file-system tree shape from the record sizes. Block numbers are not yet
	// known but do not affect record sizes, so the packing decided here matches
	// the one recomputed at write time.
	recs := b.buildFSTreeRecords()
	leaves := packFSTreeLeaves(recs, int(b.blocksize), sizeofBtreeInfo)
	if len(leaves) > 1 {
		b.fsTreeTwoLevel = true
		// Repack leaves without the root footer (only the index root carries it).
		leaves = packFSTreeLeaves(recs, int(b.blocksize), 0)
		b.numFSTreeLeaves = uint64(len(leaves))
		if b.numFSTreeLeaves > maxFSTreeLeaves {
			return fmt.Errorf("apfswrite: file-system tree needs %d leaf nodes; only a 2-level tree up to %d leaves is supported", b.numFSTreeLeaves, maxFSTreeLeaves)
		}
	}

	// Decide the extentref tree shape. One physical-extent record per file
	// that owns a physical extent (empty files own none). When they overflow a
	// single leaf the tree grows to two physical levels (an index root plus
	// leaves), the same way the file-system tree grows.
	nExtents := len(b.physFiles())
	if perLeaf := extentrefRecordsPerLeaf(int(b.blocksize)); nExtents > perLeaf {
		b.extentrefTwoLevel = true
		b.numExtentrefLeaves = uint64(divRoundUp(uint64(nExtents), uint64(perLeaf)))
		if b.numExtentrefLeaves > maxExtentrefLeaves {
			return fmt.Errorf("apfswrite: extentref tree needs %d leaf nodes; only a 2-level tree up to %d leaves is supported", b.numExtentrefLeaves, maxExtentrefLeaves)
		}
	}
	return nil
}

// maxFSTreeLeaves caps the 2-level file-system tree: L leaves need L index records in one
// root node and L omap entries in one omap leaf; both fit comfortably here.
const maxFSTreeLeaves = 64

// maxExtentrefLeaves caps the 2-level extentref tree: its L index records
// must fit in the single index root node.
const maxExtentrefLeaves = 100

// physFiles returns the stream files that own a physical extent (blocks > 0),
// i.e. every regular file except the 0-byte ones.
func (b *builder) physFiles() []*builderEntry {
	out := make([]*builderEntry, 0, len(b.streamFiles))
	for _, f := range b.streamFiles {
		if f.blocks > 0 {
			out = append(out, f)
		}
	}
	return out
}

// Attribute names that an inode flag must agree with. A checker compares each
// flag against the presence of its attribute and reports a mismatch either way,
// so these cannot be set optimistically or left alone.
const (
	resourceForkName = "com.apple.ResourceFork"
	securityName     = "com.apple.system.Security"
	finderInfoName   = "com.apple.FinderInfo"
	decmpfsName      = "com.apple.decmpfs"
)

// linkSiblingIDs gives every name its own sibling id, so a directory entry can
// point at the sibling record describing that particular name. Each name's id
// lives on the sibling list of the entry holding the inode, so the extra names
// have to be matched back to it.
func (b *builder) linkSiblingIDs() {
	for _, e := range b.entries {
		holder, name := e, e.name
		if e.primary != nil {
			holder = e.primary
		}
		for _, sib := range holder.siblings {
			if sib.parent == e.parent && sib.name == name {
				e.siblingID = sib.id
				break
			}
		}
	}
}

// splitXattrs divides an entry's attributes into those small enough to store
// inside their record and those needing a data stream.
func splitXattrs(xattrs map[string][]byte) (embedded, streamed map[string][]byte) {
	for name, value := range xattrs {
		if needsXattrStream(name, value) {
			if streamed == nil {
				streamed = map[string][]byte{}
			}
			streamed[name] = value
			continue
		}
		if embedded == nil {
			embedded = map[string][]byte{}
		}
		embedded[name] = value
	}
	return embedded, streamed
}

// needsXattrStream reports whether an attribute must be stored as a data
// stream rather than inside its record.
//
// Size is the obvious reason. A resource fork is the other: fsck_apfs requires
// one to be stream based however small it is — "com.apple.ResourceFork is
// expected to be stream based" — and accepts nothing else.
func needsXattrStream(name string, value []byte) bool {
	return name == resourceForkName || len(value) > maxEmbeddedXattrSize
}

// sortedNames returns a map's keys in order, so records are emitted the same
// way every time. Attributes arrive in a map, and reproducible output depends
// on their order being fixed.
func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateXattrs checks an entry's extended attributes can be written, and
// returns the inode flags their presence requires.
//
// A value too large to embed is refused rather than truncated: this writer does
// not yet store an attribute in a data stream of its own, and silently dropping
// content is exactly the failure this project has been removing.
func validateXattrs(e *Entry) (map[string][]byte, uint64, error) {
	// An inode with no resource fork must say so. The flag is not optional:
	// a checker treats its absence as a claim that a fork exists.
	flags := uint64(inodeNoRsrcFork)
	if len(e.Xattrs) == 0 {
		return nil, flags, nil
	}

	for name := range e.Xattrs {
		if name == "" {
			return nil, 0, fmt.Errorf("apfswrite: %q has an extended attribute with an empty name", e.Name)
		}
		if strings.ContainsRune(name, 0) {
			return nil, 0, fmt.Errorf("apfswrite: extended attribute name %q on %q contains a NUL", name, e.Name)
		}
		if name == symlinkName {
			return nil, 0, fmt.Errorf("apfswrite: %q sets %s, which the writer emits itself for symbolic links", e.Name, symlinkName)
		}

		switch name {
		case resourceForkName:
			// HAS and NO are mutually exclusive, and a checker compares each
			// against whether the attribute is actually there.
			flags = flags&^uint64(inodeNoRsrcFork) | inodeHasRsrcFork
		case decmpfsName:
			// A decmpfs attribute declares the file's content compressed, and
			// requires APFS_INOBSD_COMPRESSED in bsd_flags — which this writer
			// does not set, because it puts content in the data fork. Writing
			// the attribute alone would describe content the file does not
			// have. apfsck: "is not compressed but has decmpfs xattr".
			return nil, 0, fmt.Errorf("apfswrite: %q carries %s, which declares its content compressed; this writer stores content uncompressed in the data fork", e.Name, decmpfsName)
		case securityName:
			flags |= inodeHasSecurityEA
		case finderInfoName:
			flags |= inodeHasFinderInfo
		}
	}
	return e.Xattrs, flags, nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("apfswrite: entry has an empty name")
	}
	if strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("apfswrite: name %q contains a path separator or NUL", name)
	}
	if len(name)+1 > int(drecLenMask) {
		return fmt.Errorf("apfswrite: name %q too long", name)
	}
	return nil
}

// hasFiles reports whether any user entries are being written.

// nextObjID returns the volume's next free object id: one past the highest user
// oid in use (APFS_MIN_USER_INO_NUM when there are no entries).
func (b *builder) nextObjID() uint64 {
	next := uint64(minUserInoNum)
	// Streamed extended attributes take object ids from the same counter as
	// entries, so a volume whose highest id belongs to one must still report a
	// next id past it.
	for _, e := range append(append([]*builderEntry{}, b.entries...), b.xattrStreams...) {
		if e.oid+1 > next {
			next = e.oid + 1
		}
		// Sibling ids share the pool, and a checker rejects one at or past the
		// volume's next id as a free id in use.
		for _, sib := range e.siblings {
			if sib.id+1 > next {
				next = sib.id + 1
			}
		}
	}
	return next
}

// writeFileData writes each stream file's content into its data block,
// zero-padded to a full allocation block.
// fileCopyWindowBlocks is how much of a file writeFileData moves at a time:
// 1024 blocks, which is 4 MiB at the default 4 KiB block size. Without a
// window, a single large file cost its own size in memory — an 8 GB file inside
// an otherwise small tree needed 8 GB.
const fileCopyWindowBlocks = 1024

func (b *builder) writeFileData() error {
	var window []byte

	for _, f := range b.streamFiles {
		if f.blocks == 0 {
			continue // 0-byte file: no data block
		}

		for done := uint64(0); done < f.blocks; {
			blocks := min(f.blocks-done, uint64(fileCopyWindowBlocks))
			size := blocks * uint64(b.blocksize)
			if uint64(len(window)) < size {
				window = make([]byte, size)
			}
			chunk := window[:size]

			// A file's last block is zero-padded to a whole allocation block,
			// and the window is reused across files, so clear what the copy
			// will not overwrite rather than trusting it to be zero.
			offset := done * uint64(b.blocksize)
			copied := 0
			if offset < uint64(len(f.data)) {
				copied = copy(chunk, f.data[offset:])
			}
			clear(chunk[copied:])

			if err := b.writeBlocks(chunk, f.dataBlock+done); err != nil {
				return err
			}
			done += blocks
		}
	}
	return nil
}

// --- file-system tree record generation ---
//
// Each record is materialized as (key, value) byte slices plus the fields the
// file-system tree key comparator needs. buildFSTreeRecords returns the whole file-system tree in
// globally sorted order.

type fsTreeRecord struct {
	id      uint64 // object id (low 60 bits of the key header)
	typ     uint8  // record type (APFS_TYPE_*)
	hash    uint32 // DIR_REC: name_len_and_hash, for ordering
	name    string // DIR_REC: name, for ordering tie-break
	logical uint64 // FILE_EXTENT: logical address, for ordering
	key     []byte
	val     []byte
}

// buildFSTreeRecords generates every file-system tree record — the special root and
// private-dir records plus one dentry+inode (and, for files, dstream-id and
// file-extent) per user entry — and returns them sorted by the file-system tree key
// comparator.
func (b *builder) buildFSTreeRecords() []fsTreeRecord {
	recs := make([]fsTreeRecord, 0, 4+4*len(b.entries))

	// Special directory dentries live under the virtual root parent (id 1).
	recs = append(recs, b.dentryRecord(rootDirParent, "root", rootDirInoNum, dtDir, 0))
	recs = append(recs, b.dentryRecord(rootDirParent, "private-dir", privDirInoNum, dtDir, 0))
	// Root inode (id 2): nchildren = number of top-level entries.
	recs = append(recs, b.inodeRecord(&builderEntry{
		name: "root", isDir: true, oid: rootDirInoNum, parent: rootDirParent,
		nchildren: b.rootChildCount(),
	}))
	// Private-dir inode (id 3).
	recs = append(recs, b.inodeRecord(&builderEntry{
		name: "private-dir", isDir: true, oid: privDirInoNum, parent: rootDirParent,
	}))

	for _, e := range b.entries {
		// An extra name for an already-written file contributes a directory
		// entry pointing at that file's inode, and nothing else.
		if e.primary != nil {
			recs = append(recs, b.dentryRecord(e.parent, e.name, e.primary.oid, dtReg, e.siblingID))
			continue
		}

		dt := dtReg
		switch {
		case e.isDir:
			dt = dtDir
		case e.isSymlink:
			dt = dtLnk
		}
		recs = append(recs, b.dentryRecord(e.parent, e.name, e.oid, uint16(dt), e.siblingID))
		recs = append(recs, b.inodeRecord(e))
		for _, sib := range e.siblings {
			recs = append(recs, b.siblingLinkRecord(e.oid, sib))
			recs = append(recs, b.siblingMapRecord(e.oid, sib))
		}
		if e.isSymlink {
			// The symlink target lives in a com.apple.fs.symlink xattr record.
			recs = append(recs, b.symlinkXattrRecord(e))
		}
		recs = append(recs, b.userXattrRecords(e)...)
		for _, name := range sortedNames(e.streamedXattrs) {
			stream := e.streamedXattrs[name]
			recs = append(recs, b.streamedXattrRecord(e.oid, name, stream))
			// No DSTREAM_ID record here, unlike a file's data stream. That
			// record carries a reference count, and an attribute's stream
			// cannot be cloned, so it has exactly one reference and no count
			// to keep. apfsck reports one as "xattrs can't be cloned".
			if stream.blocks > 0 {
				recs = append(recs, b.fileExtentRecord(stream))
			}
		}
		if e.hasStream {
			recs = append(recs, b.dstreamIDRecord(e))
			// A 0-byte file has a data stream but no physical extent, so no
			// file-extent record.
			if e.blocks > 0 {
				recs = append(recs, b.fileExtentRecord(e))
			}
		}
	}

	sort.SliceStable(recs, func(i, j int) bool { return fsTreeRecordLess(recs[i], recs[j]) })
	return recs
}

// rootChildCount counts the direct children of the volume root (oid 2).
func (b *builder) rootChildCount() uint32 {
	n := uint32(0)
	for _, e := range b.entries {
		if e.parent == rootDirInoNum {
			n++
		}
	}
	return n
}

// fsTreeRecordLess is the file-system tree key comparator: object id ascending, then record type
// ascending, then the type-specific key (DIR_REC by name hash then name;
// FILE_EXTENT by logical address).
func fsTreeRecordLess(a, b fsTreeRecord) bool {
	if a.id != b.id {
		return a.id < b.id
	}
	if a.typ != b.typ {
		return a.typ < b.typ
	}
	switch a.typ {
	case typeDirRec:
		if a.hash != b.hash {
			return a.hash < b.hash
		}
		return a.name < b.name
	case typeXattr:
		return a.name < b.name
	case typeFileExtent, typeSiblingLink:
		return a.logical < b.logical
	}
	return false
}

// dentryRecord builds a hashed dentry record: key (parent, DIR_REC, hash(name)),
// value j_drec_hashed_val pointing at childID with directory-entry type dt.
//
// siblingID, when non-zero, appends the extended field naming this particular
// name's sibling record. A checker requires every sibling link to be reachable
// from a directory entry this way, and reports one that is not as orphaned.
func (b *builder) dentryRecord(parent uint64, name string, childID uint64, dt uint16, siblingID uint64) fsTreeRecord {
	key, hash := b.buildHashedDrecKey(parent, name)

	size := sizeofDrecVal
	if siblingID != 0 {
		size += sizeofXfBlob + sizeofXField + 8
	}
	val := make([]byte, size)
	binary.LittleEndian.PutUint64(val[0:], childID)     // file_id
	binary.LittleEndian.PutUint64(val[8:], b.timestamp) // date_added
	binary.LittleEndian.PutUint16(val[16:], dt)         // flags (dir-entry type)

	if siblingID != 0 {
		xblob := sizeofDrecVal
		binary.LittleEndian.PutUint16(val[xblob:], 1)   // xf_num_exts
		binary.LittleEndian.PutUint16(val[xblob+2:], 8) // xf_used_data
		xf := xblob + sizeofXfBlob
		val[xf+0] = drecExtTypeSiblingID
		val[xf+1] = xfDoNotCopy
		binary.LittleEndian.PutUint16(val[xf+2:], 8)
		binary.LittleEndian.PutUint64(val[xf+sizeofXField:], siblingID)
	}

	return fsTreeRecord{id: parent, typ: typeDirRec, hash: hash, name: name, key: key, val: val}
}

// siblingLinkRecord names one of a file's several names: key (inode oid,
// SIBLING_LINK, sibling id), value the parent directory and the name itself.
func (b *builder) siblingLinkRecord(oid uint64, sib siblingName) fsTreeRecord {
	key := make([]byte, sizeofSiblingLinkKey)
	setKeyHeader(key, 0, oid, typeSiblingLink)
	binary.LittleEndian.PutUint64(key[8:], sib.id)

	nameLen := len(sib.name) + 1
	val := make([]byte, sizeofSiblingLinkValFixed+nameLen)
	binary.LittleEndian.PutUint64(val[0:], sib.parent)
	binary.LittleEndian.PutUint16(val[8:], uint16(nameLen))
	copy(val[sizeofSiblingLinkValFixed:], sib.name)

	return fsTreeRecord{id: oid, typ: typeSiblingLink, logical: sib.id, key: key, val: val}
}

// siblingMapRecord maps a sibling id back to the inode it stands for. Every
// sibling link needs one; a checker reports a link without as unmapped.
func (b *builder) siblingMapRecord(oid uint64, sib siblingName) fsTreeRecord {
	key := make([]byte, sizeofSiblingMapKey)
	setKeyHeader(key, 0, sib.id, typeSiblingMap)
	val := make([]byte, sizeofSiblingMapVal)
	binary.LittleEndian.PutUint64(val[0:], oid)
	return fsTreeRecord{id: sib.id, typ: typeSiblingMap, key: key, val: val}
}

// inodeRecord builds an inode record: key (oid, INODE), value j_inode_val with
// a NAME xfield and, for stream files, a DSTREAM xfield.
func (b *builder) inodeRecord(e *builderEntry) fsTreeRecord {
	key := make([]byte, sizeofInodeKey)
	setKeyHeader(key, 0, e.oid, typeInode)
	val := b.inodeValue(e)
	return fsTreeRecord{id: e.oid, typ: typeInode, key: key, val: val}
}

// inodeValue serializes a j_inode_val for a directory or regular file.
func (b *builder) inodeValue(e *builderEntry) []byte {
	nameLen := len(e.name) + 1
	paddedNameLen := int(roundUp(uint64(nameLen), 8))

	numXF := 1
	extra := paddedNameLen
	if e.hasStream {
		numXF = 2
		extra += sizeofDstream
	}
	valLen := sizeofInodeVal + sizeofXfBlob + numXF*sizeofXField + extra
	val := make([]byte, valLen)

	binary.LittleEndian.PutUint64(val[0:], e.parent) // parent_id
	binary.LittleEndian.PutUint64(val[8:], e.oid)    // private_id

	// Resolve mode and timestamp, applying deterministic defaults for entries
	// (like the special root/private-dir inodes) that carry neither.
	mode := e.mode
	if mode == 0 {
		switch {
		case e.isSymlink:
			mode = sIFLNK | 0o755
		case e.isDir:
			mode = sIFDIR | 0o755
		default:
			mode = sIFREG | 0o644
		}
	}
	// The synthetic root and private-dir inodes are built inline and never go
	// through setTree, so they carry no time of their own.
	mtime := e.mtime
	if mtime == 0 {
		mtime = b.timestamp
	}

	binary.LittleEndian.PutUint64(val[16:], mtime) // create_time
	binary.LittleEndian.PutUint64(val[24:], mtime) // mod_time
	binary.LittleEndian.PutUint64(val[32:], mtime) // change_time
	binary.LittleEndian.PutUint64(val[40:], mtime) // access_time

	binary.LittleEndian.PutUint64(val[48:], e.internalFlags()) // internal_flags

	if e.isDir {
		binary.LittleEndian.PutUint32(val[56:], e.nchildren)            // nchildren
		binary.LittleEndian.PutUint32(val[60:], protectionClassDirNone) // default_protection_class
	} else {
		nlink := uint32(1)
		if e.nlink > 0 {
			nlink = e.nlink
		}
		binary.LittleEndian.PutUint32(val[56:], nlink) // nlink
	}
	binary.LittleEndian.PutUint32(val[72:], e.uid) // owner
	binary.LittleEndian.PutUint32(val[76:], e.gid) // group
	binary.LittleEndian.PutUint16(val[80:], mode)  // mode

	// xf_blob header.
	xblob := sizeofInodeVal
	binary.LittleEndian.PutUint16(val[xblob:], uint16(numXF))   // xf_num_exts
	binary.LittleEndian.PutUint16(val[xblob+2:], uint16(extra)) // xf_used_data

	// x_field[0]: NAME.
	xf0 := xblob + sizeofXfBlob
	val[xf0+0] = inoExtTypeName
	val[xf0+1] = xfDoNotCopy
	binary.LittleEndian.PutUint16(val[xf0+2:], uint16(nameLen))

	if e.hasStream {
		// x_field[1]: DSTREAM.
		xf1 := xf0 + sizeofXField
		val[xf1+0] = inoExtTypeDstream
		val[xf1+1] = xfSystemField
		binary.LittleEndian.PutUint16(val[xf1+2:], uint16(sizeofDstream))

		nameVal := xf1 + sizeofXField
		copy(val[nameVal:], e.name)
		dsVal := nameVal + paddedNameLen
		binary.LittleEndian.PutUint64(val[dsVal+0:], uint64(len(e.data))) // size
		binary.LittleEndian.PutUint64(val[dsVal+8:], e.allocedSize)       // alloced_size
		// default_crypto_id (16) = 0 on an unencrypted volume.
		binary.LittleEndian.PutUint64(val[dsVal+24:], uint64(len(e.data))) // total_bytes_written
	} else {
		nameVal := xf0 + sizeofXField
		copy(val[nameVal:], e.name)
	}
	return val
}

// dstreamIDRecord builds the data-stream id record: key (oid, DSTREAM_ID),
// value j_dstream_id_val (refcnt).
func (b *builder) dstreamIDRecord(e *builderEntry) fsTreeRecord {
	key := make([]byte, sizeofInodeKey)
	setKeyHeader(key, 0, e.oid, typeDstreamID)
	val := make([]byte, sizeofDstreamIDVal)
	binary.LittleEndian.PutUint32(val[0:], 1) // refcnt = 1
	return fsTreeRecord{id: e.oid, typ: typeDstreamID, key: key, val: val}
}

// fileExtentRecord builds the file-extent record mapping logical offset 0 to
// the file's physical data block: key (oid, FILE_EXTENT, 0), value
// j_file_extent_val.
func (b *builder) fileExtentRecord(e *builderEntry) fsTreeRecord {
	key := make([]byte, sizeofFileExtentKey)
	setKeyHeader(key, 0, e.oid, typeFileExtent)
	binary.LittleEndian.PutUint64(key[8:], 0) // logical_addr = 0
	val := make([]byte, sizeofFileExtentVal)
	binary.LittleEndian.PutUint64(val[0:], e.allocedSize) // len_and_flags (block-aligned length)
	binary.LittleEndian.PutUint64(val[8:], e.dataBlock)   // phys_block_num
	// crypto_id (16) = 0.
	return fsTreeRecord{id: e.oid, typ: typeFileExtent, logical: 0, key: key, val: val}
}

// buildHashedDrecKey builds a hashed dentry key and returns the key bytes and
// the name_len_and_hash field used for ordering. The 22-bit name hash is
// computed over the case-folded (on a case-insensitive volume), NFD-normalized
// filename — exactly the fold+normalize the reader (pkg/apfs name_hash.go) and
// fsck_apfs apply on lookup, so uppercase/Unicode names hash correctly. Case
// folding is disabled only on a case-sensitive (normalization-insensitive)
// volume, where APFS hashes the normalized bytes without folding.
func (b *builder) buildHashedDrecKey(parent uint64, name string) ([]byte, uint32) {
	nameLen := uint32(len(name) + 1)
	key := make([]byte, sizeofDrecHashedKeyFixed+int(nameLen))
	setKeyHeader(key, 0, parent, typeDirRec)
	copy(key[12:], name)
	// key[12+len(name)] = 0 already (zeroed).

	hash := apfs.CalculateNameHash([]byte(name), !b.caseSensitive)
	nameLenAndHash := (hash << 10) | nameLen
	binary.LittleEndian.PutUint32(key[8:], nameLenAndHash)
	return key, nameLenAndHash
}

// symlinkName is the extended-attribute name that stores a symbolic link's
// target, matching what the reader resolves in getSymbolicLinkData.
const symlinkName = "com.apple.fs.symlink"

// maxEmbeddedXattrSize is XATTR_MAX_EMBEDDED_SIZE: the largest value APFS
// stores inside the attribute record rather than in a data stream. A larger
// value needs a stream of its own, which this writer does not yet produce.
const maxEmbeddedXattrSize = 3804

// xattrRecord builds one extended-attribute record with its value stored
// embedded in the record: j_xattr_key_t is the inode's oid plus the
// NUL-terminated attribute name, and j_xattr_val_t is flags, length and the
// data itself.
//
// This is the representation the reader expects and that fsck_apfs accepts.
func (b *builder) xattrRecord(oid uint64, name string, data []byte, flags uint16) fsTreeRecord {
	// Key: header (oid, XATTR) + name_len(2) + NUL-terminated attribute name.
	nameLen := len(name) + 1
	key := make([]byte, sizeofXattrKeyFixed+nameLen)
	setKeyHeader(key, 0, oid, typeXattr)
	binary.LittleEndian.PutUint16(key[8:], uint16(nameLen))
	copy(key[sizeofXattrKeyFixed:], name)

	// Value: flags(2) + xdata_len(2) + xdata.
	val := make([]byte, sizeofXattrValFixed+len(data))
	binary.LittleEndian.PutUint16(val[0:], flags)
	binary.LittleEndian.PutUint16(val[2:], uint16(len(data)))
	copy(val[sizeofXattrValFixed:], data)

	return fsTreeRecord{id: oid, typ: typeXattr, name: name, key: key, val: val}
}

// symlinkXattrRecord builds the com.apple.fs.symlink record carrying a symbolic
// link's target, NUL-terminated. It is owned by the file system rather than the
// user, which is what distinguishes it from an attribute a caller supplied.
func (b *builder) symlinkXattrRecord(e *builderEntry) fsTreeRecord {
	target := make([]byte, len(e.linkTarget)+1)
	copy(target, e.linkTarget)
	return b.xattrRecord(e.oid, symlinkName, target, xattrDataEmbedded|xattrFileSystemOwned)
}

// streamedXattrRecord builds an extended-attribute record whose value lives in
// a data stream rather than inside the record. The record carries a
// j_xattr_dstream_t: the stream object's id followed by a j_dstream_t
// describing it.
func (b *builder) streamedXattrRecord(oid uint64, name string, stream *builderEntry) fsTreeRecord {
	xdata := make([]byte, sizeofXattrDstream)
	binary.LittleEndian.PutUint64(xdata[0:], stream.oid)               // xattr_obj_id
	binary.LittleEndian.PutUint64(xdata[8:], uint64(len(stream.data))) // size
	binary.LittleEndian.PutUint64(xdata[16:], stream.allocedSize)      // alloced_size
	// default_crypto_id (24) = 0 on an unencrypted volume.
	binary.LittleEndian.PutUint64(xdata[32:], uint64(len(stream.data))) // total_bytes_written
	// total_bytes_read (40) = 0.

	return b.xattrRecord(oid, name, xdata, xattrDataStream)
}

// userXattrRecords builds the records for an entry's caller-supplied extended
// attributes, in name order so the file-system tree comparator's ordering is
// reproducible.
func (b *builder) userXattrRecords(e *builderEntry) []fsTreeRecord {
	if len(e.xattrs) == 0 {
		return nil
	}
	names := make([]string, 0, len(e.xattrs))
	for name := range e.xattrs {
		names = append(names, name)
	}
	sort.Strings(names)

	recs := make([]fsTreeRecord, 0, len(names))
	for _, name := range names {
		recs = append(recs, b.xattrRecord(e.oid, name, e.xattrs[name], xattrDataEmbedded))
	}
	return recs
}

// packFSTreeLeaves greedily packs sorted records into leaf nodes of blocksize,
// reserving footer bytes at the end of each node (sizeofBtreeInfo for a node
// that also serves as the tree root, 0 for a plain leaf). Each record costs its
// key + value bytes plus one kvloc table entry.
func packFSTreeLeaves(recs []fsTreeRecord, blocksize, footer int) [][]fsTreeRecord {
	var leaves [][]fsTreeRecord
	var cur []fsTreeRecord
	keys, vals := 0, 0

	flush := func() {
		if len(cur) > 0 {
			leaves = append(leaves, cur)
			cur, keys, vals = nil, 0, 0
		}
	}

	for _, r := range recs {
		n := len(cur) + 1
		toc := tocBytesFor(n)
		used := sizeofBtreeNodePhys + toc + keys + len(r.key) + vals + len(r.val) + footer
		if used > blocksize && len(cur) > 0 {
			flush()
		}
		cur = append(cur, r)
		keys += len(r.key)
		vals += len(r.val)
	}
	flush()
	return leaves
}

// tocBytesFor returns the table-of-contents size (bytes) for a node holding
// nkeys records: room for nkeys kvloc entries, rounded up to whole increments
// of btreeTOCEntryIncrement, never below btreeTOCEntryMaxUnused entries — the
// small-node minimum the format expects.
func tocBytesFor(nkeys int) int {
	entries := roundUpInt(nkeys, btreeTOCEntryIncrement)
	if entries < btreeTOCEntryMaxUnused {
		entries = btreeTOCEntryMaxUnused
	}
	return entries * sizeofKvloc
}

func roundUpInt(x, y int) int {
	if x <= 0 {
		return 0
	}
	return ((x + y - 1) / y) * y
}

// extentrefRecordsPerLeaf returns how many physical-extent records fit in one
// plain (non-root) blockref leaf of blocksize bytes.
func extentrefRecordsPerLeaf(blocksize int) int {
	n := 0
	for {
		used := sizeofBtreeNodePhys + tocBytesFor(n+1) + (n+1)*(sizeofPhysExtKey+sizeofPhysExtVal)
		if used > blocksize {
			break
		}
		n++
	}
	return n
}

// makeExtentrefRoot builds the volume's extent-reference (blockref) tree. Each
// file that owns a physical extent contributes one record: key (phys_block,
// EXTENT), value j_phys_ext_val (len_and_kind = KIND_NEW|blocks, owning_obj_id
// = file oid, refcnt = 1). Records sort by physical block address, which our
// contiguous layout already produces in stream-file order. When they fit in one
// node the tree is a single root-leaf; when they overflow it grows to two
// physical levels: an index root plus one leaf per group of records. All nodes
// are physical objects whose oid equals their block number.
func (b *builder) makeExtentrefRoot(paddr, oid uint64) error {
	phys := b.physFiles()
	if len(phys) == 0 {
		return b.writeEmptyTree(paddr, oid, objectTypeBlockrefTree)
	}

	extents := make([]*builderEntry, len(phys))
	copy(extents, phys)
	sort.Slice(extents, func(i, j int) bool { return extents[i].dataBlock < extents[j].dataBlock })

	if !b.extentrefTwoLevel {
		return b.writeExtentrefNode(paddr, extents, true /* root */, 0 /* level */, 1 /* nodeCount */)
	}

	// Two levels: split the records into leaves, then build an index root whose
	// records map each leaf's first key to that leaf's physical block number.
	perLeaf := extentrefRecordsPerLeaf(int(b.blocksize))
	idx := make([]fsTreeRecord, 0, b.numExtentrefLeaves)
	for i := 0; i < len(extents); i += perLeaf {
		end := i + perLeaf
		if end > len(extents) {
			end = len(extents)
		}
		leaf := extents[i:end]
		leafPaddr := b.extentrefLeafBase + uint64(i/perLeaf)
		if err := b.writeExtentrefNode(leafPaddr, leaf, false /* leaf */, 0 /* level */, 0); err != nil {
			return err
		}
		key := make([]byte, sizeofPhysExtKey)
		setKeyHeader(key, 0, leaf[0].dataBlock, typeExtent)
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, leafPaddr)
		idx = append(idx, fsTreeRecord{key: key, val: val})
	}
	nodeCount := 1 + len(idx)
	return b.writeExtentrefIndex(paddr, idx, len(extents), nodeCount)
}

// writeExtentrefNode writes one blockref leaf holding the given physical extents.
// isRoot marks a single-node tree, which carries the btree_info footer.
func (b *builder) writeExtentrefNode(paddr uint64, extents []*builderEntry, isRoot bool, level uint16, nodeCount int) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := 0
	flags := uint16(btnodeLeaf)
	if isRoot {
		flags |= btnodeRoot
		infoLen = sizeofBtreeInfo
	}
	binary.LittleEndian.PutUint16(block[btnOffFlags:], flags)
	binary.LittleEndian.PutUint16(block[btnOffLevel:], level)

	nkeys := len(extents)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(nkeys))
	tocLen := tocBytesFor(nkeys)
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b:          b,
		block:      block,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}
	for _, f := range extents {
		key := make([]byte, sizeofPhysExtKey)
		setKeyHeader(key, 0, f.dataBlock, typeExtent)
		val := make([]byte, sizeofPhysExtVal)
		lenAndKind := (uint64(pextKindNew) << pextKindShift) | f.blocks
		binary.LittleEndian.PutUint64(val[0:], lenAndKind)
		binary.LittleEndian.PutUint64(val[8:], f.oid)               // owning_obj_id
		binary.LittleEndian.PutUint32(val[16:], b.extentRefcount()) // refcnt
		cur.putRecord(key, val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	objType := uint32(objectTypeBtreeNode) | objPhysical
	if isRoot {
		objType = objectTypeBtree | objPhysical
		b.setExtentrefInfo(block[int(b.blocksize)-infoLen:], nkeys, nodeCount)
	}
	setObjectHeader(block, int(b.blocksize), paddr, objType, objectTypeBlockrefTree)
	return b.writeBlock(block, paddr)
}

// writeExtentrefIndex writes the blockref index root (level 1). Each record maps a
// child leaf's first key (phys_block, EXTENT) to that leaf's physical block
// number (an 8-byte value). Being a physical tree, child pointers are block
// numbers resolved directly, without an object map.
func (b *builder) writeExtentrefIndex(paddr uint64, idx []fsTreeRecord, keyCount, nodeCount int) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(block[btnOffFlags:], btnodeRoot) // root, not leaf
	binary.LittleEndian.PutUint16(block[btnOffLevel:], 1)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(idx)))

	tocLen := tocBytesFor(len(idx))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b:          b,
		block:      block,
		tocOff:     headLen,
		keyArea:    headLen + tocLen,
		keyOff:     headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen,
		valEnd:     int(b.blocksize) - infoLen,
	}
	for _, r := range idx {
		cur.putRecord(r.key, r.val)
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	b.setExtentrefInfo(block[int(b.blocksize)-infoLen:], keyCount, nodeCount)
	setObjectHeader(block, int(b.blocksize), paddr,
		objectTypeBtree|objPhysical, objectTypeBlockrefTree)
	return b.writeBlock(block, paddr)
}

// setExtentrefInfo sets the info footer for a populated blockref-tree root.
func (b *builder) setExtentrefInfo(info []byte, keyCount, nodeCount int) {
	binary.LittleEndian.PutUint32(info[0:], btreePhysical|btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)                     // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], sizeofPhysExtKey)               // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], sizeofPhysExtVal)               // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(keyCount))               // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], uint64(nodeCount))              // bt_node_count
}

// internalFlags returns the inode's internal_flags. The synthetic root and
// private-dir inodes are built inline and carry none, so they fall back to
// asserting no resource fork, which is what they have.
func (e *builderEntry) internalFlags() uint64 {
	if e.xattrFlags == 0 {
		return inodeNoRsrcFork
	}
	return e.xattrFlags
}
