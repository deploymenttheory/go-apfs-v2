package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// FileSystemBTree represents the APFS file system B-tree
type FileSystemBTree struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The object map B-tree (for transaction identifier mapping)
	ObjectMapBTree *ObjectMapBTree

	// The block number of B-tree root node (actually a virtual OID)
	RootNodeOID uint64

	// The volume's transaction identifier (used for object map lookups)
	VolumeTransactionID uint64

	// Flag to indicate case folding should be used
	UseCaseFolding bool

	// Note: Optional caching layers can be added for performance:
	// - DataBlockVector: Vector-based block reading (currently using direct I/O)
	// - DataBlockCache: LRU cache for data blocks (currently uncached)
	// - NodeCache: LRU cache for B-tree nodes (currently uncached)
	// These are performance optimizations, not required for correctness.
}

// NewFileSystemBTree creates a new file system B-tree
func NewFileSystemBTree(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	objectMapBTree *ObjectMapBTree,
	rootNodeOID uint64,
	volumeTransactionID uint64,
	useCaseFolding bool,
) *FileSystemBTree {
	return &FileSystemBTree{
		IOHandle:            ioHandle,
		EncryptionContext:   encryptionContext,
		ObjectMapBTree:      objectMapBTree,
		RootNodeOID:         rootNodeOID,
		VolumeTransactionID: volumeTransactionID,
		UseCaseFolding:      useCaseFolding,
	}
}

// GetRootNode retrieves the root node of the file system B-tree
func (bt *FileSystemBTree) GetRootNode(
	reader io.ReaderAt,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// RootNodeOID is actually a virtual OID that needs to be resolved
	// through the volume's object map B-tree to get the physical block address
	// Per drat: get_btree_phys_omap_entry(vol_omap_root_node, apfs_root_tree_oid, apfs_o.o_xid)
	descriptor, err := bt.ObjectMapBTree.GetDescriptorByObjectIdentifier(
		reader,
		bt.RootNodeOID,         // This is a virtual OID
		bt.VolumeTransactionID, // Use the volume's transaction ID per drat
	)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve filesystem root tree OID %d: %w", bt.RootNodeOID, err)
	}

	if descriptor == nil {
		return nil, fmt.Errorf("filesystem root tree OID %d not found in object map", bt.RootNodeOID)
	}

	physicalAddress := descriptor.Value.ObjectPhysicalAddress

	// Read the root node using the resolved physical block address
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, physicalAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node at block %d (virtual OID %d): %w", physicalAddress, bt.RootNodeOID, err)
	}

	return node, nil
}

// GetSubNode retrieves a sub-node (child node) by block number
// The blockNumber can be either a physical block or virtual OID depending on the B-tree type
func (bt *FileSystemBTree) GetSubNode(
	reader io.ReaderAt,
	blockNumber uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Try to read directly first (assume it's a physical block number)
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, blockNumber)
	if err == nil {
		// Successfully read, it was a physical block
		return node, nil
	}

	// If direct read failed and we have an ObjectMap, try resolving as virtual OID
	if bt.ObjectMapBTree != nil {
		physicalAddress, omapErr := bt.ObjectMapBTree.PhysicalAddressForOID(
			reader,
			blockNumber,
			bt.VolumeTransactionID,
		)
		if omapErr == nil {
			// Successfully resolved via OMap
			node, readErr := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, physicalAddress)
			if readErr == nil {
				return node, nil
			}
			return nil, fmt.Errorf("unable to read sub-node at resolved physical block %d (virtual OID %d): %w", physicalAddress, blockNumber, readErr)
		}
	}

	// Both attempts failed, return original error
	return nil, fmt.Errorf("unable to read sub-node at block %d: %w", blockNumber, err)
}

// SubNodeOIDFromEntry extracts the sub-node block number from a branch entry
// In branch nodes, the value data contains the block number of the child node
func (bt *FileSystemBTree) SubNodeOIDFromEntry(
	reader io.ReaderAt,
	entry *BTreeEntry,
) (uint64, error) {
	if bt == nil {
		return 0, fmt.Errorf("invalid file system B-tree")
	}

	if entry == nil {
		return 0, fmt.Errorf("invalid B-tree entry")
	}

	// In branch nodes, value data should be 8 bytes (uint64 block number)
	if len(entry.ValueData) != 8 {
		return 0, fmt.Errorf("invalid value data size for branch entry: %d", len(entry.ValueData))
	}

	// Read the OID (little-endian)
	// Per drat (btree.c:377-378), in filesystem B-trees, child node references
	// are ALWAYS virtual OIDs that must be resolved through the volume's object map
	// (unlike container object map B-trees which use bit 63 to indicate virtual vs physical)
	virtualOID := binary.LittleEndian.Uint64(entry.ValueData[0:8])

	// Resolve through the volume's object map B-tree
	if bt.ObjectMapBTree == nil {
		return 0, fmt.Errorf("no object map B-tree available to resolve virtual OID %d", virtualOID)
	}

	descriptor, err := bt.ObjectMapBTree.GetDescriptorByObjectIdentifier(
		reader,
		virtualOID,
		bt.VolumeTransactionID,
	)
	if err != nil {
		return 0, fmt.Errorf("unable to resolve virtual OID %d: %w", virtualOID, err)
	}
	if descriptor == nil {
		return 0, fmt.Errorf("virtual OID %d not found in object map", virtualOID)
	}

	return descriptor.Value.ObjectPhysicalAddress, nil
}

// GetFileExtents retrieves file extents for a given identifier
func (bt *FileSystemBTree) GetFileExtents(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) ([]*FileExtent, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Use comprehensive tree traversal to get ALL records for this OID
	allRecords, err := bt.GetAllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	// Filter for file extent records only
	extents := make([]*FileExtent, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType == FileSystemRecordTypeFileExtent {
			entryID, logicalAddr, err := ParseFileExtentKey(entry.KeyData)
			if err != nil {
				continue
			}

			if entryID == identifier {
				// Parse the file extent value
				extent, err := ParseFileExtentValue(entry.ValueData)
				if err != nil {
					return nil, fmt.Errorf("unable to parse file extent value: %w", err)
				}

				// Set the logical offset from the key
				extent.LogicalOffset = logicalAddr

				extents = append(extents, extent)
			}
		}
	}

	return extents, nil
}

// GetAllRecordsForOID retrieves ALL filesystem records for a given OID
// Implements the algorithm from go-apfs GetFSRecordsForOid with descent and walk phases
func (bt *FileSystemBTree) GetAllRecordsForOID(
	reader io.ReaderAt,
	objectID uint64,
) ([]*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	rootNode, err := bt.GetRootNode(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Calculate tree height
	treeHeight := int(rootNode.NodeHeader.Level) + 1
	descPath := make([]int, treeHeight)

	records := make([]*BTreeEntry, 0)

	// PHASE 1: Descent - find first record with matching OID
	node := rootNode
	var firstLeafNode *BTreeNode
	for level := 0; level < treeHeight; level++ {
		if node.IsLeafNode() {
			firstLeafNode = node
			// Found leaf level - now position descPath at first matching record
			for idx, entry := range node.Entries {
				entryID, _ := ExtractIdentifierFromKey(entry.KeyData)
				if entryID == objectID {
					descPath[level] = idx
					break
				}
				if entryID > objectID {
					// No matching records exist
					return records, nil
				}
				descPath[level]++
			}
			break
		}

		// Find which child to descend
		foundChild := false
		for idx, entry := range node.Entries {
			entryID, _ := ExtractIdentifierFromKey(entry.KeyData)

			if entryID >= objectID {
				// Descend previous entry (or current if first)
				if idx > 0 {
					descPath[level] = idx - 1
				} else {
					descPath[level] = idx
				}

				childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
				if err != nil {
					return nil, err
				}
				node, err = bt.GetSubNode(reader, childOID)
				if err != nil {
					return nil, err
				}
				foundChild = true
				break
			}
			descPath[level] = idx + 1
		}

		if !foundChild {
			// Descend last entry
			descPath[level] = len(node.Entries) - 1
			childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
			if err != nil {
				return nil, err
			}
			node, err = bt.GetSubNode(reader, childOID)
			if err != nil {
				return nil, err
			}
		}
	}

	// FAST PATH: Check if all records are in the first leaf (common case)
	// Collect all matching records from first leaf
	leafLevel := treeHeight - 1
	allInFirstLeaf := true
	for idx := descPath[leafLevel]; idx < len(firstLeafNode.Entries); idx++ {
		entry := firstLeafNode.Entries[idx]
		entryID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}
		if entryID != objectID {
			// Hit end of matching records
			return records, nil
		}
		records = append(records, entry)
		descPath[leafLevel]++
	}

	// If we exhausted the leaf, check if there might be more in next leaf
	if descPath[leafLevel] >= len(firstLeafNode.Entries) {
		allInFirstLeaf = false
	}

	// If all records were in first leaf, we're done (common case)
	if allInFirstLeaf {
		return records, nil
	}

	// PHASE 2: Walk - collect remaining records from subsequent leaves (rare)
	if treeHeight == 1 {
		// The root is the only leaf; there is no next leaf to walk to
		return records, nil
	}

	for {
		// The current leaf is exhausted: advance to the next leaf by bumping
		// the lowest interior level and resetting everything below it
		descPath[leafLevel-1]++
		descPath[leafLevel] = 0

		// Re-descend from root using descPath, bubbling exhaustion upward
		node = rootNode
		level := 0
		for level < leafLevel {
			if descPath[level] >= len(node.Entries) {
				if level == 0 {
					// Root exhausted - whole tree walked
					return records, nil
				}
				// This interior node is exhausted: bump its parent, reset
				// this level and below, and restart the descent from root
				descPath[level-1]++
				for j := level; j < treeHeight; j++ {
					descPath[j] = 0
				}
				node = rootNode
				level = 0
				continue
			}

			childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
			if err != nil {
				return nil, err
			}
			node, err = bt.GetSubNode(reader, childOID)
			if err != nil {
				return nil, err
			}
			level++
		}

		if !node.IsLeafNode() {
			return nil, fmt.Errorf("B-tree walk reached level %d without finding a leaf node", level)
		}

		// At leaf node - collect matching records
		for idx := descPath[leafLevel]; idx < len(node.Entries); idx++ {
			entry := node.Entries[idx]
			entryID, err := ExtractIdentifierFromKey(entry.KeyData)
			if err != nil {
				continue
			}

			if entryID != objectID {
				// No more matching records
				return records, nil
			}

			records = append(records, entry)
			descPath[leafLevel]++
		}
		// Exhausted this leaf too, continue to the next one
	}
}

// GetInodeByIdentifier retrieves an inode by identifier
func (bt *FileSystemBTree) GetInodeByIdentifier(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) (*Inode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if DebugOutput {
		fmt.Printf("GetInodeByIdentifier: searching for inode %d\n", identifier)
	}

	// Use comprehensive tree traversal to get ALL records for this OID
	allRecords, err := bt.GetAllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	if DebugOutput {
		fmt.Printf("GetInodeByIdentifier: found %d total records for inode %d\n", len(allRecords), identifier)
	}

	// Find the inode entry
	for _, entry := range allRecords {
		// Check if this entry is an inode
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeInode {
			continue
		}

		entryID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if entryID == identifier {
			// Found the inode - parse it
			inode, err := NewInode()
			if err != nil {
				return nil, fmt.Errorf("unable to create inode: %w", err)
			}

			if err := inode.ReadKeyData(entry.KeyData); err != nil {
				return nil, fmt.Errorf("unable to parse inode key: %w", err)
			}

			if err := inode.ReadValueData(entry.ValueData); err != nil {
				return nil, fmt.Errorf("unable to parse inode value: %w", err)
			}

			return inode, nil
		}

		// NOTE: Do NOT break early based on entryID > identifier
		// B-tree entries are sorted by (type, id) not just (id)
		// so we must check all entries in the leaf node
	}

	return nil, fmt.Errorf("inode not found: %d", identifier)
}

// GetDirectoryEntries retrieves directory entries for a parent identifier
func (bt *FileSystemBTree) GetDirectoryEntries(
	reader io.ReaderAt,
	parentIdentifier uint64,
	xid uint64,
) ([]*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Directory records for one parent can span many leaf nodes; use the
	// full multi-leaf traversal and filter for directory entry records
	allRecords, err := bt.GetAllRecordsForOID(reader, parentIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", parentIdentifier, err)
	}

	entries := make([]*DirectoryEntryRecord, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeDirectoryEntry {
			continue
		}

		dirRecord := NewDirectoryEntryRecord()

		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			return nil, fmt.Errorf("unable to parse directory entry record key: %w", err)
		}

		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			return nil, fmt.Errorf("unable to parse directory entry record value: %w", err)
		}

		entries = append(entries, dirRecord)
	}

	return entries, nil
}

// GetAttributes retrieves extended attributes for an identifier
func (bt *FileSystemBTree) GetAttributes(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) ([]*AttributeValues, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Extended attributes for one file can span leaf nodes; use the full
	// multi-leaf traversal and filter for extended attribute records
	allRecords, err := bt.GetAllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	attributes := make([]*AttributeValues, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeExtendedAttribute {
			continue
		}

		attr := &AttributeValues{}

		if err := attr.ReadKeyData(entry.KeyData); err != nil {
			return nil, fmt.Errorf("unable to parse attribute key: %w", err)
		}

		if err := attr.ReadValueData(entry.ValueData); err != nil {
			return nil, fmt.Errorf("unable to parse attribute value: %w", err)
		}

		attributes = append(attributes, attr)
	}

	return attributes, nil
}

// GetEntryFromNodeByIdentifier retrieves an entry from a node by identifier and data type
func (bt *FileSystemBTree) GetEntryFromNodeByIdentifier(
	node *BTreeNode,
	identifier uint64,
	dataType uint8,
) (*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid node")
	}

	if DebugOutput {
		fmt.Printf("FileSystemBTree.GetEntryFromNodeByIdentifier: retrieving B-tree entry identifier: %d, data type: 0x%02x\n",
			identifier, dataType)
	}

	// Create lookup identifier (data type in upper 4 bits + identifier in lower 60 bits)
	lookupIdentifier := (uint64(dataType) << 60) | identifier

	// Search through entries
	var previousEntry *BTreeEntry
	for _, entry := range node.Entries {
		// Extract file system identifier from key
		if len(entry.KeyData) < 8 {
			continue
		}

		fsIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])
		entryIdentifier := fsIdentifier & 0x0FFFFFFFFFFFFFFF // Lower 60 bits
		entryDataType := uint8((fsIdentifier >> 60) & 0x0F)  // Upper 4 bits

		if node.IsLeafNode() {
			// In leaf node, exact match
			if entryIdentifier == identifier && (dataType == FileSystemRecordTypeAny || entryDataType == dataType) {
				return entry, nil
			}
		} else {
			// In branch node, find the entry where lookupIdentifier <= fsIdentifier
			if lookupIdentifier <= fsIdentifier {
				if previousEntry != nil {
					return previousEntry, nil
				}
				return entry, nil
			}
			previousEntry = entry
		}
	}

	// If we're in a branch node and didn't find a match, return the last entry
	if !node.IsLeafNode() && previousEntry != nil {
		return previousEntry, nil
	}

	return nil, fmt.Errorf("entry not found for identifier: %d, data type: 0x%02x", identifier, dataType)
}

// GetEntryByIdentifier retrieves an entry by identifier and data type, navigating the tree
func (bt *FileSystemBTree) GetEntryByIdentifier(
	reader io.ReaderAt,
	identifier uint64,
	dataType uint8,
	xid uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Get root node
	node, err := bt.GetRootNode(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to the correct node
	for !node.IsLeafNode() {
		entry, err := bt.GetEntryFromNodeByIdentifier(node, identifier, dataType)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get entry from node: %w", err)
		}

		// Get child block number
		childBlockNumber, err := bt.SubNodeOIDFromEntry(reader, entry)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get child block number: %w", err)
		}

		// Read child node
		node, err = bt.GetSubNode(reader, childBlockNumber)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read sub-node: %w", err)
		}
	}

	// Now we're at the leaf node, get the entry
	entry, err := bt.GetEntryFromNodeByIdentifier(node, identifier, dataType)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get entry from leaf node: %w", err)
	}

	return node, entry, nil
}

// GetDirectoryEntryRecordByUTF8Name retrieves a directory entry record by UTF-8 name
func (bt *FileSystemBTree) GetDirectoryEntryRecordByUTF8Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name string,
	xid uint64,
) (*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if name == "" {
		return nil, fmt.Errorf("invalid name")
	}

	// Calculate name hash
	nameHash := CalculateNameHash([]byte(name), bt.UseCaseFolding)

	// A directory's records can span multiple leaf nodes, and the single-key
	// descent compares identifiers only, so it can land on a leaf that holds
	// part of the directory but not the searched name. Use the full
	// multi-leaf traversal (served from the node cache) and match by hash
	// and name.
	allRecords, err := bt.GetAllRecordsForOID(reader, parentIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", parentIdentifier, err)
	}

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil || dataType != FileSystemRecordTypeDirectoryEntry {
			continue
		}

		dirRecord := NewDirectoryEntryRecord()
		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			continue
		}
		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			continue
		}

		if dirRecord.NameHash == nameHash {
			if dirRecord.CompareNameWithUTF8String([]byte(name), nameHash, bt.UseCaseFolding) == 0 {
				return dirRecord, nil
			}
		}
	}

	return nil, fmt.Errorf("directory entry record not found")
}

// GetDirectoryEntryRecordByUTF16Name retrieves a directory entry record by UTF-16 name
func (bt *FileSystemBTree) GetDirectoryEntryRecordByUTF16Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	xid uint64,
) (*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if len(name) == 0 {
		return nil, fmt.Errorf("invalid name")
	}

	// Convert UTF-16 to UTF-8 and delegate to the multi-leaf UTF-8 search
	utf8Name := UTF16ToString(name)

	return bt.GetDirectoryEntryRecordByUTF8Name(reader, parentIdentifier, utf8Name, xid)
}

// GetInodeByUTF8Name retrieves an inode and directory entry record by UTF-8 name
func (bt *FileSystemBTree) GetInodeByUTF8Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name string,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory entry record
	dirRecord, err := bt.GetDirectoryEntryRecordByUTF8Name(reader, parentIdentifier, name, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory entry record: %w", err)
	}

	// Then get the inode using the identifier from the directory entry record
	inode, err := bt.GetInodeByIdentifier(reader, dirRecord.Identifier, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// GetInodeByUTF8Path retrieves an inode and directory entry record by UTF-8 path
func (bt *FileSystemBTree) GetInodeByUTF8Path(
	reader io.ReaderAt,
	parentIdentifier uint64,
	path string,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	if path == "" {
		return nil, nil, fmt.Errorf("invalid path")
	}

	// Split path by '/'
	pathSegments := splitPath(path)

	currentParentID := parentIdentifier
	var currentInode *Inode
	var currentDirRecord *DirectoryEntryRecord
	var err error

	// Navigate through each path segment
	for _, segment := range pathSegments {
		if segment == "" {
			continue
		}

		currentInode, currentDirRecord, err = bt.GetInodeByUTF8Name(reader, currentParentID, segment, xid)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get inode for path segment '%s': %w", segment, err)
		}

		// Update parent ID for next iteration
		currentParentID = currentDirRecord.Identifier
	}

	return currentInode, currentDirRecord, nil
}

// GetInodeByUTF16Name retrieves an inode and directory entry record by UTF-16 name
func (bt *FileSystemBTree) GetInodeByUTF16Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory entry record
	dirRecord, err := bt.GetDirectoryEntryRecordByUTF16Name(reader, parentIdentifier, name, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory entry record: %w", err)
	}

	// Then get the inode using the identifier from the directory entry record
	inode, err := bt.GetInodeByIdentifier(reader, dirRecord.Identifier, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// GetInodeByUTF16Path retrieves an inode and directory entry record by UTF-16 path
func (bt *FileSystemBTree) GetInodeByUTF16Path(
	reader io.ReaderAt,
	parentIdentifier uint64,
	path []uint16,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Convert UTF-16 path to UTF-8
	utf8Path := UTF16ToString(path)

	// Use UTF-8 path function
	return bt.GetInodeByUTF8Path(reader, parentIdentifier, utf8Path, xid)
}

// splitPath splits a path string by '/' separator
func splitPath(path string) []string {
	segments := []string{}
	currentSegment := ""

	for _, char := range path {
		if char == '/' {
			if currentSegment != "" {
				segments = append(segments, currentSegment)
				currentSegment = ""
			}
		} else {
			currentSegment += string(char)
		}
	}

	if currentSegment != "" {
		segments = append(segments, currentSegment)
	}

	return segments
}
