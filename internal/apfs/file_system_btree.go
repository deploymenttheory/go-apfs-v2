package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// FileSystemBTree represents the APFS file system B-tree
// Corresponds to libfsapfs_file_system_btree.h
type FileSystemBTree struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The object map B-tree (for transaction identifier mapping)
	ObjectMapBTree *ObjectMapBTree

	// The block number of B-tree root node
	RootNodeBlockNumber uint64

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
	rootNodeBlockNumber uint64,
	useCaseFolding bool,
) *FileSystemBTree {
	return &FileSystemBTree{
		IOHandle:            ioHandle,
		EncryptionContext:   encryptionContext,
		ObjectMapBTree:      objectMapBTree,
		RootNodeBlockNumber: rootNodeBlockNumber,
		UseCaseFolding:      useCaseFolding,
	}
}

// GetRootNode retrieves the root node of the file system B-tree
func (bt *FileSystemBTree) GetRootNode(
	fileHandle io.ReaderAt,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read the root node using the ReadBTreeNode convenience function
	node, err := ReadBTreeNode(fileHandle, bt.IOHandle, bt.EncryptionContext, bt.RootNodeBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node at block %d: %w", bt.RootNodeBlockNumber, err)
	}

	return node, nil
}

// GetSubNode retrieves a sub-node (child node) by block number
func (bt *FileSystemBTree) GetSubNode(
	fileHandle io.ReaderAt,
	blockNumber uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read the sub-node using the ReadBTreeNode convenience function
	node, err := ReadBTreeNode(fileHandle, bt.IOHandle, bt.EncryptionContext, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read sub-node at block %d: %w", blockNumber, err)
	}

	return node, nil
}

// GetSubNodeBlockNumberFromEntry extracts the sub-node block number from a branch entry
// In branch nodes, the value data contains the block number of the child node
func (bt *FileSystemBTree) GetSubNodeBlockNumberFromEntry(
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

	// Read the block number (little-endian)
	blockNumber := binary.LittleEndian.Uint64(entry.ValueData[0:8])

	// Check if this is a virtual block number (bit 63 is set)
	// Virtual block numbers need to be resolved through the object map B-tree
	if (blockNumber & 0x8000000000000000) != 0 {
		// This is a virtual block number
		virtualBlockNumber := blockNumber & 0x7fffffffffffffff

		// If we have an object map B-tree, resolve to physical block number
		if bt.ObjectMapBTree != nil {
			// Object map resolution would happen here
			// For now, return an error indicating this needs object map support
			return 0, fmt.Errorf("virtual block number resolution requires object map B-tree implementation: virtual block %d", virtualBlockNumber)
		}

		// Without object map, treat as physical (this may not work for all cases)
		return virtualBlockNumber, nil
	}

	// This is a physical block number, return it directly
	return blockNumber, nil
}

// GetFileExtents retrieves file extents for a given identifier
func (bt *FileSystemBTree) GetFileExtents(
	fileHandle io.ReaderAt,
	identifier uint64,
	transactionIdentifier uint64,
) ([]*FileExtent, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read root node
	node, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to leaf node
	leafNode, err := bt.findLeafNodeForKey(fileHandle, node, CreateFileExtentKey(identifier, 0))
	if err != nil {
		return nil, fmt.Errorf("unable to find leaf node: %w", err)
	}

	// Collect all file extents for this identifier from the leaf node
	extents := make([]*FileExtent, 0)

	for _, entry := range leafNode.Entries {
		// Check if this entry is a file extent for our identifier
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemDataTypeFileExtent {
			continue
		}

		entryID, logicalAddr, err := ParseFileExtentKey(entry.KeyData)
		if err != nil {
			continue
		}

		if entryID != identifier {
			// If we've passed our identifier, we're done
			if entryID > identifier {
				break
			}
			continue
		}

		// Parse the file extent value
		extent, err := ParseFileExtentValue(entry.ValueData)
		if err != nil {
			return nil, fmt.Errorf("unable to parse file extent value: %w", err)
		}

		// Set the logical offset from the key
		extent.LogicalOffset = logicalAddr

		extents = append(extents, extent)
	}

	return extents, nil
}

// GetInodeByIdentifier retrieves an inode by identifier
func (bt *FileSystemBTree) GetInodeByIdentifier(
	fileHandle io.ReaderAt,
	identifier uint64,
	transactionIdentifier uint64,
) (*Inode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read root node
	node, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to leaf node
	leafNode, err := bt.findLeafNodeForKey(fileHandle, node, CreateInodeKey(identifier))
	if err != nil {
		return nil, fmt.Errorf("unable to find leaf node: %w", err)
	}

	// Find the inode entry in the leaf node
	for _, entry := range leafNode.Entries {
		// Check if this entry is an inode
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemDataTypeInode {
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

		// If we've passed our identifier, it doesn't exist
		if entryID > identifier {
			break
		}
	}

	return nil, fmt.Errorf("inode not found: %d", identifier)
}

// GetDirectoryEntries retrieves directory entries for a parent identifier
func (bt *FileSystemBTree) GetDirectoryEntries(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	transactionIdentifier uint64,
) ([]*DirectoryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read root node
	node, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Create a search key for directory records with this parent ID
	searchKey := make([]byte, 10)
	fsid := CreateFileSystemKey(parentIdentifier, FileSystemDataTypeDirectoryRecord)
	binary.LittleEndian.PutUint64(searchKey[0:8], fsid)
	binary.LittleEndian.PutUint16(searchKey[8:10], 0) // Minimum name size

	// Navigate to leaf node
	leafNode, err := bt.findLeafNodeForKey(fileHandle, node, searchKey)
	if err != nil {
		return nil, fmt.Errorf("unable to find leaf node: %w", err)
	}

	// Collect all directory entries for this parent identifier
	entries := make([]*DirectoryRecord, 0)

	for _, entry := range leafNode.Entries {
		// Check if this entry is a directory record
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemDataTypeDirectoryRecord {
			continue
		}

		entryParentID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if entryParentID != parentIdentifier {
			// If we've passed our parent identifier, we're done
			if entryParentID > parentIdentifier {
				break
			}
			continue
		}

		// Parse the directory record
		dirRecord := NewDirectoryRecord()

		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			return nil, fmt.Errorf("unable to parse directory record key: %w", err)
		}

		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			return nil, fmt.Errorf("unable to parse directory record value: %w", err)
		}

		entries = append(entries, dirRecord)
	}

	return entries, nil
}

// GetAttributes retrieves extended attributes for an identifier
func (bt *FileSystemBTree) GetAttributes(
	fileHandle io.ReaderAt,
	identifier uint64,
	transactionIdentifier uint64,
) ([]*AttributeValues, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Read root node
	node, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Create a search key for extended attributes with this identifier
	searchKey := make([]byte, 10)
	fsid := CreateFileSystemKey(identifier, FileSystemDataTypeExtendedAttribute)
	binary.LittleEndian.PutUint64(searchKey[0:8], fsid)
	binary.LittleEndian.PutUint16(searchKey[8:10], 0) // Minimum name size

	// Navigate to leaf node
	leafNode, err := bt.findLeafNodeForKey(fileHandle, node, searchKey)
	if err != nil {
		return nil, fmt.Errorf("unable to find leaf node: %w", err)
	}

	// Collect all extended attributes for this identifier
	attributes := make([]*AttributeValues, 0)

	for _, entry := range leafNode.Entries {
		// Check if this entry is an extended attribute
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemDataTypeExtendedAttribute {
			continue
		}

		entryID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if entryID != identifier {
			// If we've passed our identifier, we're done
			if entryID > identifier {
				break
			}
			continue
		}

		// Parse the extended attribute
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
// Corresponds to libfsapfs_file_system_btree_get_entry_from_node_by_identifier
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
		fmt.Printf("libfsapfs_file_system_btree_get_entry_from_node_by_identifier: retrieving B-tree entry identifier: %d, data type: 0x%02x\n",
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
			if entryIdentifier == identifier && (dataType == FileSystemDataTypeAny || entryDataType == dataType) {
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
// Corresponds to libfsapfs_file_system_btree_get_entry_by_identifier
func (bt *FileSystemBTree) GetEntryByIdentifier(
	fileHandle io.ReaderAt,
	identifier uint64,
	dataType uint8,
	transactionIdentifier uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Get root node
	node, err := bt.GetRootNode(fileHandle)
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
		childBlockNumber, err := bt.GetSubNodeBlockNumberFromEntry(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get child block number: %w", err)
		}

		// Read child node
		node, err = bt.GetSubNode(fileHandle, childBlockNumber)
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

// GetDirectoryRecordByUTF8Name retrieves a directory record by UTF-8 name
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf8_name (directory record portion)
func (bt *FileSystemBTree) GetDirectoryRecordByUTF8Name(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	name string,
	transactionIdentifier uint64,
) (*DirectoryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if name == "" {
		return nil, fmt.Errorf("invalid name")
	}

	// Calculate name hash
	nameHash := CalculateNameHash([]byte(name), bt.UseCaseFolding)

	// Get root node
	rootNode, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to find directory record
	return bt.getDirectoryRecordFromNode(fileHandle, rootNode, parentIdentifier, name, nameHash, transactionIdentifier)
}

// GetDirectoryRecordByUTF16Name retrieves a directory record by UTF-16 name
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf16_name (directory record portion)
func (bt *FileSystemBTree) GetDirectoryRecordByUTF16Name(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	transactionIdentifier uint64,
) (*DirectoryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if len(name) == 0 {
		return nil, fmt.Errorf("invalid name")
	}

	// Convert UTF-16 to UTF-8 for name hash calculation
	utf8Name := UTF16ToString(name)
	nameHash := CalculateNameHash([]byte(utf8Name), bt.UseCaseFolding)

	// Get root node
	rootNode, err := bt.GetRootNode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to find directory record
	return bt.getDirectoryRecordFromNode(fileHandle, rootNode, parentIdentifier, utf8Name, nameHash, transactionIdentifier)
}

// GetInodeByUTF8Name retrieves an inode and directory record by UTF-8 name
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf8_name
func (bt *FileSystemBTree) GetInodeByUTF8Name(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	name string,
	transactionIdentifier uint64,
) (*Inode, *DirectoryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory record
	dirRecord, err := bt.GetDirectoryRecordByUTF8Name(fileHandle, parentIdentifier, name, transactionIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory record: %w", err)
	}

	// Then get the inode using the identifier from the directory record
	inode, err := bt.GetInodeByIdentifier(fileHandle, dirRecord.Identifier, transactionIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// GetInodeByUTF8Path retrieves an inode and directory record by UTF-8 path
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf8_path
func (bt *FileSystemBTree) GetInodeByUTF8Path(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	path string,
	transactionIdentifier uint64,
) (*Inode, *DirectoryRecord, error) {
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
	var currentDirRecord *DirectoryRecord
	var err error

	// Navigate through each path segment
	for _, segment := range pathSegments {
		if segment == "" {
			continue
		}

		currentInode, currentDirRecord, err = bt.GetInodeByUTF8Name(fileHandle, currentParentID, segment, transactionIdentifier)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get inode for path segment '%s': %w", segment, err)
		}

		// Update parent ID for next iteration
		currentParentID = currentDirRecord.Identifier
	}

	return currentInode, currentDirRecord, nil
}

// GetInodeByUTF16Name retrieves an inode and directory record by UTF-16 name
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf16_name
func (bt *FileSystemBTree) GetInodeByUTF16Name(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	transactionIdentifier uint64,
) (*Inode, *DirectoryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory record
	dirRecord, err := bt.GetDirectoryRecordByUTF16Name(fileHandle, parentIdentifier, name, transactionIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory record: %w", err)
	}

	// Then get the inode using the identifier from the directory record
	inode, err := bt.GetInodeByIdentifier(fileHandle, dirRecord.Identifier, transactionIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// GetInodeByUTF16Path retrieves an inode and directory record by UTF-16 path
// Corresponds to libfsapfs_file_system_btree_get_inode_by_utf16_path
func (bt *FileSystemBTree) GetInodeByUTF16Path(
	fileHandle io.ReaderAt,
	parentIdentifier uint64,
	path []uint16,
	transactionIdentifier uint64,
) (*Inode, *DirectoryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Convert UTF-16 path to UTF-8
	utf8Path := UTF16ToString(path)

	// Use UTF-8 path function
	return bt.GetInodeByUTF8Path(fileHandle, parentIdentifier, utf8Path, transactionIdentifier)
}

// getDirectoryRecordFromNode is an internal helper that navigates nodes to find a directory record
func (bt *FileSystemBTree) getDirectoryRecordFromNode(
	fileHandle io.ReaderAt,
	node *BTreeNode,
	parentIdentifier uint64,
	name string,
	nameHash uint32,
	transactionIdentifier uint64,
) (*DirectoryRecord, error) {
	if node.IsLeafNode() {
		return bt.getDirectoryRecordFromLeafNode(node, parentIdentifier, name, nameHash)
	}
	return bt.getDirectoryRecordFromBranchNode(fileHandle, node, parentIdentifier, name, nameHash, transactionIdentifier, 0)
}

// getDirectoryRecordFromLeafNode searches for a directory record in a leaf node
func (bt *FileSystemBTree) getDirectoryRecordFromLeafNode(
	node *BTreeNode,
	parentIdentifier uint64,
	name string,
	nameHash uint32,
) (*DirectoryRecord, error) {
	for _, entry := range node.Entries {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil || dataType != FileSystemDataTypeDirectoryRecord {
			continue
		}

		entryParentID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil || entryParentID != parentIdentifier {
			continue
		}

		// Parse directory record
		dirRecord := NewDirectoryRecord()
		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			continue
		}
		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			continue
		}

		// Compare name and name hash
		if dirRecord.NameHash == nameHash {
			if dirRecord.CompareNameWithUTF8String([]byte(name), nameHash, bt.UseCaseFolding) == 0 {
				return dirRecord, nil
			}
		}
	}

	return nil, fmt.Errorf("directory record not found")
}

// getDirectoryRecordFromBranchNode searches for a directory record starting from a branch node
func (bt *FileSystemBTree) getDirectoryRecordFromBranchNode(
	fileHandle io.ReaderAt,
	node *BTreeNode,
	parentIdentifier uint64,
	name string,
	nameHash uint32,
	transactionIdentifier uint64,
	recursionDepth int,
) (*DirectoryRecord, error) {
	if recursionDepth >= MaximumBTreeNodeRecursionDepth {
		return nil, fmt.Errorf("maximum recursion depth exceeded")
	}

	// Find the appropriate child node
	searchKey := make([]byte, 10)
	fsid := CreateFileSystemKey(parentIdentifier, FileSystemDataTypeDirectoryRecord)
	binary.LittleEndian.PutUint64(searchKey[0:8], fsid)
	binary.LittleEndian.PutUint16(searchKey[8:10], uint16(len(name)))

	entry, err := bt.GetEntryFromNodeByIdentifier(node, parentIdentifier, FileSystemDataTypeDirectoryRecord)
	if err != nil {
		return nil, fmt.Errorf("unable to get entry from branch node: %w", err)
	}

	childBlockNumber, err := bt.GetSubNodeBlockNumberFromEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("unable to get child block number: %w", err)
	}

	childNode, err := bt.GetSubNode(fileHandle, childBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read child node: %w", err)
	}

	return bt.getDirectoryRecordFromNode(fileHandle, childNode, parentIdentifier, name, nameHash, transactionIdentifier)
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

// findLeafNodeForKey navigates from a given node to the leaf node that should contain the key
func (bt *FileSystemBTree) findLeafNodeForKey(
	fileHandle io.ReaderAt,
	node *BTreeNode,
	searchKey []byte,
) (*BTreeNode, error) {
	// If this is a leaf node, return it
	if node.IsLeafNode() {
		return node, nil
	}

	// This is a branch node - find the appropriate child
	// In branch nodes, entries contain (key, child_block_number) pairs
	// We need to find the entry with the largest key that is <= searchKey

	var childBlockNumber uint64
	found := false

	for i, entry := range node.Entries {
		// Compare keys
		cmp := CompareFileSystemKeys(searchKey, entry.KeyData, FileSystemDataTypeAny)

		if cmp <= 0 {
			// searchKey <= entry.KeyData
			// Use this entry
			var err error
			childBlockNumber, err = bt.GetSubNodeBlockNumberFromEntry(entry)
			if err != nil {
				return nil, fmt.Errorf("unable to get child block number: %w", err)
			}
			found = true
			break
		}

		// If this is the last entry and searchKey > entry.KeyData, use the last entry
		if i == len(node.Entries)-1 {
			var err error
			childBlockNumber, err = bt.GetSubNodeBlockNumberFromEntry(entry)
			if err != nil {
				return nil, fmt.Errorf("unable to get child block number: %w", err)
			}
			found = true
		}
	}

	if !found {
		// If no suitable entry found, use the first entry
		if len(node.Entries) > 0 {
			var err error
			childBlockNumber, err = bt.GetSubNodeBlockNumberFromEntry(node.Entries[0])
			if err != nil {
				return nil, fmt.Errorf("unable to get child block number: %w", err)
			}
		} else {
			return nil, fmt.Errorf("branch node has no entries")
		}
	}

	// Read the child node
	childNode, err := bt.GetSubNode(fileHandle, childBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read child node at block %d: %w", childBlockNumber, err)
	}

	// Recursively search in child node
	return bt.findLeafNodeForKey(fileHandle, childNode, searchKey)
}
