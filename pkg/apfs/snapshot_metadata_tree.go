// Snapshot metadata tree functions
// Corresponds to libfsapfs_snapshot_metadata_tree.c and libfsapfs_snapshot_metadata_tree.h
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// SnapshotMetadataTree represents the APFS snapshot metadata B-tree
// Corresponds to libfsapfs_snapshot_metadata_tree_t
type SnapshotMetadataTree struct {
	IOHandle            *IOHandle
	ObjectMapBTree      *ObjectMapBTree
	RootNodeBlockNumber uint64
	nodeCache           map[uint64]*BTreeNode
}

// NewSnapshotMetadataTree creates a new snapshot metadata tree
// Corresponds to libfsapfs_snapshot_metadata_tree_initialize
func NewSnapshotMetadataTree(
	ioHandle *IOHandle,
	objectMapBTree *ObjectMapBTree,
	rootNodeBlockNumber uint64,
) (*SnapshotMetadataTree, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	if objectMapBTree == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	return &SnapshotMetadataTree{
		IOHandle:            ioHandle,
		ObjectMapBTree:      objectMapBTree,
		RootNodeBlockNumber: rootNodeBlockNumber,
		nodeCache:           make(map[uint64]*BTreeNode),
	}, nil
}

// Free releases resources associated with the snapshot metadata tree
// Corresponds to libfsapfs_snapshot_metadata_tree_free
func (t *SnapshotMetadataTree) Free() error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	// Clear the node cache
	t.nodeCache = nil

	return nil
}

// GetSubNodeBlockNumberFromEntry retrieves the sub node block number from a B-tree entry
// Corresponds to libfsapfs_snapshot_metadata_tree_get_sub_node_block_number_from_entry
func (t *SnapshotMetadataTree) GetSubNodeBlockNumberFromEntry(
	fileHandle io.ReaderAt,
	entry *BTreeEntry,
	transactionIdentifier uint64,
) (uint64, error) {
	if t == nil {
		return 0, fmt.Errorf("invalid snapshot metadata tree")
	}

	if entry == nil {
		return 0, fmt.Errorf("invalid B-tree entry")
	}

	if len(entry.ValueData) != 8 {
		return 0, fmt.Errorf("invalid B-tree entry - unsupported value data size")
	}

	// Parse sub node object identifier
	subNodeObjectIdentifier := binary.LittleEndian.Uint64(entry.ValueData)

	if IsVerbose() {
		Printf("%s: sub node object identifier: %d (transaction: %d)\n",
			"GetSubNodeBlockNumberFromEntry", subNodeObjectIdentifier, transactionIdentifier)
	}

	// Get the physical block number from the object map
	descriptor, err := t.ObjectMapBTree.GetDescriptorByObjectIdentifier(
		fileHandle,
		subNodeObjectIdentifier,
		transactionIdentifier,
	)
	if err != nil {
		return 0, fmt.Errorf("unable to retrieve object map descriptor for sub node object identifier: %d (transaction: %d): %w",
			subNodeObjectIdentifier, transactionIdentifier, err)
	}

	if descriptor == nil {
		return 0, nil
	}

	physicalAddress, err := descriptor.GetPhysicalAddress()
	if err != nil {
		return 0, fmt.Errorf("unable to get physical address: %w", err)
	}

	if IsVerbose() {
		Printf("%s: sub node block number: %d\n", "GetSubNodeBlockNumberFromEntry", physicalAddress)
	}

	return physicalAddress, nil
}

// GetRootNode retrieves the snapshot metadata tree root node
// Corresponds to libfsapfs_snapshot_metadata_tree_get_root_node
func (t *SnapshotMetadataTree) GetRootNode(
	fileHandle io.ReaderAt,
	rootNodeBlockNumber uint64,
) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if rootNodeBlockNumber > common.Int32Max {
		return nil, fmt.Errorf("invalid root node block number value out of bounds")
	}

	// Check cache first
	if node, found := t.nodeCache[rootNodeBlockNumber]; found {
		return node, nil
	}

	// Start profiling if enabled
	var startTimestamp int64
	if t.IOHandle.Profiler != nil {
		var err error
		startTimestamp, err = t.IOHandle.Profiler.StartTiming()
		if err != nil {
			return nil, fmt.Errorf("unable to start timing: %w", err)
		}
	}

	// Read the block data
	blockOffset := int64(rootNodeBlockNumber) * int64(t.IOHandle.BlockSize)
	blockData := make([]byte, t.IOHandle.BlockSize)
	n, err := fileHandle.ReadAt(blockData, blockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("unable to read data block: %d: %w", rootNodeBlockNumber, err)
	}
	if n != int(t.IOHandle.BlockSize) {
		return nil, fmt.Errorf("unable to read data block: %d", rootNodeBlockNumber)
	}

	// Parse the B-tree node
	node := NewBTreeNode()

	if err := node.ReadData(blockData); err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type and subtype
	if node.ObjectType != 0x40000002 {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	if node.ObjectSubtype != 0x00000010 {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate node is a root node
	if node.NodeHeader == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing node header")
	}

	if (node.NodeHeader.Flags & 0x0001) == 0 {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	// Validate footer
	if node.Footer == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing footer")
	}

	if node.Footer.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds")
	}

	if node.Footer.KeySize != 0 {
		return nil, fmt.Errorf("invalid key size value out of bounds")
	}

	if node.Footer.ValueSize != 0 {
		return nil, fmt.Errorf("invalid value size value out of bounds")
	}

	// Cache the node
	t.nodeCache[rootNodeBlockNumber] = node

	// Stop profiling if enabled
	if t.IOHandle.Profiler != nil {
		if err := t.IOHandle.Profiler.StopTiming(
			startTimestamp,
			"GetRootNode",
			blockOffset,
			uint64(t.IOHandle.BlockSize),
		); err != nil {
			return nil, fmt.Errorf("unable to stop timing: %w", err)
		}
	}

	return node, nil
}

// GetSubNode retrieves a snapshot metadata tree sub node
// Corresponds to libfsapfs_snapshot_metadata_tree_get_sub_node
func (t *SnapshotMetadataTree) GetSubNode(
	fileHandle io.ReaderAt,
	subNodeBlockNumber uint64,
) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if subNodeBlockNumber > common.Int32Max {
		return nil, fmt.Errorf("invalid sub node block number value out of bounds")
	}

	// Check cache first
	if node, found := t.nodeCache[subNodeBlockNumber]; found {
		return node, nil
	}

	// Start profiling if enabled
	var startTimestamp int64
	if t.IOHandle.Profiler != nil {
		var err error
		startTimestamp, err = t.IOHandle.Profiler.StartTiming()
		if err != nil {
			return nil, fmt.Errorf("unable to start timing: %w", err)
		}
	}

	// Read the block data
	blockOffset := int64(subNodeBlockNumber) * int64(t.IOHandle.BlockSize)
	blockData := make([]byte, t.IOHandle.BlockSize)
	n, err := fileHandle.ReadAt(blockData, blockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("unable to read data block: %d: %w", subNodeBlockNumber, err)
	}
	if n != int(t.IOHandle.BlockSize) {
		return nil, fmt.Errorf("unable to read data block: %d", subNodeBlockNumber)
	}

	// Parse the B-tree node
	node := NewBTreeNode()

	if err := node.ReadData(blockData); err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type and subtype
	if node.ObjectType != 0x40000002 {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	if node.ObjectSubtype != 0x00000010 {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate footer
	if node.Footer == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing footer")
	}

	if node.Footer.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds")
	}

	// Cache the node
	t.nodeCache[subNodeBlockNumber] = node

	// Stop profiling if enabled
	if t.IOHandle.Profiler != nil {
		if err := t.IOHandle.Profiler.StopTiming(
			startTimestamp,
			"GetSubNode",
			blockOffset,
			uint64(t.IOHandle.BlockSize),
		); err != nil {
			return nil, fmt.Errorf("unable to stop timing: %w", err)
		}
	}

	return node, nil
}

// GetEntryFromNodeByIdentifier retrieves a B-tree entry from a node by object identifier
// Corresponds to libfsapfs_snapshot_metadata_tree_get_entry_from_node_by_identifier
func (t *SnapshotMetadataTree) GetEntryFromNodeByIdentifier(
	node *BTreeNode,
	objectIdentifier uint64,
) (*BTreeEntry, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if node.Entries == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing entries")
	}

	// Binary search for the entry
	for _, entry := range node.Entries {
		if len(entry.KeyData) < 8 {
			continue
		}

		entryObjectIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])

		if entryObjectIdentifier == objectIdentifier {
			return entry, nil
		}
	}

	return nil, nil
}

// GetEntryByIdentifier retrieves a B-tree entry by object identifier
// Corresponds to libfsapfs_snapshot_metadata_tree_get_entry_by_identifier
func (t *SnapshotMetadataTree) GetEntryByIdentifier(
	fileHandle io.ReaderAt,
	objectIdentifier uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the root node
	node, err := t.GetRootNode(fileHandle, t.RootNodeBlockNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Traverse the tree
	for {
		if node == nil {
			return nil, nil, fmt.Errorf("invalid B-tree node")
		}

		// Check if this is a leaf node
		isLeaf := node.NodeHeader != nil && (node.NodeHeader.Flags&0x0002) != 0

		if isLeaf {
			// Search for the entry in the leaf node
			entry, err := t.GetEntryFromNodeByIdentifier(node, objectIdentifier)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to get entry from node: %w", err)
			}
			return node, entry, nil
		}

		// Branch node - find the appropriate sub node
		var subNodeBlockNumber uint64
		found := false

		for _, entry := range node.Entries {
			if len(entry.KeyData) < 8 {
				continue
			}

			entryObjectIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])

			if objectIdentifier <= entryObjectIdentifier {
				// Get sub node block number
				subNodeBlockNumber, err = t.GetSubNodeBlockNumberFromEntry(fileHandle, entry, 0)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to get sub node block number: %w", err)
				}
				found = true
				break
			}
		}

		if !found {
			// Not found
			return nil, nil, nil
		}

		// Get the sub node
		node, err = t.GetSubNode(fileHandle, subNodeBlockNumber)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get sub node: %w", err)
		}
	}
}

// SnapshotMetadata represents snapshot metadata
// Corresponds to libfsapfs_snapshot_metadata_t
type SnapshotMetadata struct {
	ObjectIdentifier            uint64
	VolumeSuperblockBlockNumber uint64
	SuperblockObjectIdentifier  uint64 // Alias for VolumeSuperblockBlockNumber
	Name                        string
}

// GetMetadataByObjectIdentifier retrieves snapshot metadata by object identifier
// Corresponds to libfsapfs_snapshot_metadata_tree_get_metadata_by_object_identifier
func (t *SnapshotMetadataTree) GetMetadataByObjectIdentifier(
	fileHandle io.ReaderAt,
	objectIdentifier uint64,
) (*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the entry
	_, entry, err := t.GetEntryByIdentifier(fileHandle, objectIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get entry by identifier: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// Parse the metadata
	metadata := &SnapshotMetadata{
		ObjectIdentifier: objectIdentifier,
	}

	// Parse value data
	if len(entry.ValueData) >= 46 {
		metadata.VolumeSuperblockBlockNumber = binary.LittleEndian.Uint64(entry.ValueData[8:16])
		metadata.SuperblockObjectIdentifier = metadata.VolumeSuperblockBlockNumber

		// Parse name
		nameSize := binary.LittleEndian.Uint16(entry.ValueData[44:46])
		if len(entry.ValueData) >= 46+int(nameSize) {
			metadata.Name = string(entry.ValueData[46 : 46+nameSize])
		}
	}

	return metadata, nil
}

// GetSnapshots retrieves all snapshots from the tree
// Corresponds to libfsapfs_snapshot_metadata_tree_get_snapshots
func (t *SnapshotMetadataTree) GetSnapshots(
	fileHandle io.ReaderAt,
	transactionIdentifier uint64,
) ([]*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the root node
	node, err := t.GetRootNode(fileHandle, t.RootNodeBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Initialize snapshots array
	snapshots := make([]*SnapshotMetadata, 0)

	// Check if this is a leaf node
	isLeaf := node.NodeHeader != nil && (node.NodeHeader.Flags&0x0002) != 0

	if isLeaf {
		// Get snapshots from leaf node
		if err := t.getSnapshotsFromLeafNode(node, &snapshots); err != nil {
			return nil, fmt.Errorf("unable to get snapshots from leaf node: %w", err)
		}
	} else {
		// Get snapshots from branch node
		if err := t.getSnapshotsFromBranchNode(fileHandle, node, transactionIdentifier, &snapshots, 0); err != nil {
			return nil, fmt.Errorf("unable to get snapshots from branch node: %w", err)
		}
	}

	return snapshots, nil
}

// getSnapshotsFromLeafNode retrieves snapshots from a leaf node
// Corresponds to libfsapfs_snapshot_metadata_tree_get_snapshots_from_leaf_node
func (t *SnapshotMetadataTree) getSnapshotsFromLeafNode(
	node *BTreeNode,
	snapshots *[]*SnapshotMetadata,
) error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if snapshots == nil {
		return fmt.Errorf("invalid snapshots array")
	}

	// Iterate through all entries in the leaf node
	for _, entry := range node.Entries {
		if len(entry.KeyData) < 8 {
			continue
		}

		objectIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])

		metadata := &SnapshotMetadata{
			ObjectIdentifier: objectIdentifier,
		}

		// Parse value data
		if len(entry.ValueData) >= 46 {
			metadata.VolumeSuperblockBlockNumber = binary.LittleEndian.Uint64(entry.ValueData[8:16])
			metadata.SuperblockObjectIdentifier = metadata.VolumeSuperblockBlockNumber

			// Parse name
			nameSize := binary.LittleEndian.Uint16(entry.ValueData[44:46])
			if len(entry.ValueData) >= 46+int(nameSize) {
				metadata.Name = string(entry.ValueData[46 : 46+nameSize])
			}
		}

		*snapshots = append(*snapshots, metadata)
	}

	return nil
}

// GetNumberOfEntries retrieves the number of snapshot entries in the tree
// Corresponds to libfsapfs_snapshot_metadata_tree_get_number_of_entries
func (t *SnapshotMetadataTree) GetNumberOfEntries(fileHandle io.ReaderAt) (int, error) {
	if t == nil {
		return 0, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get all snapshots
	snapshots, err := t.GetSnapshots(fileHandle, 0)
	if err != nil {
		return 0, fmt.Errorf("unable to get snapshots: %w", err)
	}

	return len(snapshots), nil
}

// GetEntryByIndex retrieves a snapshot metadata entry by index
// Corresponds to libfsapfs_snapshot_metadata_tree_get_entry_by_index
func (t *SnapshotMetadataTree) GetEntryByIndex(fileHandle io.ReaderAt, index int) (*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get all snapshots
	snapshots, err := t.GetSnapshots(fileHandle, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to get snapshots: %w", err)
	}

	if index < 0 || index >= len(snapshots) {
		return nil, fmt.Errorf("index %d out of range (0-%d)", index, len(snapshots)-1)
	}

	return snapshots[index], nil
}

// getSnapshotsFromBranchNode retrieves snapshots from a branch node (recursive)
// Corresponds to libfsapfs_snapshot_metadata_tree_get_snapshots_from_branch_node
func (t *SnapshotMetadataTree) getSnapshotsFromBranchNode(
	fileHandle io.ReaderAt,
	node *BTreeNode,
	transactionIdentifier uint64,
	snapshots *[]*SnapshotMetadata,
	recursionDepth int,
) error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if snapshots == nil {
		return fmt.Errorf("invalid snapshots array")
	}

	if recursionDepth > MaximumBTreeNodeRecursionDepth {
		return fmt.Errorf("maximum recursion depth exceeded")
	}

	// Iterate through all entries in the branch node
	for _, entry := range node.Entries {
		// Get sub node block number
		subNodeBlockNumber, err := t.GetSubNodeBlockNumberFromEntry(fileHandle, entry, transactionIdentifier)
		if err != nil {
			return fmt.Errorf("unable to get sub node block number: %w", err)
		}

		if subNodeBlockNumber == 0 {
			continue
		}

		// Get the sub node
		subNode, err := t.GetSubNode(fileHandle, subNodeBlockNumber)
		if err != nil {
			return fmt.Errorf("unable to get sub node: %w", err)
		}

		// Check if this is a leaf node
		isLeaf := subNode.NodeHeader != nil && (subNode.NodeHeader.Flags&0x0002) != 0

		if isLeaf {
			// Get snapshots from leaf node
			if err := t.getSnapshotsFromLeafNode(subNode, snapshots); err != nil {
				return fmt.Errorf("unable to get snapshots from leaf node: %w", err)
			}
		} else {
			// Recursively get snapshots from branch node
			if err := t.getSnapshotsFromBranchNode(fileHandle, subNode, transactionIdentifier, snapshots, recursionDepth+1); err != nil {
				return fmt.Errorf("unable to get snapshots from branch node: %w", err)
			}
		}
	}

	return nil
}
