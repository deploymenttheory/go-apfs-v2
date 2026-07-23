// Object map B-tree functions
// Corresponds to libfsapfs_object_map_btree.c and libfsapfs_object_map_btree.h
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// Object types for object map B-tree nodes
	ObjectMapBTreeRootNodeType = 0x40000002 // OBJECT_TYPE_BTREE
	ObjectMapBTreeSubNodeType  = 0x40000003 // OBJECT_TYPE_BTREE_NODE

	// Object subtype for object map B-tree
	ObjectMapBTreeSubtype = 0x0000000b // OBJECT_SUBTYPE_OMAP

	// B-tree node flags
	BTreeNodeFlagRoot           = 0x0001
	BTreeNodeFlagLeaf           = 0x0002
	BTreeNodeFlagFixedKVSize    = 0x0004
	BTreeNodeFlagHashed         = 0x0008
	BTreeNodeFlagNoHeader       = 0x0010
	BTreeNodeFlagCheckKOffInval = 0x8000

	// Maximum B-tree recursion depth
	MaxBTreeRecursionDepth = 32

	// Object map B-tree key and value sizes
	ObjectMapBTreeKeySize   = 16
	ObjectMapBTreeValueSize = 16
)

// ObjectMapBTree represents the APFS object map B-tree
// This B-tree maps object identifiers and transaction identifiers to physical block numbers
// Corresponds to libfsapfs_object_map_btree_t
type ObjectMapBTree struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The block number of B-tree root node
	RootNodeBlockNumber uint64

	// Note: Optional caching layers can be added for performance:
	// - DataBlockCache: LRU cache for data blocks (currently uncached)
	// - NodeCache: LRU cache for B-tree nodes (currently uncached)
	// These are performance optimizations, not required for correctness.
}

// ObjectMapKey represents a key in the object map B-tree
// Corresponds to fsapfs_object_map_btree_key (16 bytes)
type ObjectMapKey struct {
	ObjectIdentifier            uint64
	ObjectTransactionIdentifier uint64
}

// ObjectMapValue represents a value in the object map B-tree
// Corresponds to fsapfs_object_map_btree_value (16 bytes)
type ObjectMapValue struct {
	ObjectFlags           uint32
	ObjectSize            uint32
	ObjectPhysicalAddress uint64
}

// ObjectMapDescriptor contains both key and value data from an object map entry
// Corresponds to libfsapfs_object_map_descriptor_t
type ObjectMapDescriptor struct {
	Key   *ObjectMapKey
	Value *ObjectMapValue
}

// NewObjectMapDescriptor creates a new object map descriptor
// Corresponds to libfsapfs_object_map_descriptor_initialize
func NewObjectMapDescriptor() (*ObjectMapDescriptor, error) {
	return &ObjectMapDescriptor{}, nil
}

// Free releases resources associated with the object map descriptor
// Corresponds to libfsapfs_object_map_descriptor_free
func (d *ObjectMapDescriptor) Free() error {
	if d == nil {
		return fmt.Errorf("invalid object map descriptor")
	}
	// Go's garbage collector handles cleanup
	return nil
}

// ReadKeyData reads the object map descriptor B-tree key data
// Corresponds to libfsapfs_object_map_descriptor_read_key_data
func (d *ObjectMapDescriptor) ReadKeyData(data []byte) error {
	if d == nil {
		return fmt.Errorf("invalid object map descriptor")
	}

	if len(data) < ObjectMapBTreeKeySize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if IsVerbose() {
		Printf("%s: object map B-tree key data:\n", "ReadKeyData")
		PrintData(data[:ObjectMapBTreeKeySize], true)
	}

	// Parse the key
	key, err := ParseObjectMapKey(data)
	if err != nil {
		return fmt.Errorf("unable to parse key data: %w", err)
	}

	d.Key = key

	if IsVerbose() {
		Printf("%s: object identifier\t\t: %d\n", "ReadKeyData", d.Key.ObjectIdentifier)
		Printf("%s: object transaction identifier\t: %d\n", "ReadKeyData", d.Key.ObjectTransactionIdentifier)
		Printf("\n")
	}

	return nil
}

// ReadValueData reads the object map descriptor B-tree value data
// Corresponds to libfsapfs_object_map_descriptor_read_value_data
func (d *ObjectMapDescriptor) ReadValueData(data []byte) error {
	if d == nil {
		return fmt.Errorf("invalid object map descriptor")
	}

	if len(data) < ObjectMapBTreeValueSize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if IsVerbose() {
		Printf("%s: object map B-tree value data:\n", "ReadValueData")
		PrintData(data[:ObjectMapBTreeValueSize], true)
	}

	// Parse the value
	value, err := ParseObjectMapValue(data)
	if err != nil {
		return fmt.Errorf("unable to parse value data: %w", err)
	}

	d.Value = value

	if IsVerbose() {
		Printf("%s: object flags\t\t\t: 0x%04x\n", "ReadValueData", d.Value.ObjectFlags)
		Printf("%s: object size\t\t\t: %d\n", "ReadValueData", d.Value.ObjectSize)
		Printf("%s: object physical address\t: %d\n", "ReadValueData", d.Value.ObjectPhysicalAddress)
		Printf("\n")
	}

	return nil
}

// GetIdentifier returns the object identifier
func (d *ObjectMapDescriptor) GetIdentifier() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	return d.Key.ObjectIdentifier, nil
}

// GetTransactionIdentifier returns the transaction identifier
func (d *ObjectMapDescriptor) GetTransactionIdentifier() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	return d.Key.ObjectTransactionIdentifier, nil
}

// GetPhysicalAddress returns the physical address
func (d *ObjectMapDescriptor) GetPhysicalAddress() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectPhysicalAddress, nil
}

// GetFlags returns the object flags
func (d *ObjectMapDescriptor) GetFlags() (uint32, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectFlags, nil
}

// GetSize returns the object size
func (d *ObjectMapDescriptor) GetSize() (uint32, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectSize, nil
}

// NewObjectMapBTree creates a new object map B-tree
// Corresponds to libfsapfs_object_map_btree_initialize
func NewObjectMapBTree(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	rootNodeBlockNumber uint64,
) (*ObjectMapBTree, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	return &ObjectMapBTree{
		IOHandle:            ioHandle,
		EncryptionContext:   encryptionContext,
		RootNodeBlockNumber: rootNodeBlockNumber,
	}, nil
}

// Free releases resources associated with the object map B-tree
// Corresponds to libfsapfs_object_map_btree_free
func (bt *ObjectMapBTree) Free() error {
	if bt == nil {
		return fmt.Errorf("invalid object map B-tree")
	}
	// Go's garbage collector handles cleanup
	return nil
}

// GetRootNode retrieves the root node of the B-tree
// Corresponds to libfsapfs_object_map_btree_get_root_node
func (bt *ObjectMapBTree) GetRootNode(
	fileHandle io.ReaderAt,
	rootNodeBlockNumber uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read the root node
	node, err := ReadBTreeNode(fileHandle, bt.IOHandle, bt.EncryptionContext, rootNodeBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type (must be OBJECT_TYPE_BTREE for root)
	if node.ObjectType != ObjectMapBTreeRootNodeType {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	// Validate object subtype (must be OBJECT_SUBTYPE_OMAP)
	if node.ObjectSubtype != ObjectMapBTreeSubtype {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate flags (must be root and have fixed KV size)
	if !node.IsRootNode() || !node.HasFixedKVSize() {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	// Validate node size
	if node.Footer.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds: %d", node.Footer.NodeSize)
	}

	// Validate key size
	if node.Footer.KeySize != ObjectMapBTreeKeySize {
		return nil, fmt.Errorf("invalid key size value out of bounds: %d", node.Footer.KeySize)
	}

	// Validate value size
	if node.Footer.ValueSize != ObjectMapBTreeValueSize {
		return nil, fmt.Errorf("invalid value size value out of bounds: %d", node.Footer.ValueSize)
	}

	return node, nil
}

// GetSubNode retrieves a sub-node (child node) by block number
// Corresponds to libfsapfs_object_map_btree_get_sub_node
func (bt *ObjectMapBTree) GetSubNode(
	fileHandle io.ReaderAt,
	subNodeBlockNumber uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read the sub-node
	node, err := ReadBTreeNode(fileHandle, bt.IOHandle, bt.EncryptionContext, subNodeBlockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type (must be OBJECT_TYPE_BTREE_NODE for sub-nodes)
	if node.ObjectType != ObjectMapBTreeSubNodeType {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	// Validate object subtype (must be OBJECT_SUBTYPE_OMAP)
	if node.ObjectSubtype != ObjectMapBTreeSubtype {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate flags (must NOT be root but must have fixed KV size)
	if node.IsRootNode() || !node.HasFixedKVSize() {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	return node, nil
}

// GetEntryFromNodeByIdentifier finds an entry in a specific node by identifier
// Corresponds to libfsapfs_object_map_btree_get_entry_from_node_by_identifier
func (bt *ObjectMapBTree) GetEntryFromNodeByIdentifier(
	node *BTreeNode,
	objectIdentifier uint64,
	transactionIdentifier uint64,
) (*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if IsVerbose() {
		Printf("%s: retrieving B-tree entry identifier: %d (transaction: %d).\n",
			"GetEntryFromNodeByIdentifier", objectIdentifier, transactionIdentifier)
	}

	isLeafNode := node.IsLeafNode()

	var previousEntry *BTreeEntry
	var previousObjectMapIdentifier uint64

	// Iterate through entries to find matching object identifier
	for entryIndex, entry := range node.Entries {
		// Validate key data
		if len(entry.KeyData) < ObjectMapBTreeKeySize {
			return nil, fmt.Errorf("invalid B-tree entry: %d - key data size value out of bounds: %d",
				entryIndex, len(entry.KeyData))
		}

		// Parse the key
		objectMapIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])
		objectMapTransaction := binary.LittleEndian.Uint64(entry.KeyData[8:16])

		if IsVerbose() {
			Printf("%s: B-tree entry: %d, identifier: %d (transaction: %d)\n",
				"GetEntryFromNodeByIdentifier", entryIndex, objectMapIdentifier, objectMapTransaction)
		}

		// If we've passed the target identifier, stop searching
		if objectMapIdentifier > objectIdentifier {
			break
		} else if objectMapIdentifier == objectIdentifier && objectMapTransaction > transactionIdentifier {
			break
		}

		previousEntry = entry
		previousObjectMapIdentifier = objectMapIdentifier
	}

	// For leaf nodes, return entry only if we found exact match on object identifier
	if isLeafNode {
		if previousObjectMapIdentifier == objectIdentifier {
			return previousEntry, nil
		}
		return nil, fmt.Errorf("entry not found for object identifier %d", objectIdentifier)
	}

	// For branch nodes, return the entry to follow down the tree
	if previousEntry == nil {
		return nil, fmt.Errorf("entry not found for object identifier %d", objectIdentifier)
	}

	return previousEntry, nil
}

// GetEntryByIdentifier retrieves a B-tree entry by object and transaction identifier
// Corresponds to libfsapfs_object_map_btree_get_entry_by_identifier
func (bt *ObjectMapBTree) GetEntryByIdentifier(
	fileHandle io.ReaderAt,
	objectIdentifier uint64,
	transactionIdentifier uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read root node
	node, err := bt.GetRootNode(fileHandle, bt.RootNodeBlockNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve B-tree root node: %w", err)
	}

	// Navigate through the B-tree with recursion depth limit
	recursionDepth := 0

	for {
		if recursionDepth < 0 || recursionDepth > MaxBTreeRecursionDepth {
			return nil, nil, fmt.Errorf("invalid recursion depth value out of bounds: %d", recursionDepth)
		}

		// Check if this is a leaf node
		isLeafNode := node.IsLeafNode()

		// Search for entry in this node
		entry, err := bt.GetEntryFromNodeByIdentifier(node, objectIdentifier, transactionIdentifier)
		if err != nil {
			// Entry not found
			return nil, nil, nil
		}

		// If this is a leaf node, we found it
		if isLeafNode {
			return node, entry, nil
		}

		// This is a branch node - extract sub-node block number
		if len(entry.ValueData) != 8 {
			return nil, nil, fmt.Errorf("invalid B-tree entry - unsupported value data size: %d", len(entry.ValueData))
		}

		subNodeBlockNumber := binary.LittleEndian.Uint64(entry.ValueData[0:8])

		if IsVerbose() {
			Printf("%s: B-tree sub node block number: %d\n",
				"GetEntryByIdentifier", subNodeBlockNumber)
		}

		// Read the sub-node
		node, err = bt.GetSubNode(fileHandle, subNodeBlockNumber)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to retrieve B-tree sub node from block: %d: %w", subNodeBlockNumber, err)
		}

		recursionDepth++
	}
}

// GetDescriptorByObjectIdentifier retrieves the object map descriptor of a specific object identifier
// Corresponds to libfsapfs_object_map_btree_get_descriptor_by_object_identifier
func (bt *ObjectMapBTree) GetDescriptorByObjectIdentifier(
	fileHandle io.ReaderAt,
	objectIdentifier uint64,
	transactionIdentifier uint64,
) (*ObjectMapDescriptor, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Find the entry
	_, entry, err := bt.GetEntryByIdentifier(fileHandle, objectIdentifier, transactionIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve entry from B-tree: %w", err)
	}

	if entry == nil {
		// Entry not found (not an error, just return nil)
		return nil, nil
	}

	// Create a new descriptor
	descriptor, err := NewObjectMapDescriptor()
	if err != nil {
		return nil, fmt.Errorf("unable to create object map descriptor: %w", err)
	}

	// Read key data
	if err := descriptor.ReadKeyData(entry.KeyData); err != nil {
		return nil, fmt.Errorf("unable to read object map descriptor key data: %w", err)
	}

	// Read value data
	if err := descriptor.ReadValueData(entry.ValueData); err != nil {
		return nil, fmt.Errorf("unable to read object map descriptor value data: %w", err)
	}

	return descriptor, nil
}

// GetPhysicalBlockNumber retrieves the physical block number for an object
// This is a convenience function that looks up an object in the object map
func (bt *ObjectMapBTree) GetPhysicalBlockNumber(
	fileHandle io.ReaderAt,
	objectIdentifier uint64,
	transactionIdentifier uint64,
) (uint64, error) {
	descriptor, err := bt.GetDescriptorByObjectIdentifier(fileHandle, objectIdentifier, transactionIdentifier)
	if err != nil {
		return 0, fmt.Errorf("unable to retrieve descriptor for object %d: %w", objectIdentifier, err)
	}

	if descriptor == nil {
		return 0, fmt.Errorf("object %d not found in object map", objectIdentifier)
	}

	return descriptor.Value.ObjectPhysicalAddress, nil
}

// ParseObjectMapKey parses an object map key from binary data
func ParseObjectMapKey(data []byte) (*ObjectMapKey, error) {
	if len(data) < ObjectMapBTreeKeySize {
		return nil, fmt.Errorf("invalid key size: expected at least %d bytes, got %d", ObjectMapBTreeKeySize, len(data))
	}

	return &ObjectMapKey{
		ObjectIdentifier:            binary.LittleEndian.Uint64(data[0:8]),
		ObjectTransactionIdentifier: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

// ParseObjectMapValue parses an object map value from binary data
func ParseObjectMapValue(data []byte) (*ObjectMapValue, error) {
	if len(data) < ObjectMapBTreeValueSize {
		return nil, fmt.Errorf("invalid value size: expected at least %d bytes, got %d", ObjectMapBTreeValueSize, len(data))
	}

	return &ObjectMapValue{
		ObjectFlags:           binary.LittleEndian.Uint32(data[0:4]),
		ObjectSize:            binary.LittleEndian.Uint32(data[4:8]),
		ObjectPhysicalAddress: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}
