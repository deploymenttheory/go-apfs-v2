package apfs

import (
	"encoding/binary"
	"fmt"
)

// ObjectSize is the size of the APFS object header in bytes
const ObjectSize = 32

// BTreeNode represents a B-tree node
// Corresponds to libfsapfs_btree_node.h
type BTreeNode struct {
	// The object type
	ObjectType uint32

	// The object subtype
	ObjectSubtype uint32

	// The B-tree node header
	NodeHeader *BTreeNodeHeader

	// The B-tree footer (only present for root nodes)
	Footer *BTreeFooter

	// The B-tree entries
	Entries []*BTreeEntry
}

// NewBTreeNode creates a new B-tree node
func NewBTreeNode() *BTreeNode {
	return &BTreeNode{
		Entries: make([]*BTreeEntry, 0),
	}
}

// ReadObjectData reads the APFS object header from binary data
func (n *BTreeNode) ReadObjectData(data []byte) error {
	if n == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if len(data) < ObjectSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes for object header, got %d", ObjectSize, len(data))
	}

	// Read object type and subtype
	n.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	n.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type (should be 0x00000000, 0x00000002, or 0x00000003 for B-tree nodes)
	objectType := n.ObjectType & 0x0fffffff
	if objectType != 0x00000000 && objectType != 0x00000002 && objectType != 0x00000003 {
		return fmt.Errorf("invalid object type: 0x%08x", n.ObjectType)
	}

	return nil
}

// ReadData reads the B-tree node from binary data
func (n *BTreeNode) ReadData(data []byte) error {
	if n == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if n.NodeHeader != nil {
		return fmt.Errorf("node header already set")
	}

	minimumDataSize := ObjectSize + BTreeNodeHeaderSize + BTreeFooterSize
	if len(data) < minimumDataSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes, got %d", minimumDataSize, len(data))
	}

	// Read object header
	if err := n.ReadObjectData(data); err != nil {
		return fmt.Errorf("unable to read object data: %w", err)
	}

	dataOffset := ObjectSize

	// Read node header
	n.NodeHeader = NewBTreeNodeHeader()
	if err := n.NodeHeader.ReadData(data[dataOffset : dataOffset+BTreeNodeHeaderSize]); err != nil {
		return fmt.Errorf("unable to read node header: %w", err)
	}
	dataOffset += BTreeNodeHeaderSize

	// Calculate remaining data size
	remainingDataSize := len(data) - minimumDataSize

	// Validate offsets and sizes
	if int(n.NodeHeader.EntriesDataOffset) >= remainingDataSize {
		return fmt.Errorf("invalid entries data offset: %d >= %d", n.NodeHeader.EntriesDataOffset, remainingDataSize)
	}
	remainingDataSize -= int(n.NodeHeader.EntriesDataOffset)

	if int(n.NodeHeader.EntriesDataSize) > remainingDataSize {
		return fmt.Errorf("invalid entries data size: %d > %d", n.NodeHeader.EntriesDataSize, remainingDataSize)
	}

	// Determine footer offset
	footerOffset := len(data)

	// Read footer if this is a root node (flag 0x0001)
	if (n.NodeHeader.Flags & 0x0001) != 0 {
		n.Footer = NewBTreeFooter()
		footerDataOffset := len(data) - BTreeFooterSize
		if err := n.Footer.ReadData(data[footerDataOffset:]); err != nil {
			return fmt.Errorf("unable to read footer: %w", err)
		}
		footerOffset -= BTreeFooterSize
	}

	// Parse entries
	if err := n.parseEntries(data, dataOffset, footerOffset); err != nil {
		return fmt.Errorf("unable to parse entries: %w", err)
	}

	return nil
}

// parseEntries parses B-tree entries from the node data
func (n *BTreeNode) parseEntries(data []byte, dataOffset int, footerOffset int) error {
	// Determine entry size based on fixed/variable flag
	var entryDataSize int
	hasFixedSizeKeys := (n.NodeHeader.Flags & 0x0004) != 0

	if hasFixedSizeKeys {
		entryDataSize = 4 // sizeof(BTreeFixedSizeEntry)
	} else {
		entryDataSize = 8 // sizeof(BTreeVariableSizeEntry)
	}

	// Validate number of keys
	if int(n.NodeHeader.NumberOfKeys) > int(n.NodeHeader.EntriesDataSize)/entryDataSize {
		return fmt.Errorf("invalid number of keys: %d", n.NodeHeader.NumberOfKeys)
	}

	// Current position in the entry table (TOC starts at btn_data + EntriesDataOffset)
	currentOffset := dataOffset + int(n.NodeHeader.EntriesDataOffset)

	// Parse each entry
	for i := uint32(0); i < n.NodeHeader.NumberOfKeys; i++ {
		var keyDataOffset, keyDataSize, valueDataOffset, valueDataSize uint16

		if !hasFixedSizeKeys {
			// Variable size entry
			if currentOffset+8 > len(data) {
				return fmt.Errorf("invalid entry offset: %d", currentOffset)
			}

			keyDataOffset = binary.LittleEndian.Uint16(data[currentOffset : currentOffset+2])
			keyDataSize = binary.LittleEndian.Uint16(data[currentOffset+2 : currentOffset+4])
			valueDataOffset = binary.LittleEndian.Uint16(data[currentOffset+4 : currentOffset+6])
			valueDataSize = binary.LittleEndian.Uint16(data[currentOffset+6 : currentOffset+8])
		} else {
			// Fixed size entry
			if currentOffset+4 > len(data) {
				return fmt.Errorf("invalid entry offset: %d", currentOffset)
			}

			keyDataOffset = binary.LittleEndian.Uint16(data[currentOffset : currentOffset+2])
			valueDataOffset = binary.LittleEndian.Uint16(data[currentOffset+2 : currentOffset+4])

			// For fixed size entries, size depends on object subtype
			switch n.ObjectSubtype {
			case 0x0000000b: // Object map B-tree
				keyDataSize = 16   // sizeof(fsapfs_object_map_btree_key_t)
				valueDataSize = 16 // sizeof(fsapfs_object_map_btree_value_t)
			default:
				return fmt.Errorf("unsupported object subtype for fixed size entries: 0x%08x", n.ObjectSubtype)
			}

			// For non-leaf nodes, value is just a block number (8 bytes)
			if (n.NodeHeader.Flags & 0x0002) == 0 {
				valueDataSize = 8
			}
		}

		currentOffset += entryDataSize

		// Calculate absolute offsets for key and value data
		// Per drat implementation (include/drat/func/btree.c lines 60-62, 83, 123):
		// - toc_start = btn_data + table_space.off
		// - key_start = toc_start + table_space.len  (keys start AFTER the TOC)
		// - keyDataOffset is relative to key_start
		// - valueDataOffset is relative to val_end (grows backward from footerOffset)
		keyStart := uint16(dataOffset) + n.NodeHeader.EntriesDataOffset + n.NodeHeader.EntriesDataSize
		absoluteKeyOffset := keyStart + keyDataOffset
		absoluteValueOffset := uint16(footerOffset) - valueDataOffset

		// Validate offsets
		if int(absoluteKeyOffset) > len(data) || int(keyDataSize) > len(data)-int(absoluteKeyOffset) {
			return fmt.Errorf("invalid key data offset: offset=%d, size=%d, dataLen=%d", absoluteKeyOffset, keyDataSize, len(data))
		}

		if int(absoluteValueOffset) > len(data) || int(valueDataSize) > len(data)-int(absoluteValueOffset) {
			return fmt.Errorf("invalid value data offset: offset=%d, size=%d, dataLen=%d", absoluteValueOffset, valueDataSize, len(data))
		}

		// Extract key and value data
		keyData := data[absoluteKeyOffset : absoluteKeyOffset+keyDataSize]
		valueData := data[absoluteValueOffset : absoluteValueOffset+valueDataSize]

		// Create entry
		entry := NewBTreeEntry()
		entry.SetKeyData(keyData)
		entry.SetValueData(valueData)

		n.Entries = append(n.Entries, entry)
	}

	return nil
}

// IsLeafNode returns true if this is a leaf node
func (n *BTreeNode) IsLeafNode() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.IsLeaf()
}

// IsRootNode returns true if this is a root node
func (n *BTreeNode) IsRootNode() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.IsRoot()
}

// HasFixedKVSize returns true if this node has fixed key-value size
func (n *BTreeNode) HasFixedKVSize() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.HasFixedKVSize()
}

// GetNumberOfEntries returns the number of entries in this node
func (n *BTreeNode) GetNumberOfEntries() int {
	if n == nil {
		return 0
	}
	return len(n.Entries)
}

// GetEntryByIndex returns the entry at the specified index
func (n *BTreeNode) GetEntryByIndex(index int) (*BTreeEntry, error) {
	if n == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if index < 0 || index >= len(n.Entries) {
		return nil, fmt.Errorf("index out of bounds: %d (total entries: %d)", index, len(n.Entries))
	}

	return n.Entries[index], nil
}
