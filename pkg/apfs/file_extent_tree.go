package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// A sealed volume keeps file data extents in a dedicated B-tree, the file extent
// tree (apfs_fext_tree_oid), instead of in per-file records in the file system
// tree. It is a physical B-tree (like the extent reference tree) whose entries
// map (private_id, logical_addr) to (length, physical block). Without it the
// system volume's files appear to have no content at all.
const (
	// FileExtentTreeKeySize is sizeof(fext_tree_key_t): private id + logical address.
	FileExtentTreeKeySize = 16

	// FileExtentTreeValueSize is sizeof(fext_tree_val_t): length/flags + physical block.
	FileExtentTreeValueSize = 16

	// fileExtentLengthMask is J_FILE_EXTENT_LEN_MASK, the low 60 bits of
	// fext_tree_val_t.len_and_flags.
	fileExtentLengthMask uint64 = 0x0fffffffffffffff
)

// FileExtentTree is the file extent B-tree of a sealed APFS volume.
type FileExtentTree struct {
	// IOHandle is the container I/O handle.
	IOHandle *IOHandle

	// EncryptionContext decrypts nodes on encrypted volumes (nil when unencrypted).
	EncryptionContext *EncryptionContext

	// RootNodeOID is the physical block number of the tree's root node.
	RootNodeOID uint64

	// TransactionID is the volume transaction identifier.
	TransactionID uint64
}

// NewFileExtentTree creates a file extent tree accessor.
func NewFileExtentTree(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	rootNodeOID uint64,
	transactionID uint64,
) (*FileExtentTree, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}
	if rootNodeOID == 0 {
		return nil, fmt.Errorf("invalid file extent tree root node")
	}

	return &FileExtentTree{
		IOHandle:          ioHandle,
		EncryptionContext: encryptionContext,
		RootNodeOID:       rootNodeOID,
		TransactionID:     transactionID,
	}, nil
}

// RootNode reads and validates the tree's root node.
func (t *FileExtentTree) RootNode(reader io.ReaderAt) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid file extent tree")
	}

	node, err := ReadBTreeNodeWithSizes(
		reader, t.IOHandle, t.EncryptionContext, t.RootNodeOID,
		FileExtentTreeKeySize, FileExtentTreeValueSize,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read file extent tree root node: %w", err)
	}

	if node.Info != nil {
		if node.Info.NodeSize != 0 && node.Info.NodeSize != t.IOHandle.BlockSize {
			return nil, fmt.Errorf("invalid file extent tree node size: %d", node.Info.NodeSize)
		}
		if node.Info.KeySize != 0 && node.Info.KeySize != FileExtentTreeKeySize {
			return nil, fmt.Errorf("invalid file extent tree key size: %d", node.Info.KeySize)
		}
		if node.Info.ValueSize != 0 && node.Info.ValueSize != FileExtentTreeValueSize {
			return nil, fmt.Errorf("invalid file extent tree value size: %d", node.Info.ValueSize)
		}
	}

	return node, nil
}

// SubNode reads a child node by its physical block number.
func (t *FileExtentTree) SubNode(reader io.ReaderAt, blockNumber uint64) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid file extent tree")
	}

	node, err := ReadBTreeNodeWithSizes(
		reader, t.IOHandle, t.EncryptionContext, blockNumber,
		FileExtentTreeKeySize, FileExtentTreeValueSize,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read file extent tree node %d: %w", blockNumber, err)
	}

	return node, nil
}

// fileExtentTreeKey is the fext_tree_key_t key.
type fileExtentTreeKey struct {
	privateID   uint64
	logicalAddr uint64
}

func parseFileExtentTreeKey(data []byte) (fileExtentTreeKey, error) {
	if len(data) < FileExtentTreeKeySize {
		return fileExtentTreeKey{}, fmt.Errorf("invalid file extent tree key size: %d", len(data))
	}
	return fileExtentTreeKey{
		privateID:   binary.LittleEndian.Uint64(data[0:8]),
		logicalAddr: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

func compareFileExtentTreeKeys(a, b fileExtentTreeKey) int {
	switch {
	case a.privateID < b.privateID:
		return -1
	case a.privateID > b.privateID:
		return 1
	case a.logicalAddr < b.logicalAddr:
		return -1
	case a.logicalAddr > b.logicalAddr:
		return 1
	default:
		return 0
	}
}

// childBlockOf returns the physical child block stored in a branch entry.
func (t *FileExtentTree) childBlockOf(entry *BTreeEntry) (uint64, error) {
	if entry == nil {
		return 0, fmt.Errorf("invalid file extent tree entry")
	}
	if len(entry.ValueData) < 8 {
		return 0, fmt.Errorf("invalid file extent tree branch value size: %d", len(entry.ValueData))
	}
	return binary.LittleEndian.Uint64(entry.ValueData[0:8]), nil
}

// ExtentsForPrivateID returns every file extent stored for a data stream's
// private identifier, ordered by logical offset.
func (t *FileExtentTree) ExtentsForPrivateID(
	reader io.ReaderAt,
	privateID uint64,
) ([]*FileExtent, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid file extent tree")
	}

	root, err := t.RootNode(reader)
	if err != nil {
		return nil, err
	}

	target := fileExtentTreeKey{privateID: privateID}

	type frame struct {
		node *BTreeNode
		idx  int
	}
	path := make([]frame, 0, 4)

	node := root
	for !node.IsLeafNode() {
		if len(node.Entries) == 0 {
			return nil, fmt.Errorf("file extent tree index node has no entries")
		}

		// Branch keys are the smallest key of each child: follow the last
		// child whose first key does not exceed the target.
		idx := 0
		for i, entry := range node.Entries {
			key, err := parseFileExtentTreeKey(entry.KeyData)
			if err != nil {
				return nil, err
			}
			if compareFileExtentTreeKeys(key, target) <= 0 {
				idx = i
				continue
			}
			break
		}

		path = append(path, frame{node: node, idx: idx})
		childBlock, err := t.childBlockOf(node.Entries[idx])
		if err != nil {
			return nil, err
		}
		node, err = t.SubNode(reader, childBlock)
		if err != nil {
			return nil, err
		}
	}

	extents := make([]*FileExtent, 0, 4)
	idx := 0
	for idx < len(node.Entries) {
		key, err := parseFileExtentTreeKey(node.Entries[idx].KeyData)
		if err != nil {
			return nil, err
		}
		if compareFileExtentTreeKeys(key, target) >= 0 {
			break
		}
		idx++
	}

	for {
		for idx < len(node.Entries) {
			entry := node.Entries[idx]
			key, err := parseFileExtentTreeKey(entry.KeyData)
			if err != nil {
				return nil, err
			}
			if key.privateID > privateID {
				return extents, nil
			}
			if key.privateID == privateID {
				if len(entry.ValueData) < FileExtentTreeValueSize {
					return nil, fmt.Errorf("invalid file extent tree value size: %d", len(entry.ValueData))
				}
				lengthAndFlags := binary.LittleEndian.Uint64(entry.ValueData[0:8])
				extents = append(extents, &FileExtent{
					LogicalOffset:        key.logicalAddr,
					PhysicalBlockNumber:  binary.LittleEndian.Uint64(entry.ValueData[8:16]),
					DataSize:             lengthAndFlags & fileExtentLengthMask,
					EncryptionIdentifier: 0,
				})
			}
			idx++
		}

		// Move to the next leaf: bump the nearest ancestor with a sibling,
		// then descend its leftmost branch.
		moved := false
		for len(path) > 0 {
			top := &path[len(path)-1]
			if top.idx+1 >= len(top.node.Entries) {
				path = path[:len(path)-1]
				continue
			}
			top.idx++
			node = top.node
			childBlock, err := t.childBlockOf(node.Entries[top.idx])
			if err != nil {
				return nil, err
			}
			node, err = t.SubNode(reader, childBlock)
			if err != nil {
				return nil, err
			}
			for !node.IsLeafNode() {
				if len(node.Entries) == 0 {
					return nil, fmt.Errorf("file extent tree index node has no entries")
				}
				path = append(path, frame{node: node, idx: 0})
				childBlock, err := t.childBlockOf(node.Entries[0])
				if err != nil {
					return nil, err
				}
				node, err = t.SubNode(reader, childBlock)
				if err != nil {
					return nil, err
				}
			}
			idx = 0
			moved = true
			break
		}

		if !moved {
			return extents, nil
		}
	}
}
