package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ExtentReferenceTree represents the APFS extent reference tree structure
// Corresponds to fsapfs_extent_reference_tree_t
type ExtentReferenceTree struct {
	// The object checksum
	// Consists of 8 bytes
	ObjectChecksum uint64

	// The object identifier
	// Consists of 8 bytes
	ObjectIdentifier uint64

	// The object transaction identifier
	// Consists of 8 bytes
	ObjectTransactionIdentifier uint64

	// The object type
	// Consists of 4 bytes
	ObjectType uint32

	// The object subtype
	// Consists of 4 bytes
	ObjectSubtype uint32

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32
}

// Expected object type and subtype for extent reference tree
const (
	ExtentReferenceTreeObjectType    = 0x40000002
	ExtentReferenceTreeObjectSubtype = 0x0000000F
)

// NewExtentReferenceTree creates a new extent reference tree
// Corresponds to libfsapfs_extent_reference_tree_initialize
func NewExtentReferenceTree() *ExtentReferenceTree {
	return &ExtentReferenceTree{}
}

// ReadFromFile reads the extent reference tree from a file at a specific offset
// Corresponds to libfsapfs_extent_reference_tree_read_file_io_handle
func (ert *ExtentReferenceTree) ReadFromFile(fileHandle io.ReaderAt, fileOffset int64) error {
	if ert == nil {
		return fmt.Errorf("invalid extent reference tree")
	}

	if DebugOutput {
		fmt.Printf("libfsapfs_extent_reference_tree_read_file_io_handle: reading extent reference tree at offset: %d (0x%08x)\n",
			fileOffset, fileOffset)
	}

	// Read extent reference tree data (4096 bytes = one block)
	data := make([]byte, 4096)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read extent reference tree data at offset: %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read extent reference tree data at offset: %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the extent reference tree data
	if err := ert.ReadData(data); err != nil {
		return fmt.Errorf("unable to read extent reference tree data: %w", err)
	}

	return nil
}

// ReadData reads the extent reference tree from data
// Corresponds to libfsapfs_extent_reference_tree_read_data
func (ert *ExtentReferenceTree) ReadData(data []byte) error {
	if ert == nil {
		return fmt.Errorf("invalid extent reference tree")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// Minimum size check (40 bytes for the structure)
	const minSize = 40
	if len(data) < minSize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: extent reference tree data:\n")
		PrintData(data, true)
	}

	// Read object checksum (8 bytes at offset 0)
	ert.ObjectChecksum = binary.LittleEndian.Uint64(data[0:8])

	// Read object identifier (8 bytes at offset 8)
	ert.ObjectIdentifier = binary.LittleEndian.Uint64(data[8:16])

	// Read object transaction identifier (8 bytes at offset 16)
	ert.ObjectTransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])

	// Read object type (4 bytes at offset 24)
	ert.ObjectType = binary.LittleEndian.Uint32(data[24:28])

	// Read object subtype (4 bytes at offset 28)
	ert.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Read unknown1 (4 bytes at offset 32)
	ert.Unknown1 = binary.LittleEndian.Uint32(data[32:36])

	// Validate object type
	if ert.ObjectType != ExtentReferenceTreeObjectType {
		return fmt.Errorf("invalid object type: 0x%08x", ert.ObjectType)
	}

	// Validate object subtype
	if ert.ObjectSubtype != ExtentReferenceTreeObjectSubtype {
		return fmt.Errorf("invalid object subtype: 0x%08x", ert.ObjectSubtype)
	}

	if DebugOutput {
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: object checksum\t\t\t: 0x%08x\n", ert.ObjectChecksum)
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: object identifier\t\t\t: %d\n", ert.ObjectIdentifier)
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: object transaction identifier\t: %d\n", ert.ObjectTransactionIdentifier)
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: object type\t\t\t\t: 0x%08x\n", ert.ObjectType)
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: object subtype\t\t\t: 0x%08x\n", ert.ObjectSubtype)
		fmt.Printf("libfsapfs_extent_reference_tree_read_data: unknown1\t\t\t\t: 0x%08x\n", ert.Unknown1)
		fmt.Println()
	}

	return nil
}
