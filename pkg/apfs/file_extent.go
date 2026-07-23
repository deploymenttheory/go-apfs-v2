package apfs

import (
	"encoding/binary"
	"fmt"
)

// FileExtent represents a file extent structure
// Corresponds to libfsapfs_file_extent_t
type FileExtent struct {
	// The logical offset
	LogicalOffset uint64

	// The physical block number
	PhysicalBlockNumber uint64

	// Data size
	DataSize uint64

	// Encryption identifier
	EncryptionIdentifier uint64
}

// NewFileExtent creates a new file extent
// Corresponds to libfsapfs_file_extent_initialize
func NewFileExtent() *FileExtent {
	return &FileExtent{}
}

// ReadKeyData reads the file extent key data
// Corresponds to libfsapfs_file_extent_read_key_data
func (fe *FileExtent) ReadKeyData(data []byte) error {
	if fe == nil {
		return fmt.Errorf("invalid file extent")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// FileSystemBTreeKeyFileExtent is 16 bytes minimum
	const minKeySize = 16
	if len(data) < minKeySize {
		return fmt.Errorf("invalid data size for file extent key: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("libfsapfs_file_extent_read_key_data: file extent key data:\n")
		PrintData(data, true)
	}

	// Read file system identifier (8 bytes at offset 0) - contains identifier and type
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])

	// Read logical address (8 bytes at offset 8)
	fe.LogicalOffset = binary.LittleEndian.Uint64(data[8:16])

	if DebugOutput {
		fmt.Printf("libfsapfs_file_extent_read_key_data: identifier\t\t\t\t: 0x%08x\n", fileSystemIdentifier)
		fmt.Printf("libfsapfs_file_extent_read_key_data: logical address\t\t\t: 0x%08x\n", fe.LogicalOffset)
		fmt.Println()
	}

	return nil
}

// ReadValueData reads the file extent value data
// Corresponds to libfsapfs_file_extent_read_value_data
func (fe *FileExtent) ReadValueData(data []byte) error {
	if fe == nil {
		return fmt.Errorf("invalid file extent")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// FileSystemBTreeValueFileExtent is 24 bytes minimum
	const minValueSize = 24
	if len(data) < minValueSize {
		return fmt.Errorf("invalid data size for file extent value: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("libfsapfs_file_extent_read_value_data: file extent value data:\n")
		PrintData(data, true)
	}

	// Read data size and flags (8 bytes at offset 0)
	dataSizeAndFlags := binary.LittleEndian.Uint64(data[0:8])
	fe.DataSize = dataSizeAndFlags & 0x00FFFFFFFFFFFFFF // Lower 56 bits (mask out upper 8 bits)

	// Read physical block number (8 bytes at offset 8)
	fe.PhysicalBlockNumber = binary.LittleEndian.Uint64(data[8:16])

	// Read encryption identifier (8 bytes at offset 16)
	fe.EncryptionIdentifier = binary.LittleEndian.Uint64(data[16:24])

	if DebugOutput {
		flags := dataSizeAndFlags >> 56
		fmt.Printf("libfsapfs_file_extent_read_value_data: data size and flags\t\t: 0x%08x (data size: %d, flags: 0x%02x)\n",
			dataSizeAndFlags, fe.DataSize, flags)
		fmt.Printf("libfsapfs_file_extent_read_value_data: physical block number\t\t: %d\n", fe.PhysicalBlockNumber)
		fmt.Printf("libfsapfs_file_extent_read_value_data: encryption identifier\t\t: %d\n", fe.EncryptionIdentifier)
		fmt.Println()
	}

	return nil
}
