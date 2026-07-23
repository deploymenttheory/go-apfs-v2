package apfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// ContainerDataHandle represents a handle for reading data blocks from the container
// Corresponds to libfsapfs_container_data_handle_t
type ContainerDataHandle struct {
	// The IO handle
	IOHandle *IOHandle
}

// NewContainerDataHandle creates a new container data handle
// Corresponds to libfsapfs_container_data_handle_initialize
func NewContainerDataHandle(ioHandle *IOHandle) (*ContainerDataHandle, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	return &ContainerDataHandle{
		IOHandle: ioHandle,
	}, nil
}

// Free releases resources associated with the container data handle
// In Go, this is primarily for API consistency with the C implementation
func (cdh *ContainerDataHandle) Free() error {
	if cdh == nil {
		return fmt.Errorf("invalid container data handle")
	}

	// Nothing to free in Go, but method exists for API consistency
	return nil
}

// ReadDataBlock reads a data block from the container
// This is a callback function for a data block vector
// Corresponds to libfsapfs_container_data_handle_read_data_block
//
// Parameters align with the libfdata vector callback structure:
//   - fileIOHandle: The file handle to read from
//   - elementIndex: The index of the element in the vector (unused here)
//   - elementDataFileIndex: The file index (unused for containers)
//   - elementDataOffset: The offset in the file to read from
//   - elementDataSize: The size of the data to read
//   - elementDataFlags: Flags for the data (unused here)
//
// Returns the data block read from the container
func (cdh *ContainerDataHandle) ReadDataBlock(
	fileIOHandle io.ReaderAt,
	elementIndex int,
	elementDataFileIndex int,
	elementDataOffset int64,
	elementDataSize int64,
	elementDataFlags uint32,
) (*DataBlock, error) {
	if cdh == nil {
		return nil, fmt.Errorf("invalid container data handle")
	}

	if cdh.IOHandle == nil {
		return nil, fmt.Errorf("invalid container data handle - missing IO handle")
	}

	if elementDataSize > common.Int32Max {
		return nil, fmt.Errorf("invalid element data size value exceeds maximum")
	}

	// Create data block
	dataBlock, err := NewDataBlock(int(elementDataSize))
	if err != nil {
		return nil, fmt.Errorf("unable to create data block: %w", err)
	}

	// Read the data block from the container
	// Container blocks are not encrypted (encryption is at the volume level)
	// So we pass nil for the encryption context and 0 for encryption identifier
	err = dataBlock.Read(
		fileIOHandle,
		cdh.IOHandle,
		nil, // No encryption at container level
		elementDataOffset,
		0, // No encryption identifier needed
	)
	if err != nil {
		return nil, fmt.Errorf("unable to read data block: %w", err)
	}

	return dataBlock, nil
}
