package apfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// FileSystemDataHandle represents a file system data handle for managing data blocks
// Corresponds to libfsapfs_file_system_data_handle_t
type FileSystemDataHandle struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The file extents
	FileExtents []*FileExtent
}

// NewFileSystemDataHandle creates a new file system data handle
// Corresponds to libfsapfs_file_system_data_handle_initialize
func NewFileSystemDataHandle(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	fileExtents []*FileExtent,
) (*FileSystemDataHandle, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	return &FileSystemDataHandle{
		IOHandle:          ioHandle,
		EncryptionContext: encryptionContext,
		FileExtents:       fileExtents,
	}, nil
}

// Note: Free function (libfsapfs_file_system_data_handle_free) is not needed in Go
// as garbage collection handles memory management automatically.

// ReadDataBlock reads a data block from the file system
// This method corresponds to libfsapfs_file_system_data_handle_read_data_block
// Parameters align with the libfdata vector callback structure
func (fsdh *FileSystemDataHandle) ReadDataBlock(
	fileIOHandle io.ReaderAt,
	elementDataFileIndex int,
	elementDataOffset int64,
	elementDataSize int64,
	elementDataFlags uint32,
) (*DataBlock, error) {
	if fsdh == nil {
		return nil, fmt.Errorf("invalid file system data handle")
	}

	if fsdh.IOHandle == nil {
		return nil, fmt.Errorf("invalid file system data handle - missing IO handle")
	}

	if elementDataSize > common.Int32Max {
		return nil, fmt.Errorf("invalid element data size value exceeds maximum")
	}

	// Create data block
	dataBlock, err := NewDataBlock(int(elementDataSize))
	if err != nil {
		return nil, fmt.Errorf("unable to create data block: %w", err)
	}

	// Check if this is a sparse range
	const isSparseFlag = 0x1 // LIBFDATA_RANGE_FLAG_IS_SPARSE
	if (elementDataFlags & isSparseFlag) != 0 {
		// Sparse range - clear the data block
		err = dataBlock.Clear()
		if err != nil {
			return nil, fmt.Errorf("unable to clear data block: %w", err)
		}
	} else {
		// Non-sparse range - read and decrypt
		encryptionIdentifier := uint64(elementDataOffset / elementDataSize)

		// Get file extent if available
		var fileExtent *FileExtent
		if len(fsdh.FileExtents) > 0 && elementDataFileIndex >= 0 && elementDataFileIndex < len(fsdh.FileExtents) {
			fileExtent = fsdh.FileExtents[elementDataFileIndex]
			if fileExtent == nil {
				return nil, fmt.Errorf("missing file extent: %d", elementDataFileIndex)
			}

			// Calculate file extent offset
			fileExtentOffset := int64(encryptionIdentifier) - int64(fileExtent.PhysicalBlockNumber)
			encryptionIdentifier = fileExtent.EncryptionIdentifier + uint64(fileExtentOffset)
		}

		// Read the data block
		err = dataBlock.Read(fileIOHandle, fsdh.IOHandle, fsdh.EncryptionContext, elementDataOffset, encryptionIdentifier)
		if err != nil {
			return nil, fmt.Errorf("unable to read data block: %w", err)
		}
	}

	return dataBlock, nil
}
