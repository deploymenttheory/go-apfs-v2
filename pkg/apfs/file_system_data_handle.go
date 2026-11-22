package apfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// FileSystemDataHandle represents a file system data handle for managing data blocks
type FileSystemDataHandle struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The file extents
	FileExtents []*FileExtent

	// PerFileContext, when set, returns the encryption context for one
	// crypto identifier — the per-file key named by a file extent on a
	// volume with APFS_INCOMPAT_PFK. A nil returned context means the
	// extent is stored unencrypted and is read in the clear. When unset,
	// every extent is decrypted with the handle's own EncryptionContext
	// (the whole-volume key).
	PerFileContext func(cryptoID uint64) (*EncryptionContext, error)
}

// NewFileSystemDataHandle creates a new file system data handle
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

// Note: Free function (FileSystemDataHandle.Free) is not needed in Go
// as garbage collection handles memory management automatically.

// ReadDataBlock reads a data block from the file system
// This method corresponds to FileSystemDataHandle.ReadDataBlock
// Parameters follow the segment-reader shape used by DataBlockVector.
func (fsdh *FileSystemDataHandle) ReadDataBlock(
	reader io.ReaderAt,
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
	const isSparseFlag = 0x1 // the extent is a sparse (unallocated) range
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
		encryptionContext := fsdh.EncryptionContext
		if len(fsdh.FileExtents) > 0 && elementDataFileIndex >= 0 && elementDataFileIndex < len(fsdh.FileExtents) {
			fileExtent = fsdh.FileExtents[elementDataFileIndex]
			if fileExtent == nil {
				return nil, fmt.Errorf("missing file extent: %d", elementDataFileIndex)
			}

			// Calculate file extent offset
			fileExtentOffset := int64(encryptionIdentifier) - int64(fileExtent.PhysicalBlockNumber)
			encryptionIdentifier = fileExtent.EncryptionIdentifier + uint64(fileExtentOffset)

			// On a per-file-key volume the extent's crypto identifier
			// names the key that encrypts this extent; the whole-volume
			// context would garble it. The resolver also maps the
			// unencrypted identifiers to a nil context (read in clear).
			if fsdh.PerFileContext != nil {
				encryptionContext, err = fsdh.PerFileContext(fileExtent.EncryptionIdentifier)
				if err != nil {
					return nil, fmt.Errorf("unable to resolve per-file key for extent %d: %w", elementDataFileIndex, err)
				}
			}
		}

		// Read the data block
		err = dataBlock.Read(reader, fsdh.IOHandle, encryptionContext, elementDataOffset, encryptionIdentifier)
		if err != nil {
			return nil, fmt.Errorf("unable to read data block: %w", err)
		}
	}

	return dataBlock, nil
}
