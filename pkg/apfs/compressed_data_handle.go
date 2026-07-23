package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Compression method constants
const (
	CompressionMethodNone     = 0
	CompressionMethodDeflate  = 1
	CompressionMethodLZFSE    = 2
	CompressionMethodLZVN     = 3
	CompressionMethodUnknown5 = 5
)

// CompressedDataHandleBlockSize is the size of each compressed block
const CompressedDataHandleBlockSize = 65536

// CompressedDataHandle represents a handle for compressed data in APFS
// Corresponds to libfsapfs_compressed_data_handle.h
type CompressedDataHandle struct {
	// The current segment offset
	CurrentSegmentOffset int64

	// The compressed data stream
	CompressedDataStream *DataStream

	// The uncompressed data size
	UncompressedDataSize uint64

	// The compression method
	CompressionMethod int

	// The current compressed block index
	CurrentCompressedBlockIndex uint32

	// The compressed segment data buffer
	CompressedSegmentData []byte

	// The (uncompressed) segment data buffer
	SegmentData []byte

	// The (uncompressed) segment data size
	SegmentDataSize int

	// The number of compressed blocks
	NumberOfCompressedBlocks uint32

	// The compressed block offsets
	CompressedBlockOffsets []uint32
}

// NewCompressedDataHandle creates a new compressed data handle
// Corresponds to libfsapfs_compressed_data_handle_initialize
func NewCompressedDataHandle(
	compressedDataStream *DataStream,
	uncompressedDataSize uint64,
	compressionMethod int,
) (*CompressedDataHandle, error) {
	if compressedDataStream == nil {
		return nil, fmt.Errorf("invalid compressed data stream")
	}

	if compressionMethod != CompressionMethodDeflate &&
		compressionMethod != CompressionMethodLZVN &&
		compressionMethod != CompressionMethodUnknown5 {
		return nil, fmt.Errorf("unsupported compression method: %d", compressionMethod)
	}

	handle := &CompressedDataHandle{
		CurrentSegmentOffset:        0,
		CompressedDataStream:        compressedDataStream,
		UncompressedDataSize:        uncompressedDataSize,
		CompressionMethod:           compressionMethod,
		CurrentCompressedBlockIndex: 0xFFFFFFFF, // -1 in uint32
		NumberOfCompressedBlocks:    0,
	}

	// Allocate compressed segment data buffer
	// Size is BlockSize + 1 to handle edge cases
	handle.CompressedSegmentData = make([]byte, CompressedDataHandleBlockSize+1)

	// Allocate uncompressed segment data buffer
	// Not needed for UNKNOWN5 compression method
	if compressionMethod != CompressionMethodUnknown5 {
		handle.SegmentData = make([]byte, CompressedDataHandleBlockSize)
	}

	return handle, nil
}

// Free releases resources associated with the compressed data handle
// In Go, this is primarily for explicit cleanup if needed
func (cdh *CompressedDataHandle) Free() error {
	if cdh == nil {
		return fmt.Errorf("invalid compressed data handle")
	}

	// Clear buffers to free memory
	cdh.SegmentData = nil
	cdh.CompressedSegmentData = nil
	cdh.CompressedBlockOffsets = nil

	return nil
}

// GetCompressedBlockOffsets determines the compressed block offsets
// Corresponds to libfsapfs_compressed_data_handle_get_compressed_block_offsets
func (cdh *CompressedDataHandle) GetCompressedBlockOffsets(fileIOHandle io.ReaderAt) error {
	if cdh == nil {
		return fmt.Errorf("invalid compressed data handle")
	}

	if cdh.CompressedBlockOffsets != nil {
		return fmt.Errorf("compressed block offsets already set")
	}

	compressedDataSize := cdh.CompressedDataStream.Size()

	// Read the first 4 bytes to check for signature
	readCount, err := cdh.CompressedDataStream.ReadAt(cdh.CompressedSegmentData[:4], 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read buffer at offset 0: %w", err)
	}
	if readCount != 4 {
		return fmt.Errorf("unable to read 4 bytes at offset 0")
	}

	// Check for "fpmc" signature
	isFPMC := bytes.Equal(cdh.CompressedSegmentData[:4], []byte("fpmc"))

	var compressedBlockDescriptorSize int
	var compressedDescriptorsOffset uint32
	var segmentDataOffset int

	if isFPMC {
		if compressedDataSize > uint64(CompressedDataHandleBlockSize+1) {
			return fmt.Errorf("invalid segment data size value out of bounds")
		}
		cdh.NumberOfCompressedBlocks = 1
	} else if cdh.CompressionMethod == CompressionMethodDeflate {
		// Read compressed descriptors offset (big endian)
		compressedDescriptorsOffset = binary.BigEndian.Uint32(cdh.CompressedSegmentData[:4])

		if compressedDescriptorsOffset != 0x00000100 {
			return fmt.Errorf("invalid compressed descriptors offset: 0x%08x", compressedDescriptorsOffset)
		}

		readSize := int(compressedDescriptorsOffset) + 16 - 4

		readCount, err = cdh.CompressedDataStream.ReadAt(cdh.CompressedSegmentData[4:4+readSize], 4)
		if err != nil && err != io.EOF {
			return fmt.Errorf("unable to read compressed header data at offset 4: %w", err)
		}
		if readCount != readSize {
			return fmt.Errorf("unable to read %d bytes at offset 4", readSize)
		}

		// Read number of compressed blocks at offset 260 (little endian)
		cdh.NumberOfCompressedBlocks = binary.LittleEndian.Uint32(cdh.CompressedSegmentData[260:264])

		if cdh.NumberOfCompressedBlocks > (0xFFFFFFFF / 8) {
			return fmt.Errorf("invalid number of compressed blocks value out of bounds")
		}

		segmentDataOffset = 264
		compressedDescriptorsOffset += 4
		compressedBlockDescriptorSize = 8
	} else if cdh.CompressionMethod == CompressionMethodLZVN {
		segmentDataOffset = 0
		compressedBlockDescriptorSize = 4

		// Read first compressed block offset (little endian)
		compressedBlockOffset := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[:4])

		if compressedBlockOffset <= 0x00000004 ||
			compressedBlockOffset >= uint32(CompressedDataHandleBlockSize+1) {
			return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
		}

		cdh.NumberOfCompressedBlocks = compressedBlockOffset / 4
	}

	// Allocate compressed block offsets array
	// Size is NumberOfCompressedBlocks + 1 to store the end offset
	if int(cdh.NumberOfCompressedBlocks) > (int(^uint(0)>>1)/4 - 1) {
		return fmt.Errorf("invalid number of compressed blocks exceeds maximum allocation size")
	}

	cdh.CompressedBlockOffsets = make([]uint32, cdh.NumberOfCompressedBlocks+1)

	var compressedBlockIndex uint32
	var previousCompressedBlockOffset uint32

	if isFPMC {
		cdh.CompressedBlockOffsets[0] = 16
		compressedBlockIndex = 1
		previousCompressedBlockOffset = 16
	} else {
		// Read the first block offset
		compressedBlockOffset := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[segmentDataOffset:])
		segmentDataOffset += 4

		if compressedBlockOffset <= uint32(compressedBlockDescriptorSize) ||
			compressedBlockOffset >= uint32(CompressedDataHandleBlockSize+1) {
			return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
		}

		compressedBlockOffset += compressedDescriptorsOffset
		cdh.CompressedBlockOffsets[0] = compressedBlockOffset
		previousCompressedBlockOffset = compressedBlockOffset

		if cdh.CompressionMethod == CompressionMethodDeflate {
			segmentDataOffset += 4 // Skip size field
		}

		// Read remaining compressed block descriptors
		readSize := int(cdh.NumberOfCompressedBlocks-1) * compressedBlockDescriptorSize

		readCount, err = cdh.CompressedDataStream.ReadAt(
			cdh.CompressedSegmentData[segmentDataOffset:segmentDataOffset+readSize],
			int64(segmentDataOffset),
		)
		if err != nil && err != io.EOF {
			return fmt.Errorf("unable to read compressed block descriptors at offset %d: %w", segmentDataOffset, err)
		}
		if readCount != readSize {
			return fmt.Errorf("unable to read %d bytes at offset %d", readSize, segmentDataOffset)
		}

		// Parse remaining block offsets
		for compressedBlockIndex = 1; compressedBlockIndex < cdh.NumberOfCompressedBlocks; compressedBlockIndex++ {
			compressedBlockOffset := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[segmentDataOffset:])
			segmentDataOffset += 4

			compressedBlockOffset += compressedDescriptorsOffset

			if previousCompressedBlockOffset > compressedBlockOffset ||
				(compressedBlockOffset-previousCompressedBlockOffset) > uint32(CompressedDataHandleBlockSize+1) {
				return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
			}

			cdh.CompressedBlockOffsets[compressedBlockIndex] = compressedBlockOffset
			previousCompressedBlockOffset = compressedBlockOffset

			if cdh.CompressionMethod == CompressionMethodDeflate {
				segmentDataOffset += 4 // Skip size field
			}
		}

		compressedBlockIndex = cdh.NumberOfCompressedBlocks
	}

	// Store the end offset (size of compressed data)
	if previousCompressedBlockOffset > uint32(compressedDataSize) ||
		(uint32(compressedDataSize)-previousCompressedBlockOffset) > uint32(CompressedDataHandleBlockSize+1) {
		return fmt.Errorf("invalid compressed block offset: 0x%08x", previousCompressedBlockOffset)
	}

	cdh.CompressedBlockOffsets[compressedBlockIndex] = uint32(compressedDataSize)

	return nil
}

// ReadSegmentData reads data from the current offset into a buffer
// This is a callback for the data stream
// Corresponds to libfsapfs_compressed_data_handle_read_segment_data
func (cdh *CompressedDataHandle) ReadSegmentData(
	fileIOHandle io.ReaderAt,
	segmentIndex int,
	segmentData []byte,
) (int, error) {
	if cdh == nil {
		return 0, fmt.Errorf("invalid compressed data handle")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentData == nil {
		return 0, fmt.Errorf("invalid segment data")
	}

	if int64(len(segmentData)) > common.Int32Max {
		return 0, fmt.Errorf("invalid segment data size value exceeds maximum")
	}

	// Get compressed block offsets if not already loaded
	if cdh.CompressedBlockOffsets == nil {
		if err := cdh.GetCompressedBlockOffsets(fileIOHandle); err != nil {
			return 0, fmt.Errorf("unable to determine compressed block offsets: %w", err)
		}
	}

	// Check if we've reached the end
	if uint64(cdh.CurrentSegmentOffset) >= cdh.UncompressedDataSize {
		return 0, io.EOF
	}

	// Handle UNKNOWN5 compression method (sparse data)
	if cdh.CompressionMethod == CompressionMethodUnknown5 {
		readSize := len(segmentData)
		if uint64(cdh.CurrentSegmentOffset)+uint64(readSize) > cdh.UncompressedDataSize {
			readSize = int(cdh.UncompressedDataSize - uint64(cdh.CurrentSegmentOffset))
		}

		// Zero out the data for sparse blocks
		for i := 0; i < readSize; i++ {
			segmentData[i] = 0
		}

		cdh.CurrentSegmentOffset += int64(readSize)
		return readSize, nil
	}

	// Calculate which compressed block we need
	compressedBlockIndex := uint32(cdh.CurrentSegmentOffset / CompressedDataHandleBlockSize)
	segmentDataOffset := 0
	dataOffset := int(cdh.CurrentSegmentOffset % CompressedDataHandleBlockSize)

	totalBytesRead := 0

	for len(segmentData) > segmentDataOffset {
		if compressedBlockIndex >= cdh.NumberOfCompressedBlocks {
			return 0, fmt.Errorf("invalid compressed block index value out of bounds")
		}

		// Decompress the block if it's not the current one
		if cdh.CurrentCompressedBlockIndex != compressedBlockIndex {
			dataStreamOffset := int64(cdh.CompressedBlockOffsets[compressedBlockIndex])
			readSize := int(cdh.CompressedBlockOffsets[compressedBlockIndex+1] - cdh.CompressedBlockOffsets[compressedBlockIndex])

			readCount, err := cdh.CompressedDataStream.ReadAt(
				cdh.CompressedSegmentData[:readSize],
				dataStreamOffset,
			)
			if err != nil && err != io.EOF {
				return totalBytesRead, fmt.Errorf("unable to read buffer at offset %d: %w", dataStreamOffset, err)
			}
			if readCount != readSize {
				return totalBytesRead, fmt.Errorf("unable to read %d bytes at offset %d", readSize, dataStreamOffset)
			}

			// Decompress the data
			cdh.SegmentDataSize = CompressedDataHandleBlockSize

			// Decompress the compressed segment data
			if err := DecompressData(
				cdh.CompressedSegmentData[:readCount],
				cdh.CompressionMethod,
				cdh.SegmentData,
				&cdh.SegmentDataSize,
			); err != nil {
				return totalBytesRead, fmt.Errorf("unable to decompress data: %w", err)
			}

			// Verify segment data size for non-final blocks
			uncompressedBlockOffset := int64(compressedBlockIndex+1) * CompressedDataHandleBlockSize
			if uint64(uncompressedBlockOffset) < cdh.UncompressedDataSize &&
				cdh.SegmentDataSize != CompressedDataHandleBlockSize {
				return totalBytesRead, fmt.Errorf("invalid uncompressed segment data size value out of bounds")
			}

			cdh.CurrentCompressedBlockIndex = compressedBlockIndex
		}

		// Validate data offset
		if dataOffset >= cdh.SegmentDataSize {
			return totalBytesRead, fmt.Errorf("invalid data offset value out of bounds")
		}

		// Calculate how much data to copy from this block
		readSize := cdh.SegmentDataSize - dataOffset
		if readSize > len(segmentData)-segmentDataOffset {
			readSize = len(segmentData) - segmentDataOffset
		}

		// Copy data from the decompressed buffer
		copy(segmentData[segmentDataOffset:segmentDataOffset+readSize], cdh.SegmentData[dataOffset:dataOffset+readSize])

		dataOffset = 0
		segmentDataOffset += readSize
		totalBytesRead += readSize
		compressedBlockIndex++
	}

	cdh.CurrentSegmentOffset += int64(totalBytesRead)

	return totalBytesRead, nil
}

// SeekSegmentOffset seeks to a specific offset in the data
// This is a callback for the data stream
// Corresponds to libfsapfs_compressed_data_handle_seek_segment_offset
func (cdh *CompressedDataHandle) SeekSegmentOffset(
	segmentIndex int,
	segmentOffset int64,
) (int64, error) {
	if cdh == nil {
		return 0, fmt.Errorf("invalid compressed data handle")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentOffset < 0 {
		return 0, fmt.Errorf("invalid segment offset value out of bounds")
	}

	cdh.CurrentSegmentOffset = segmentOffset

	return segmentOffset, nil
}
