// The APFS chunk information block definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// ChunkInformationBlockSize is the size of the chunk information block in bytes
const ChunkInformationBlockSize = 4096

// ChunkInformationBlock represents the APFS chunk information block structure
type ChunkInformationBlock struct {
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

// NewChunkInformationBlock creates a new chunk information block
func NewChunkInformationBlock() *ChunkInformationBlock {
	return &ChunkInformationBlock{}
}

// ReadFileIOHandle reads the chunk information block from a file handle at the specified offset
func (cib *ChunkInformationBlock) ReadFileIOHandle(fileHandle io.ReaderAt, fileOffset int64) error {
	if cib == nil {
		return fmt.Errorf("invalid chunk information block")
	}

	// Allocate 4096 bytes for chunk information block data
	chunkInformationBlockData := make([]byte, ChunkInformationBlockSize)

	// Read data from file
	n, err := fileHandle.ReadAt(chunkInformationBlockData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read chunk information block data at offset %d: %w", fileOffset, err)
	}

	if n != ChunkInformationBlockSize {
		return fmt.Errorf("unable to read complete chunk information block data: expected %d bytes, got %d", ChunkInformationBlockSize, n)
	}

	// Parse the data
	if err := cib.ReadData(chunkInformationBlockData); err != nil {
		return fmt.Errorf("unable to read chunk information block data: %w", err)
	}

	return nil
}

// ReadData reads the chunk information block from binary data
func (cib *ChunkInformationBlock) ReadData(data []byte) error {
	if cib == nil {
		return fmt.Errorf("invalid chunk information block")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 32 || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read chunk information block header fields
	cib.ObjectChecksum = binary.LittleEndian.Uint64(data[0:8])
	cib.ObjectIdentifier = binary.LittleEndian.Uint64(data[8:16])
	cib.ObjectTransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	cib.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	cib.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])
	cib.Unknown1 = binary.LittleEndian.Uint32(data[32:36])

	// Validate object type
	if cib.ObjectType != 0x40000007 {
		return fmt.Errorf("invalid object type: 0x%08x", cib.ObjectType)
	}

	// Validate object subtype
	if cib.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", cib.ObjectSubtype)
	}

	return nil
}
