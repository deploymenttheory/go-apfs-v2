package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// CompressedDataHeaderSignature is the expected signature for compressed data headers
var CompressedDataHeaderSignature = [4]byte{'f', 'p', 'm', 'c'}

// CompressedDataHeaderSize is the size of the compressed data header in bytes
const CompressedDataHeaderSize = 16

// CompressedDataHeader represents the header for compressed data in APFS
// Corresponds to fsapfs_compressed_data_header_t and libfsapfs_compressed_data_header_t
type CompressedDataHeader struct {
	// The compression method
	CompressionMethod uint32

	// The uncompressed data size
	UncompressedDataSize uint64
}

// NewCompressedDataHeader creates a new compressed data header
// Corresponds to libfsapfs_compressed_data_header_initialize
func NewCompressedDataHeader() (*CompressedDataHeader, error) {
	return &CompressedDataHeader{
		CompressionMethod:    0,
		UncompressedDataSize: 0,
	}, nil
}

// Free releases resources associated with the compressed data header
// In Go, this is primarily for consistency with the C API
func (cdh *CompressedDataHeader) Free() error {
	if cdh == nil {
		return fmt.Errorf("invalid compressed data header")
	}
	// Nothing to free in Go, but method exists for API consistency
	return nil
}

// ReadData reads the compressed data header from a byte slice
// Returns true if successful, false if the signature does not match
// Corresponds to libfsapfs_compressed_data_header_read_data
func (cdh *CompressedDataHeader) ReadData(data []byte) (bool, error) {
	if cdh == nil {
		return false, fmt.Errorf("invalid compressed data header")
	}

	if data == nil {
		return false, fmt.Errorf("invalid data")
	}

	if len(data) < CompressedDataHeaderSize {
		return false, fmt.Errorf("invalid data size: expected at least %d bytes, got %d", CompressedDataHeaderSize, len(data))
	}

	if int64(len(data)) > common.Int32Max {
		return false, fmt.Errorf("invalid data size value out of bounds")
	}

	// Check signature (first 4 bytes)
	signature := data[0:4]
	if !bytes.Equal(signature, CompressedDataHeaderSignature[:]) {
		// Signature does not match - return false but no error
		return false, nil
	}

	// Read compression method (bytes 4-7, little endian)
	cdh.CompressionMethod = binary.LittleEndian.Uint32(data[4:8])

	// Read uncompressed data size (bytes 8-15, little endian)
	cdh.UncompressedDataSize = binary.LittleEndian.Uint64(data[8:16])

	return true, nil
}

// ParseCompressedDataHeader is a convenience function to parse a compressed data header
// Returns the header if successful, nil if signature doesn't match, or an error
func ParseCompressedDataHeader(data []byte) (*CompressedDataHeader, error) {
	header, err := NewCompressedDataHeader()
	if err != nil {
		return nil, fmt.Errorf("unable to create compressed data header: %w", err)
	}

	match, err := header.ReadData(data)
	if err != nil {
		return nil, fmt.Errorf("unable to read compressed data header: %w", err)
	}

	if !match {
		// Signature doesn't match, return nil with no error
		return nil, nil
	}

	return header, nil
}
