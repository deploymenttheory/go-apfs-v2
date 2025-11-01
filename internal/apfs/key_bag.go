// The APFS key bag definitions
package apfs

import (
	"encoding/binary"
	"fmt"
)

// KeyBagHeader represents the APFS key bag header structure
// Corresponds to libfsapfs_key_bag_header_t and fsapfs_key_bag_header_t
type KeyBagHeader struct {
	// The format version
	// Consists of 2 bytes
	FormatVersion uint16

	// The number of entries
	// Consists of 2 bytes
	NumberOfEntries uint16

	// The data size
	// Consists of 4 bytes
	DataSize uint32

	// Unknown
	// Consists of 8 bytes
	Unknown1 uint64
}

// KeyBagEntryHeader represents the APFS key bag entry header structure
type KeyBagEntryHeader struct {
	// The identifier
	// Consists of 16 bytes
	// Contains an UUID
	Identifier [16]byte

	// The entry type
	// Consists of 2 bytes
	EntryType uint16

	// The entry data size
	// Consists of 2 bytes
	DataSize uint16

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32
}

// KeyBagKEKMetadata represents the APFS key bag KEK metadata structure
type KeyBagKEKMetadata struct {
	// The encryption method
	// Consists of 4 bytes
	EncryptionMethod uint32

	// Unknown
	// Consists of 2 bytes
	Unknown1 uint16

	// Unknown
	// Consists of 1 byte
	Unknown2 uint8

	// Unknown
	// Consists of 1 byte
	Unknown3 uint8
}

// KeyBagExtent represents the APFS key bag extent structure
type KeyBagExtent struct {
	// The block number
	// Consists of 8 bytes
	BlockNumber uint64

	// The number of blocks
	// Consists of 8 bytes
	NumberOfBlocks uint64
}

// NewKeyBagHeader creates a new key bag header
// Corresponds to libfsapfs_key_bag_header_initialize
func NewKeyBagHeader() (*KeyBagHeader, error) {
	return &KeyBagHeader{
		FormatVersion:   0,
		NumberOfEntries: 0,
		DataSize:        0,
		Unknown1:        0,
	}, nil
}

// ReadData reads the key bag header from binary data
// Corresponds to libfsapfs_key_bag_header_read_data
func (h *KeyBagHeader) ReadData(data []byte) error {
	if h == nil {
		return fmt.Errorf("invalid key bag header")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 16 {
		return fmt.Errorf("invalid data size: expected at least 16 bytes, got %d", len(data))
	}

	// Read header fields (16 bytes total)
	h.FormatVersion = binary.LittleEndian.Uint16(data[0:2])
	h.NumberOfEntries = binary.LittleEndian.Uint16(data[2:4])
	h.DataSize = binary.LittleEndian.Uint32(data[4:8])
	h.Unknown1 = binary.LittleEndian.Uint64(data[8:16])

	// Validate format version (must be 2 according to C library)
	if h.FormatVersion != 2 {
		return fmt.Errorf("unsupported key bag header format version: %d (expected 2)", h.FormatVersion)
	}

	return nil
}

// NewKeyBagEntryHeader creates a new key bag entry header
// Corresponds to the entry header portion of libfsapfs_key_bag_entry_t
func NewKeyBagEntryHeader() (*KeyBagEntryHeader, error) {
	return &KeyBagEntryHeader{
		Identifier: [16]byte{},
		EntryType:  0,
		DataSize:   0,
		Unknown1:   0,
	}, nil
}

// ReadData reads the key bag entry header from binary data
// Corresponds to reading the header portion in libfsapfs_key_bag_entry_read_data
func (h *KeyBagEntryHeader) ReadData(data []byte) error {
	if h == nil {
		return fmt.Errorf("invalid key bag entry header")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 24 {
		return fmt.Errorf("invalid data size: expected at least 24 bytes, got %d", len(data))
	}

	// Read entry header fields (24 bytes total)
	copy(h.Identifier[:], data[0:16])
	h.EntryType = binary.LittleEndian.Uint16(data[16:18])
	h.DataSize = binary.LittleEndian.Uint16(data[18:20])
	h.Unknown1 = binary.LittleEndian.Uint32(data[20:24])

	return nil
}
