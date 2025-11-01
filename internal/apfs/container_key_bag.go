package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Container key bag object type
const ContainerKeyBagObjectType = 0x6b657973 // 'keys'

// Key bag entry types
const (
	KeyBagEntryTypeUnknown         = 0
	KeyBagEntryTypeVolumeKey       = 2 // Volume master key (encrypted)
	KeyBagEntryTypeVolumeKeyExtent = 3 // Volume key bag extent location
)

// ContainerKeyBag represents an APFS container key bag
// Corresponds to libfsapfs_container_key_bag_t
type ContainerKeyBag struct {
	// The entries array
	Entries []*KeyBagEntry

	// Value to indicate if the container key bag is locked
	IsLocked bool
}

// KeyBagEntry represents a single key bag entry
// Corresponds to libfsapfs_key_bag_entry_t
type KeyBagEntry struct {
	// The identifier (UUID)
	Identifier [16]byte

	// The entry type
	Type uint16

	// The entry data
	Data []byte

	// The data size
	DataSize uint16

	// The total size including header
	Size int
}

// NewKeyBagEntry creates a new key bag entry
// Corresponds to libfsapfs_key_bag_entry_initialize
func NewKeyBagEntry() (*KeyBagEntry, error) {
	return &KeyBagEntry{
		Identifier: [16]byte{},
		Type:       0,
		Data:       nil,
		DataSize:   0,
		Size:       0,
	}, nil
}

// ReadData reads a key bag entry from binary data
// Corresponds to libfsapfs_key_bag_entry_read_data
func (e *KeyBagEntry) ReadData(data []byte) error {
	if e == nil {
		return fmt.Errorf("invalid key bag entry")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 24 {
		return fmt.Errorf("invalid data size: expected at least 24 bytes for entry header, got %d", len(data))
	}

	// Read entry header (24 bytes)
	copy(e.Identifier[:], data[0:16])
	e.Type = binary.LittleEndian.Uint16(data[16:18])
	e.DataSize = binary.LittleEndian.Uint16(data[18:20])
	// Unknown1 at offset 20-24 is not stored in KeyBagEntry

	// Verify we have enough data for the entry data
	totalSize := 24 + int(e.DataSize)
	if len(data) < totalSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes (header + data), got %d", totalSize, len(data))
	}

	// Read entry data
	if e.DataSize > 0 {
		e.Data = make([]byte, e.DataSize)
		copy(e.Data, data[24:24+e.DataSize])
	}

	// Set total size
	e.Size = totalSize

	return nil
}

// NewContainerKeyBag creates a new container key bag
// Corresponds to libfsapfs_container_key_bag_initialize
func NewContainerKeyBag() (*ContainerKeyBag, error) {
	return &ContainerKeyBag{
		Entries:  make([]*KeyBagEntry, 0),
		IsLocked: false,
	}, nil
}

// Free releases resources associated with the container key bag
func (ckb *ContainerKeyBag) Free() error {
	if ckb == nil {
		return fmt.Errorf("invalid container key bag")
	}

	// Clear entries
	ckb.Entries = nil
	return nil
}

// ReadFileIOHandle reads the container key bag from a file
// Corresponds to libfsapfs_container_key_bag_read_file_io_handle
func (ckb *ContainerKeyBag) ReadFileIOHandle(
	ioHandle *IOHandle,
	fileHandle io.ReaderAt,
	fileOffset int64,
	dataSize uint64,
	containerIdentifier []byte,
) error {
	if ckb == nil {
		return fmt.Errorf("invalid container key bag")
	}

	if ioHandle == nil {
		return fmt.Errorf("invalid IO handle")
	}

	if ioHandle.BytesPerSector == 0 {
		return fmt.Errorf("invalid IO handle - missing bytes per sector")
	}

	if dataSize == 0 || dataSize > 0x7FFFFFFF { // Max reasonable size
		return fmt.Errorf("invalid container key bag size value out of bounds")
	}

	// Read encrypted data
	encryptedData := make([]byte, dataSize)
	n, err := fileHandle.ReadAt(encryptedData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read encrypted data at offset %d: %w", fileOffset, err)
	}
	if n != int(dataSize) {
		return fmt.Errorf("unable to read complete encrypted data: expected %d bytes, got %d", dataSize, n)
	}

	// Allocate buffer for decrypted data
	data := make([]byte, dataSize)

	// Create encryption context using AES-128-XTS with container identifier
	encryptionContext, err := NewEncryptionContext(uint32(EncryptionMethodAES128XTS))
	if err != nil {
		return fmt.Errorf("unable to create encryption context: %w", err)
	}

	// Use container identifier as both key and tweak key (first 16 bytes)
	if len(containerIdentifier) < 16 {
		return fmt.Errorf("invalid container identifier: must be at least 16 bytes")
	}

	err = encryptionContext.SetKeys(containerIdentifier[:16], containerIdentifier[:16])
	if err != nil {
		return fmt.Errorf("unable to set keys in encryption context: %w", err)
	}

	// Decrypt the data
	sectorNumber := uint64(fileOffset) / uint64(ioHandle.BytesPerSector)
	err = encryptionContext.Decrypt(encryptedData, data, sectorNumber, ioHandle.BytesPerSector)
	if err != nil {
		return fmt.Errorf("unable to decrypt data: %w", err)
	}

	// Parse the decrypted data
	return ckb.ReadData(data)
}

// ReadData reads the container key bag from decrypted data
// Corresponds to libfsapfs_container_key_bag_read_data
func (ckb *ContainerKeyBag) ReadData(data []byte) error {
	if ckb == nil {
		return fmt.Errorf("invalid container key bag")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 32 { // Minimum: object header (32)
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read object header (first 32 bytes)
	storedChecksum := binary.LittleEndian.Uint64(data[0:8])
	objectType := binary.LittleEndian.Uint32(data[24:28])
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])

	// Verify object type
	if objectType != ContainerKeyBagObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", objectType, ContainerKeyBagObjectType)
	}

	// Verify object subtype
	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	// Verify checksum
	calculatedChecksum, err := CalculateFletcher64(data[8:], 0)
	if err != nil {
		return fmt.Errorf("unable to calculate Fletcher-64 checksum: %w", err)
	}

	if storedChecksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch (0x%016x != 0x%016x)", storedChecksum, calculatedChecksum)
	}

	dataOffset := 32 // After object header

	// Read key bag header using KeyBagHeader.ReadData()
	if len(data) < dataOffset+16 {
		return fmt.Errorf("insufficient data for key bag header")
	}

	header, err := NewKeyBagHeader()
	if err != nil {
		return fmt.Errorf("unable to create key bag header: %w", err)
	}

	if err := header.ReadData(data[dataOffset:]); err != nil {
		return fmt.Errorf("unable to read key bag header: %w", err)
	}

	dataOffset += 16 // Key bag header size

	if int(header.DataSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid key bag header data size value out of bounds")
	}

	// Read key bag entries using KeyBagEntry.ReadData()
	for i := uint16(0); i < header.NumberOfEntries; i++ {
		if len(data) < dataOffset+24 { // Minimum entry header size
			return fmt.Errorf("insufficient data for key bag entry %d", i)
		}

		entry, err := NewKeyBagEntry()
		if err != nil {
			return fmt.Errorf("unable to create key bag entry %d: %w", i, err)
		}

		// Read entry using the new ReadData method
		if err := entry.ReadData(data[dataOffset:]); err != nil {
			return fmt.Errorf("unable to read key bag entry %d: %w", i, err)
		}

		// Advance offset by the entry size
		dataOffset += entry.Size

		// Add entry to array
		ckb.Entries = append(ckb.Entries, entry)

		// Handle alignment padding (entries are aligned to 16-byte boundaries)
		alignmentPaddingSize := dataOffset % 16
		if alignmentPaddingSize != 0 {
			alignmentPaddingSize = 16 - alignmentPaddingSize

			if dataOffset+alignmentPaddingSize > len(data) {
				return fmt.Errorf("invalid data size for alignment padding")
			}

			dataOffset += alignmentPaddingSize
		}
	}

	return nil
}

// GetVolumeKeyBagExtentByIdentifier retrieves the volume key bag extent for a specific volume
// Returns block number and number of blocks, or error
// Corresponds to libfsapfs_container_key_bag_get_volume_key_bag_extent_by_identifier
func (ckb *ContainerKeyBag) GetVolumeKeyBagExtentByIdentifier(
	volumeIdentifier []byte,
) (blockNumber uint64, numberOfBlocks uint64, found bool, err error) {
	if ckb == nil {
		return 0, 0, false, fmt.Errorf("invalid container key bag")
	}

	if len(volumeIdentifier) != 16 {
		return 0, 0, false, fmt.Errorf("invalid volume identifier: must be 16 bytes")
	}

	// Search for matching entry
	for _, entry := range ckb.Entries {
		// Check if this is a volume key extent entry
		if entry.Type != KeyBagEntryTypeVolumeKeyExtent {
			continue
		}

		// Check if identifier matches
		if !bytes.Equal(entry.Identifier[:], volumeIdentifier) {
			continue
		}

		// Verify data size
		if len(entry.Data) != 16 {
			return 0, 0, false, fmt.Errorf("invalid entry data size: expected 16 bytes, got %d", len(entry.Data))
		}

		// Parse extent data
		blockNumber = binary.LittleEndian.Uint64(entry.Data[0:8])
		numberOfBlocks = binary.LittleEndian.Uint64(entry.Data[8:16])

		return blockNumber, numberOfBlocks, true, nil
	}

	return 0, 0, false, nil // Not found
}

// GetVolumeMasterKeyByIdentifier retrieves the volume master key for a specific volume
// Returns the decrypted master key, or error
// Corresponds to libfsapfs_container_key_bag_get_volume_master_key_by_identifier
func (ckb *ContainerKeyBag) GetVolumeMasterKeyByIdentifier(
	volumeIdentifier []byte,
	volumeKey []byte,
) (masterKey []byte, found bool, err error) {
	if ckb == nil {
		return nil, false, fmt.Errorf("invalid container key bag")
	}

	if len(volumeIdentifier) != 16 {
		return nil, false, fmt.Errorf("invalid volume identifier: must be 16 bytes")
	}

	// Search for matching entry
	for _, entry := range ckb.Entries {
		// Check if this is a volume key entry
		if entry.Type != KeyBagEntryTypeVolumeKey {
			continue
		}

		// Check if identifier matches
		if !bytes.Equal(entry.Identifier[:], volumeIdentifier) {
			continue
		}

		// Parse key encrypted key from entry data
		kek, err := NewKeyEncryptedKey()
		if err != nil {
			return nil, false, fmt.Errorf("unable to create key encrypted key: %w", err)
		}

		if err := kek.ReadData(entry.Data); err != nil {
			return nil, false, fmt.Errorf("unable to read key encrypted key: %w", err)
		}

		// Unlock the key encrypted key using the volume key
		masterKey, err = kek.UnlockWithKey(volumeKey)
		if err != nil {
			return nil, false, fmt.Errorf("unable to unlock key encrypted key: %w", err)
		}

		return masterKey, true, nil
	}

	return nil, false, nil // Not found
}
