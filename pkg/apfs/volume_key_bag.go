// Volume key bag functions
// Corresponds to libfsapfs_volume_key_bag.c and libfsapfs_volume_key_bag.h
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// VolumeKeyBag represents an APFS volume key bag
// Corresponds to libfsapfs_volume_key_bag_t
type VolumeKeyBag struct {
	Entries []*KeyBagEntry
}

// NewVolumeKeyBag creates a new volume key bag
// Corresponds to libfsapfs_volume_key_bag_initialize
func NewVolumeKeyBag() (*VolumeKeyBag, error) {
	return &VolumeKeyBag{
		Entries: make([]*KeyBagEntry, 0),
	}, nil
}

// Free releases resources associated with the volume key bag
// Corresponds to libfsapfs_volume_key_bag_free
func (v *VolumeKeyBag) Free() error {
	if v == nil {
		return fmt.Errorf("invalid volume key bag")
	}

	// Clear entries (Go's GC will handle the cleanup)
	v.Entries = nil
	return nil
}

// ReadFileIOHandle reads the volume key bag from a file at the specified offset
// Corresponds to libfsapfs_volume_key_bag_read_file_io_handle
func (v *VolumeKeyBag) ReadFileIOHandle(
	ioHandle *IOHandle,
	fileHandle io.ReaderAt,
	fileOffset int64,
	dataSize uint64,
	volumeIdentifier []byte,
) error {
	if v == nil {
		return fmt.Errorf("invalid volume key bag")
	}

	if ioHandle == nil {
		return fmt.Errorf("invalid IO handle")
	}

	if ioHandle.BytesPerSector == 0 {
		return fmt.Errorf("invalid IO handle - missing bytes per sector")
	}

	if dataSize == 0 || dataSize > common.Int32Max {
		return fmt.Errorf("invalid volume key bag size value out of bounds")
	}

	// Read encrypted data
	encryptedData := make([]byte, dataSize)

	if IsVerbose() {
		Printf("%s: reading volume key bag data at offset: %d (0x%08x)\n",
			"ReadFileIOHandle", fileOffset, fileOffset)
	}

	n, err := fileHandle.ReadAt(encryptedData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read encrypted data at offset: %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != int(dataSize) {
		return fmt.Errorf("unable to read encrypted data at offset: %d (0x%08x)",
			fileOffset, fileOffset)
	}

	// Decrypt the data using AES-128-XTS with volume identifier as both encryption and tweak key
	encryptionContext, err := NewEncryptionContext(uint32(EncryptionMethodAES128XTS))
	if err != nil {
		return fmt.Errorf("unable to initialize encryption context: %w", err)
	}

	if err := encryptionContext.SetKeys(volumeIdentifier[:16], volumeIdentifier[:16]); err != nil {
		return fmt.Errorf("unable to set keys in encryption context: %w", err)
	}

	data := make([]byte, dataSize)
	if err := encryptionContext.Crypt(
		CryptModeDecrypt,
		encryptedData,
		data,
		uint64(fileOffset/int64(ioHandle.BytesPerSector)),
		uint16(ioHandle.BytesPerSector),
	); err != nil {
		return fmt.Errorf("unable to decrypt data: %w", err)
	}

	if IsVerbose() {
		Printf("%s: unencrypted volume key bag data:\n", "ReadFileIOHandle")
		PrintData(data, true)
	}

	// Read the decrypted data
	if err := v.ReadData(data); err != nil {
		return fmt.Errorf("unable to read volume key bag: %w", err)
	}

	return nil
}

// ReadData reads the volume key bag from binary data
// Corresponds to libfsapfs_volume_key_bag_read_data
func (v *VolumeKeyBag) ReadData(data []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume key bag")
	}

	if len(data) < 32 || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if IsVerbose() {
		Printf("%s: volume key bag object data:\n", "ReadData")
		PrintData(data[:32], true)
	}

	// Parse object header (32 bytes)
	objectType := binary.LittleEndian.Uint32(data[24:28])
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])

	// Object type should be 0x72656373 ("recs" in ASCII)
	if objectType != 0x72656373 {
		return fmt.Errorf("invalid object type: 0x%08x", objectType)
	}

	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	if IsVerbose() {
		objectChecksum := binary.LittleEndian.Uint64(data[0:8])
		objectIdentifier := binary.LittleEndian.Uint64(data[8:16])
		objectTransactionIdentifier := binary.LittleEndian.Uint64(data[16:24])

		Printf("%s: object checksum\t\t\t: 0x%08x\n", "ReadData", objectChecksum)
		Printf("%s: object identifier\t\t\t: %d\n", "ReadData", objectIdentifier)
		Printf("%s: object transaction identifier\t: %d\n", "ReadData", objectTransactionIdentifier)
		Printf("%s: object type\t\t\t\t: 0x%08x\n", "ReadData", objectType)
		Printf("%s: object subtype\t\t\t\t: 0x%08x\n", "ReadData", objectSubtype)
		Printf("\n")
	}

	dataOffset := 32

	// Read key bag header (16 bytes)
	bagHeader, err := NewKeyBagHeader()
	if err != nil {
		return fmt.Errorf("unable to create key bag header: %w", err)
	}

	if err := bagHeader.ReadData(data[dataOffset:]); err != nil {
		return fmt.Errorf("unable to read key bag header: %w", err)
	}

	if int(bagHeader.DataSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid key bag header data size value out of bounds")
	}

	dataOffset += 16

	// Read all entries
	for bagEntryIndex := uint16(0); bagEntryIndex < bagHeader.NumberOfEntries; bagEntryIndex++ {
		bagEntry, err := NewKeyBagEntry()
		if err != nil {
			return fmt.Errorf("unable to create key bag entry: %d: %w", bagEntryIndex, err)
		}

		if err := bagEntry.ReadData(data[dataOffset:]); err != nil {
			return fmt.Errorf("unable to read key bag entry: %d: %w", bagEntryIndex, err)
		}

		v.Entries = append(v.Entries, bagEntry)

		dataOffset += bagEntry.Size

		// Handle 16-byte alignment padding
		alignmentPaddingSize := dataOffset % 16
		if alignmentPaddingSize != 0 {
			alignmentPaddingSize = 16 - alignmentPaddingSize

			if alignmentPaddingSize > len(data) || dataOffset > len(data)-alignmentPaddingSize {
				return fmt.Errorf("invalid data size value out of bounds")
			}

			if IsVerbose() {
				Printf("%s: alignment padding data:\n", "ReadData")
				PrintData(data[dataOffset:dataOffset+alignmentPaddingSize], true)
			}

			dataOffset += alignmentPaddingSize
		}
	}

	return nil
}

// GetVolumeKey retrieves the volume key that can be unlocked with the given passwords
// Returns true and the key if successful, false if no key could be unlocked
// Corresponds to libfsapfs_volume_key_bag_get_volume_key
func (v *VolumeKeyBag) GetVolumeKey(
	userPassword []byte,
	recoveryPassword []byte,
) ([]byte, bool, error) {
	if v == nil {
		return nil, false, fmt.Errorf("invalid volume key bag")
	}

	// Iterate through all entries looking for type 3 (KEK entries)
	for entryIndex, bagEntry := range v.Entries {
		if bagEntry == nil {
			return nil, false, fmt.Errorf("missing entry: %d", entryIndex)
		}

		// Type 3 is the key encrypted key (KEK) entry
		if bagEntry.Type != 3 {
			continue
		}

		// Parse the key encrypted key
		keyEncryptedKey, err := NewKeyEncryptedKey()
		if err != nil {
			return nil, false, fmt.Errorf("unable to create key encrypted key: %w", err)
		}

		if err := keyEncryptedKey.ReadData(bagEntry.Data); err != nil {
			return nil, false, fmt.Errorf("unable to read key encrypted key: %w", err)
		}

		// Try to unlock with user password first
		if len(userPassword) > 0 {
			key, err := keyEncryptedKey.UnlockWithPassword(userPassword)
			if err == nil && key != nil {
				return key, true, nil
			}
		}

		// Try recovery password if user password failed
		if len(recoveryPassword) > 0 {
			key, err := keyEncryptedKey.UnlockWithPassword(recoveryPassword)
			if err == nil && key != nil {
				return key, true, nil
			}
		}
	}

	// No key could be unlocked
	return nil, false, nil
}
