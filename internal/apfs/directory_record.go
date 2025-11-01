package apfs

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// DirectoryRecord represents an APFS directory record (directory entry)
// Corresponds to libfsapfs_directory_record_t
type DirectoryRecord struct {
	// Identifier (inode number of the directory entry)
	Identifier uint64

	// ParentIdentifier (from the key)
	ParentIdentifier uint64

	// NameSize is the size of the name in bytes
	NameSize uint16

	// Name is the UTF-8 encoded name
	Name []byte

	// NameHash is the optional name hash (if present in key)
	NameHash uint32

	// AddedTime is the time when entry was added (nanoseconds since Unix epoch)
	AddedTime uint64

	// Flags are the directory entry flags
	Flags uint16

	// ExtendedFields stores any parsed extended fields
	ExtendedFields []ExtendedField
}

// ExtendedField represents an extended field in a directory record
type ExtendedField struct {
	Type  uint8
	Flags uint8
	Data  []byte
}

// DirectoryRecordExtendedFieldType constants
const (
	DirectoryRecordExtendedFieldTypeSiblingID = 1
)

// NewDirectoryRecord creates a new directory record
// Corresponds to libfsapfs_directory_record_initialize
func NewDirectoryRecord() *DirectoryRecord {
	return &DirectoryRecord{}
}

// ReadKeyData reads the directory record key data from a B-tree entry
func (dr *DirectoryRecord) ReadKeyData(data []byte) error {
	if dr == nil {
		return fmt.Errorf("invalid directory record")
	}

	if dr.Name != nil {
		return fmt.Errorf("name value already set")
	}

	// Minimum size is FileSystemBTreeKeyDirectoryRecord (8 + 2 = 10 bytes)
	const minKeySize = 10

	if len(data) < minKeySize {
		return fmt.Errorf("invalid key data size: expected at least %d bytes, got %d", minKeySize, len(data))
	}

	// Read parent identifier (lower 60 bits)
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])
	dr.ParentIdentifier = fileSystemIdentifier & 0x0fffffffffffffff

	// Read name size field (lower 10 bits)
	nameSizeField := binary.LittleEndian.Uint16(data[8:10])
	nameSize := uint32(nameSizeField) & 0x000003ff

	dataOffset := 10

	// Determine if this key contains a hash
	// If there's more data than just the name, it might be a hash variant
	if int(nameSize) < (len(data) - dataOffset) {
		// This is a directory record with hash
		if len(data) < 12 {
			return fmt.Errorf("invalid key data size for hash variant: expected at least 12 bytes, got %d", len(data))
		}

		// Read name size and hash (combined in 32 bits)
		nameSizeAndHash := binary.LittleEndian.Uint32(data[8:12])
		nameSize = nameSizeAndHash & 0x000003ff
		dr.NameHash = (nameSizeAndHash & 0xfffffc00) >> 10

		dataOffset = 12
	}

	// Validate name size
	if nameSize == 0 || int(nameSize) > (len(data)-dataOffset) {
		return fmt.Errorf("invalid name size: %d (available: %d)", nameSize, len(data)-dataOffset)
	}

	// Copy name data
	dr.Name = make([]byte, nameSize)
	copy(dr.Name, data[dataOffset:dataOffset+int(nameSize)])
	dr.NameSize = uint16(nameSize)

	return nil
}

// ReadValueData reads the directory record value data from a B-tree entry
// Corresponds to libfsapfs_directory_record_read_value_data
func (dr *DirectoryRecord) ReadValueData(data []byte) error {
	if dr == nil {
		return fmt.Errorf("invalid directory record")
	}

	// Minimum size is FileSystemBTreeValueDirectoryRecord (8 + 8 + 2 = 18 bytes)
	const minValueSize = 18

	if len(data) < minValueSize {
		return fmt.Errorf("invalid value data size: expected at least %d bytes, got %d", minValueSize, len(data))
	}

	// Read fixed fields
	dr.Identifier = binary.LittleEndian.Uint64(data[0:8])
	dr.AddedTime = binary.LittleEndian.Uint64(data[8:16])
	dr.Flags = binary.LittleEndian.Uint16(data[16:18])

	// Debug output
	if DebugOutput {
		fmt.Printf("libfsapfs_directory_record_read_value_data: directory record value data:\n")
		PrintData(data, true)

		fmt.Printf("libfsapfs_directory_record_read_value_data: identifier\t\t\t\t: %d\n", dr.Identifier)

		timeBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(timeBytes, dr.AddedTime)
		if err := PrintPOSIXTimeValue("libfsapfs_directory_record_read_value_data", "added time", timeBytes, binary.LittleEndian, "nanoseconds"); err != nil {
			fmt.Printf("Warning: unable to print added time: %v\n", err)
		}

		fmt.Printf("libfsapfs_directory_record_read_value_data: directory entry flags\t\t: 0x%04x\n", dr.Flags)
		PrintDirectoryEntryFlags(dr.Flags)
		fmt.Printf("\n")
	}

	// Parse extended fields if present
	if len(data) > minValueSize {
		if err := dr.parseExtendedFields(data[minValueSize:]); err != nil {
			return fmt.Errorf("failed to parse extended fields: %w", err)
		}
	}

	return nil
}

// parseExtendedFields parses the extended fields from directory record value data
func (dr *DirectoryRecord) parseExtendedFields(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("insufficient data for extended fields header")
	}

	dataOffset := 0
	numberOfExtendedFields := binary.LittleEndian.Uint16(data[dataOffset : dataOffset+2])

	if DebugOutput {
		fmt.Printf("libfsapfs_directory_record_read_value_data: number of extended fields\t\t: %d\n", numberOfExtendedFields)
		unknown1 := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])
		fmt.Printf("libfsapfs_directory_record_read_value_data: unknown1\t\t\t\t: 0x%04x\n", unknown1)
	}

	dataOffset += 4
	valueDataOffset := dataOffset + (int(numberOfExtendedFields) * 4)

	if valueDataOffset > len(data) {
		return fmt.Errorf("invalid extended fields: offset out of bounds")
	}

	dr.ExtendedFields = make([]ExtendedField, 0, numberOfExtendedFields)

	for fieldIndex := uint16(0); fieldIndex < numberOfExtendedFields; fieldIndex++ {
		if dataOffset+4 > len(data) {
			return fmt.Errorf("invalid extended field header at index %d", fieldIndex)
		}

		fieldType := data[dataOffset]
		fieldFlags := data[dataOffset+1]
		valueDataSize := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])

		if DebugOutput {
			fmt.Printf("libfsapfs_directory_record_read_value_data: extended field: %d type\t\t: %d %s\n",
				fieldIndex, fieldType, GetDirectoryRecordExtendedFieldTypeName(fieldType))
			fmt.Printf("libfsapfs_directory_record_read_value_data: extended field: %d flags\t\t: 0x%02x\n",
				fieldIndex, fieldFlags)
			PrintExtendedFieldFlags(fieldFlags)
			fmt.Printf("\n")
			fmt.Printf("libfsapfs_directory_record_read_value_data: extended field: %d value data size\t: %d\n",
				fieldIndex, valueDataSize)
		}

		dataOffset += 4

		if valueDataOffset+int(valueDataSize) > len(data) {
			return fmt.Errorf("invalid extended field value data at index %d", fieldIndex)
		}

		valueData := make([]byte, valueDataSize)
		copy(valueData, data[valueDataOffset:valueDataOffset+int(valueDataSize)])

		if DebugOutput && valueDataSize > 0 {
			fmt.Printf("libfsapfs_directory_record_read_value_data: extended field: %d value data:\n", fieldIndex)
			PrintData(valueData, false)
		}

		// Validate supported field types
		switch fieldType {
		case DirectoryRecordExtendedFieldTypeSiblingID:
			// Valid field type
		default:
			return fmt.Errorf("unsupported extended field type: %d", fieldType)
		}

		dr.ExtendedFields = append(dr.ExtendedFields, ExtendedField{
			Type:  fieldType,
			Flags: fieldFlags,
			Data:  valueData,
		})

		valueDataOffset += int(valueDataSize)

		// Handle trailing padding (aligned to 8 bytes)
		trailingDataSize := int(valueDataSize) % 8
		if trailingDataSize > 0 {
			trailingDataSize = 8 - trailingDataSize
			if valueDataOffset+trailingDataSize > len(data) {
				trailingDataSize = len(data) - valueDataOffset
			}

			if DebugOutput && trailingDataSize > 0 {
				fmt.Printf("libfsapfs_directory_record_read_value_data: extended field: %d trailing data:\n", fieldIndex)
				PrintData(data[valueDataOffset:valueDataOffset+trailingDataSize], false)
			}

			valueDataOffset += trailingDataSize
		}
	}

	if DebugOutput {
		fmt.Printf("\n")
	}

	return nil
}

// Clone creates a deep copy of the directory record
// Corresponds to libfsapfs_directory_record_clone
func (dr *DirectoryRecord) Clone() (*DirectoryRecord, error) {
	if dr == nil {
		return nil, nil
	}

	clone := &DirectoryRecord{
		Identifier:       dr.Identifier,
		ParentIdentifier: dr.ParentIdentifier,
		NameSize:         dr.NameSize,
		NameHash:         dr.NameHash,
		AddedTime:        dr.AddedTime,
		Flags:            dr.Flags,
	}

	if dr.Name != nil {
		clone.Name = make([]byte, len(dr.Name))
		copy(clone.Name, dr.Name)
	}

	if dr.ExtendedFields != nil {
		clone.ExtendedFields = make([]ExtendedField, len(dr.ExtendedFields))
		for i, field := range dr.ExtendedFields {
			clone.ExtendedFields[i] = ExtendedField{
				Type:  field.Type,
				Flags: field.Flags,
			}
			if field.Data != nil {
				clone.ExtendedFields[i].Data = make([]byte, len(field.Data))
				copy(clone.ExtendedFields[i].Data, field.Data)
			}
		}
	}

	return clone, nil
}

// GetIdentifier retrieves the identifier (inode number)
// Corresponds to libfsapfs_directory_record_get_identifier
func (dr *DirectoryRecord) GetIdentifier() (uint64, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory record")
	}
	return dr.Identifier, nil
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded name
// The returned size includes the end-of-string character
// Corresponds to libfsapfs_directory_record_get_utf8_name_size
func (dr *DirectoryRecord) GetUTF8NameSize() (int, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory record")
	}
	// Return size + 1 for null terminator to match C API behavior
	return len(dr.Name) + 1, nil
}

// GetUTF8Name retrieves the UTF-8 encoded name
// Corresponds to libfsapfs_directory_record_get_utf8_name
func (dr *DirectoryRecord) GetUTF8Name() (string, error) {
	if dr == nil {
		return "", fmt.Errorf("invalid directory record")
	}
	if dr.Name == nil {
		return "", nil
	}
	return string(dr.Name), nil
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded name
// The returned size includes the end-of-string character
// Corresponds to libfsapfs_directory_record_get_utf16_name_size
func (dr *DirectoryRecord) GetUTF16NameSize() (int, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory record")
	}

	// Count the UTF-16 code units needed
	utf16Count := 0
	nameBytes := dr.Name
	for len(nameBytes) > 0 {
		r, size := utf8.DecodeRune(nameBytes)
		if r == utf8.RuneError {
			return 0, fmt.Errorf("invalid UTF-8 sequence")
		}
		if r <= 0xFFFF {
			utf16Count++
		} else {
			utf16Count += 2 // Surrogate pair
		}
		nameBytes = nameBytes[size:]
	}

	// Add 1 for null terminator
	return utf16Count + 1, nil
}

// GetUTF16Name retrieves the UTF-16 encoded name
// Corresponds to libfsapfs_directory_record_get_utf16_name
func (dr *DirectoryRecord) GetUTF16Name() ([]uint16, error) {
	if dr == nil {
		return nil, fmt.Errorf("invalid directory record")
	}
	if dr.Name == nil {
		return nil, nil
	}

	// Convert UTF-8 to UTF-16
	runes := []rune(string(dr.Name))
	utf16Encoded := utf16.Encode(runes)

	return utf16Encoded, nil
}

// CompareNameWithUTF8String compares an UTF-8 string with a directory record name
// Returns -1 if less, 0 if equal, 1 if greater
// Corresponds to libfsapfs_directory_record_compare_name_with_utf8_string
func (dr *DirectoryRecord) CompareNameWithUTF8String(utf8String []byte, nameHash uint32, useCaseFolding bool) int {
	if dr == nil {
		return -1
	}

	// Compare name hash first if both are available
	if dr.NameHash != 0 && nameHash != 0 {
		if nameHash < dr.NameHash {
			return -1
		}
		if nameHash > dr.NameHash {
			return 1
		}
	}

	// Compare names
	if dr.Name != nil {
		return compareNamesWithUTF8(dr.Name, utf8String, useCaseFolding)
	}

	return 0
}

// CompareNameWithUTF16String compares an UTF-16 string with a directory record name
// Returns -1 if less, 0 if equal, 1 if greater
// Corresponds to libfsapfs_directory_record_compare_name_with_utf16_string
func (dr *DirectoryRecord) CompareNameWithUTF16String(utf16String []uint16, nameHash uint32, useCaseFolding bool) int {
	if dr == nil {
		return -1
	}

	// Compare name hash first if both are available
	if dr.NameHash != 0 && nameHash != 0 {
		if nameHash < dr.NameHash {
			return -1
		}
		if nameHash > dr.NameHash {
			return 1
		}
	}

	// Compare names
	if dr.Name != nil {
		// Convert UTF-16 to UTF-8 for comparison
		runes := utf16.Decode(utf16String)
		utf8Bytes := []byte(string(runes))
		return compareNamesWithUTF8(dr.Name, utf8Bytes, useCaseFolding)
	}

	return 0
}

// GetAddedTime retrieves the added time
// The timestamp is a signed 64-bit POSIX date and time value in nanoseconds
// Corresponds to libfsapfs_directory_record_get_added_time
func (dr *DirectoryRecord) GetAddedTime() (int64, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory record")
	}
	return int64(dr.AddedTime), nil
}

// GetName returns the name as a string (convenience method)
func (dr *DirectoryRecord) GetName() string {
	if dr == nil || dr.Name == nil {
		return ""
	}
	return string(dr.Name)
}

// IsDirectory returns true if this record represents a directory
func (dr *DirectoryRecord) IsDirectory() bool {
	// Flag 0x0001 indicates a directory
	return (dr.Flags & 0x0001) != 0
}

// CompareName compares the directory record name with the given name (convenience method)
// Returns 0 if equal, <0 if dr.Name < name, >0 if dr.Name > name
func (dr *DirectoryRecord) CompareName(name []byte, nameHash uint32, useCaseFolding bool) int {
	return dr.CompareNameWithUTF8String(name, nameHash, useCaseFolding)
}

// compareNamesWithUTF8 compares two UTF-8 encoded names
// Corresponds to libfsapfs_name_compare_with_utf8_string
// Uses the proper Unicode normalization and case folding implementation from name_hash.go
func compareNamesWithUTF8(name1, name2 []byte, useCaseFolding bool) int {
	// Use the full Unicode-aware comparison from name_hash.go
	// This provides proper NFD normalization and case folding as per the C library
	return CompareNamesWithUTF8(name1, name2, useCaseFolding)
}
