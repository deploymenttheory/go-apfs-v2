package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// ModifiedByInfo represents who last formatted or modified the volume
// Corresponds to apfs_modified_by_t in APFS spec
type ModifiedByInfo struct {
	// ID/name of the software (32 bytes)
	ID [32]byte
	// Timestamp when modified (8 bytes)
	Timestamp uint64
	// Last transaction ID (8 bytes)
	LastTransactionID uint64
}

// VolumeSuperblock represents the APFS volume superblock structure
type VolumeSuperblock struct {
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

	// The file system signature
	// Consists of 4 bytes
	// Contains: "APSB"
	Signature [4]byte

	// The file system index (apfs_fs_index)
	// Consists of 4 bytes
	FileSystemIndex uint32

	// Compatible features flags
	// Consists of 8 bytes
	CompatibleFeaturesFlags uint64

	// Read only compatible features flags
	// Consists of 8 bytes
	ReadOnlyCompatibleFeaturesFlags uint64

	// Incompatible features flags
	// Consists of 8 bytes
	IncompatibleFeaturesFlags uint64

	// Last unmount time (apfs_unmount_time) - nanoseconds since Unix epoch
	// Consists of 8 bytes
	UnmountTime uint64

	// The number of reserved blocks
	// Consists of 8 bytes
	NumberOfReservedBlocks uint64

	// The number of quota blocks
	// Consists of 8 bytes
	NumberOfQuotaBlocks uint64

	// The number of allocated blocks (apfs_fs_alloc_count)
	// Consists of 8 bytes
	NumberOfAllocatedBlocks uint64

	// Unknown fields between allocated blocks and tree types
	// This region may contain wrapped_meta_crypto_state_t
	// Total: 8 + 4 + 4 + 4 = 20 bytes
	Unknown9  uint64
	Unknown10 uint32
	Unknown11 uint32
	Unknown12 uint32

	// The file system root tree object type
	// Consists of 4 bytes
	FileSystemRootTreeObjectType uint32

	// The extent-reference tree object type
	// Consists of 4 bytes
	ExtentReferenceTreeObjectType uint32

	// The snapshot metadata tree object type
	// Consists of 4 bytes
	SnapshotMetadataTreeObjectType uint32

	// The object map block number
	// Consists of 8 bytes
	ObjectMapBlockNumber uint64

	// The file system root object identifier
	// Consists of 8 bytes
	FileSystemRootObjectIdentifier uint64

	// The extent-reference tree block number
	// Consists of 8 bytes
	ExtentReferenceTreeBlockNumber uint64

	// The snapshot metadata tree block number
	// Consists of 8 bytes
	SnapshotMetadataTreeBlockNumber uint64

	// Revert to transaction identifier (apfs_revert_to_xid)
	// Consists of 8 bytes
	RevertToTransactionIdentifier uint64

	// Revert to superblock object identifier (apfs_revert_to_sblock_oid)
	// Consists of 8 bytes
	RevertToSuperblockObjectIdentifier uint64

	// The next file system object identifier
	// Consists of 8 bytes
	NextFileSystemObjectIdentifier uint64

	// Number of regular files (apfs_num_files)
	// Consists of 8 bytes
	NumberOfFiles uint64

	// Number of directories (apfs_num_directories)
	// Consists of 8 bytes
	NumberOfDirectories uint64

	// Number of symbolic links (apfs_num_symlinks)
	// Consists of 8 bytes
	NumberOfSymlinks uint64

	// Number of other file system objects (apfs_num_other_fsobjects)
	// Consists of 8 bytes
	NumberOfOtherFileSystemObjects uint64

	// Number of snapshots (apfs_num_snapshots)
	// Consists of 8 bytes
	NumberOfSnapshots uint64

	// Total blocks allocated ever (apfs_total_block_alloced)
	// Consists of 8 bytes
	TotalBlocksAllocated uint64

	// Total blocks freed ever (apfs_total_blocks_freed)
	// Consists of 8 bytes
	TotalBlocksFreed uint64

	// The volume identifier
	// Consists of 16 bytes
	// Contains an UUID
	VolumeIdentifier [16]byte

	// The volume (last) modification date and time
	// Consists of 8 bytes
	ModificationTime uint64

	// The volume flags
	// Consists of 8 bytes
	VolumeFlags uint64

	// Who formatted the volume (apfs_formatted_by)
	// Offset 272-320, consists of 48 bytes (32 + 8 + 8)
	FormattedBy ModifiedByInfo

	// History of who modified the volume (apfs_modified_by)
	// Offset 320-704, consists of 8 * 48 = 384 bytes
	ModifiedBy [8]ModifiedByInfo

	// The volume name
	// Consists of 256 bytes
	VolumeName [256]byte

	// The next (available) document identifier
	// Consists of 4 bytes
	NextDocumentIdentifier uint32

	// Unknown
	// Consists of 4 bytes
	Unknown60 uint32

	// Unknown
	// Consists of 8 bytes
	Unknown61 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown62 [32]byte

	// Parsed volume name as string (not part of binary structure)
	volumeName string
}

// Volume superblock methods
// Corresponds to libfsapfs_volume_superblock.c and libfsapfs_volume_superblock.h

// NewVolumeSuperblock creates a new volume superblock
// Corresponds to libfsapfs_volume_superblock_initialize
func NewVolumeSuperblock() *VolumeSuperblock {
	return &VolumeSuperblock{}
}

// Free releases resources associated with the volume superblock
// Corresponds to libfsapfs_volume_superblock_free
func (vs *VolumeSuperblock) Free() error {
	if vs == nil {
		return fmt.Errorf("invalid volume superblock")
	}
	// Go's garbage collector handles memory cleanup
	return nil
}

// ReadFileIOHandle reads the volume superblock from a file at the specified offset
// Corresponds to libfsapfs_volume_superblock_read_file_io_handle
func (vs *VolumeSuperblock) ReadFileIOHandle(fileHandle io.ReaderAt, fileOffset int64, isSnapshot bool) error {
	if vs == nil {
		return fmt.Errorf("invalid volume superblock")
	}

	if DebugOutput {
		fmt.Printf("Reading volume superblock at offset: %d (0x%08x)\n", fileOffset, fileOffset)
	}

	// Read 4096 bytes (size of volume superblock)
	data := make([]byte, 4096)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read volume superblock data at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read volume superblock data at offset %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the data
	if err := vs.ReadData(data, isSnapshot); err != nil {
		return fmt.Errorf("unable to read volume superblock data: %w", err)
	}

	return nil
}

// ReadData reads the volume superblock from binary data
// Corresponds to libfsapfs_volume_superblock_read_data
func (vs *VolumeSuperblock) ReadData(data []byte, isSnapshot bool) error {
	if vs == nil {
		return fmt.Errorf("invalid volume superblock")
	}
	if data == nil {
		return fmt.Errorf("invalid data")
	}
	if len(data) < 1024 {
		return fmt.Errorf("invalid data size: %d bytes (minimum 1024)", len(data))
	}

	// Determine expected object type based on snapshot flag
	var expectedObjectType uint32
	if isSnapshot {
		expectedObjectType = 0x4000000d // Snapshot volume superblock
	} else {
		expectedObjectType = 0x0000000d // Regular volume superblock
	}

	// Parse object header (first 32 bytes)
	vs.ObjectChecksum = binary.LittleEndian.Uint64(data[0:8])
	vs.ObjectIdentifier = binary.LittleEndian.Uint64(data[8:16])
	vs.ObjectTransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	vs.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	vs.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if vs.ObjectType != expectedObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", vs.ObjectType, expectedObjectType)
	}

	// Validate object subtype (must be 0)
	if vs.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x (expected 0x00000000)", vs.ObjectSubtype)
	}

	// Parse signature (offset 32, 4 bytes)
	copy(vs.Signature[:], data[32:36])

	// Validate signature ("APSB")
	expectedSignature := [4]byte{'A', 'P', 'S', 'B'}
	if vs.Signature != expectedSignature {
		return fmt.Errorf("invalid signature: %s (expected APSB)", string(vs.Signature[:]))
	}

	// Parse remaining fields
	vs.FileSystemIndex = binary.LittleEndian.Uint32(data[36:40])
	vs.CompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[40:48])
	vs.ReadOnlyCompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[48:56])
	vs.IncompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[56:64])
	vs.UnmountTime = binary.LittleEndian.Uint64(data[64:72])
	vs.NumberOfReservedBlocks = binary.LittleEndian.Uint64(data[72:80])
	vs.NumberOfQuotaBlocks = binary.LittleEndian.Uint64(data[80:88])
	vs.NumberOfAllocatedBlocks = binary.LittleEndian.Uint64(data[88:96])
	vs.Unknown9 = binary.LittleEndian.Uint64(data[96:104])
	vs.Unknown10 = binary.LittleEndian.Uint32(data[104:108])
	vs.Unknown11 = binary.LittleEndian.Uint32(data[108:112])
	vs.Unknown12 = binary.LittleEndian.Uint32(data[112:116])
	vs.FileSystemRootTreeObjectType = binary.LittleEndian.Uint32(data[116:120])
	vs.ExtentReferenceTreeObjectType = binary.LittleEndian.Uint32(data[120:124])
	vs.SnapshotMetadataTreeObjectType = binary.LittleEndian.Uint32(data[124:128])
	vs.ObjectMapBlockNumber = binary.LittleEndian.Uint64(data[128:136])
	vs.FileSystemRootObjectIdentifier = binary.LittleEndian.Uint64(data[136:144])
	vs.ExtentReferenceTreeBlockNumber = binary.LittleEndian.Uint64(data[144:152])
	vs.SnapshotMetadataTreeBlockNumber = binary.LittleEndian.Uint64(data[152:160])
	vs.RevertToTransactionIdentifier = binary.LittleEndian.Uint64(data[160:168])
	vs.RevertToSuperblockObjectIdentifier = binary.LittleEndian.Uint64(data[168:176])
	vs.NextFileSystemObjectIdentifier = binary.LittleEndian.Uint64(data[176:184])
	vs.NumberOfFiles = binary.LittleEndian.Uint64(data[184:192])
	vs.NumberOfDirectories = binary.LittleEndian.Uint64(data[192:200])
	vs.NumberOfSymlinks = binary.LittleEndian.Uint64(data[200:208])
	vs.NumberOfOtherFileSystemObjects = binary.LittleEndian.Uint64(data[208:216])
	vs.NumberOfSnapshots = binary.LittleEndian.Uint64(data[216:224])
	vs.TotalBlocksAllocated = binary.LittleEndian.Uint64(data[224:232])
	vs.TotalBlocksFreed = binary.LittleEndian.Uint64(data[232:240])

	// Volume identifier (offset 240, 16 bytes UUID)
	copy(vs.VolumeIdentifier[:], data[240:256])

	// Modification time (offset 256, 8 bytes)
	vs.ModificationTime = binary.LittleEndian.Uint64(data[256:264])

	// Volume flags (offset 264, 8 bytes)
	vs.VolumeFlags = binary.LittleEndian.Uint64(data[264:272])

	// FormattedBy (offset 272-320, 48 bytes)
	copy(vs.FormattedBy.ID[:], data[272:304])
	vs.FormattedBy.Timestamp = binary.LittleEndian.Uint64(data[304:312])
	vs.FormattedBy.LastTransactionID = binary.LittleEndian.Uint64(data[312:320])

	// ModifiedBy[8] (offset 320-704, 384 bytes = 8 * 48 bytes)
	for i := 0; i < 8; i++ {
		offset := 320 + (i * 48)
		copy(vs.ModifiedBy[i].ID[:], data[offset:offset+32])
		vs.ModifiedBy[i].Timestamp = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
		vs.ModifiedBy[i].LastTransactionID = binary.LittleEndian.Uint64(data[offset+40 : offset+48])
	}

	// Volume name (offset 704, 256 bytes - UTF-8 string)
	copy(vs.VolumeName[:], data[704:960])

	// Parse and store the volume name as a string
	// Find null terminator in volume name
	nullIndex := bytes.IndexByte(vs.VolumeName[:], 0)
	if nullIndex >= 0 {
		vs.volumeName = string(vs.VolumeName[:nullIndex])
	} else {
		vs.volumeName = string(vs.VolumeName[:])
	}

	// Next document identifier (offset 960, 4 bytes)
	vs.NextDocumentIdentifier = binary.LittleEndian.Uint32(data[960:964])

	// Parse remaining unknown fields
	vs.Unknown60 = binary.LittleEndian.Uint32(data[964:968])
	vs.Unknown61 = binary.LittleEndian.Uint64(data[968:976])
	copy(vs.Unknown62[:], data[976:1008])

	return nil
}

// GetVolumeIdentifier retrieves the volume identifier (UUID)
// Corresponds to libfsapfs_volume_superblock_get_volume_identifier
func (vs *VolumeSuperblock) GetVolumeIdentifier() ([16]byte, error) {
	if vs == nil {
		return [16]byte{}, fmt.Errorf("invalid volume superblock")
	}
	return vs.VolumeIdentifier, nil
}

// GetFileSystemIndex retrieves the file system index
func (vs *VolumeSuperblock) GetFileSystemIndex() (uint32, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.FileSystemIndex, nil
}

// GetUnmountTime retrieves the last unmount time (nanoseconds since Unix epoch)
func (vs *VolumeSuperblock) GetUnmountTime() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.UnmountTime, nil
}

// GetRevertToTransactionIdentifier retrieves the revert-to transaction identifier
func (vs *VolumeSuperblock) GetRevertToTransactionIdentifier() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.RevertToTransactionIdentifier, nil
}

// GetRevertToSuperblockObjectIdentifier retrieves the revert-to superblock object identifier
func (vs *VolumeSuperblock) GetRevertToSuperblockObjectIdentifier() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.RevertToSuperblockObjectIdentifier, nil
}

// GetNumberOfFiles retrieves the number of regular files
func (vs *VolumeSuperblock) GetNumberOfFiles() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.NumberOfFiles, nil
}

// GetNumberOfDirectories retrieves the number of directories
func (vs *VolumeSuperblock) GetNumberOfDirectories() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.NumberOfDirectories, nil
}

// GetNumberOfSymlinks retrieves the number of symbolic links
func (vs *VolumeSuperblock) GetNumberOfSymlinks() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.NumberOfSymlinks, nil
}

// GetNumberOfOtherFileSystemObjects retrieves the number of other file system objects
func (vs *VolumeSuperblock) GetNumberOfOtherFileSystemObjects() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.NumberOfOtherFileSystemObjects, nil
}

// GetNumberOfSnapshots retrieves the number of snapshots
func (vs *VolumeSuperblock) GetNumberOfSnapshots() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.NumberOfSnapshots, nil
}

// GetTotalBlocksAllocated retrieves the total blocks ever allocated
func (vs *VolumeSuperblock) GetTotalBlocksAllocated() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.TotalBlocksAllocated, nil
}

// GetTotalBlocksFreed retrieves the total blocks ever freed
func (vs *VolumeSuperblock) GetTotalBlocksFreed() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.TotalBlocksFreed, nil
}

// GetUTF8VolumeNameSize retrieves the size of the UTF-8 encoded volume name
// The returned size includes the end of string character
// Corresponds to libfsapfs_volume_superblock_get_utf8_volume_name_size
func (vs *VolumeSuperblock) GetUTF8VolumeNameSize() (int, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	// Return the length of the parsed name plus 1 for null terminator
	return len(vs.volumeName) + 1, nil
}

// GetUTF8VolumeName retrieves the UTF-8 encoded volume name
// Corresponds to libfsapfs_volume_superblock_get_utf8_volume_name
func (vs *VolumeSuperblock) GetUTF8VolumeName() (string, error) {
	if vs == nil {
		return "", fmt.Errorf("invalid volume superblock")
	}
	return vs.volumeName, nil
}

// GetUTF16VolumeNameSize retrieves the size of the UTF-16 encoded volume name
// The returned size includes the end of string character
// Corresponds to libfsapfs_volume_superblock_get_utf16_volume_name_size
func (vs *VolumeSuperblock) GetUTF16VolumeNameSize() (int, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(vs.volumeName)
	utf16Data := utf16.Encode(runes)

	// Return the length plus 1 for null terminator
	return len(utf16Data) + 1, nil
}

// GetUTF16VolumeName retrieves the UTF-16 encoded volume name
// Corresponds to libfsapfs_volume_superblock_get_utf16_volume_name
func (vs *VolumeSuperblock) GetUTF16VolumeName() ([]uint16, error) {
	if vs == nil {
		return nil, fmt.Errorf("invalid volume superblock")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(vs.volumeName)
	utf16Data := utf16.Encode(runes)

	// Add null terminator
	result := make([]uint16, len(utf16Data)+1)
	copy(result, utf16Data)
	result[len(utf16Data)] = 0

	return result, nil
}

// GetFormattedBy retrieves who formatted this volume
func (vs *VolumeSuperblock) GetFormattedBy() string {
	if vs == nil {
		return ""
	}
	// Find the null terminator
	for i, b := range vs.FormattedBy.ID {
		if b == 0 {
			return string(vs.FormattedBy.ID[:i])
		}
	}
	return string(vs.FormattedBy.ID[:])
}

// GetLastModifiedBy retrieves who last modified this volume (most recent entry)
func (vs *VolumeSuperblock) GetLastModifiedBy() string {
	if vs == nil {
		return ""
	}
	// Find the most recent non-empty entry
	for i := 7; i >= 0; i-- {
		// Check if this entry has data
		hasData := false
		for _, b := range vs.ModifiedBy[i].ID {
			if b != 0 {
				hasData = true
				break
			}
		}
		if hasData {
			// Find the null terminator
			for j, b := range vs.ModifiedBy[i].ID {
				if b == 0 {
					return string(vs.ModifiedBy[i].ID[:j])
				}
			}
			return string(vs.ModifiedBy[i].ID[:])
		}
	}
	return ""
}

// GetModifiedByHistory retrieves the full modification history
// Returns a slice of strings from most recent to oldest, excluding empty entries
func (vs *VolumeSuperblock) GetModifiedByHistory() []string {
	if vs == nil {
		return nil
	}

	history := make([]string, 0, 8)

	// Iterate from most recent (7) to oldest (0)
	for i := 7; i >= 0; i-- {
		// Check if this entry has data
		hasData := false
		for _, b := range vs.ModifiedBy[i].ID {
			if b != 0 {
				hasData = true
				break
			}
		}

		if hasData {
			// Find the null terminator and extract the string
			var modifiedBy string
			for j, b := range vs.ModifiedBy[i].ID {
				if b == 0 {
					modifiedBy = string(vs.ModifiedBy[i].ID[:j])
					break
				}
			}
			if modifiedBy == "" {
				modifiedBy = string(vs.ModifiedBy[i].ID[:])
			}
			history = append(history, modifiedBy)
		}
	}

	return history
}
