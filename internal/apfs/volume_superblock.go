package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

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

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32

	// Compatible features flags
	// Consists of 8 bytes
	CompatibleFeaturesFlags uint64

	// Read only compatible features flags
	// Consists of 8 bytes
	ReadOnlyCompatibleFeaturesFlags uint64

	// Incompatible features flags
	// Consists of 8 bytes
	IncompatibleFeaturesFlags uint64

	// Unknown
	// Consists of 8 bytes
	Unknown5 uint64

	// The number of reserved blocks
	// Consists of 8 bytes
	NumberOfReservedBlocks uint64

	// The number of quota blocks
	// Consists of 8 bytes
	NumberOfQuotaBlocks uint64

	// Unknown
	// Consists of 8 bytes
	Unknown8 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown9 uint64

	// Unknown
	// Consists of 4 bytes
	Unknown10 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown11 uint32

	// Unknown
	// Consists of 4 bytes
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

	// Unknown
	// Consists of 8 bytes
	Unknown20 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown21 uint64

	// The next file system object identifier
	// Consists of 8 bytes
	NextFileSystemObjectIdentifier uint64

	// Unknown
	// Consists of 8 bytes
	Unknown23 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown24 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown25 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown26 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown27 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown28 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown29 uint64

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

	// Unknown
	// Consists of 32 bytes
	Unknown32 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown33 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown34 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown35 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown36 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown37 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown38 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown39 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown40 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown41 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown42 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown43 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown44 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown45 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown46 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown47 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown48 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown49 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown50 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown51 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown52 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown53 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown54 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown55 uint64

	// Unknown
	// Consists of 32 bytes
	Unknown56 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown57 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown58 uint64

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
	vs.Unknown1 = binary.LittleEndian.Uint32(data[36:40])
	vs.CompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[40:48])
	vs.ReadOnlyCompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[48:56])
	vs.IncompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[56:64])
	vs.Unknown5 = binary.LittleEndian.Uint64(data[64:72])
	vs.NumberOfReservedBlocks = binary.LittleEndian.Uint64(data[72:80])
	vs.NumberOfQuotaBlocks = binary.LittleEndian.Uint64(data[80:88])
	vs.Unknown8 = binary.LittleEndian.Uint64(data[88:96])
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
	vs.Unknown20 = binary.LittleEndian.Uint64(data[160:168])
	vs.Unknown21 = binary.LittleEndian.Uint64(data[168:176])
	vs.NextFileSystemObjectIdentifier = binary.LittleEndian.Uint64(data[176:184])
	vs.Unknown23 = binary.LittleEndian.Uint64(data[184:192])
	vs.Unknown24 = binary.LittleEndian.Uint64(data[192:200])
	vs.Unknown25 = binary.LittleEndian.Uint64(data[200:208])
	vs.Unknown26 = binary.LittleEndian.Uint64(data[208:216])
	vs.Unknown27 = binary.LittleEndian.Uint64(data[216:224])
	vs.Unknown28 = binary.LittleEndian.Uint64(data[224:232])
	vs.Unknown29 = binary.LittleEndian.Uint64(data[232:240])

	// Volume identifier (offset 240, 16 bytes UUID)
	copy(vs.VolumeIdentifier[:], data[240:256])

	// Modification time (offset 256, 8 bytes)
	vs.ModificationTime = binary.LittleEndian.Uint64(data[256:264])

	// Volume flags (offset 264, 8 bytes)
	vs.VolumeFlags = binary.LittleEndian.Uint64(data[264:272])

	// Parse unknown fields
	copy(vs.Unknown32[:], data[272:304])
	vs.Unknown33 = binary.LittleEndian.Uint64(data[304:312])
	vs.Unknown34 = binary.LittleEndian.Uint64(data[312:320])
	copy(vs.Unknown35[:], data[320:352])
	vs.Unknown36 = binary.LittleEndian.Uint64(data[352:360])
	vs.Unknown37 = binary.LittleEndian.Uint64(data[360:368])
	copy(vs.Unknown38[:], data[368:400])
	vs.Unknown39 = binary.LittleEndian.Uint64(data[400:408])
	vs.Unknown40 = binary.LittleEndian.Uint64(data[408:416])
	copy(vs.Unknown41[:], data[416:448])
	vs.Unknown42 = binary.LittleEndian.Uint64(data[448:456])
	vs.Unknown43 = binary.LittleEndian.Uint64(data[456:464])
	copy(vs.Unknown44[:], data[464:496])
	vs.Unknown45 = binary.LittleEndian.Uint64(data[496:504])
	vs.Unknown46 = binary.LittleEndian.Uint64(data[504:512])
	copy(vs.Unknown47[:], data[512:544])
	vs.Unknown48 = binary.LittleEndian.Uint64(data[544:552])
	vs.Unknown49 = binary.LittleEndian.Uint64(data[552:560])
	copy(vs.Unknown50[:], data[560:592])
	vs.Unknown51 = binary.LittleEndian.Uint64(data[592:600])
	vs.Unknown52 = binary.LittleEndian.Uint64(data[600:608])
	copy(vs.Unknown53[:], data[608:640])
	vs.Unknown54 = binary.LittleEndian.Uint64(data[640:648])
	vs.Unknown55 = binary.LittleEndian.Uint64(data[648:656])
	copy(vs.Unknown56[:], data[656:688])
	vs.Unknown57 = binary.LittleEndian.Uint64(data[688:696])
	vs.Unknown58 = binary.LittleEndian.Uint64(data[696:704])

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
