// The APFS container superblock definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ContainerSuperblock represents the APFS container superblock structure
type ContainerSuperblock struct {
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
	// Contains: "NXSB"
	Signature [4]byte

	// The block size
	// Consists of 4 bytes
	BlockSize uint32

	// The number of blocks
	// Consists of 8 bytes
	NumberOfBlocks uint64

	// Compatible features flags
	// Consists of 8 bytes
	CompatibleFeaturesFlags uint64

	// Read only compatible features flags
	// Consists of 8 bytes
	ReadOnlyCompatibleFeaturesFlags uint64

	// Incompatible features flags
	// Consists of 8 bytes
	IncompatibleFeaturesFlags uint64

	// The container identifier
	// Consists of 16 bytes
	// Contains an UUID
	ContainerIdentifier [16]byte

	// The next object identifier
	// Consists of 8 bytes
	NextObjectIdentifier uint64

	// The next transaction identifier
	// Consists of 8 bytes
	NextTransactionIdentifier uint64

	// The checkpoint descriptor area number of blocks
	// Consists of 4 bytes
	CheckpointDescriptorAreaNumberOfBlocks uint32

	// The checkpoint data area number of blocks
	// Consists of 4 bytes
	CheckpointDataAreaNumberOfBlocks uint32

	// The checkpoint descriptor area block number
	// Consists of 8 bytes
	CheckpointDescriptorAreaBlockNumber uint64

	// The checkpoint data area block number
	// Consists of 8 bytes
	CheckpointDataAreaBlockNumber uint64

	// Unknown
	// Consists of 4 bytes
	Unknown8 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown9 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown10 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown11 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown12 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown13 uint32

	// The space manager object identifier
	// Consists of 8 bytes
	SpaceManagerObjectIdentifier uint64

	// The object map block number
	// Consists of 8 bytes
	ObjectMapBlockNumber uint64

	// The reaper object identifier
	// Consists of 8 bytes
	ReaperObjectIdentifier uint64

	// Unknown
	// Consists of 4 bytes
	Unknown17 uint32

	// The maximum number of volumes
	// Consists of 4 bytes
	MaximumNumberOfVolumes uint32

	// The volume object identifiers
	// Consists of 100 x 8 bytes
	VolumeObjectIdentifiers [800]byte

	// The counters
	// Consists of 32 x 8 bytes
	Counters [256]byte

	// Unknown
	// Consists of 8 bytes
	Unknown20 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown21 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown22 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown23 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown24 uint64

	// The Fusion set identifier
	// Consists of 16 bytes
	// Contains an UUID
	FusionSetIdentifier [16]byte

	// The key bag block number
	// Consists of 8 bytes
	KeyBagBlockNumber uint64

	// The key bag number of blocks
	// Consists of 8 bytes
	KeyBagNumberOfBlocks uint64

	// Unknown
	// Consists of 4 x 8 bytes
	Unknown29 [32]byte

	// Unknown
	// Consists of 8 bytes
	Unknown30 uint64

	// The Fusion middle tree block number
	// Consists of 8 bytes
	FusionMiddleTreeBlockNumber uint64

	// The Fusion write-back cache object identifier
	// Consists of 8 bytes
	FusionWriteBackCacheObjectIdentifier uint64

	// Unknown
	// Consists of 8 bytes
	Unknown33 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown34 uint64
}

// Container superblock constants
const (
	ContainerSuperblockObjectType = 0x80000001
	ContainerSuperblockSignature  = "NXSB"
	ContainerSuperblockSize       = 4096
)

// NewContainerSuperblock creates a new container superblock
// Corresponds to libfsapfs_container_superblock_initialize
func NewContainerSuperblock() (*ContainerSuperblock, error) {
	return &ContainerSuperblock{}, nil
}

// Free releases resources associated with the container superblock
func (csb *ContainerSuperblock) Free() error {
	if csb == nil {
		return fmt.Errorf("invalid container superblock")
	}

	// Nothing to free currently
	return nil
}

// ReadFileIOHandle reads the container superblock from a file
// Corresponds to libfsapfs_container_superblock_read_file_io_handle
func (csb *ContainerSuperblock) ReadFileIOHandle(
	fileHandle io.ReaderAt,
	fileOffset int64,
) error {
	if csb == nil {
		return fmt.Errorf("invalid container superblock")
	}

	// Container superblock is always 4096 bytes
	data := make([]byte, ContainerSuperblockSize)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read container superblock data at offset %d: %w", fileOffset, err)
	}
	if n != ContainerSuperblockSize {
		return fmt.Errorf("unable to read complete container superblock data: expected %d bytes, got %d", ContainerSuperblockSize, n)
	}

	return csb.ReadData(data)
}

// ReadData reads the container superblock from data
// Corresponds to libfsapfs_container_superblock_read_data
func (csb *ContainerSuperblock) ReadData(data []byte) error {
	if csb == nil {
		return fmt.Errorf("invalid container superblock")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ContainerSuperblockSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes, got %d", ContainerSuperblockSize, len(data))
	}

	// Read and validate checksum
	storedChecksum := binary.LittleEndian.Uint64(data[0:8])
	calculatedChecksum, err := CalculateFletcher64(data[8:], 0)
	if err != nil {
		return fmt.Errorf("unable to calculate Fletcher-64 checksum: %w", err)
	}
	if storedChecksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch (0x%016x != 0x%016x)", storedChecksum, calculatedChecksum)
	}

	// Parse object header
	csb.ObjectChecksum = storedChecksum
	csb.ObjectIdentifier = binary.LittleEndian.Uint64(data[8:16])
	csb.ObjectTransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	csb.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	csb.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if csb.ObjectType != ContainerSuperblockObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", csb.ObjectType, ContainerSuperblockObjectType)
	}

	// Validate object subtype
	if csb.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", csb.ObjectSubtype)
	}

	// Read signature
	copy(csb.Signature[:], data[32:36])
	if string(csb.Signature[:]) != ContainerSuperblockSignature {
		return fmt.Errorf("invalid signature: %s (expected %s)", string(csb.Signature[:]), ContainerSuperblockSignature)
	}

	// Read superblock fields
	csb.BlockSize = binary.LittleEndian.Uint32(data[36:40])
	csb.NumberOfBlocks = binary.LittleEndian.Uint64(data[40:48])
	csb.CompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[48:56])
	csb.ReadOnlyCompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[56:64])
	csb.IncompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[64:72])

	// Debug output for container feature flags
	if DebugOutput {
		fmt.Printf("Container compatible features flags: 0x%016x\n", csb.CompatibleFeaturesFlags)
		PrintContainerCompatibleFeaturesFlags(csb.CompatibleFeaturesFlags)
		fmt.Printf("Container read-only compatible features flags: 0x%016x\n", csb.ReadOnlyCompatibleFeaturesFlags)
		PrintContainerReadOnlyCompatibleFeaturesFlags(csb.ReadOnlyCompatibleFeaturesFlags)
		fmt.Printf("Container incompatible features flags: 0x%016x\n", csb.IncompatibleFeaturesFlags)
		PrintContainerIncompatibleFeaturesFlags(csb.IncompatibleFeaturesFlags)
	}

	copy(csb.ContainerIdentifier[:], data[72:88])

	// Debug output for container identifier GUID
	if DebugOutput {
		if err := PrintGUIDValue("libfsapfs_container_superblock_read_data", "container identifier", csb.ContainerIdentifier[:], binary.LittleEndian); err != nil {
			fmt.Printf("Warning: unable to print container identifier GUID: %v\n", err)
		}
	}

	csb.NextObjectIdentifier = binary.LittleEndian.Uint64(data[88:96])
	csb.NextTransactionIdentifier = binary.LittleEndian.Uint64(data[96:104])
	csb.CheckpointDescriptorAreaNumberOfBlocks = binary.LittleEndian.Uint32(data[104:108])
	csb.CheckpointDataAreaNumberOfBlocks = binary.LittleEndian.Uint32(data[108:112])
	csb.CheckpointDescriptorAreaBlockNumber = binary.LittleEndian.Uint64(data[112:120])
	csb.CheckpointDataAreaBlockNumber = binary.LittleEndian.Uint64(data[120:128])
	csb.Unknown8 = binary.LittleEndian.Uint32(data[128:132])
	csb.Unknown9 = binary.LittleEndian.Uint32(data[132:136])
	csb.Unknown10 = binary.LittleEndian.Uint32(data[136:140])
	csb.Unknown11 = binary.LittleEndian.Uint32(data[140:144])
	csb.Unknown12 = binary.LittleEndian.Uint32(data[144:148])
	csb.Unknown13 = binary.LittleEndian.Uint32(data[148:152])
	csb.SpaceManagerObjectIdentifier = binary.LittleEndian.Uint64(data[152:160])
	csb.ObjectMapBlockNumber = binary.LittleEndian.Uint64(data[160:168])
	csb.ReaperObjectIdentifier = binary.LittleEndian.Uint64(data[168:176])
	csb.Unknown17 = binary.LittleEndian.Uint32(data[176:180])
	csb.MaximumNumberOfVolumes = binary.LittleEndian.Uint32(data[180:184])

	// Read volume object identifiers (100 x 8 bytes = 800 bytes at offset 184)
	copy(csb.VolumeObjectIdentifiers[:], data[184:984])

	// Read counters (32 x 8 bytes = 256 bytes at offset 984)
	copy(csb.Counters[:], data[984:1240])

	// Read remaining fields
	csb.Unknown20 = binary.LittleEndian.Uint64(data[1240:1248])
	csb.Unknown21 = binary.LittleEndian.Uint64(data[1248:1256])
	csb.Unknown22 = binary.LittleEndian.Uint64(data[1256:1264])
	csb.Unknown23 = binary.LittleEndian.Uint64(data[1264:1272])
	csb.Unknown24 = binary.LittleEndian.Uint64(data[1272:1280])
	copy(csb.FusionSetIdentifier[:], data[1280:1296])

	// Debug output for Fusion set identifier GUID
	if DebugOutput {
		if err := PrintGUIDValue("libfsapfs_container_superblock_read_data", "Fusion set identifier", csb.FusionSetIdentifier[:], binary.BigEndian); err != nil {
			fmt.Printf("Warning: unable to print Fusion set identifier GUID: %v\n", err)
		}
	}

	csb.KeyBagBlockNumber = binary.LittleEndian.Uint64(data[1296:1304])
	csb.KeyBagNumberOfBlocks = binary.LittleEndian.Uint64(data[1304:1312])
	copy(csb.Unknown29[:], data[1312:1344])
	csb.Unknown30 = binary.LittleEndian.Uint64(data[1344:1352])
	csb.FusionMiddleTreeBlockNumber = binary.LittleEndian.Uint64(data[1352:1360])
	csb.FusionWriteBackCacheObjectIdentifier = binary.LittleEndian.Uint64(data[1360:1368])
	csb.Unknown33 = binary.LittleEndian.Uint64(data[1368:1376])
	csb.Unknown34 = binary.LittleEndian.Uint64(data[1376:1384])

	// Validate incompatible features
	if (csb.IncompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		return fmt.Errorf("unsupported format version 1")
	}

	// Validate block size
	if csb.BlockSize != 4096 {
		return fmt.Errorf("unsupported block size: %d (expected 4096)", csb.BlockSize)
	}

	// Validate checkpoint descriptor area
	if (csb.CheckpointDescriptorAreaNumberOfBlocks & 0x80000000) != 0 {
		return fmt.Errorf("unsupported checkpoint descriptor area number of blocks - MSB is set")
	}

	if csb.CheckpointDescriptorAreaBlockNumber == 0 {
		return fmt.Errorf("invalid checkpoint descriptor area block number: 0")
	}

	// Validate maximum number of volumes
	if csb.MaximumNumberOfVolumes > 100 {
		return fmt.Errorf("invalid maximum number of volumes: %d (max 100)", csb.MaximumNumberOfVolumes)
	}

	return nil
}

// GetContainerIdentifier retrieves the container identifier (UUID)
// Corresponds to libfsapfs_container_superblock_get_container_identifier
func (csb *ContainerSuperblock) GetContainerIdentifier() ([]byte, error) {
	if csb == nil {
		return nil, fmt.Errorf("invalid container superblock")
	}

	// Return a copy of the container identifier
	identifier := make([]byte, 16)
	copy(identifier, csb.ContainerIdentifier[:])
	return identifier, nil
}

// GetVolumeObjectIdentifiers returns the array of volume object identifiers
// Returns a slice of uint64 values (non-zero entries only)
func (csb *ContainerSuperblock) GetVolumeObjectIdentifiers() ([]uint64, error) {
	if csb == nil {
		return nil, fmt.Errorf("invalid container superblock")
	}

	volumeIDs := make([]uint64, 0, 100)

	// Parse the 800-byte array as 100 uint64 values
	for i := 0; i < 100; i++ {
		offset := i * 8
		volumeID := binary.LittleEndian.Uint64(csb.VolumeObjectIdentifiers[offset : offset+8])
		if volumeID != 0 {
			volumeIDs = append(volumeIDs, volumeID)
		}
	}

	return volumeIDs, nil
}
