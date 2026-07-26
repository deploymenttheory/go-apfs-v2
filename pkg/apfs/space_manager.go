package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// SpaceManager represents the APFS space manager structure
type SpaceManager struct {
	// The object checksum
	// Consists of 8 bytes
	Checksum uint64

	// The object identifier
	// Consists of 8 bytes
	OID uint64

	// The object transaction identifier
	// Consists of 8 bytes
	XID uint64

	// The object type
	// Consists of 4 bytes
	ObjectType uint32

	// The object subtype
	// Consists of 4 bytes
	ObjectSubtype uint32

	// The block size
	// Consists of 4 bytes
	BlockSize uint32

	// The number of blocks per chunk
	// Consists of 4 bytes
	BlocksPerChunk uint32

	// The number of chunks per CIB
	// Consists of 4 bytes
	ChunksPerCIB uint32

	// The number of CIBs per CAB
	// Consists of 4 bytes
	CIBsPerCAB uint32

	// The number of blocks of the main device
	// Consists of 8 bytes
	MainDeviceNumberOfBlocks uint64

	// The number of chunks of the main device
	// Consists of 8 bytes
	MainDeviceNumberOfChunks uint64

	// The number of CIBs of the main device
	// Consists of 4 bytes
	MainDeviceNumberOfCIBs uint32

	// The number of CABs of the main device
	// Consists of 4 bytes
	MainDeviceNumberOfCABs uint32

	// The number of unused blocks of the main device
	// Consists of 8 bytes
	MainDeviceNumberOfUnusedBlocks uint64

	// The offset of the main device
	// Consists of 4 bytes
	MainDeviceOffset uint32

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32

	// Unknown
	// Consists of 8 bytes
	Unknown2 uint64

	// The number of blocks of the tier2 device
	// Consists of 8 bytes
	Tier2DeviceNumberOfBlocks uint64

	// The number of chunks of the tier2 device
	// Consists of 8 bytes
	Tier2DeviceNumberOfChunks uint64

	// The number of CIBs of the tier2 device
	// Consists of 4 bytes
	Tier2DeviceNumberOfCIBs uint32

	// The number of CABs of the tier2 device
	// Consists of 4 bytes
	Tier2DeviceNumberOfCABs uint32

	// The number of unused blocks of the tier2 device
	// Consists of 8 bytes
	Tier2DeviceNumberOfUnusedBlocks uint64

	// The offset of the tier2 device
	// Consists of 4 bytes
	Tier2DeviceOffset uint32

	// Unknown
	// Consists of 4 bytes
	Unknown8 uint32

	// Unknown
	// Consists of 8 bytes
	Unknown9 uint64

	// The flags
	// Consists of 4 bytes
	Flags uint32

	// Unknown
	// Consists of 4 bytes
	Unknown11 uint32

	// Unknown
	// Consists of 8 bytes
	Unknown12 uint64

	// Unknown
	// Consists of 4 bytes
	Unknown13 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown14 uint32

	// Unknown
	// Consists of 8 bytes
	Unknown15 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown16 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown17 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown18 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown19 uint64

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

	// Unknown
	// Consists of 8 bytes
	Unknown30 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown31 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown32 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown33 uint64

	// Unknown
	// Consists of 2 bytes
	Unknown34 uint16

	// Unknown
	// Consists of 2 bytes
	Unknown35 uint16

	// Unknown
	// Consists of 4 bytes
	Unknown36 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown37 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown38 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown39 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown40 uint32

	// The main allocation zones
	// Consists of 8 x 72 bytes
	Unknown41 [576]byte

	// The tier2 allocation zones
	// Consists of 8 x 72 bytes
	Unknown42 [576]byte
}

// Space manager methods

// NewSpaceManager creates a new space manager
func NewSpaceManager() *SpaceManager {
	return &SpaceManager{}
}

// ReadFrom reads the space manager from a file at the specified offset
func (sm *SpaceManager) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if sm == nil {
		return fmt.Errorf("invalid space manager")
	}

	if DebugOutput {
		fmt.Printf("Reading space manager at offset: %d (0x%08x)\n", fileOffset, fileOffset)
	}

	// Read 4096 bytes (size of space manager)
	data := make([]byte, 4096)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read space manager data at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read space manager data at offset %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the data
	if err := sm.ReadData(data); err != nil {
		return fmt.Errorf("unable to read space manager data: %w", err)
	}

	return nil
}

// ReadData reads the space manager from binary data
func (sm *SpaceManager) ReadData(data []byte) error {
	if sm == nil {
		return fmt.Errorf("invalid space manager")
	}
	if data == nil {
		return fmt.Errorf("invalid data")
	}
	if len(data) < 200 {
		return fmt.Errorf("invalid data size: %d bytes (minimum 200)", len(data))
	}

	// Parse object header (first 32 bytes)
	sm.Checksum = binary.LittleEndian.Uint64(data[0:8])
	sm.OID = binary.LittleEndian.Uint64(data[8:16])
	sm.XID = binary.LittleEndian.Uint64(data[16:24])
	sm.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	sm.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type (must be 0x80000005)
	if sm.ObjectType != 0x80000005 {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x80000005)", sm.ObjectType)
	}

	// Validate object subtype (must be 0)
	if sm.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x (expected 0x00000000)", sm.ObjectSubtype)
	}

	// Parse space manager fields (offset 32)
	sm.BlockSize = binary.LittleEndian.Uint32(data[32:36])
	sm.BlocksPerChunk = binary.LittleEndian.Uint32(data[36:40])
	sm.ChunksPerCIB = binary.LittleEndian.Uint32(data[40:44])
	sm.CIBsPerCAB = binary.LittleEndian.Uint32(data[44:48])

	// Parse main device information (offset 48)
	sm.MainDeviceNumberOfBlocks = binary.LittleEndian.Uint64(data[48:56])
	sm.MainDeviceNumberOfChunks = binary.LittleEndian.Uint64(data[56:64])
	sm.MainDeviceNumberOfCIBs = binary.LittleEndian.Uint32(data[64:68])
	sm.MainDeviceNumberOfCABs = binary.LittleEndian.Uint32(data[68:72])
	sm.MainDeviceNumberOfUnusedBlocks = binary.LittleEndian.Uint64(data[72:80])
	sm.MainDeviceOffset = binary.LittleEndian.Uint32(data[80:84])
	sm.Unknown1 = binary.LittleEndian.Uint32(data[84:88])
	sm.Unknown2 = binary.LittleEndian.Uint64(data[88:96])

	// Parse tier2 device information (offset 96)
	sm.Tier2DeviceNumberOfBlocks = binary.LittleEndian.Uint64(data[96:104])
	sm.Tier2DeviceNumberOfChunks = binary.LittleEndian.Uint64(data[104:112])
	sm.Tier2DeviceNumberOfCIBs = binary.LittleEndian.Uint32(data[112:116])
	sm.Tier2DeviceNumberOfCABs = binary.LittleEndian.Uint32(data[116:120])
	sm.Tier2DeviceNumberOfUnusedBlocks = binary.LittleEndian.Uint64(data[120:128])
	sm.Tier2DeviceOffset = binary.LittleEndian.Uint32(data[128:132])
	sm.Unknown8 = binary.LittleEndian.Uint32(data[132:136])
	sm.Unknown9 = binary.LittleEndian.Uint64(data[136:144])

	// Parse flags and unknown fields (offset 144)
	sm.Flags = binary.LittleEndian.Uint32(data[144:148])
	sm.Unknown11 = binary.LittleEndian.Uint32(data[148:152])
	sm.Unknown12 = binary.LittleEndian.Uint64(data[152:160])
	sm.Unknown13 = binary.LittleEndian.Uint32(data[160:164])
	sm.Unknown14 = binary.LittleEndian.Uint32(data[164:168])
	sm.Unknown15 = binary.LittleEndian.Uint64(data[168:176])
	sm.Unknown16 = binary.LittleEndian.Uint64(data[176:184])
	sm.Unknown17 = binary.LittleEndian.Uint64(data[184:192])
	sm.Unknown18 = binary.LittleEndian.Uint64(data[192:200])

	// Parse free queue fields (offset 200)
	sm.Unknown19 = binary.LittleEndian.Uint64(data[200:208])
	sm.Unknown20 = binary.LittleEndian.Uint64(data[208:216])
	sm.Unknown21 = binary.LittleEndian.Uint64(data[216:224])
	sm.Unknown22 = binary.LittleEndian.Uint64(data[224:232])
	sm.Unknown23 = binary.LittleEndian.Uint64(data[232:240])

	// Parse main free queue fields (offset 240)
	sm.Unknown24 = binary.LittleEndian.Uint64(data[240:248])
	sm.Unknown25 = binary.LittleEndian.Uint64(data[248:256])
	sm.Unknown26 = binary.LittleEndian.Uint64(data[256:264])
	sm.Unknown27 = binary.LittleEndian.Uint64(data[264:272])
	sm.Unknown28 = binary.LittleEndian.Uint64(data[272:280])

	// Parse tier2 free queue fields (offset 280)
	sm.Unknown29 = binary.LittleEndian.Uint64(data[280:288])
	sm.Unknown30 = binary.LittleEndian.Uint64(data[288:296])
	sm.Unknown31 = binary.LittleEndian.Uint64(data[296:304])
	sm.Unknown32 = binary.LittleEndian.Uint64(data[304:312])
	sm.Unknown33 = binary.LittleEndian.Uint64(data[312:320])

	// Parse remaining unknown fields (offset 320)
	sm.Unknown34 = binary.LittleEndian.Uint16(data[320:322])
	sm.Unknown35 = binary.LittleEndian.Uint16(data[322:324])
	sm.Unknown36 = binary.LittleEndian.Uint32(data[324:328])
	sm.Unknown37 = binary.LittleEndian.Uint32(data[328:332])
	sm.Unknown38 = binary.LittleEndian.Uint32(data[332:336])
	sm.Unknown39 = binary.LittleEndian.Uint32(data[336:340])
	sm.Unknown40 = binary.LittleEndian.Uint32(data[340:344])

	// Parse allocation zones (offset 344)
	copy(sm.Unknown41[:], data[344:920])  // Main allocation zones (576 bytes)
	copy(sm.Unknown42[:], data[920:1496]) // Tier2 allocation zones (576 bytes)

	// Note: Additional space manager data structures at main_device_offset and tier2_device_offset
	//
	// The space manager header contains offsets (MainDeviceOffset at 0x128 and Tier2DeviceOffset at 0x158)
	// that point to additional data structures. The format and purpose of these structures is currently
	// unknown and not documented in any public APFS specification.
	//
	// The original C library (libfsapfs) also does not implement reading these structures:
	//   From SpaceManager.c lines 809-810:
	//     /* TODO read value at main device offset */
	//     /* TODO read value at tier2 device offset */
	//
	// These structures are likely related to:
	//   - Additional allocation bitmaps for Fusion drives (main SSD + tier2 HDD)
	//   - Extended metadata for tiered storage management
	//   - Free space tracking for multi-device volumes
	//
	// Implementation would require:
	//   1. Reverse engineering the data structures at these offsets
	//   2. Understanding their relationship to allocation zones
	//   3. Determining whether offsets are block numbers or byte offsets
	//   4. Testing with real Fusion drive APFS volumes
	//
	// Current status: Intentionally not implemented, matching reference library behavior.
	// This does not affect reading of standard (non-Fusion) APFS volumes.

	return nil
}
