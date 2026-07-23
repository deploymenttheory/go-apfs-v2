// The APFS object map definitions
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// ObjectMap represents the APFS object map structure
type ObjectMap struct {
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

	// The flags
	// Consists of 4 bytes
	Flags uint32

	// The number of snapshots
	// Consists of 4 bytes
	NumberOfSnapshots uint32

	// The B-tree type
	// Consists of 4 bytes
	BTreeType uint32

	// The snapshots B-tree type
	// Consists of 4 bytes
	SnapshotsBTreeType uint32

	// The B-tree block number
	// Consists of 8 bytes
	BTreeBlockNumber uint64

	// The snapshots B-tree block number
	// Consists of 8 bytes
	SnapshotsBTreeBlockNumber uint64

	// The most recent snapshot object identifier
	// Consists of 8 bytes
	MostRecentSnapshotIdentifier uint64

	// Unknown
	// Consists of 8 bytes
	Unknown2 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown3 uint64
}

// ObjectMapSize is the size of an object map in bytes
const ObjectMapSize = 104

// ObjectMapObjectType is the object type for an object map
const ObjectMapObjectType = 0x4000000b

// NewObjectMap creates a new object map
func NewObjectMap() (*ObjectMap, error) {
	return &ObjectMap{}, nil
}

// Free releases resources associated with the object map
func (om *ObjectMap) Free() error {
	if om == nil {
		return fmt.Errorf("invalid object map")
	}
	// Nothing to free in Go
	return nil
}

// ReadFileIOHandle reads the object map from a file at the specified offset
// Corresponds to libfsapfs_object_map_read_file_io_handle
func (om *ObjectMap) ReadFileIOHandle(fileHandle io.ReaderAt, fileOffset int64) error {
	if om == nil {
		return fmt.Errorf("invalid object map")
	}

	if IsVerbose() {
		Printf("%s: reading object map at offset: %d (0x%08x)\n",
			"ReadFileIOHandle", fileOffset, fileOffset)
	}

	// Read object map data (104 bytes)
	data := make([]byte, ObjectMapSize)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read object map data at offset %d (0x%08x): %w", fileOffset, fileOffset, err)
	}
	if n != ObjectMapSize {
		return fmt.Errorf("unable to read object map data at offset %d (0x%08x)", fileOffset, fileOffset)
	}

	if err := om.ReadData(data); err != nil {
		return fmt.Errorf("unable to read object map data: %w", err)
	}

	return nil
}

// ReadData reads the object map from binary data
// Corresponds to libfsapfs_object_map_read_data
func (om *ObjectMap) ReadData(data []byte) error {
	if om == nil {
		return fmt.Errorf("invalid object map")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ObjectMapSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if IsVerbose() {
		Printf("%s: object map data:\n", "ReadData")
		PrintData(data[:ObjectMapSize], true)
	}

	// Parse object type and subtype first for validation
	om.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	om.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if om.ObjectType != ObjectMapObjectType {
		return fmt.Errorf("invalid object type: 0x%08x", om.ObjectType)
	}

	// Validate object subtype
	if om.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", om.ObjectSubtype)
	}

	// Parse the fields we actually use (from C implementation)
	om.NumberOfSnapshots = binary.LittleEndian.Uint32(data[36:40])
	om.BTreeBlockNumber = binary.LittleEndian.Uint64(data[48:56])
	om.SnapshotsBTreeBlockNumber = binary.LittleEndian.Uint64(data[56:64])
	om.MostRecentSnapshotIdentifier = binary.LittleEndian.Uint64(data[64:72])

	// Parse remaining fields for completeness
	om.ObjectChecksum = binary.LittleEndian.Uint64(data[0:8])
	om.ObjectIdentifier = binary.LittleEndian.Uint64(data[8:16])
	om.ObjectTransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	om.Flags = binary.LittleEndian.Uint32(data[32:36])
	om.BTreeType = binary.LittleEndian.Uint32(data[40:44])
	om.SnapshotsBTreeType = binary.LittleEndian.Uint32(data[44:48])
	om.Unknown2 = binary.LittleEndian.Uint64(data[72:80])
	om.Unknown3 = binary.LittleEndian.Uint64(data[80:88])

	if IsVerbose() {
		Printf("%s: object checksum\t\t\t\t: 0x%08x\n", "ReadData", om.ObjectChecksum)
		Printf("%s: object identifier\t\t\t: %d\n", "ReadData", om.ObjectIdentifier)
		Printf("%s: object transaction identifier\t\t: %d\n", "ReadData", om.ObjectTransactionIdentifier)
		Printf("%s: object type\t\t\t\t: 0x%08x\n", "ReadData", om.ObjectType)
		Printf("%s: object subtype\t\t\t\t: 0x%08x\n", "ReadData", om.ObjectSubtype)
		Printf("%s: flags\t\t\t\t\t: 0x%08x\n", "ReadData", om.Flags)
		Printf("%s: number of snapshots\t\t\t: %d\n", "ReadData", om.NumberOfSnapshots)
		Printf("%s: B-tree type\t\t\t\t: 0x%08x\n", "ReadData", om.BTreeType)
		Printf("%s: snapshots B-tree type\t\t\t: 0x%08x\n", "ReadData", om.SnapshotsBTreeType)
		Printf("%s: B-tree block number\t\t\t: %d\n", "ReadData", om.BTreeBlockNumber)
		Printf("%s: snapshots B-tree block number\t\t: %d\n", "ReadData", om.SnapshotsBTreeBlockNumber)
		Printf("%s: most recent snapshot identifier\t\t: %d\n", "ReadData", om.MostRecentSnapshotIdentifier)
		Printf("%s: unknown2\t\t\t\t: %d\n", "ReadData", om.Unknown2)
		Printf("%s: unknown3\t\t\t\t: %d\n", "ReadData", om.Unknown3)
		Printf("\n")
	}

	return nil
}

// GetNumberOfSnapshots retrieves the number of snapshots
func (om *ObjectMap) GetNumberOfSnapshots() (uint32, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.NumberOfSnapshots, nil
}

// GetBTreeBlockNumber retrieves the B-tree block number
func (om *ObjectMap) GetBTreeBlockNumber() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.BTreeBlockNumber, nil
}

// GetSnapshotsBTreeBlockNumber retrieves the snapshots B-tree block number
func (om *ObjectMap) GetSnapshotsBTreeBlockNumber() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.SnapshotsBTreeBlockNumber, nil
}

// GetMostRecentSnapshotIdentifier retrieves the most recent snapshot identifier
func (om *ObjectMap) GetMostRecentSnapshotIdentifier() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.MostRecentSnapshotIdentifier, nil
}

// ObjectMapBTreeKey represents the APFS object map B-tree key structure
type ObjectMapBTreeKey struct {
	// The key object identifier
	// Consists of 8 bytes
	ObjectIdentifier uint64

	// The key object transaction identifier
	// Consists of 8 bytes
	ObjectTransactionIdentifier uint64
}

// ObjectMapBTreeValue represents the APFS object map B-tree value structure
type ObjectMapBTreeValue struct {
	// The object flags
	// Consists of 4 bytes
	ObjectFlags uint32

	// The object size
	// Consists of 4 bytes
	ObjectSize uint32

	// The object physical address
	// Consists of 8 bytes
	ObjectPhysicalAddress uint64
}
