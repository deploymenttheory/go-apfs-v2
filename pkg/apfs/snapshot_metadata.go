package apfs

// SnapshotMetadataBTreeKey represents the APFS snapshot metadata B-tree key structure
type SnapshotMetadataBTreeKey struct {
	// The key object identifier
	// Consists of 8 bytes
	ObjectIdentifier uint64
}

// SnapshotMetadataBTreeValue represents the APFS snapshot metadata B-tree value structure
type SnapshotMetadataBTreeValue struct {
	// The extent-reference tree block number
	// Consists of 8 bytes
	ExtentReferenceTreeBlockNumber uint64

	// The volume superblock block number
	// Consists of 8 bytes
	VolumeSuperblockBlockNumber uint64

	// The creation date and time
	// Consists of 8 bytes
	CreationTime uint64

	// The change date and time
	// Consists of 8 bytes
	ChangeTime uint64

	// Unknown
	// Consists of 8 bytes
	Unknown1 uint64

	// The extent-reference tree object type
	// Consists of 4 bytes
	ExtentReferenceTreeObjectType uint32

	// The flags
	// Consists of 4 bytes
	Flags uint32

	// The name size
	// Consists of 2 bytes
	NameSize uint16

	// The name string
	// Contains an UTF-8 string with end-of-string character
	// Variable length field - not included in struct
}
