// The APFS file system definitions
package apfs

// FileSystemBTreeKeyCommon represents the APFS file system B-tree key common structure
type FileSystemBTreeKeyCommon struct {
	// The file system identifier (FSID) and data type
	// Consists of 8 bytes
	FileSystemIdentifier uint64
}

// FileSystemBTreeKeyDirectoryRecord represents the APFS file system B-tree key directory record structure
type FileSystemBTreeKeyDirectoryRecord struct {
	// The file system identifier (FSID) and data type
	// Consists of 8 bytes
	FileSystemIdentifier uint64

	// The name size
	// Consists of 2 bytes
	NameSize uint16

	// The name string
	// Contains an UTF-8 string with end-of-string character
	// Variable length field - not included in struct
}

// FileSystemBTreeKeyDirectoryRecordWithHash represents the APFS file system B-tree key directory record with hash structure
type FileSystemBTreeKeyDirectoryRecordWithHash struct {
	// The file system identifier (FSID) and data type
	// Consists of 8 bytes
	FileSystemIdentifier uint64

	// The name size and hash
	// Consists of 4 bytes
	NameSizeAndHash uint32

	// The name string
	// Contains an UTF-8 string with end-of-string character
	// Variable length field - not included in struct
}

// FileSystemBTreeKeyExtendedAttribute represents the APFS file system B-tree key extended attribute structure
type FileSystemBTreeKeyExtendedAttribute struct {
	// The file system identifier (FSID) and data type
	// Consists of 8 bytes
	FileSystemIdentifier uint64

	// The name size
	// Consists of 2 bytes
	NameSize uint16

	// The name string
	// Contains an UTF-8 string with end-of-string character
	// Variable length field - not included in struct
}

// FileSystemBTreeKeyFileExtent represents the APFS file system B-tree key file extent structure
type FileSystemBTreeKeyFileExtent struct {
	// The file system identifier (FSID) and data type
	// Consists of 8 bytes
	FileSystemIdentifier uint64

	// The logical address
	// Consists of 8 bytes
	LogicalAddress uint64
}

// FileSystemBTreeValueDirectoryRecord represents the APFS file system B-tree value directory record structure
type FileSystemBTreeValueDirectoryRecord struct {
	// The file system identifier (FSID)
	// Consists of 8 bytes
	FileSystemIdentifier uint64

	// The added date and time
	// Consists of 8 bytes
	AddedTime uint64

	// The directory entry flags
	// Consists of 2 bytes
	DirectoryEntryFlags uint16

	// Extended fields
	// Variable length fields - not included in struct
}

// FileSystemBTreeValueExtendedAttribute represents the APFS file system B-tree value extended attribute structure
type FileSystemBTreeValueExtendedAttribute struct {
	// The flags
	// Consists of 2 bytes
	Flags uint16

	// The data size
	// Consists of 2 bytes
	DataSize uint16

	// The data
	// Variable length field - not included in struct
}

// FileSystemExtendedAttributeDataStream represents the APFS file system extended attribute data stream structure
type FileSystemExtendedAttributeDataStream struct {
	// The data stream identifier
	// Consists of 8 bytes
	DataStreamIdentifier uint64

	// The used size
	// Consists of 8 bytes
	UsedSize uint64

	// The allocated size
	// Consists of 8 bytes
	AllocatedSize uint64

	// The encryption identifier
	// Consists of 8 bytes
	EncryptionIdentifier uint64

	// The number of bytes written
	// Consists of 8 bytes
	NumberOfBytesWritten uint64

	// The number of bytes read
	// Consists of 8 bytes
	NumberOfBytesRead uint64
}

// FileSystemBTreeValueFileExtent represents the APFS file system B-tree value file extent structure
type FileSystemBTreeValueFileExtent struct {
	// The data size and flags
	// Consists of 8 bytes
	DataSizeAndFlags uint64

	// The physical block number
	// Consists of 8 bytes
	PhysicalBlockNumber uint64

	// The encryption identifier
	// Consists of 8 bytes
	EncryptionIdentifier uint64
}

// FileSystemBTreeValueInode represents the APFS file system B-tree value inode structure
type FileSystemBTreeValueInode struct {
	// The parent file system identifier (FSID)
	// Consists of 8 bytes
	ParentIdentifier uint64

	// The data stream file system identifier (FSID)
	// Consists of 8 bytes
	DataStreamIdentifier uint64

	// The modification date and time
	// Consists of 8 bytes
	ModificationTime uint64

	// The creation date and time
	// Consists of 8 bytes
	CreationTime uint64

	// The inode change date and time
	// Consists of 8 bytes
	InodeChangeTime uint64

	// The access date and time
	// Consists of 8 bytes
	AccessTime uint64

	// The inode flags
	// Consists of 8 bytes
	InodeFlags uint64

	// The number of (hard) links (or children of a directory)
	// Consists of 4 bytes
	NumberOfLinks uint32

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32

	// Unknown
	// Consists of 4 bytes
	Unknown2 uint32

	// The BSD flags
	// Consists of 4 bytes
	BSDFlags uint32

	// The owner user identifier (UID)
	// Consists of 4 bytes
	OwnerIdentifier uint32

	// The group identifier (GID)
	// Consists of 4 bytes
	GroupIdentifier uint32

	// The file mode
	// Consists of 2 bytes
	FileMode uint16

	// Unknown
	// Consists of 2 bytes
	Unknown3 uint16

	// Unknown
	// Consists of 8 bytes
	Unknown4 uint64

	// Extended fields
	// Variable length fields - not included in struct
}

// FileSystemDataStreamAttribute represents the APFS file system data stream attribute structure
type FileSystemDataStreamAttribute struct {
	// The used size
	// Consists of 8 bytes
	UsedSize uint64

	// The allocated size
	// Consists of 8 bytes
	AllocatedSize uint64

	// The encryption identifier
	// Consists of 8 bytes
	EncryptionIdentifier uint64

	// The number of bytes written
	// Consists of 8 bytes
	NumberOfBytesWritten uint64

	// The number of bytes read
	// Consists of 8 bytes
	NumberOfBytesRead uint64
}
