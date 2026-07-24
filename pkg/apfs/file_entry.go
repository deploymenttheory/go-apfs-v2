package apfs

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// FileEntry represents an APFS file entry (file, directory, or special file)
// Corresponds to libfsapfs_file_entry_t / libfsapfs_internal_file_entry_t
type FileEntry struct {
	// IOHandle is the I/O handle
	IOHandle *IOHandle

	// FileHandle is the file I/O handle
	FileHandle io.ReaderAt

	// EncryptionContext is the encryption context
	EncryptionContext *EncryptionContext

	// FileSystemBTree is the file system B-tree
	FileSystemBTree *FileSystemBTree

	// Inode contains the inode metadata
	Inode *Inode

	// DirectoryRecord contains the directory record (may be nil for root)
	DirectoryRecord *DirectoryRecord

	// TransactionIdentifier is the transaction identifier
	TransactionIdentifier uint64

	// ExtendedAttributes is the array of extended attributes (lazily initialized)
	ExtendedAttributes []*AttributeValues

	// CompressedDataAttributeValues holds com.apple.decmpfs attribute
	CompressedDataAttributeValues *AttributeValues

	// CompressedDataHeader contains the compressed data header
	CompressedDataHeader *CompressedDataHeader

	// ResourceForkAttributeValues holds com.apple.ResourceFork attribute
	ResourceForkAttributeValues *AttributeValues

	// SymbolicLinkAttributeValues holds com.apple.fs.symlink attribute
	SymbolicLinkAttributeValues *AttributeValues

	// SymbolicLinkData contains the symbolic link target data
	SymbolicLinkData []byte

	// DirectoryEntries contains sub-directory entries (lazily initialized)
	DirectoryEntries []*DirectoryRecord

	// DataSize is the cached data size
	DataSize int64 // -1 indicates not yet determined

	// FileExtents contains the file extents (lazily initialized)
	FileExtents []*FileExtent

	// DataStream is the data stream (lazily initialized)
	DataStream *DataStream

	// currentOffset tracks the current read position
	currentOffset int64
}

// NewFileEntry creates a new file entry
// Corresponds to libfsapfs_file_entry_initialize
func NewFileEntry(
	ioHandle *IOHandle,
	fileHandle io.ReaderAt,
	encryptionContext *EncryptionContext,
	fileSystemBTree *FileSystemBTree,
	inode *Inode,
	directoryRecord *DirectoryRecord,
	transactionIdentifier uint64,
) (*FileEntry, error) {
	return &FileEntry{
		IOHandle:              ioHandle,
		FileHandle:            fileHandle,
		EncryptionContext:     encryptionContext,
		FileSystemBTree:       fileSystemBTree,
		Inode:                 inode,
		DirectoryRecord:       directoryRecord,
		TransactionIdentifier: transactionIdentifier,
		DataSize:              -1, // Not yet determined
		currentOffset:         0,
	}, nil
}

// GetIdentifier retrieves the identifier
// Corresponds to libfsapfs_file_entry_get_identifier
func (fe *FileEntry) GetIdentifier() (uint64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.Identifier, nil
}

// GetParentIdentifier retrieves the parent identifier
// Corresponds to libfsapfs_file_entry_get_parent_identifier
func (fe *FileEntry) GetParentIdentifier() (uint64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.ParentIdentifier, nil
}

// GetParentFileEntry retrieves the parent file entry
// Corresponds to libfsapfs_file_entry_get_parent_file_entry
func (fe *FileEntry) GetParentFileEntry() (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return nil, fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	parentIdentifier := fe.Inode.ParentIdentifier
	if parentIdentifier == 0 {
		return nil, nil // No parent (root)
	}

	// Get parent inode
	parentInode, err := fe.FileSystemBTree.GetInodeByIdentifier(
		fe.FileHandle,
		parentIdentifier,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve parent inode: %w", err)
	}

	// Get parent directory record (may be nil for root)
	// For now, we create the parent without a directory record
	return NewFileEntry(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		parentInode,
		nil, // No directory record for parent
		fe.TransactionIdentifier,
	)
}

// GetCreationTime retrieves the creation time
// Corresponds to libfsapfs_file_entry_get_creation_time
func (fe *FileEntry) GetCreationTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.CreationTime / 1000000000), nil
}

// GetModificationTime retrieves the modification time
// Corresponds to libfsapfs_file_entry_get_modification_time
func (fe *FileEntry) GetModificationTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.ModificationTime / 1000000000), nil
}

// GetAccessTime retrieves the access time
// Corresponds to libfsapfs_file_entry_get_access_time
func (fe *FileEntry) GetAccessTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.AccessTime / 1000000000), nil
}

// GetInodeChangeTime retrieves the inode change time
// Corresponds to libfsapfs_file_entry_get_inode_change_time
func (fe *FileEntry) GetInodeChangeTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.InodeChangeTime / 1000000000), nil
}

// GetAddedTime retrieves the added time (from directory record)
// Corresponds to libfsapfs_file_entry_get_added_time
func (fe *FileEntry) GetAddedTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryRecord == nil {
		return 0, fmt.Errorf("invalid directory record")
	}

	return fe.DirectoryRecord.GetAddedTime()
}

// GetOwnerIdentifier retrieves the owner identifier (UID)
// Corresponds to libfsapfs_file_entry_get_owner_identifier
func (fe *FileEntry) GetOwnerIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.OwnerIdentifier, nil
}

// GetGroupIdentifier retrieves the group identifier (GID)
// Corresponds to libfsapfs_file_entry_get_group_identifier
func (fe *FileEntry) GetGroupIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.GroupIdentifier, nil
}

// GetDeviceIdentifier retrieves the device identifier
// Corresponds to libfsapfs_file_entry_get_device_identifier
func (fe *FileEntry) GetDeviceIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.DeviceIdentifier, nil
}

// GetDeviceNumber retrieves the major and minor device numbers
// Corresponds to libfsapfs_file_entry_get_device_number
func (fe *FileEntry) GetDeviceNumber() (major uint32, minor uint32, err error) {
	if fe == nil {
		return 0, 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, 0, fmt.Errorf("invalid inode")
	}

	// Extract major and minor from device identifier
	// Major is upper 8 bits, minor is lower 24 bits
	major = (fe.Inode.DeviceIdentifier >> 24) & 0xFF
	minor = fe.Inode.DeviceIdentifier & 0xFFFFFF

	return major, minor, nil
}

// GetFileMode retrieves the file mode (permissions and type)
// Corresponds to libfsapfs_file_entry_get_file_mode
func (fe *FileEntry) GetFileMode() (uint16, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.FileMode, nil
}

// GetNumberOfLinks retrieves the number of hard links
// Corresponds to libfsapfs_file_entry_get_number_of_links
func (fe *FileEntry) GetNumberOfLinks() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.NumberOfLinks, nil
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded name
// Corresponds to libfsapfs_file_entry_get_utf8_name_size
func (fe *FileEntry) GetUTF8NameSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryRecord != nil {
		return fe.DirectoryRecord.GetUTF8NameSize()
	}

	// For root or entries without directory record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		return len(fe.Inode.Name) + 1, nil // +1 for null terminator
	}

	return 0, fmt.Errorf("no name available")
}

// GetUTF8Name retrieves the UTF-8 encoded name
// Corresponds to libfsapfs_file_entry_get_utf8_name
func (fe *FileEntry) GetUTF8Name() (string, error) {
	if fe == nil {
		return "", fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryRecord != nil {
		return fe.DirectoryRecord.GetUTF8Name()
	}

	// For root or entries without directory record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		return string(fe.Inode.Name), nil
	}

	return "", fmt.Errorf("no name available")
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded name
// Corresponds to libfsapfs_file_entry_get_utf16_name_size
func (fe *FileEntry) GetUTF16NameSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryRecord != nil {
		return fe.DirectoryRecord.GetUTF16NameSize()
	}

	// For root or entries without directory record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		// Count UTF-16 code units
		utf16Count := 0
		nameBytes := fe.Inode.Name
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
		return utf16Count + 1, nil // +1 for null terminator
	}

	return 0, fmt.Errorf("no name available")
}

// GetUTF16Name retrieves the UTF-16 encoded name
// Corresponds to libfsapfs_file_entry_get_utf16_name
func (fe *FileEntry) GetUTF16Name() ([]uint16, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryRecord != nil {
		return fe.DirectoryRecord.GetUTF16Name()
	}

	// For root or entries without directory record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		runes := []rune(string(fe.Inode.Name))
		return utf16.Encode(runes), nil
	}

	return nil, fmt.Errorf("no name available")
}

// getExtendedAttributes retrieves the extended attributes (lazy initialization)
// Corresponds to libfsapfs_internal_file_entry_get_extended_attributes
func (fe *FileEntry) getExtendedAttributes() error {
	if fe.ExtendedAttributes != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get extended attributes from the file system B-tree
	attributes, err := fe.FileSystemBTree.GetAttributes(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	fe.ExtendedAttributes = attributes

	// Look for special attributes
	for _, attr := range attributes {
		name := attr.GetName()
		switch name {
		case "com.apple.decmpfs":
			fe.CompressedDataAttributeValues = attr
		case "com.apple.ResourceFork":
			fe.ResourceForkAttributeValues = attr
		case "com.apple.fs.symlink":
			fe.SymbolicLinkAttributeValues = attr
		}
	}

	return nil
}

// GetNumberOfExtendedAttributes retrieves the number of extended attributes
// Corresponds to libfsapfs_file_entry_get_number_of_extended_attributes
func (fe *FileEntry) GetNumberOfExtendedAttributes() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return 0, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	return len(fe.ExtendedAttributes), nil
}

// GetExtendedAttributeByIndex retrieves an extended attribute by index
// Corresponds to libfsapfs_file_entry_get_extended_attribute_by_index
func (fe *FileEntry) GetExtendedAttributeByIndex(index int) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return nil, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	if index < 0 || index >= len(fe.ExtendedAttributes) {
		return nil, fmt.Errorf("invalid extended attribute index: %d", index)
	}

	// Create extended attribute from attribute values
	return NewExtendedAttribute(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		fe.ExtendedAttributes[index],
		fe.TransactionIdentifier,
	)
}

// HasExtendedAttributeByName checks if an extended attribute exists by name
// Corresponds to libfsapfs_file_entry_has_extended_attribute_by_utf8_name
func (fe *FileEntry) HasExtendedAttributeByName(name string) (bool, error) {
	if fe == nil {
		return false, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return false, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	for _, attr := range fe.ExtendedAttributes {
		if attr.GetName() == name {
			return true, nil
		}
	}

	return false, nil
}

// GetExtendedAttributeByName retrieves an extended attribute by name
// Corresponds to libfsapfs_file_entry_get_extended_attribute_by_utf8_name
func (fe *FileEntry) GetExtendedAttributeByName(name string) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return nil, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	for _, attr := range fe.ExtendedAttributes {
		if attr.GetName() == name {
			// Create extended attribute from attribute values
			return NewExtendedAttribute(
				fe.IOHandle,
				fe.FileHandle,
				fe.EncryptionContext,
				fe.FileSystemBTree,
				attr,
				fe.TransactionIdentifier,
			)
		}
	}

	return nil, fmt.Errorf("extended attribute not found: %s", name)
}

// HasExtendedAttributeByUTF16Name checks if an extended attribute exists by UTF-16 name
// Corresponds to libfsapfs_file_entry_has_extended_attribute_by_utf16_name
func (fe *FileEntry) HasExtendedAttributeByUTF16Name(utf16Name []uint16) (bool, error) {
	if fe == nil {
		return false, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.HasExtendedAttributeByName(name)
}

// GetExtendedAttributeByUTF16Name retrieves an extended attribute by UTF-16 name
// Corresponds to libfsapfs_file_entry_get_extended_attribute_by_utf16_name
func (fe *FileEntry) GetExtendedAttributeByUTF16Name(utf16Name []uint16) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.GetExtendedAttributeByName(name)
}

// getSymbolicLinkData retrieves the symbolic link data (lazy initialization)
// Corresponds to libfsapfs_internal_file_entry_get_symbolic_link_data
func (fe *FileEntry) getSymbolicLinkData() error {
	if fe.SymbolicLinkData != nil {
		return nil
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	if fe.SymbolicLinkAttributeValues == nil {
		return fmt.Errorf("no symbolic link attribute")
	}

	// Get data stream from symbolic link attribute
	dataStream, err := fe.SymbolicLinkAttributeValues.GetDataStream(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve symbolic link data stream: %w", err)
	}

	if dataStream == nil {
		return fmt.Errorf("no symbolic link data stream")
	}

	// Read symbolic link data
	size := dataStream.Size()
	fe.SymbolicLinkData = make([]byte, size)
	n, err := dataStream.ReadAt(fe.SymbolicLinkData, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read symbolic link data: %w", err)
	}
	if n != int(size) {
		return fmt.Errorf("unable to read symbolic link data: read %d bytes, expected %d", n, size)
	}

	return nil
}

// GetSymbolicLinkTargetSize retrieves the size of the symbolic link target
// Corresponds to libfsapfs_file_entry_get_utf8_symbolic_link_target_size
func (fe *FileEntry) GetSymbolicLinkTargetSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return 0, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	return len(fe.SymbolicLinkData) + 1, nil // +1 for null terminator
}

// GetSymbolicLinkTarget retrieves the symbolic link target
// Corresponds to libfsapfs_file_entry_get_utf8_symbolic_link_target
func (fe *FileEntry) GetSymbolicLinkTarget() (string, error) {
	if fe == nil {
		return "", fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return "", fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	// Trim trailing null bytes and spaces to prevent "invalid argument" errors
	// when creating symlinks on the filesystem
	target := string(fe.SymbolicLinkData)
	target = strings.TrimRight(target, "\x00 \t\r\n")

	return target, nil
}

// GetSymbolicLinkTargetUTF16Size retrieves the size of the UTF-16 encoded symbolic link target
// Corresponds to libfsapfs_file_entry_get_utf16_symbolic_link_target_size
func (fe *FileEntry) GetSymbolicLinkTargetUTF16Size() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return 0, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	// Count UTF-16 code units
	utf16Count := 0
	linkBytes := fe.SymbolicLinkData
	for len(linkBytes) > 0 {
		r, size := utf8.DecodeRune(linkBytes)
		if r == utf8.RuneError {
			return 0, fmt.Errorf("invalid UTF-8 sequence")
		}
		if r <= 0xFFFF {
			utf16Count++
		} else {
			utf16Count += 2 // Surrogate pair
		}
		linkBytes = linkBytes[size:]
	}

	return utf16Count + 1, nil // +1 for null terminator
}

// GetSymbolicLinkTargetUTF16 retrieves the UTF-16 encoded symbolic link target
// Corresponds to libfsapfs_file_entry_get_utf16_symbolic_link_target
func (fe *FileEntry) GetSymbolicLinkTargetUTF16() ([]uint16, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return nil, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	runes := []rune(string(fe.SymbolicLinkData))
	return utf16.Encode(runes), nil
}

// getDirectoryEntries retrieves the directory entries (lazy initialization)
// Corresponds to libfsapfs_internal_file_entry_get_directory_entries
func (fe *FileEntry) getDirectoryEntries() error {
	if fe.DirectoryEntries != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get directory entries from the file system B-tree
	entries, err := fe.FileSystemBTree.GetDirectoryEntries(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	fe.DirectoryEntries = entries
	return nil
}

// GetNumberOfSubFileEntries retrieves the number of sub-file entries (directory children)
// Corresponds to libfsapfs_file_entry_get_number_of_sub_file_entries
func (fe *FileEntry) GetNumberOfSubFileEntries() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return 0, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	return len(fe.DirectoryEntries), nil
}

// GetSubFileEntryByIndex retrieves a sub-file entry by index
// Corresponds to libfsapfs_file_entry_get_sub_file_entry_by_index
func (fe *FileEntry) GetSubFileEntryByIndex(index int) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return nil, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	if index < 0 || index >= len(fe.DirectoryEntries) {
		return nil, fmt.Errorf("invalid sub-file entry index: %d", index)
	}

	directoryRecord := fe.DirectoryEntries[index]

	// Get inode for this directory entry
	inode, err := fe.FileSystemBTree.GetInodeByIdentifier(
		fe.FileHandle,
		directoryRecord.Identifier,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve inode for identifier %d: %w", directoryRecord.Identifier, err)
	}

	// Create file entry
	return NewFileEntry(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		inode,
		directoryRecord,
		fe.TransactionIdentifier,
	)
}

// GetSubFileEntryByName retrieves a sub-file entry by name
// Corresponds to libfsapfs_file_entry_get_sub_file_entry_by_utf8_name
func (fe *FileEntry) GetSubFileEntryByName(name string) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return nil, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	for _, directoryRecord := range fe.DirectoryEntries {
		entryName, err := directoryRecord.GetUTF8Name()
		if err != nil {
			continue
		}

		if entryName == name {
			// Get inode for this directory entry
			inode, err := fe.FileSystemBTree.GetInodeByIdentifier(
				fe.FileHandle,
				directoryRecord.Identifier,
				fe.TransactionIdentifier,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve inode for identifier %d: %w", directoryRecord.Identifier, err)
			}

			// Create file entry
			return NewFileEntry(
				fe.IOHandle,
				fe.FileHandle,
				fe.EncryptionContext,
				fe.FileSystemBTree,
				inode,
				directoryRecord,
				fe.TransactionIdentifier,
			)
		}
	}

	return nil, fmt.Errorf("sub-file entry not found: %s", name)
}

// GetSubFileEntryByUTF16Name retrieves a sub-file entry by UTF-16 name
// Corresponds to libfsapfs_file_entry_get_sub_file_entry_by_utf16_name
func (fe *FileEntry) GetSubFileEntryByUTF16Name(utf16Name []uint16) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.GetSubFileEntryByName(name)
}

// getFileExtents retrieves the file extents (lazy initialization)
// Corresponds to libfsapfs_internal_file_entry_get_file_extents
func (fe *FileEntry) getFileExtents() error {
	if fe.FileExtents != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get file extents from the file system B-tree
	// First try using the inode identifier (most common case)
	extents, err := fe.FileSystemBTree.GetFileExtents(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.TransactionIdentifier,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	// If no extents found and DataStreamIdentifier is set, try using that
	// This handles files where data is stored via a separate data stream
	if len(extents) == 0 && fe.Inode.DataStreamIdentifier != 0 {
		extents, err = fe.FileSystemBTree.GetFileExtents(
			fe.FileHandle,
			fe.Inode.DataStreamIdentifier,
			fe.TransactionIdentifier,
		)
		if err != nil {
			return fmt.Errorf("unable to retrieve file extents via data stream ID: %w", err)
		}
	}

	fe.FileExtents = extents
	return nil
}

// internalCompressionMethod maps a raw com.apple.decmpfs type to the
// internal compression method codes used by CompressedDataHandle:
// decmpfs 3/4 = zlib (attr/rsrc), 5 = sparse, 7/8 = LZVN, 11/12 = LZFSE.
// The attr-vs-rsrc distinction is handled by where the data is read from,
// not by the method code.
func internalCompressionMethod(decmpfsType uint32) (int, error) {
	switch decmpfsType {
	case 3, 4:
		return CompressionMethodDeflate, nil
	case 5:
		return CompressionMethodUnknown5, nil
	case 7, 8:
		return CompressionMethodLZVN, nil
	case 11, 12:
		return 0, fmt.Errorf("decmpfs LZFSE compression (type %d) is not supported yet", decmpfsType)
	default:
		return 0, fmt.Errorf("unsupported decmpfs compression type: %d", decmpfsType)
	}
}

// getDataStream retrieves the data stream (lazy initialization)
// Corresponds to libfsapfs_internal_file_entry_get_data_stream
func (fe *FileEntry) getDataStream() error {
	if fe.DataStream != nil {
		return nil
	}

	// Check for compressed data attribute first
	// Files with com.apple.decmpfs may not have file extents
	if err := fe.getExtendedAttributes(); err == nil {

		if fe.CompressedDataAttributeValues != nil {

			// Parse compressed data header from attribute
			if len(fe.CompressedDataAttributeValues.ValueData) >= 16 {
				header, err := ParseCompressedDataHeader(fe.CompressedDataAttributeValues.ValueData)
				if err != nil {
					return fmt.Errorf("unable to parse compressed data header: %w", err)
				}

				if header != nil {
					fe.CompressedDataHeader = header

					// Map the raw decmpfs type to the internal method code
					method, err := internalCompressionMethod(header.CompressionMethod)
					if err != nil {
						return err
					}

					// Check if data is embedded in the attribute (inline compression)
					if len(fe.CompressedDataAttributeValues.ValueData) > 16 {
						// Data is embedded in the attribute after the header
						compressedData := fe.CompressedDataAttributeValues.ValueData[16:]

						// Create data stream from embedded compressed data
						compressedDataStream, err := NewDataStreamFromData(compressedData)
						if err != nil {
							return fmt.Errorf("unable to create compressed data stream from embedded data: %w", err)
						}

						// Create decompressed data stream
						dataStream, err := NewDataStreamFromCompressedDataStream(
							compressedDataStream,
							header.UncompressedDataSize,
							method,
						)
						if err != nil {
							return fmt.Errorf("unable to create decompressed data stream: %w", err)
						}

						if cdReader, ok := dataStream.readerAt.(*compressedDataReader); ok {
							cdReader.SetFileHandle(fe.FileHandle)
						}

						fe.DataStream = dataStream
						return nil
					} else {
						// Compressed data is stored in resource fork
						if fe.ResourceForkAttributeValues != nil {
							resourceForkStream, err := fe.ResourceForkAttributeValues.GetDataStream(
								fe.IOHandle,
								fe.FileHandle,
								fe.EncryptionContext,
								fe.FileSystemBTree,
								fe.TransactionIdentifier,
							)
							if err != nil {
								return fmt.Errorf("unable to get resource fork data stream: %w", err)
							}

							if resourceForkStream != nil {
								// Create decompressed data stream from resource fork
								dataStream, err := NewDataStreamFromCompressedDataStream(
									resourceForkStream,
									header.UncompressedDataSize,
									method,
								)
								if err != nil {
									return fmt.Errorf("unable to create decompressed data stream from resource fork: %w", err)
								}

								if cdReader, ok := dataStream.readerAt.(*compressedDataReader); ok {
									cdReader.SetFileHandle(fe.FileHandle)
								}

								fe.DataStream = dataStream
								return nil
							}
						}
					}
				}
			}
		} else {
		}
	} else {
	}

	// Try to get file extents for normal files
	if err := fe.getFileExtents(); err != nil {
		return fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	if len(fe.FileExtents) == 0 {
		// Check if this is a zero-length file
		size, err := fe.GetDataSize()
		if err == nil && size == 0 {
			// Create empty data stream for zero-length files
			dataStream, err := NewDataStreamFromData([]byte{})
			if err != nil {
				return fmt.Errorf("unable to create empty data stream: %w", err)
			}
			fe.DataStream = dataStream
			return nil
		}

		// If DataStreamIdentifier is 0, the data might be inline in the inode
		if fe.Inode.DataStreamIdentifier == 0 {
			// TODO: Check if inode has inline data
			// For now, this is an unsupported case
		}

		return fmt.Errorf("no file extents and no compressed data")
	}

	// Get data size
	size, err := fe.GetDataSize()
	if err != nil {
		return fmt.Errorf("unable to get data size: %w", err)
	}

	// Create data stream from file extents
	dataStream, err := NewDataStreamFromFileExtents(
		fe.IOHandle,
		fe.EncryptionContext,
		fe.FileExtents,
		uint64(size),
		false, // Not sparse
	)
	if err != nil {
		return fmt.Errorf("unable to create data stream from file extents: %w", err)
	}

	// Set the file handle for the data stream reader
	if dbReader, ok := dataStream.readerAt.(*dataBlockReader); ok {
		dbReader.SetFileHandle(fe.FileHandle)
	}

	fe.DataStream = dataStream
	return nil
}

// Read reads data at the current offset into a buffer
// Corresponds to libfsapfs_file_entry_read_buffer
func (fe *FileEntry) Read(buffer []byte) (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure data stream is initialized
	if err := fe.getDataStream(); err != nil {
		return 0, fmt.Errorf("unable to determine data stream: %w", err)
	}

	// Read from data stream at current offset
	n, err := fe.DataStream.ReadAt(buffer, fe.currentOffset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer from data stream: %w", err)
	}

	// Update current offset
	fe.currentOffset += int64(n)

	return n, err
}

// ReadAt reads data at a specific offset
// Corresponds to libfsapfs_file_entry_read_buffer_at_offset
func (fe *FileEntry) ReadAt(buffer []byte, offset int64) (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure data stream is initialized
	if err := fe.getDataStream(); err != nil {
		return 0, fmt.Errorf("unable to determine data stream: %w", err)
	}

	// Read from data stream at specified offset
	n, err := fe.DataStream.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer at offset from data stream: %w", err)
	}

	return n, err
}

// Seek seeks to a certain offset
// Corresponds to libfsapfs_file_entry_seek_offset
func (fe *FileEntry) Seek(offset int64, whence int) (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Get the data size for calculations
	size, err := fe.GetDataSize()
	if err != nil {
		return 0, fmt.Errorf("unable to get data size: %w", err)
	}

	// Calculate new offset based on whence
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = fe.currentOffset + offset
	case io.SeekEnd:
		newOffset = size + offset
	default:
		return 0, fmt.Errorf("invalid whence value: %d", whence)
	}

	// Validate new offset
	if newOffset < 0 {
		return 0, fmt.Errorf("invalid offset value out of bounds")
	}

	fe.currentOffset = newOffset
	return newOffset, nil
}

// GetOffset retrieves the current offset
// Corresponds to libfsapfs_file_entry_get_offset
func (fe *FileEntry) GetOffset() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	return fe.currentOffset, nil
}

// GetDataSize retrieves the data size (lazy calculation)
// Corresponds to libfsapfs_internal_file_entry_get_data_size
func (fe *FileEntry) GetDataSize() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Return cached value if available
	if fe.DataSize != -1 {
		return fe.DataSize, nil
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// decmpfs-compressed files record their uncompressed size in the
	// com.apple.decmpfs header; their inode data stream is empty
	if fe.Inode.DataStreamSize == 0 {
		if err := fe.getExtendedAttributes(); err == nil && fe.CompressedDataAttributeValues != nil {
			if len(fe.CompressedDataAttributeValues.ValueData) >= 16 {
				if header, err := ParseCompressedDataHeader(fe.CompressedDataAttributeValues.ValueData); err == nil && header != nil {
					fe.DataSize = int64(header.UncompressedDataSize)
					return fe.DataSize, nil
				}
			}
		}
	}

	// Use data stream size from inode
	fe.DataSize = int64(fe.Inode.DataStreamSize)
	return fe.DataSize, nil
}

// GetSize retrieves the size
// Corresponds to libfsapfs_file_entry_get_size
func (fe *FileEntry) GetSize() (uint64, error) {
	size, err := fe.GetDataSize()
	if err != nil {
		return 0, err
	}
	return uint64(size), nil
}

// GetNumberOfExtents retrieves the number of extents
// Corresponds to libfsapfs_file_entry_get_number_of_extents
func (fe *FileEntry) GetNumberOfExtents() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure file extents are loaded
	if err := fe.getFileExtents(); err != nil {
		return 0, fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	return len(fe.FileExtents), nil
}

// GetExtentByIndex retrieves an extent by index
// Corresponds to libfsapfs_file_entry_get_extent_by_index
func (fe *FileEntry) GetExtentByIndex(index int) (offset int64, size uint64, flags uint32, err error) {
	if fe == nil {
		return 0, 0, 0, fmt.Errorf("invalid file entry")
	}

	// Ensure file extents are loaded
	if err := fe.getFileExtents(); err != nil {
		return 0, 0, 0, fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	if index < 0 || index >= len(fe.FileExtents) {
		return 0, 0, 0, fmt.Errorf("invalid extent index: %d", index)
	}

	extent := fe.FileExtents[index]

	// Calculate physical offset (physical block number * block size)
	physicalOffset := int64(extent.PhysicalBlockNumber * 4096)

	// Data size is already in bytes
	dataSize := extent.DataSize

	// Flags currently return 0 (not stored separately in FileExtent)
	extentFlags := uint32(0)

	return physicalOffset, dataSize, extentFlags, nil
}
