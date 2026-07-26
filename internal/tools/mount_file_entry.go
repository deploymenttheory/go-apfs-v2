// Mount file entry abstraction for FUSE operations
package tools

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// MountFileEntry represents a file entry in the mounted filesystem
// This wraps apfs.FileEntry and provides additional mount-specific functionality
type MountFileEntry struct {
	FileSystem *MountFileSystem
	name       string
	FileEntry  *apfs.FileEntry
}

// NewMountFileEntry creates a new mount file entry
func NewMountFileEntry(fs *MountFileSystem, name string, entry *apfs.FileEntry) (*MountFileEntry, error) {
	if fs == nil {
		return nil, fmt.Errorf("file system cannot be nil")
	}
	if entry == nil {
		return nil, fmt.Errorf("file entry cannot be nil")
	}

	return &MountFileEntry{
		FileSystem: fs,
		name:       name,
		FileEntry:  entry,
	}, nil
}

// Free frees the mount file entry resources
func (mfe *MountFileEntry) Close() error {
	// File entry cleanup is handled by the APFS library
	mfe.FileEntry = nil
	mfe.FileSystem = nil
	return nil
}

// ParentFileEntry returns the parent file entry
func (mfe *MountFileEntry) ParentFileEntry() (*MountFileEntry, error) {
	if mfe.FileEntry == nil {
		return nil, fmt.Errorf("file entry not initialized")
	}

	parentEntry, err := mfe.FileEntry.ParentFileEntry()
	if err != nil {
		return nil, fmt.Errorf("unable to get parent file entry: %w", err)
	}

	parentName, err := mfe.FileSystem.FilenameFromFileEntry(parentEntry)
	if err != nil {
		return nil, fmt.Errorf("unable to get parent filename: %w", err)
	}

	return NewMountFileEntry(mfe.FileSystem, parentName, parentEntry)
}

// CreationTime returns the creation time in nanoseconds since epoch
func (mfe *MountFileEntry) CreationTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.CreationTime()
}

// AccessTime returns the access time in nanoseconds since epoch
func (mfe *MountFileEntry) AccessTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.AccessTime()
}

// ModificationTime returns the modification time in nanoseconds since epoch
func (mfe *MountFileEntry) ModificationTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.ModificationTime()
}

// InodeChangeTime returns the inode change time in nanoseconds since epoch
func (mfe *MountFileEntry) InodeChangeTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.InodeChangeTime()
}

// FileMode returns the file mode (permissions)
func (mfe *MountFileEntry) FileMode() (uint16, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.FileMode()
}

// Name returns the name of the file entry
func (mfe *MountFileEntry) Name() (string, error) {
	if mfe.name != "" {
		return mfe.name, nil
	}

	if mfe.FileEntry == nil {
		return "", fmt.Errorf("file entry not initialized")
	}

	name, err := mfe.FileEntry.UTF8Name()
	if err != nil {
		return "", fmt.Errorf("unable to get file entry name: %w", err)
	}

	mfe.name = string(name)
	return mfe.name, nil
}

// SymbolicLinkTarget returns the target of a symbolic link
func (mfe *MountFileEntry) SymbolicLinkTarget() (string, error) {
	if mfe.FileEntry == nil {
		return "", fmt.Errorf("file entry not initialized")
	}

	target, err := mfe.FileEntry.SymbolicLinkTarget()
	if err != nil {
		return "", fmt.Errorf("unable to get symbolic link target: %w", err)
	}

	return target, nil
}

// NumberOfSubFileEntries returns the number of sub-entries (for directories)
func (mfe *MountFileEntry) NumberOfSubFileEntries() (int, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.NumberOfSubFileEntries()
}

// SubFileEntryByIndex returns a sub-entry by its index
func (mfe *MountFileEntry) SubFileEntryByIndex(index int) (*MountFileEntry, error) {
	if mfe.FileEntry == nil {
		return nil, fmt.Errorf("file entry not initialized")
	}

	subEntry, err := mfe.FileEntry.SubFileEntryByIndex(index)
	if err != nil {
		return nil, fmt.Errorf("unable to get sub-entry %d: %w", index, err)
	}

	subName, err := mfe.FileSystem.FilenameFromFileEntry(subEntry)
	if err != nil {
		return nil, fmt.Errorf("unable to get sub-entry filename: %w", err)
	}

	return NewMountFileEntry(mfe.FileSystem, subName, subEntry)
}

// ReadBufferAtOffset reads data from the file entry at a specific offset
func (mfe *MountFileEntry) ReadBufferAtOffset(buffer []byte, offset int64) (int, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}

	if len(buffer) == 0 {
		return 0, fmt.Errorf("invalid buffer")
	}

	// Seek to the offset
	_, err := mfe.FileEntry.Seek(offset, 0)
	if err != nil {
		return 0, fmt.Errorf("unable to seek to offset %d: %w", offset, err)
	}

	// Read the data
	n, err := mfe.FileEntry.Read(buffer)
	if err != nil {
		return n, fmt.Errorf("unable to read data: %w", err)
	}

	return n, nil
}

// Size returns the size of the file
func (mfe *MountFileEntry) Size() (uint64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}

	// Try to get data size first (for files)
	size, err := mfe.FileEntry.DataSize()
	if err == nil {
		return uint64(size), nil
	}

	// Fall back to regular size
	regularSize, err := mfe.FileEntry.Size()
	if err != nil {
		return 0, err
	}
	return regularSize, nil
}

// IsDirectory checks if the entry is a directory
func (mfe *MountFileEntry) IsDirectory() (bool, error) {
	fileMode, err := mfe.FileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0x4000) != 0, nil // S_IFDIR
}

// IsRegularFile checks if the entry is a regular file
func (mfe *MountFileEntry) IsRegularFile() (bool, error) {
	fileMode, err := mfe.FileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0x8000) != 0, nil // S_IFREG
}

// IsSymbolicLink checks if the entry is a symbolic link
func (mfe *MountFileEntry) IsSymbolicLink() (bool, error) {
	fileMode, err := mfe.FileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0xA000) == 0xA000, nil // S_IFLNK
}

// Identifier returns the file entry identifier (inode number)
func (mfe *MountFileEntry) Identifier() (uint64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.Identifier()
}

// OwnerIdentifier returns the owner ID
func (mfe *MountFileEntry) OwnerIdentifier() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.OwnerIdentifier()
}

// GroupIdentifier returns the group ID
func (mfe *MountFileEntry) GroupIdentifier() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GroupIdentifier()
}

// NumberOfHardLinks returns the number of hard links
func (mfe *MountFileEntry) NumberOfHardLinks() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.NumberOfLinks()
}
