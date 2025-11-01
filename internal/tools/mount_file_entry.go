// Mount file entry abstraction for FUSE operations
// Corresponds to libfsapfs mount_file_entry.c and mount_file_entry.h
package tools

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
)

// MountFileEntry represents a file entry in the mounted filesystem
// This wraps apfs.FileEntry and provides additional mount-specific functionality
type MountFileEntry struct {
	FileSystem *MountFileSystem
	Name       string
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
		Name:       name,
		FileEntry:  entry,
	}, nil
}

// Free frees the mount file entry resources
func (mfe *MountFileEntry) Free() error {
	// File entry cleanup is handled by the APFS library
	mfe.FileEntry = nil
	mfe.FileSystem = nil
	return nil
}

// GetParentFileEntry returns the parent file entry
func (mfe *MountFileEntry) GetParentFileEntry() (*MountFileEntry, error) {
	if mfe.FileEntry == nil {
		return nil, fmt.Errorf("file entry not initialized")
	}

	parentEntry, err := mfe.FileEntry.GetParentFileEntry()
	if err != nil {
		return nil, fmt.Errorf("unable to get parent file entry: %w", err)
	}

	parentName, err := mfe.FileSystem.GetFilenameFromFileEntry(parentEntry)
	if err != nil {
		return nil, fmt.Errorf("unable to get parent filename: %w", err)
	}

	return NewMountFileEntry(mfe.FileSystem, parentName, parentEntry)
}

// GetCreationTime returns the creation time in nanoseconds since epoch
func (mfe *MountFileEntry) GetCreationTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetCreationTime()
}

// GetAccessTime returns the access time in nanoseconds since epoch
func (mfe *MountFileEntry) GetAccessTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetAccessTime()
}

// GetModificationTime returns the modification time in nanoseconds since epoch
func (mfe *MountFileEntry) GetModificationTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetModificationTime()
}

// GetInodeChangeTime returns the inode change time in nanoseconds since epoch
func (mfe *MountFileEntry) GetInodeChangeTime() (int64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetInodeChangeTime()
}

// GetFileMode returns the file mode (permissions)
func (mfe *MountFileEntry) GetFileMode() (uint16, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetFileMode()
}

// GetName returns the name of the file entry
func (mfe *MountFileEntry) GetName() (string, error) {
	if mfe.Name != "" {
		return mfe.Name, nil
	}

	if mfe.FileEntry == nil {
		return "", fmt.Errorf("file entry not initialized")
	}

	name, err := mfe.FileEntry.GetUTF8Name()
	if err != nil {
		return "", fmt.Errorf("unable to get file entry name: %w", err)
	}

	mfe.Name = string(name)
	return mfe.Name, nil
}

// GetSymbolicLinkTarget returns the target of a symbolic link
func (mfe *MountFileEntry) GetSymbolicLinkTarget() (string, error) {
	if mfe.FileEntry == nil {
		return "", fmt.Errorf("file entry not initialized")
	}

	target, err := mfe.FileEntry.GetSymbolicLinkTarget()
	if err != nil {
		return "", fmt.Errorf("unable to get symbolic link target: %w", err)
	}

	return target, nil
}

// GetNumberOfSubFileEntries returns the number of sub-entries (for directories)
func (mfe *MountFileEntry) GetNumberOfSubFileEntries() (int, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetNumberOfSubFileEntries()
}

// GetSubFileEntryByIndex returns a sub-entry by its index
func (mfe *MountFileEntry) GetSubFileEntryByIndex(index int) (*MountFileEntry, error) {
	if mfe.FileEntry == nil {
		return nil, fmt.Errorf("file entry not initialized")
	}

	subEntry, err := mfe.FileEntry.GetSubFileEntryByIndex(index)
	if err != nil {
		return nil, fmt.Errorf("unable to get sub-entry %d: %w", index, err)
	}

	subName, err := mfe.FileSystem.GetFilenameFromFileEntry(subEntry)
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

// GetSize returns the size of the file
func (mfe *MountFileEntry) GetSize() (uint64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}

	// Try to get data size first (for files)
	size, err := mfe.FileEntry.GetDataSize()
	if err == nil {
		return uint64(size), nil
	}

	// Fall back to regular size
	regularSize, err := mfe.FileEntry.GetSize()
	if err != nil {
		return 0, err
	}
	return regularSize, nil
}

// IsDirectory checks if the entry is a directory
func (mfe *MountFileEntry) IsDirectory() (bool, error) {
	fileMode, err := mfe.GetFileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0x4000) != 0, nil // S_IFDIR
}

// IsRegularFile checks if the entry is a regular file
func (mfe *MountFileEntry) IsRegularFile() (bool, error) {
	fileMode, err := mfe.GetFileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0x8000) != 0, nil // S_IFREG
}

// IsSymbolicLink checks if the entry is a symbolic link
func (mfe *MountFileEntry) IsSymbolicLink() (bool, error) {
	fileMode, err := mfe.GetFileMode()
	if err != nil {
		return false, err
	}
	return (fileMode & 0xA000) == 0xA000, nil // S_IFLNK
}

// GetIdentifier returns the file entry identifier (inode number)
func (mfe *MountFileEntry) GetIdentifier() (uint64, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetIdentifier()
}

// GetOwnerIdentifier returns the owner ID
func (mfe *MountFileEntry) GetOwnerIdentifier() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetOwnerIdentifier()
}

// GetGroupIdentifier returns the group ID
func (mfe *MountFileEntry) GetGroupIdentifier() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetGroupIdentifier()
}

// GetNumberOfHardLinks returns the number of hard links
func (mfe *MountFileEntry) GetNumberOfHardLinks() (uint32, error) {
	if mfe.FileEntry == nil {
		return 0, fmt.Errorf("file entry not initialized")
	}
	return mfe.FileEntry.GetNumberOfLinks()
}
