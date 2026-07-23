package apfs

import (
	"fmt"
	"io"
	"sync"
)

// FileSystem represents an APFS file system
// Corresponds to libfsapfs_file_system_t
type FileSystem struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The file system B-tree
	FileSystemBTree *FileSystemBTree

	// Read/write mutex for thread safety (corresponds to libcthreads_read_write_lock)
	mu sync.RWMutex
}

// NewFileSystem creates a new file system
// Corresponds to libfsapfs_file_system_initialize
func NewFileSystem(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	fileSystemBTree *FileSystemBTree,
) (*FileSystem, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	if fileSystemBTree == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	return &FileSystem{
		IOHandle:          ioHandle,
		EncryptionContext: encryptionContext,
		FileSystemBTree:   fileSystemBTree,
	}, nil
}

// GetFileEntryByIdentifier retrieves a file entry for a specific identifier from the file system B-tree
// Corresponds to libfsapfs_file_system_get_file_entry_by_identifier
// Returns the file entry if found, nil if not found, or an error
func (fs *FileSystem) GetFileEntryByIdentifier(
	fileHandle io.ReaderAt,
	identifier uint64,
	transactionIdentifier uint64,
) (*FileEntry, error) {
	if fs == nil {
		return nil, fmt.Errorf("invalid file system")
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Get inode from file system B-tree
	inode, err := fs.FileSystemBTree.GetInodeByIdentifier(fileHandle, identifier, transactionIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve inode %d from file system B-tree: %w", identifier, err)
	}

	if inode == nil {
		return nil, nil // Not found
	}

	// Create file entry
	fileEntry, err := NewFileEntry(
		fs.IOHandle,
		fileHandle,
		fs.EncryptionContext,
		fs.FileSystemBTree,
		inode,
		nil, // directory_record (will be nil for lookup by identifier)
		transactionIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// GetFileEntryByUTF8Path retrieves a file entry for a UTF-8 encoded path from the file system
// Corresponds to libfsapfs_file_system_get_file_entry_by_utf8_path
// Returns the file entry if found, nil if not found, or an error
func (fs *FileSystem) GetFileEntryByUTF8Path(
	fileHandle io.ReaderAt,
	path string,
	transactionIdentifier uint64,
) (*FileEntry, error) {
	if fs == nil {
		return nil, fmt.Errorf("invalid file system")
	}

	if path == "" {
		return nil, fmt.Errorf("invalid path")
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Root directory identifier is typically 2 in APFS
	const rootDirectoryIdentifier = 2

	// Get inode and directory record by path
	inode, dirRecord, err := fs.FileSystemBTree.GetInodeByUTF8Path(
		fileHandle,
		rootDirectoryIdentifier,
		path,
		transactionIdentifier,
	)

	if err != nil {
		return nil, fmt.Errorf("unable to retrieve inode by path '%s': %w", path, err)
	}

	if inode == nil {
		return nil, nil // Not found
	}

	// Create file entry
	fileEntry, err := NewFileEntry(
		fs.IOHandle,
		fileHandle,
		fs.EncryptionContext,
		fs.FileSystemBTree,
		inode,
		dirRecord,
		transactionIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// GetFileEntryByUTF16Path retrieves a file entry for a UTF-16 encoded path from the file system
// Corresponds to libfsapfs_file_system_get_file_entry_by_utf16_path
// Returns the file entry if found, nil if not found, or an error
func (fs *FileSystem) GetFileEntryByUTF16Path(
	fileHandle io.ReaderAt,
	path []uint16,
	transactionIdentifier uint64,
) (*FileEntry, error) {
	if fs == nil {
		return nil, fmt.Errorf("invalid file system")
	}

	if len(path) == 0 {
		return nil, fmt.Errorf("invalid path")
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Root directory identifier is typically 2 in APFS
	const rootDirectoryIdentifier = 2

	// Get inode and directory record by UTF-16 path
	inode, dirRecord, err := fs.FileSystemBTree.GetInodeByUTF16Path(
		fileHandle,
		rootDirectoryIdentifier,
		path,
		transactionIdentifier,
	)

	if err != nil {
		// Convert path to string for error message
		pathStr := UTF16ToString(path)
		return nil, fmt.Errorf("unable to retrieve inode by path '%s': %w", pathStr, err)
	}

	if inode == nil {
		return nil, nil // Not found
	}

	// Create file entry
	fileEntry, err := NewFileEntry(
		fs.IOHandle,
		fileHandle,
		fs.EncryptionContext,
		fs.FileSystemBTree,
		inode,
		dirRecord,
		transactionIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// GetRootDirectory retrieves the root directory file entry
// This is a convenience method not present in the C library
func (fs *FileSystem) GetRootDirectory(
	fileHandle io.ReaderAt,
	transactionIdentifier uint64,
) (*FileEntry, error) {
	const rootDirectoryIdentifier = 2
	return fs.GetFileEntryByIdentifier(fileHandle, rootDirectoryIdentifier, transactionIdentifier)
}
