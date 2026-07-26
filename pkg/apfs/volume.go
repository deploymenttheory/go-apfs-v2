// Volume functions
// Corresponds to libfsapfs_volume.c and libfsapfs_volume.h
package apfs

import (
	"fmt"
	"io"
)

// Volume represents an APFS volume
// Corresponds to libfsapfs_internal_volume_t
type Volume struct {
	// The volume superblock
	Superblock *VolumeSuperblock

	// The volume object map B-tree
	ObjectMapBTree *ObjectMapBTree

	// The file system B-tree
	FileSystemBTree *FileSystemBTree

	// The extent reference tree (optional)
	ExtentReferenceTree *ExtentReferenceTree

	// The snapshot metadata tree (optional)
	SnapshotMetadataTree *SnapshotMetadataTree

	// The volume key bag (optional, for encryption)
	KeyBag *ContainerKeyBag

	// The encryption context (optional)
	EncryptionContext *EncryptionContext

	// The IO handle
	IOHandle *IOHandle

	// The file IO handle
	FileIOHandle io.ReaderAt

	// The container key bag reference
	ContainerKeyBag *ContainerKeyBag

	// The container data handle
	ContainerDataHandle *ContainerDataHandle

	// Value to indicate if the volume is locked (private to avoid conflict with IsLocked method)
	isLocked bool

	// The user password (for encrypted volumes)
	UserPassword []byte

	// The recovery password (for encrypted volumes)
	RecoveryPassword []byte
}

// NewVolume creates a new volume
// Corresponds to libfsapfs_volume_initialize
func NewVolume(
	ioHandle *IOHandle,
	fileIOHandle io.ReaderAt,
	containerKeyBag *ContainerKeyBag,
) (*Volume, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}
	if fileIOHandle == nil {
		return nil, fmt.Errorf("invalid file IO handle")
	}

	return &Volume{
		IOHandle:        ioHandle,
		FileIOHandle:    fileIOHandle,
		ContainerKeyBag: containerKeyBag,
	}, nil
}

// Free releases resources associated with the volume
// Corresponds to libfsapfs_volume_free
func (v *Volume) Free() error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	// Free snapshot metadata tree
	if v.SnapshotMetadataTree != nil {
		if err := v.SnapshotMetadataTree.Free(); err != nil {
			return fmt.Errorf("unable to free snapshot metadata tree: %w", err)
		}
		v.SnapshotMetadataTree = nil
	}

	// Free extent reference tree
	if v.ExtentReferenceTree != nil {

		v.ExtentReferenceTree = nil
	}

	// Free file system B-tree
	if v.FileSystemBTree != nil {

		v.FileSystemBTree = nil
	}

	// Free encryption context
	if v.EncryptionContext != nil {

		v.EncryptionContext = nil
	}

	// Free volume key bag
	if v.KeyBag != nil {
		if err := v.KeyBag.Free(); err != nil {
			return fmt.Errorf("unable to free volume key bag: %w", err)
		}
		v.KeyBag = nil
	}

	// Free object map B-tree
	if v.ObjectMapBTree != nil {
		if err := v.ObjectMapBTree.Free(); err != nil {
			return fmt.Errorf("unable to free object map B-tree: %w", err)
		}
		v.ObjectMapBTree = nil
	}

	// Free container data handle
	if v.ContainerDataHandle != nil {
		if err := v.ContainerDataHandle.Free(); err != nil {
			return fmt.Errorf("unable to free container data handle: %w", err)
		}
		v.ContainerDataHandle = nil
	}

	// Free volume superblock
	if v.Superblock != nil {
		if err := v.Superblock.Free(); err != nil {
			return fmt.Errorf("unable to free volume superblock: %w", err)
		}
		v.Superblock = nil
	}

	// Zero out passwords before freeing
	if v.UserPassword != nil {
		for i := range v.UserPassword {
			v.UserPassword[i] = 0
		}
		v.UserPassword = nil
	}

	if v.RecoveryPassword != nil {
		for i := range v.RecoveryPassword {
			v.RecoveryPassword[i] = 0
		}
		v.RecoveryPassword = nil
	}

	return nil
}

// OpenRead opens a volume for reading
// Corresponds to libfsapfs_internal_volume_open_read
func (v *Volume) OpenRead(fileHandle io.ReaderAt, fileOffset int64) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}
	if v.IOHandle == nil {
		return fmt.Errorf("invalid volume - missing IO handle")
	}
	if v.Superblock != nil {
		return fmt.Errorf("invalid volume - superblock already set")
	}

	if DebugOutput {
		fmt.Println("Reading volume superblock")
	}

	// Read volume superblock
	volumeSuperblock := NewVolumeSuperblock()
	if volumeSuperblock == nil {
		return fmt.Errorf("unable to create volume superblock")
	}

	if err := volumeSuperblock.ReadFileIOHandle(fileHandle, fileOffset, false); err != nil {
		return fmt.Errorf("unable to read volume superblock at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}

	v.Superblock = volumeSuperblock

	// Create container data handle
	containerDataHandle, err := NewContainerDataHandle(v.IOHandle)
	if err != nil {
		return fmt.Errorf("unable to create container data handle: %w", err)
	}
	v.ContainerDataHandle = containerDataHandle

	// Read object map
	if v.Superblock.ObjectMapBlockNumber == 0 {
		return fmt.Errorf("missing object map block number")
	}

	if DebugOutput {
		fmt.Println("Reading volume object map")
	}

	objectMapOffset := int64(v.Superblock.ObjectMapBlockNumber) * int64(v.IOHandle.BlockSize)

	objectMap, err := NewObjectMap()
	if err != nil {
		return fmt.Errorf("unable to create object map: %w", err)
	}

	if err := objectMap.ReadFileIOHandle(fileHandle, objectMapOffset); err != nil {
		objectMap.Free()
		return fmt.Errorf("unable to read object map at offset %d: %w", objectMapOffset, err)
	}

	if objectMap.BTreeBlockNumber == 0 {
		objectMap.Free()
		return fmt.Errorf("missing object map B-tree block number")
	}

	if DebugOutput {
		fmt.Println("Reading volume object map B-tree")
	}

	// Create encryption context if volume has key bag
	var encryptionContext *EncryptionContext

	// Note: Volume key bag reading
	// The volume superblock contains key bag block number and size in Unknown24/Unknown25 fields
	// However, volume key bags use a different structure than container key bags
	// Volume key bags are wrapped with different encryption and need volume-specific unwrapping
	//
	// Current implementation uses ContainerKeyBag which is designed for container-level keys
	// Volume-specific key bag implementation requires:
	// 1. Volume key bag structure definition (different from container key bag)
	// 2. Volume-specific key unwrapping algorithms
	// 3. Integration with volume-level encryption context
	//
	// For now, encryption context is created without volume key bag, using container keys
	// This matches the behavior when volume key bag reading fails in C library

	// Create object map B-tree with encryption context
	objectMapBTree, err := NewObjectMapBTree(
		v.IOHandle,
		encryptionContext,
		objectMap.BTreeBlockNumber,
	)
	if err != nil {
		objectMap.Free()
		return fmt.Errorf("unable to create object map B-tree: %w", err)
	}
	v.ObjectMapBTree = objectMapBTree

	// Free the object map as we only needed it to get the B-tree block number
	objectMap.Free()

	// Read file system B-tree
	fileSystemRootObjectID := v.Superblock.FileSystemRootObjectIdentifier
	if fileSystemRootObjectID == 0 {
		return fmt.Errorf("missing file system root object identifier")
	}

	if DebugOutput {
		fmt.Println("Reading file system B-tree")
	}

	fileSystemBTree := NewFileSystemBTree(
		v.IOHandle,
		encryptionContext,
		objectMapBTree,
		fileSystemRootObjectID,
		v.Superblock.ObjectTransactionIdentifier, // Volume's transaction ID
		true,                                     // Use case folding
	)
	v.FileSystemBTree = fileSystemBTree

	// Read extent reference tree if present
	if v.Superblock.ExtentReferenceTreeBlockNumber > 0 {
		if DebugOutput {
			fmt.Println("Reading extent reference tree")
		}

		extentReferenceTree := NewExtentReferenceTree()

		// Calculate offset and read extent reference tree data
		extentReferenceTreeOffset := int64(v.Superblock.ExtentReferenceTreeBlockNumber) * int64(v.IOHandle.BlockSize)

		if err := extentReferenceTree.ReadFromFile(fileHandle, extentReferenceTreeOffset); err != nil {
			// Extent reference tree read failure is not fatal - volume can still be used
			// This matches the C library behavior which continues on read failure
			if DebugOutput {
				fmt.Printf("Warning: unable to read extent reference tree: %v\n", err)
			}
		}

		v.ExtentReferenceTree = extentReferenceTree
	}

	// Read snapshot metadata tree if present
	if v.Superblock.SnapshotMetadataTreeBlockNumber > 0 {
		if DebugOutput {
			fmt.Println("Reading snapshot metadata tree")
		}

		snapshotMetadataTree, err := NewSnapshotMetadataTree(
			v.IOHandle,
			objectMapBTree,
			v.Superblock.SnapshotMetadataTreeBlockNumber,
		)
		if err != nil {
			return fmt.Errorf("unable to create snapshot metadata tree: %w", err)
		}
		v.SnapshotMetadataTree = snapshotMetadataTree
	}

	return nil
}

// Close closes a volume
// Corresponds to libfsapfs_internal_volume_close
func (v *Volume) Close() error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}
	if v.IOHandle == nil {
		return fmt.Errorf("invalid volume - missing IO handle")
	}

	// Clear file IO handle reference
	v.FileIOHandle = nil

	// Free snapshot metadata tree
	if v.SnapshotMetadataTree != nil {

		v.SnapshotMetadataTree = nil
	}

	// Free extent reference tree
	if v.ExtentReferenceTree != nil {

		v.ExtentReferenceTree = nil
	}

	// Free file system B-tree
	if v.FileSystemBTree != nil {

		v.FileSystemBTree = nil
	}

	// Free encryption context
	if v.EncryptionContext != nil {

		v.EncryptionContext = nil
	}

	// Free volume key bag
	if v.KeyBag != nil {
		v.KeyBag.Free()
		v.KeyBag = nil
	}

	// Free object map B-tree
	if v.ObjectMapBTree != nil {
		v.ObjectMapBTree.Free()
		v.ObjectMapBTree = nil
	}

	// Free container data handle
	if v.ContainerDataHandle != nil {
		v.ContainerDataHandle.Free()
		v.ContainerDataHandle = nil
	}

	// Free volume superblock
	if v.Superblock != nil {
		v.Superblock.Free()
		v.Superblock = nil
	}

	return nil
}

// GetUTF8NameSize retrieves the size of the UTF-8 encoded volume name
// The returned size includes the end of string character
// Corresponds to libfsapfs_volume_get_utf8_name_size
func (v *Volume) GetUTF8NameSize() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.GetUTF8VolumeNameSize()
}

// GetUTF8Name retrieves the UTF-8 encoded volume name
// Corresponds to libfsapfs_volume_get_utf8_name
func (v *Volume) GetUTF8Name() (string, error) {
	if v == nil {
		return "", fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return "", fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.GetUTF8VolumeName()
}

// GetUTF16NameSize retrieves the size of the UTF-16 encoded volume name
// The returned size includes the end of string character
// Corresponds to libfsapfs_volume_get_utf16_name_size
func (v *Volume) GetUTF16NameSize() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.GetUTF16VolumeNameSize()
}

// GetUTF16Name retrieves the UTF-16 encoded volume name
// Corresponds to libfsapfs_volume_get_utf16_name
func (v *Volume) GetUTF16Name() ([]uint16, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return nil, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.GetUTF16VolumeName()
}

// GetIdentifier retrieves the volume identifier (UUID)
// Corresponds to libfsapfs_volume_get_identifier
func (v *Volume) GetIdentifier() ([16]byte, error) {
	if v == nil {
		return [16]byte{}, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return [16]byte{}, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.GetVolumeIdentifier()
}

// IsLocked checks if the volume is locked (encrypted)
// Corresponds to libfsapfs_volume_is_locked
func (v *Volume) IsLocked() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.KeyBag == nil {
		// No key bag means no encryption
		return false, nil
	}

	return v.KeyBag.IsLocked, nil
}

// GetNumberOfSnapshots retrieves the number of snapshots
// Corresponds to libfsapfs_volume_get_number_of_snapshots
func (v *Volume) GetNumberOfSnapshots() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.SnapshotMetadataTree == nil {
		return 0, nil
	}

	return v.SnapshotMetadataTree.GetNumberOfEntries(v.FileIOHandle)
}

// GetSnapshot retrieves a snapshot by index
// Corresponds to libfsapfs_volume_get_snapshot
func (v *Volume) GetSnapshot(index int) (*Snapshot, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.SnapshotMetadataTree == nil {
		return nil, fmt.Errorf("no snapshot metadata tree")
	}

	// Get snapshot metadata by index
	snapshotMetadata, err := v.SnapshotMetadataTree.GetEntryByIndex(v.FileIOHandle, index)
	if err != nil {
		return nil, fmt.Errorf("unable to get snapshot metadata at index %d: %w", index, err)
	}

	// Create snapshot
	snapshot, err := NewSnapshot(v.IOHandle, v.FileIOHandle, snapshotMetadata)
	if err != nil {
		return nil, fmt.Errorf("unable to create snapshot: %w", err)
	}

	// The snapshot's volume superblock is a physical object, so sblock_oid is its
	// block number directly (not an object-map-resolved virtual oid).
	blockNumber := snapshotMetadata.VolumeSuperblockBlockNumber

	// Open snapshot (reads volume superblock)
	offset := int64(blockNumber) * int64(v.IOHandle.BlockSize)
	err = snapshot.OpenRead(v.FileIOHandle, offset)
	if err != nil {
		snapshot.Free()
		return nil, fmt.Errorf("unable to open snapshot: %w", err)
	}

	return snapshot, nil
}

// GetRootDirectory retrieves the root directory file entry
// Corresponds to libfsapfs_volume_get_root_directory
func (v *Volume) GetRootDirectory() (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	// Root directory inode is always 2 in APFS
	// (Inode 1 is the private directory and may not exist)
	return v.GetFileEntryByIdentifier(2)
}

// GetFileEntryByIdentifier retrieves a file entry by inode number
// Corresponds to libfsapfs_volume_get_file_entry_by_identifier
func (v *Volume) GetFileEntryByIdentifier(identifier uint64) (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	// Get inode from file system B-tree
	inode, err := v.FileSystemBTree.GetInodeByIdentifier(v.FileIOHandle, identifier, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to get inode %d: %w", identifier, err)
	}

	if inode == nil {
		return nil, fmt.Errorf("inode %d not found", identifier)
	}

	// Create file entry from inode
	// Note: Using NewFileEntry with all required parameters
	fileEntry, err := NewFileEntry(
		v.IOHandle,
		v.FileIOHandle,
		v.EncryptionContext,
		v.FileSystemBTree,
		inode,
		nil, // directory record - not available when accessing by identifier
		inode.ParentIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// GetFileEntryByPath retrieves a file entry by path
// Corresponds to libfsapfs_volume_get_file_entry_by_utf8_path
func (v *Volume) GetFileEntryByPath(path string) (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	// If path is empty or root, return root directory
	if path == "" || path == "/" {
		return v.GetRootDirectory()
	}

	// Use FileSystemBTree.GetInodeByUTF8Path to traverse the path
	// This starts from the root (identifier 2, not 1 which is private-dir)
	inode, directoryRecord, err := v.FileSystemBTree.GetInodeByUTF8Path(
		v.FileIOHandle,
		2, // Start from root directory (identifier 2)
		path,
		0, // transaction identifier
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get inode by path %s: %w", path, err)
	}

	if inode == nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}

	// Create file entry from inode and directory record
	fileEntry, err := NewFileEntry(
		v.IOHandle,
		v.FileIOHandle,
		v.EncryptionContext,
		v.FileSystemBTree,
		inode,
		directoryRecord,
		inode.ParentIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// SetUTF8Password sets the user password for unlocking an encrypted volume
// Corresponds to libfsapfs_volume_set_utf8_password
// This function must be called before Unlock() for password-based unlocking
func (v *Volume) SetUTF8Password(password []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if password == nil {
		return fmt.Errorf("invalid password")
	}

	// Clear existing password if set
	if v.UserPassword != nil {
		// Zero out the old password for security
		for i := range v.UserPassword {
			v.UserPassword[i] = 0
		}
		v.UserPassword = nil
	}

	// Store a copy of the password
	v.UserPassword = make([]byte, len(password))
	copy(v.UserPassword, password)

	if IsVerbose() {
		Printf("SetUTF8Password: password set (length: %d)\n", len(password))
	}

	return nil
}

// SetUTF16Password sets the user password from UTF-16 encoding
// Corresponds to libfsapfs_volume_set_utf16_password
func (v *Volume) SetUTF16Password(utf16Password []uint16) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if utf16Password == nil {
		return fmt.Errorf("invalid password")
	}

	// Convert UTF-16 to UTF-8
	utf8Password := []byte(UTF16ToString(utf16Password))

	return v.SetUTF8Password(utf8Password)
}

// SetUTF8RecoveryPassword sets the recovery password for unlocking an encrypted volume
// Corresponds to libfsapfs_volume_set_utf8_recovery_password
// This function must be called before Unlock() for recovery password-based unlocking
func (v *Volume) SetUTF8RecoveryPassword(password []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if password == nil {
		return fmt.Errorf("invalid password")
	}

	// Clear existing recovery password if set
	if v.RecoveryPassword != nil {
		// Zero out the old password for security
		for i := range v.RecoveryPassword {
			v.RecoveryPassword[i] = 0
		}
		v.RecoveryPassword = nil
	}

	// Store a copy of the password
	v.RecoveryPassword = make([]byte, len(password))
	copy(v.RecoveryPassword, password)

	if IsVerbose() {
		Printf("SetUTF8RecoveryPassword: recovery password set (length: %d)\n", len(password))
	}

	return nil
}

// SetUTF16RecoveryPassword sets the recovery password from UTF-16 encoding
// Corresponds to libfsapfs_volume_set_utf16_recovery_password
func (v *Volume) SetUTF16RecoveryPassword(utf16Password []uint16) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if utf16Password == nil {
		return fmt.Errorf("invalid password")
	}

	// Convert UTF-16 to UTF-8
	utf8Password := []byte(UTF16ToString(utf16Password))

	return v.SetUTF8RecoveryPassword(utf8Password)
}

// Unlock attempts to unlock an encrypted volume using the provided passwords
// Corresponds to libfsapfs_volume_unlock and libfsapfs_internal_volume_unlock
// Returns true if unlocked successfully, false if password is incorrect, error on failure
func (v *Volume) Unlock() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}

	// If not locked, already unlocked
	if !v.isLocked {
		return true, nil
	}

	// If no key bag, volume is not encrypted
	if v.KeyBag == nil {
		v.isLocked = false
		return true, nil
	}

	// Note: Full volume unlock requires volume key bag reading which is complex
	// The C implementation reads volume key bags from volume superblock Unknown24/Unknown25 fields
	// Volume key bags use a different structure and unwrapping method than container key bags
	// This would require:
	// 1. Reading volume key bag blocks from volume superblock
	// 2. Parsing volume key bag structure (different from container key bag)
	// 3. Unwrapping keys using PBKDF2 and provided passwords
	// 4. Getting volume master key from container key bag
	// 5. Setting up encryption context
	//
	// For now, this returns an error indicating the feature needs full implementation
	// The building blocks exist (PBKDF2, key bag structures, encryption context)
	// but volume key bag reading needs to be completed in OpenRead first

	return false, fmt.Errorf("volume unlock requires volume key bag reading - not yet fully implemented")
}

// GetFeaturesFlags retrieves the volume feature flags
// Corresponds to libfsapfs_volume_get_features_flags
func (v *Volume) GetFeaturesFlags() (compatible, incompatible, readOnlyCompatible uint64, err error) {
	if v == nil {
		return 0, 0, 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, 0, 0, fmt.Errorf("invalid volume - missing superblock")
	}

	compatible = v.Superblock.CompatibleFeaturesFlags
	incompatible = v.Superblock.IncompatibleFeaturesFlags
	readOnlyCompatible = v.Superblock.ReadOnlyCompatibleFeaturesFlags

	return compatible, incompatible, readOnlyCompatible, nil
}

// GetSize retrieves the size of the volume in bytes
// Corresponds to libfsapfs_volume_get_size
func (v *Volume) GetSize() (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	if v.IOHandle == nil {
		return 0, fmt.Errorf("invalid volume - missing IO handle")
	}

	// Calculate volume size from allocated blocks (apfs_fs_alloc_count field)
	// This represents the number of blocks currently allocated on this volume
	volumeSize := v.Superblock.NumberOfAllocatedBlocks * uint64(v.IOHandle.BlockSize)

	return volumeSize, nil
}

// GetNextFileEntryIdentifier retrieves the next file entry identifier
// Corresponds to libfsapfs_volume_get_next_file_entry_identifier
func (v *Volume) GetNextFileEntryIdentifier() (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	// Note: The superblock may not directly expose NextObjectIdentifier
	// In the C library, this traverses the file system B-tree to find the highest inode
	// For now, return an error indicating this needs B-tree traversal
	return 0, fmt.Errorf("GetNextFileEntryIdentifier requires B-tree traversal - not yet implemented")
}
