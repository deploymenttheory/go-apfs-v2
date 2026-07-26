// Mount file system abstraction for FUSE operations
// Corresponds to libfsapfs mount_file_system.c and mount_file_system.h
package tools

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// MountFileSystem represents a mounted APFS filesystem
// This is an abstraction layer between the APFS library and FUSE
type MountFileSystem struct {
	Volume           *apfs.Volume
	MountedTimestamp time.Time
	abort            bool
}

// NewMountFileSystem creates a new mount filesystem
func NewMountFileSystem() *MountFileSystem {
	return &MountFileSystem{
		MountedTimestamp: time.Now(),
	}
}

// Free frees the mount filesystem resources
func (mfs *MountFileSystem) Close() error {
	if mfs.Volume != nil {
		// Note: Volume cleanup is handled by the mount handle
		mfs.Volume = nil
	}
	return nil
}

// SignalAbort signals the filesystem to abort operations
func (mfs *MountFileSystem) SignalAbort() {
	mfs.abort = true
}

// IsAborted returns whether the filesystem has been signaled to abort
func (mfs *MountFileSystem) IsAborted() bool {
	return mfs.abort
}

// SetVolume sets the APFS volume for this filesystem
func (mfs *MountFileSystem) SetVolume(volume *apfs.Volume) error {
	if volume == nil {
		return fmt.Errorf("volume cannot be nil")
	}
	mfs.Volume = volume
	return nil
}

// FileEntryByPath retrieves a file entry by its path
func (mfs *MountFileSystem) FileEntryByPath(path string) (*apfs.FileEntry, error) {
	if mfs.Volume == nil {
		return nil, fmt.Errorf("no volume mounted")
	}

	// Get the root directory
	root, err := mfs.Volume.RootDirectory()
	if err != nil {
		return nil, fmt.Errorf("unable to get root directory: %w", err)
	}

	// If requesting root, return it
	if path == "/" || path == "" {
		return root, nil
	}

	// Split and traverse the path
	pathSegments := SplitPath(path)
	if len(pathSegments) == 0 {
		return root, nil
	}

	currentEntry := root
	for i, segment := range pathSegments {
		if segment == "" {
			continue
		}

		// Check if we should abort
		if mfs.abort {
			return nil, fmt.Errorf("operation aborted")
		}

		// Get the number of sub-entries
		numSubEntries, err := currentEntry.NumberOfSubFileEntries()
		if err != nil {
			return nil, fmt.Errorf("unable to get number of sub-entries at level %d: %w", i, err)
		}

		// Search for the segment
		found := false
		for j := 0; j < numSubEntries; j++ {
			subEntry, err := currentEntry.SubFileEntryByIndex(j)
			if err != nil {
				continue
			}

			name, err := subEntry.UTF8Name()
			if err != nil {
				continue
			}

			if string(name) == segment {
				currentEntry = subEntry
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("path component '%s' not found", segment)
		}
	}

	return currentEntry, nil
}

// FilenameFromFileEntry retrieves the filename from a file entry
func (mfs *MountFileSystem) FilenameFromFileEntry(fileEntry *apfs.FileEntry) (string, error) {
	if fileEntry == nil {
		return "", fmt.Errorf("file entry cannot be nil")
	}

	name, err := fileEntry.UTF8Name()
	if err != nil {
		return "", fmt.Errorf("unable to get file entry name: %w", err)
	}

	return string(name), nil
}

// RootFileEntry returns the root directory entry
func (mfs *MountFileSystem) RootFileEntry() (*apfs.FileEntry, error) {
	if mfs.Volume == nil {
		return nil, fmt.Errorf("no volume mounted")
	}

	return mfs.Volume.RootDirectory()
}

// IsVolumeSet returns whether a volume has been set
func (mfs *MountFileSystem) IsVolumeSet() bool {
	return mfs.Volume != nil
}
