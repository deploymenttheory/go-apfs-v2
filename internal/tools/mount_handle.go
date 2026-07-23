// Mount handle for APFS filesystem mounting
// Corresponds to libfsapfs mount_handle.c and mount_handle.h
package tools

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// MountHandle manages the state for mounting an APFS container
type MountHandle struct {
	FileSystemIndex   int
	VolumeOffset      int64
	UserPassword      string
	RecoveryPassword  string
	InputContainer    *apfs.Container
	ContainerIsLocked bool
	IsLocked          bool
	NotifyStream      io.Writer
	inputFile         io.Closer
}

// NewMountHandle creates a new mount handle
func NewMountHandle() *MountHandle {
	return &MountHandle{
		FileSystemIndex: -1, // -1 means mount all volumes
		VolumeOffset:    0,
		NotifyStream:    os.Stderr,
	}
}

// SetFileSystemIndex sets the file system index from a string
// Accepts a number or "all" to mount all volumes
func (mh *MountHandle) SetFileSystemIndex(indexStr string) error {
	if indexStr == "all" {
		mh.FileSystemIndex = -1 // -1 indicates all volumes
		return nil
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return fmt.Errorf("invalid file system index: %w", err)
	}

	if index < 0 {
		return fmt.Errorf("file system index must be non-negative")
	}

	mh.FileSystemIndex = index
	return nil
}

// SetOffset sets the volume offset from a string
func (mh *MountHandle) SetOffset(offsetStr string) error {
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid offset: %w", err)
	}

	if offset < 0 {
		return fmt.Errorf("offset must be non-negative")
	}

	mh.VolumeOffset = offset
	return nil
}

// SetPassword sets the user password
func (mh *MountHandle) SetPassword(password string) error {
	mh.UserPassword = password
	return nil
}

// SetRecoveryPassword sets the recovery password
func (mh *MountHandle) SetRecoveryPassword(password string) error {
	mh.RecoveryPassword = password
	return nil
}

// Open opens the APFS container for mounting
func (mh *MountHandle) Open(filename string) error {
	// Open the image with content-based format detection (DMG, GPT raw
	// image, or bare container)
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(filename)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	mh.inputFile = closer

	// An explicit offset always wins over the sniffed partition offset
	offset := mh.VolumeOffset
	if offset == 0 {
		offset = sniffedOffset
	}

	// Create IO handle
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		closer.Close()
		return fmt.Errorf("unable to create IO handle: %w", err)
	}

	// Create container
	container, err := apfs.NewContainer(ioHandle)
	if err != nil {
		closer.Close()
		return fmt.Errorf("unable to create container: %w", err)
	}

	// Open the container
	if err := container.OpenRead(reader, offset); err != nil {
		closer.Close()
		return fmt.Errorf("unable to open container: %w", err)
	}
	mh.InputContainer = container

	// Check if container is locked
	isLocked, err := container.IsLocked()
	if err != nil {
		return fmt.Errorf("unable to determine if container is locked: %w", err)
	}
	mh.ContainerIsLocked = isLocked

	// Set passwords if provided
	if mh.UserPassword != "" || mh.RecoveryPassword != "" {
		if err := mh.unlockVolumes(); err != nil {
			if mh.NotifyStream != nil {
				fmt.Fprintf(mh.NotifyStream, "Warning: failed to unlock volumes: %v\n", err)
			}
		}
	}

	return nil
}

// unlockVolumes attempts to unlock all volumes with the provided passwords
func (mh *MountHandle) unlockVolumes() error {
	if mh.InputContainer == nil {
		return fmt.Errorf("container not opened")
	}

	numberOfVolumes, err := mh.InputContainer.GetNumberOfVolumes()
	if err != nil {
		return fmt.Errorf("unable to get number of volumes: %w", err)
	}

	for i := 0; i < numberOfVolumes; i++ {
		volume, err := mh.InputContainer.GetVolume(i)
		if err != nil {
			if mh.NotifyStream != nil {
				fmt.Fprintf(mh.NotifyStream, "Warning: unable to get volume %d: %v\n", i, err)
			}
			continue
		}

		// Try user password first
		if mh.UserPassword != "" {
			if err := volume.SetUTF8Password([]byte(mh.UserPassword)); err != nil {
				if mh.NotifyStream != nil {
					fmt.Fprintf(mh.NotifyStream, "Warning: failed to set password for volume %d: %v\n", i, err)
				}
			}
		}

		// Try recovery password
		if mh.RecoveryPassword != "" {
			if err := volume.SetUTF8RecoveryPassword([]byte(mh.RecoveryPassword)); err != nil {
				if mh.NotifyStream != nil {
					fmt.Fprintf(mh.NotifyStream, "Warning: failed to set recovery password for volume %d: %v\n", i, err)
				}
			}
		}

		// Attempt unlock
		unlocked, err := volume.Unlock()
		if err != nil {
			if mh.NotifyStream != nil {
				fmt.Fprintf(mh.NotifyStream, "Warning: failed to unlock volume %d: %v\n", i, err)
			}
		} else if unlocked {
			if mh.NotifyStream != nil {
				fmt.Fprintf(mh.NotifyStream, "Volume %d unlocked successfully\n", i)
			}
		}
	}

	return nil
}

// Close closes the mount handle
func (mh *MountHandle) Close() error {
	if mh.InputContainer != nil {
		if err := mh.InputContainer.Free(); err != nil {
			return fmt.Errorf("unable to free container: %w", err)
		}
		mh.InputContainer = nil
	}

	if mh.inputFile != nil {
		if err := mh.inputFile.Close(); err != nil {
			return fmt.Errorf("unable to close file: %w", err)
		}
		mh.inputFile = nil
	}

	return nil
}

// SignalAbort signals the mount handle to abort
func (mh *MountHandle) SignalAbort() {
	mh.IsLocked = true
}

// GetVolumeByIndex retrieves a volume by its index
func (mh *MountHandle) GetVolumeByIndex(index int) (*apfs.Volume, error) {
	if mh.InputContainer == nil {
		return nil, fmt.Errorf("container not opened")
	}

	return mh.InputContainer.GetVolume(index)
}

// GetNumberOfVolumes returns the number of volumes in the container
func (mh *MountHandle) GetNumberOfVolumes() (int, error) {
	if mh.InputContainer == nil {
		return 0, fmt.Errorf("container not opened")
	}

	return mh.InputContainer.GetNumberOfVolumes()
}

// GetFileEntryByPath retrieves a file entry by its path from a specific volume
func (mh *MountHandle) GetFileEntryByPath(volumeIndex int, path string) (*apfs.FileEntry, error) {
	volume, err := mh.GetVolumeByIndex(volumeIndex)
	if err != nil {
		return nil, fmt.Errorf("unable to get volume %d: %w", volumeIndex, err)
	}

	// Get the root directory
	root, err := volume.GetRootDirectory()
	if err != nil {
		return nil, fmt.Errorf("unable to get root directory: %w", err)
	}

	// If path is root, return root directory
	if path == "/" || path == "" {
		return root, nil
	}

	// Normalize and split the path
	pathSegments := SplitPath(path)
	if len(pathSegments) == 0 {
		return root, nil
	}

	// Traverse the path
	currentEntry := root
	for i, segment := range pathSegments {
		if segment == "" {
			continue
		}

		// Get the number of sub-entries
		numSubEntries, err := currentEntry.GetNumberOfSubFileEntries()
		if err != nil {
			return nil, fmt.Errorf("unable to get number of sub-entries at level %d: %w", i, err)
		}

		// Search for the segment
		found := false
		for j := 0; j < numSubEntries; j++ {
			subEntry, err := currentEntry.GetSubFileEntryByIndex(j)
			if err != nil {
				continue
			}

			name, err := subEntry.GetUTF8Name()
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

// IsContainerLocked returns whether the container is locked
func (mh *MountHandle) IsContainerLocked() bool {
	return mh.ContainerIsLocked
}
