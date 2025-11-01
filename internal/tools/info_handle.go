// Info handle for displaying APFS container and volume information
// Corresponds to libfsapfs info_handle.c and info_handle.h
package tools

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
)

// InfoHandle provides functionality for displaying APFS information
// Corresponds to info_handle_t
type InfoHandle struct {
	// FileSystemIndex specifies which file system/volume to show (or -1 for all)
	FileSystemIndex int

	// RecoveryPassword for encrypted volumes
	RecoveryPassword string

	// UserPassword for encrypted volumes
	UserPassword string

	// VolumeOffset specifies the byte offset of the volume
	VolumeOffset int64

	// InputContainer holds the opened APFS container
	InputContainer *apfs.Container

	// ContainerIsLocked indicates if the container is encrypted and locked
	ContainerIsLocked bool

	// CalculateMD5 indicates if MD5 hashes should be calculated for files
	CalculateMD5 bool

	// BodyfileStream is the output stream for bodyfile format
	BodyfileStream io.Writer

	// NotifyStream is the stream for notifications and information output
	NotifyStream io.Writer

	// Abort flag for signal handling
	Abort bool
}

// NewInfoHandle creates a new info handle
// Corresponds to info_handle_initialize
func NewInfoHandle(calculateMD5 bool) (*InfoHandle, error) {
	return &InfoHandle{
		FileSystemIndex:   -1, // -1 means all file systems
		VolumeOffset:      0,
		CalculateMD5:      calculateMD5,
		NotifyStream:      os.Stdout,
		ContainerIsLocked: false,
		Abort:             false,
	}, nil
}

// SetBodyfile sets the bodyfile output stream
// Corresponds to info_handle_set_bodyfile
func (ih *InfoHandle) SetBodyfile(filename string) error {
	if filename == "" {
		return fmt.Errorf("invalid filename")
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("unable to create bodyfile: %w", err)
	}

	ih.BodyfileStream = file
	return nil
}

// SetFileSystemIndex sets the file system index from a string
// Corresponds to info_handle_set_file_system_index
func (ih *InfoHandle) SetFileSystemIndex(indexStr string) error {
	if indexStr == "all" {
		ih.FileSystemIndex = -1
		return nil
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return fmt.Errorf("invalid file system index: %w", err)
	}

	if index < 0 {
		return fmt.Errorf("invalid file system index: must be non-negative")
	}

	ih.FileSystemIndex = index
	return nil
}

// SetPassword sets the user password
// Corresponds to info_handle_set_password
func (ih *InfoHandle) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("invalid password")
	}

	ih.UserPassword = password
	return nil
}

// SetRecoveryPassword sets the recovery password
// Corresponds to info_handle_set_recovery_password
func (ih *InfoHandle) SetRecoveryPassword(password string) error {
	if password == "" {
		return fmt.Errorf("invalid recovery password")
	}

	ih.RecoveryPassword = password
	return nil
}

// SetVolumeOffset sets the volume offset from a string
// Corresponds to info_handle_set_volume_offset
func (ih *InfoHandle) SetVolumeOffset(offsetStr string) error {
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid volume offset: %w", err)
	}

	if offset < 0 {
		return fmt.Errorf("invalid volume offset: must be non-negative")
	}

	ih.VolumeOffset = offset
	return nil
}

// OpenInput opens the APFS container from a file
// Corresponds to info_handle_open_input
func (ih *InfoHandle) OpenInput(filename string) error {
	if filename == "" {
		return fmt.Errorf("invalid filename")
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}

	// Create IO handle
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		file.Close()
		return fmt.Errorf("unable to create IO handle: %w", err)
	}

	// Create container
	container, err := apfs.NewContainer(ioHandle)
	if err != nil {
		file.Close()
		return fmt.Errorf("unable to create container: %w", err)
	}

	// Open container for reading
	if err := container.OpenRead(file, ih.VolumeOffset); err != nil {
		file.Close()
		return fmt.Errorf("unable to open container: %w", err)
	}

	ih.InputContainer = container

	// Check if container is locked
	isLocked, err := container.IsLocked()
	if err != nil {
		return fmt.Errorf("unable to determine if container is locked: %w", err)
	}
	ih.ContainerIsLocked = isLocked

	// If we have passwords, set them on all volumes for later unlocking
	// Note: Passwords need to be set per-volume, not at container level
	if ih.UserPassword != "" || ih.RecoveryPassword != "" {
		numberOfVolumes, err := container.GetNumberOfVolumes()
		if err != nil {
			return fmt.Errorf("unable to get number of volumes: %w", err)
		}

		for i := 0; i < numberOfVolumes; i++ {
			volume, err := container.GetVolume(i)
			if err != nil {
				continue // Skip volumes that can't be retrieved
			}

			// Set user password if provided
			if ih.UserPassword != "" {
				if err := volume.SetUTF8Password([]byte(ih.UserPassword)); err != nil {
					// Non-fatal: continue even if password setting fails
					if ih.NotifyStream != nil {
						fmt.Fprintf(ih.NotifyStream, "Warning: failed to set password for volume %d: %v\n", i, err)
					}
				}
			}

			// Set recovery password if provided
			if ih.RecoveryPassword != "" {
				if err := volume.SetUTF8RecoveryPassword([]byte(ih.RecoveryPassword)); err != nil {
					// Non-fatal: continue even if password setting fails
					if ih.NotifyStream != nil {
						fmt.Fprintf(ih.NotifyStream, "Warning: failed to set recovery password for volume %d: %v\n", i, err)
					}
				}
			}

			// Attempt to unlock the volume
			unlocked, err := volume.Unlock()
			if err != nil {
				// Non-fatal: volume may not be encrypted or may have wrong password
				if ih.NotifyStream != nil {
					fmt.Fprintf(ih.NotifyStream, "Warning: failed to unlock volume %d: %v\n", i, err)
				}
			} else if unlocked {
				if ih.NotifyStream != nil {
					fmt.Fprintf(ih.NotifyStream, "Volume %d unlocked successfully\n", i)
				}
			}
		}
	}

	return nil
}

// CloseInput closes the input container
// Corresponds to info_handle_close_input
func (ih *InfoHandle) CloseInput() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Free container resources
	if err := ih.InputContainer.Free(); err != nil {
		return fmt.Errorf("unable to free container: %w", err)
	}

	ih.InputContainer = nil
	return nil
}

// GetVolumeByIndex retrieves a volume by its index
// Corresponds to info_handle_get_volume_by_index
func (ih *InfoHandle) GetVolumeByIndex(volumeIndex int) (*apfs.Volume, error) {
	if ih.InputContainer == nil {
		return nil, fmt.Errorf("invalid info handle - input container not set")
	}

	numberOfVolumes, err := ih.InputContainer.GetNumberOfVolumes()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve number of volumes: %w", err)
	}

	if volumeIndex < 0 || volumeIndex >= numberOfVolumes {
		return nil, fmt.Errorf("invalid volume index: %d (available: 0-%d)", volumeIndex, numberOfVolumes-1)
	}

	volume, err := ih.InputContainer.GetVolume(volumeIndex)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve volume: %w", err)
	}

	return volume, nil
}

// SignalAbort sets the abort flag
// Corresponds to info_handle_signal_abort
func (ih *InfoHandle) SignalAbort() error {
	if ih == nil {
		return fmt.Errorf("invalid info handle")
	}

	ih.Abort = true
	return nil
}

// PrintContainerInfo prints information about the APFS container
// Corresponds to info_handle_container_fprint
func (ih *InfoHandle) PrintContainerInfo() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	fmt.Fprintf(ih.NotifyStream, "Apple File System (APFS) information:\n\n")

	// Print container identifier
	identifier, err := ih.InputContainer.GetIdentifier()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "Container identifier:\t\t%s\n", identifier)
	}

	// Print number of volumes
	numberOfVolumes, err := ih.InputContainer.GetNumberOfVolumes()
	if err != nil {
		return fmt.Errorf("unable to retrieve number of volumes: %w", err)
	}
	fmt.Fprintf(ih.NotifyStream, "Number of volumes:\t\t%d\n", numberOfVolumes)

	// Print container size
	size, err := ih.InputContainer.GetSize()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "Container size:\t\t\t%d bytes\n", size)
	}

	fmt.Fprintf(ih.NotifyStream, "\n")

	// Print volume information based on FileSystemIndex
	if ih.FileSystemIndex == -1 {
		// Print all volumes
		for i := 0; i < numberOfVolumes; i++ {
			volume, err := ih.GetVolumeByIndex(i)
			if err != nil {
				return fmt.Errorf("unable to retrieve volume %d: %w", i, err)
			}

			if err := ih.PrintVolumeInfo(i, volume); err != nil {
				return fmt.Errorf("unable to print volume %d info: %w", i, err)
			}

			if i < numberOfVolumes-1 {
				fmt.Fprintf(ih.NotifyStream, "\n")
			}
		}
	} else {
		// Print specific volume
		if ih.FileSystemIndex >= numberOfVolumes {
			return fmt.Errorf("file system index %d out of range (0-%d)", ih.FileSystemIndex, numberOfVolumes-1)
		}

		volume, err := ih.GetVolumeByIndex(ih.FileSystemIndex)
		if err != nil {
			return fmt.Errorf("unable to retrieve volume %d: %w", ih.FileSystemIndex, err)
		}

		if err := ih.PrintVolumeInfo(ih.FileSystemIndex, volume); err != nil {
			return fmt.Errorf("unable to print volume info: %w", err)
		}
	}

	return nil
}

// PrintVolumeInfo prints information about a specific volume
// Corresponds to info_handle_volume_fprint
func (ih *InfoHandle) PrintVolumeInfo(volumeIndex int, volume *apfs.Volume) error {
	if volume == nil {
		return fmt.Errorf("invalid volume")
	}

	fmt.Fprintf(ih.NotifyStream, "Volume: %d\n", volumeIndex+1)

	// Print volume name
	name, err := volume.GetUTF8Name()
	if err == nil && name != "" {
		fmt.Fprintf(ih.NotifyStream, "\tName:\t\t\t%s\n", name)
	}

	// Print volume identifier
	identifier, err := volume.GetIdentifier()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tIdentifier:\t\t%s\n", identifier)
	}

	// Check if volume is locked
	isLocked, err := volume.IsLocked()
	if err == nil {
		if isLocked {
			fmt.Fprintf(ih.NotifyStream, "\tIs locked:\t\tyes\n")
		} else {
			fmt.Fprintf(ih.NotifyStream, "\tIs locked:\t\tno\n")
		}
	}

	// Print volume size
	size, err := volume.GetSize()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tSize:\t\t\t%d bytes\n", size)
	}

	// Print feature flags
	compatible, incompatible, readOnlyCompatible, err := volume.GetFeaturesFlags()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tCompatible features:\t0x%08x\n", compatible)
		fmt.Fprintf(ih.NotifyStream, "\tIncompatible features:\t0x%08x\n", incompatible)
		fmt.Fprintf(ih.NotifyStream, "\tRead-only compatible:\t0x%08x\n", readOnlyCompatible)
	}

	return nil
}

// PrintFileSystemHierarchy prints the file system hierarchy
// Corresponds to info_handle_file_system_hierarchy_fprint
func (ih *InfoHandle) PrintFileSystemHierarchy() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume to display
	var volume *apfs.Volume
	var err error

	if ih.FileSystemIndex == -1 {
		// Default to first volume if "all" was specified
		volume, err = ih.GetVolumeByIndex(0)
	} else {
		volume, err = ih.GetVolumeByIndex(ih.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get root file entry
	rootEntry, err := volume.GetRootDirectory()
	if err != nil {
		return fmt.Errorf("unable to get root directory: %w", err)
	}

	fmt.Fprintf(ih.NotifyStream, "File system hierarchy:\n")
	return ih.printFileEntryRecursive(rootEntry, "/", 0)
}

// printFileEntryRecursive recursively prints file entries
func (ih *InfoHandle) printFileEntryRecursive(entry *apfs.FileEntry, path string, depth int) error {
	if ih.Abort {
		return fmt.Errorf("aborted")
	}

	// Print current entry
	indent := ""
	for i := 0; i < depth; i++ {
		indent += "  "
	}

	name, _ := entry.GetUTF8Name()
	fmt.Fprintf(ih.NotifyStream, "%s%s\n", indent, name)

	// Check if this is a directory by checking file mode
	fileMode, err := entry.GetFileMode()
	if err != nil {
		return err
	}

	isDirectory := (fileMode & 0x4000) != 0 // S_IFDIR equivalent

	if isDirectory {
		numberOfSubEntries, err := entry.GetNumberOfSubFileEntries()
		if err != nil {
			return err
		}

		for i := 0; i < numberOfSubEntries; i++ {
			subEntry, err := entry.GetSubFileEntryByIndex(i)
			if err != nil {
				continue
			}

			subName, _ := subEntry.GetUTF8Name()
			subPath := path
			if path != "/" {
				subPath += "/"
			}
			subPath += subName

			if err := ih.printFileEntryRecursive(subEntry, subPath, depth+1); err != nil {
				return err
			}
		}
	}

	return nil
}

// PrintFileEntryByIdentifier prints information about a file entry by its identifier
// Corresponds to info_handle_file_entry_fprint_by_identifier
func (ih *InfoHandle) PrintFileEntryByIdentifier(identifier uint64) error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.FileSystemIndex == -1 {
		volume, err = ih.GetVolumeByIndex(0)
	} else {
		volume, err = ih.GetVolumeByIndex(ih.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get file entry by identifier
	fileEntry, err := volume.GetFileEntryByIdentifier(identifier)
	if err != nil {
		return fmt.Errorf("unable to get file entry by identifier %d: %w", identifier, err)
	}

	return ih.printFileEntryInfo(fileEntry, "")
}

// PrintFileEntryByPath prints information about a file entry by its path
// Corresponds to info_handle_file_entry_fprint_by_path
func (ih *InfoHandle) PrintFileEntryByPath(path string) error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.FileSystemIndex == -1 {
		volume, err = ih.GetVolumeByIndex(0)
	} else {
		volume, err = ih.GetVolumeByIndex(ih.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get file entry by path
	fileEntry, err := volume.GetFileEntryByPath(path)
	if err != nil {
		return fmt.Errorf("unable to get file entry by path %s: %w", path, err)
	}

	return ih.printFileEntryInfo(fileEntry, path)
}

// printFileEntryInfo prints detailed information about a file entry
func (ih *InfoHandle) printFileEntryInfo(entry *apfs.FileEntry, path string) error {
	if entry == nil {
		return fmt.Errorf("invalid file entry")
	}

	// Get name if path not provided
	if path == "" {
		name, _ := entry.GetUTF8Name()
		path = name
	}

	fmt.Fprintf(ih.NotifyStream, "File entry: %s\n", path)

	// Print identifier
	if identifier, err := entry.GetIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tIdentifier:\t\t%d\n", identifier)
	}

	// Print parent identifier
	if parentID, err := entry.GetParentIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tParent identifier:\t%d\n", parentID)
	}

	// Print file mode
	if fileMode, err := entry.GetFileMode(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tFile mode:\t\t0%o\n", fileMode)
	}

	// Print owner/group
	if uid, err := entry.GetOwnerIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tOwner UID:\t\t%d\n", uid)
	}
	if gid, err := entry.GetGroupIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tGroup GID:\t\t%d\n", gid)
	}

	// Print size
	if size, err := entry.GetSize(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tSize:\t\t\t%d bytes\n", size)
	}

	// Print number of links
	if links, err := entry.GetNumberOfLinks(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tNumber of links:\t%d\n", links)
	}

	// Print timestamps
	if ctime, err := entry.GetCreationTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tCreation time:\t\t%s\n", FormatTimestamp(ctime))
	}
	if mtime, err := entry.GetModificationTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tModification time:\t%s\n", FormatTimestamp(mtime))
	}
	if atime, err := entry.GetAccessTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tAccess time:\t\t%s\n", FormatTimestamp(atime))
	}
	if itime, err := entry.GetInodeChangeTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tInode change time:\t%s\n", FormatTimestamp(itime))
	}

	// Calculate MD5 if requested
	if ih.CalculateMD5 {
		fileMode, _ := entry.GetFileMode()
		isRegularFile := (fileMode & 0x8000) != 0
		if isRegularFile {
			md5Hash, err := CalculateMD5Hash(entry)
			if err == nil {
				fmt.Fprintf(ih.NotifyStream, "\tMD5 hash:\t\t%s\n", md5Hash)
			}
		}
	}

	return nil
}

// PrintFileEntries prints all file entries in bodyfile format
// Corresponds to info_handle_file_entries_fprint
func (ih *InfoHandle) PrintFileEntries() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	if ih.BodyfileStream == nil {
		return fmt.Errorf("bodyfile stream not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.FileSystemIndex == -1 {
		volume, err = ih.GetVolumeByIndex(0)
	} else {
		volume, err = ih.GetVolumeByIndex(ih.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get root directory
	rootEntry, err := volume.GetRootDirectory()
	if err != nil {
		return fmt.Errorf("unable to get root directory: %w", err)
	}

	// Process all entries recursively
	return ih.printFileEntriesRecursive(rootEntry, "/")
}

// printFileEntriesRecursive recursively prints file entries in bodyfile format
func (ih *InfoHandle) printFileEntriesRecursive(entry *apfs.FileEntry, path string) error {
	if ih.Abort {
		return fmt.Errorf("aborted")
	}

	// Create bodyfile entry
	bodyfileEntry, err := FileEntryToBodyfileEntry(entry, path, ih.CalculateMD5)
	if err != nil {
		return fmt.Errorf("unable to create bodyfile entry: %w", err)
	}

	// Write to bodyfile stream
	if err := WriteBodyfileEntry(ih.BodyfileStream, bodyfileEntry); err != nil {
		return fmt.Errorf("unable to write bodyfile entry: %w", err)
	}

	// Process subdirectories
	fileMode, err := entry.GetFileMode()
	if err != nil {
		return err
	}

	isDirectory := (fileMode & 0x4000) != 0
	if isDirectory {
		numberOfSubEntries, err := entry.GetNumberOfSubFileEntries()
		if err != nil {
			return err
		}

		for i := 0; i < numberOfSubEntries; i++ {
			subEntry, err := entry.GetSubFileEntryByIndex(i)
			if err != nil {
				continue
			}

			subName, _ := subEntry.GetUTF8Name()
			subPath := path
			if path != "/" {
				subPath += "/"
			}
			subPath += subName

			if err := ih.printFileEntriesRecursive(subEntry, subPath); err != nil {
				return err
			}
		}
	}

	return nil
}
