package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/apfs"
	"github.com/spf13/cobra"
)

// ListCmd represents the list command
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List directory contents or show file information",
	Long: `List directory contents or display information about a specific file.

This command navigates the APFS filesystem structure without mounting the volume,
allowing you to browse directories and view file metadata.

Examples:
  # List root directory of volume 0
  apfs list --container /dev/disk0s2 --volume 0 --path /

  # List specific directory
  apfs list --container /dev/disk0s2 --volume 0 --path /Users

  # Show detailed file information
  apfs list --container /dev/disk0s2 --volume 0 --path /etc/hosts --verbose

  # List by filesystem object ID (FSOID)
  apfs list --container /dev/disk0s2 --volume 0 --fsoid 2`,
	RunE: runList,
}

var (
	listContainerPath string
	listVolumeIndex   int
	listPath          string
	listFSOID         uint64
	listVerbose       bool
	listLongFormat    bool
	listRecursive     bool
	listColor         bool
)

// ANSI color codes
const (
	colorReset      = "\033[0m"
	colorBlue       = "\033[34m"   // Directories
	colorCyan       = "\033[36m"   // Symlinks
	colorGreen      = "\033[32m"   // Executables
	colorBrightBlue = "\033[1;34m" // Directories (bold)
)

func init() {
	ListCmd.Flags().StringVarP(&listContainerPath, "container", "c", "", "Path to APFS container (required)")
	ListCmd.Flags().IntVarP(&listVolumeIndex, "volume", "f", 0, "Volume index (default: 0)")
	ListCmd.Flags().StringVarP(&listPath, "path", "p", "/", "Directory or file path")
	ListCmd.Flags().Uint64VarP(&listFSOID, "fsoid", "F", 0, "Filesystem object ID (alternative to --path)")
	ListCmd.Flags().BoolVarP(&listVerbose, "verbose", "v", false, "Verbose output")
	ListCmd.Flags().BoolVarP(&listLongFormat, "long", "l", false, "Use long listing format (like ls -l)")
	ListCmd.Flags().BoolVarP(&listRecursive, "recursive", "R", false, "List subdirectories recursively")
	ListCmd.Flags().BoolVar(&listColor, "color", true, "Colorize output (directories=blue, symlinks=cyan)")

	ListCmd.MarkFlagRequired("container")
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
	// Use the existing InfoHandle infrastructure
	handle, err := NewInfoHandle(false)
	if err != nil {
		return fmt.Errorf("unable to create info handle: %w", err)
	}

	handle.FileSystemIndex = listVolumeIndex
	if listVerbose {
		handle.NotifyStream = os.Stderr
		fmt.Fprintf(os.Stderr, "Container: %s\n", listContainerPath)
		fmt.Fprintf(os.Stderr, "Volume: index %d\n", listVolumeIndex)
		if listPath != "" {
			fmt.Fprintf(os.Stderr, "Path: %s\n\n", listPath)
		}
	}

	if err := handle.OpenInput(listContainerPath); err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer handle.CloseInput()

	// List directory or show file info
	if listFSOID > 0 {
		return listByFSOID(handle, listFSOID)
	} else {
		return listByPath(handle, listPath, listLongFormat, listRecursive)
	}
}

// listByFSOID lists a file or directory by its filesystem object ID
func listByFSOID(handle *InfoHandle, fsoid uint64) error {
	fmt.Printf("Listing by FSOID: 0x%x (%d)\n", fsoid, fsoid)
	fmt.Println()

	// Use the existing file entry printing functionality
	return handle.PrintFileEntryByIdentifier(fsoid)
}

// listByPath lists a directory or shows file information by path
func listByPath(handle *InfoHandle, path string, longFormat, recursive bool) error {
	// Clean the path
	path = filepath.Clean(path)
	if path == "" {
		path = "/"
	}

	// For root directory, list its contents
	if path == "/" {
		return listRootDirectory(handle, longFormat, recursive)
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if handle.FileSystemIndex == -1 {
		volume, err = handle.GetVolumeByIndex(0)
	} else {
		volume, err = handle.GetVolumeByIndex(handle.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get the file entry for the path
	fileEntry, err := volume.GetFileEntryByPath(path)
	if err != nil {
		return fmt.Errorf("unable to get file entry by path %s: %w", path, err)
	}

	// Check if it's a directory
	fileType := fileEntry.Inode.FileMode & 0xf000
	if fileType == 0x4000 {
		// It's a directory - list its contents
		return listDirectoryContents(volume, fileEntry.Inode.Identifier, longFormat, recursive, "")
	}

	// It's a file or symlink - show its info
	return handle.PrintFileEntryByPath(path)
}

// listRootDirectory lists the root directory of the volume
func listRootDirectory(handle *InfoHandle, longFormat, recursive bool) error {
	// Get the volume
	var volume *apfs.Volume
	var err error

	if handle.FileSystemIndex == -1 {
		volume, err = handle.GetVolumeByIndex(0)
	} else {
		volume, err = handle.GetVolumeByIndex(handle.FileSystemIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get root directory (FSOID 2 is the root directory in APFS)
	rootFSOID := uint64(2)

	// List contents of the root directory
	return listDirectoryContents(volume, rootFSOID, longFormat, recursive, "")
}

// listDirectoryContents lists the contents of a directory by its FSOID.
// When recursive is set, entries are printed as paths relative to the
// starting directory (find-style) and subdirectories are descended into.
func listDirectoryContents(volume *apfs.Volume, parentFSOID uint64, longFormat, recursive bool, prefix string) error {
	// Get the directory's file entry to ensure it exists and is a directory
	dirEntry, err := volume.GetFileEntryByIdentifier(parentFSOID)
	if err != nil {
		return fmt.Errorf("unable to get directory: %w", err)
	}

	// Check if it's a directory
	fileType := dirEntry.Inode.FileMode & 0xf000
	if fileType != 0x4000 {
		return fmt.Errorf("not a directory (file mode: 0%o)", dirEntry.Inode.FileMode)
	}

	// Get directory entries (children)
	fileHandle := volume.FileIOHandle
	if fileHandle == nil {
		return fmt.Errorf("no file handle available")
	}

	fsTree := dirEntry.FileSystemBTree
	if fsTree == nil {
		return fmt.Errorf("no filesystem B-tree available")
	}

	dirRecords, err := fsTree.GetDirectoryEntries(fileHandle, parentFSOID, volume.Superblock.ObjectTransactionIdentifier)
	if err != nil {
		return fmt.Errorf("unable to get directory entries: %w", err)
	}

	if len(dirRecords) == 0 {
		// Empty directory
		return nil
	}

	// Print header if using long format
	if longFormat {
		printLsStyleHeader()
	}

	// Display each directory entry
	for _, dirRecord := range dirRecords {
		// Get the inode for this entry
		childEntry, err := volume.GetFileEntryByIdentifier(dirRecord.Identifier)
		if err != nil {
			// DEBUG: Print the error instead of silently skipping
			fmt.Fprintf(os.Stderr, "Warning: unable to get entry for '%s' (FSOID %d): %v\n", string(dirRecord.Name), dirRecord.Identifier, err)
			continue
		}

		inode := childEntry.Inode
		name := string(dirRecord.Name)
		displayName := name
		if recursive && prefix != "" {
			displayName = prefix + "/" + name
		}

		// Get color based on file type
		color := getColorForFileMode(inode.FileMode, listColor)
		coloredName := colorize(displayName, color, listColor)

		if longFormat {
			// Print in ls-style format
			perms := formatPermissionsFromMode(inode.FileMode)
			size := formatHumanSize(inode.DataStreamSize)
			timestamp := formatTimestampShort(inode.ModificationTime)

			fmt.Printf("%-12s %5d %6d %6d %7s %-15s %6d  %s\n",
				perms,
				inode.NumberOfLinks,
				inode.OwnerIdentifier,
				inode.GroupIdentifier,
				size,
				timestamp,
				inode.Identifier,
				coloredName)
		} else {
			// Simple format: just the name
			fmt.Println(coloredName)
		}

		// Descend into subdirectories when listing recursively
		if recursive && (inode.FileMode&0xf000) == 0x4000 {
			childPrefix := name
			if prefix != "" {
				childPrefix = prefix + "/" + name
			}
			if err := listDirectoryContents(volume, inode.Identifier, longFormat, true, childPrefix); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: unable to list %s: %v\n", childPrefix, err)
			}
		}
	}

	return nil
}

// formatTimestamp formats a Unix timestamp as a string
func formatTimestamp(timestamp uint64) string {
	// APFS stores timestamps as nanoseconds since Unix epoch
	t := time.Unix(0, int64(timestamp))
	return t.Format("2006-01-02 15:04:05")
}

// formatTimestampShort formats a Unix timestamp as a short string (for ls-style output)
func formatTimestampShort(timestamp uint64) string {
	// APFS stores timestamps as nanoseconds since Unix epoch
	t := time.Unix(0, int64(timestamp))
	now := time.Now()

	// If within the last 6 months, show month/day/time
	if now.Sub(t) < 180*24*time.Hour {
		return t.Format("Jan  2 15:04")
	}
	// Otherwise show month/day/year
	return t.Format("Jan  2  2006")
}

// formatHumanSize formats a size in bytes to human-readable format
func formatHumanSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"K", "M", "G", "T", "P", "E"}
	return fmt.Sprintf("%.1f%s", float64(bytes)/float64(div), units[exp])
}

// formatPermissions formats a file mode into Unix-style permissions string
func formatPermissionsFromMode(fileMode uint16) string {
	var perms strings.Builder

	// File type
	mode := fileMode & 0xf000
	switch mode {
	case 0x4000: // Directory
		perms.WriteRune('d')
	case 0xa000: // Symlink
		perms.WriteRune('l')
	case 0x8000: // Regular file
		perms.WriteRune('-')
	case 0x6000: // Block device
		perms.WriteRune('b')
	case 0x2000: // Character device
		perms.WriteRune('c')
	case 0x1000: // FIFO
		perms.WriteRune('p')
	case 0xc000: // Socket
		perms.WriteRune('s')
	default:
		perms.WriteRune('?')
	}

	// Owner permissions
	perm := fileMode & 0x01ff
	if perm&0400 != 0 {
		perms.WriteRune('r')
	} else {
		perms.WriteRune('-')
	}
	if perm&0200 != 0 {
		perms.WriteRune('w')
	} else {
		perms.WriteRune('-')
	}
	if perm&0100 != 0 {
		perms.WriteRune('x')
	} else {
		perms.WriteRune('-')
	}

	// Group permissions
	if perm&0040 != 0 {
		perms.WriteRune('r')
	} else {
		perms.WriteRune('-')
	}
	if perm&0020 != 0 {
		perms.WriteRune('w')
	} else {
		perms.WriteRune('-')
	}
	if perm&0010 != 0 {
		perms.WriteRune('x')
	} else {
		perms.WriteRune('-')
	}

	// Other permissions
	if perm&0004 != 0 {
		perms.WriteRune('r')
	} else {
		perms.WriteRune('-')
	}
	if perm&0002 != 0 {
		perms.WriteRune('w')
	} else {
		perms.WriteRune('-')
	}
	if perm&0001 != 0 {
		perms.WriteRune('x')
	} else {
		perms.WriteRune('-')
	}

	return perms.String()
}

// printLsStyleHeader prints the header for ls-style output
func printLsStyleHeader() {
	fmt.Printf("%-12s %5s %6s %6s %7s %-15s %6s  %s\n",
		"Permissions", "Links", "Owner", "Group", "Size", "Modified", "FSOID", "Name")
}

// getColorForFileMode returns the ANSI color code for a file based on its mode
func getColorForFileMode(fileMode uint16, useColor bool) string {
	if !useColor {
		return ""
	}

	// Extract file type from mode
	fileType := fileMode & 0xf000
	permissions := fileMode & 0x01ff

	switch fileType {
	case 0x4000: // Directory
		return colorBrightBlue
	case 0xa000: // Symlink
		return colorCyan
	case 0x8000: // Regular file
		// Check if executable
		if permissions&0111 != 0 { // Any execute bit set
			return colorGreen
		}
		return "" // Default color
	default:
		return "" // Default color for special files
	}
}

// colorize wraps text in ANSI color codes if color is enabled
func colorize(text string, color string, useColor bool) string {
	if !useColor || color == "" {
		return text
	}
	return color + text + colorReset
}
