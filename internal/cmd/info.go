package cmd

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
)

var (
	// Info command flags
	infoBodyfileOutput   string
	infoCalculateMD5     bool
	infoFileEntryID      uint64
	infoFileEntryPath    string
	infoVolumeIndex      int
	infoShowHierarchy    bool
	infoVolumeOffset     int64
	infoUserPassword     string
	infoRecoveryPassword string
	infoVerbose          bool

	infoCmd = &cobra.Command{
		Use:   "info [options] <container>",
		Short: "Display information about APFS containers and volumes",
		Long: `Display detailed information about Apple File System (APFS) containers and volumes.

The info command can show:
  - Container metadata and properties
  - Volume information and encryption status
  - File system hierarchy
  - Individual file entries by ID or path
  - Generate bodyfile output for forensic analysis`,
		Example: `  # Display container information
  apfs info /dev/disk2

  # Show file system hierarchy
  apfs info --hierarchy /dev/disk2

  # Generate bodyfile with MD5 hashes
  apfs info --bodyfile output.bodyfile --calculate-md5 /dev/disk2

  # Show specific file entry by path
  apfs info --entry-path /Users/test/file.txt /dev/disk2

  # Use with encrypted volume
  apfs info --password "secret" /dev/disk2`,
		Args:              cobra.ExactArgs(1),
		RunE:              runInfo,
		DisableAutoGenTag: true,
	}
)

func init() {
	// Output flags
	infoCmd.Flags().StringVarP(&infoBodyfileOutput, "bodyfile", "B", "", "write bodyfile output to file")
	infoCmd.Flags().BoolVarP(&infoCalculateMD5, "calculate-md5", "d", false, "calculate MD5 hashes for files")

	// Query flags
	infoCmd.Flags().Uint64VarP(&infoFileEntryID, "entry-id", "E", 0, "show file entry by identifier")
	infoCmd.Flags().StringVarP(&infoFileEntryPath, "entry-path", "F", "", "show file entry by path")
	infoCmd.Flags().IntVarP(&infoVolumeIndex, "volume", "f", 0, "select volume by index (default: 0)")
	infoCmd.Flags().BoolVarP(&infoShowHierarchy, "hierarchy", "H", false, "show file system hierarchy")

	// Container flags
	infoCmd.Flags().Int64VarP(&infoVolumeOffset, "offset", "o", 0, "container offset in bytes")
	infoCmd.Flags().StringVarP(&infoUserPassword, "password", "p", "", "user password for encrypted volumes")
	infoCmd.Flags().StringVarP(&infoRecoveryPassword, "recovery-password", "r", "", "recovery password for encrypted volumes")

	// General flags
	infoCmd.Flags().BoolVarP(&infoVerbose, "verbose", "v", false, "verbose output to stderr")
}

func runInfo(cmd *cobra.Command, args []string) error {
	containerPath := args[0]

	// Create info handle
	handle, err := tools.NewInfoHandle(false)
	if err != nil {
		return fmt.Errorf("unable to create info handle: %w", err)
	}
	handle.FileSystemIndex = infoVolumeIndex
	handle.VolumeOffset = infoVolumeOffset
	handle.UserPassword = infoUserPassword
	handle.RecoveryPassword = infoRecoveryPassword
	handle.CalculateMD5 = infoCalculateMD5

	if infoVerbose {
		handle.NotifyStream = os.Stderr
	}

	// Open bodyfile output if specified
	if infoBodyfileOutput != "" {
		file, err := os.Create(infoBodyfileOutput)
		if err != nil {
			return fmt.Errorf("unable to create bodyfile: %w", err)
		}
		defer file.Close()
		handle.BodyfileStream = file
	}

	// Open the container
	if err := handle.OpenInput(containerPath); err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer handle.CloseInput()

	// Execute the appropriate operation
	switch {
	case infoFileEntryID > 0:
		return handle.PrintFileEntryByIdentifier(infoFileEntryID)

	case infoFileEntryPath != "":
		return handle.PrintFileEntryByPath(infoFileEntryPath)

	case infoShowHierarchy:
		return handle.PrintFileSystemHierarchy()

	case infoBodyfileOutput != "":
		return handle.PrintFileEntries()

	default:
		return handle.PrintContainerInfo()
	}
}
