// apfs info IMAGE — container and volume summary.
package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/spf13/cobra"
)

var (
	infoHierarchy bool
	infoBodyfile  string
	infoMD5       bool
	infoEntryID   uint64
	infoFilePath  string
)

var infoCmd = &cobra.Command{
	Use:   "info IMAGE",
	Short: "Display container and volume information",
	Long: `Display information about the APFS container in an image and each of
its volumes.

Legacy forensic flags (--hierarchy, --bodyfile, --md5, --entry, --file-path)
produce the detailed fsapfsinfo-style text report; they are text-only.

Examples:
  apfs info image.dmg
  apfs info -o json image.dmg | jq '.volumes[0].name'
  apfs info --bodyfile out.body image.dmg`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runInfo,
}

func init() {
	infoCmd.Flags().BoolVar(&infoHierarchy, "hierarchy", false, "print the full file system hierarchy (text only)")
	infoCmd.Flags().StringVar(&infoBodyfile, "bodyfile", "", "write a Sleuth Kit bodyfile to this path (text only)")
	infoCmd.Flags().BoolVar(&infoMD5, "md5", false, "calculate MD5 hashes in the bodyfile (text only)")
	infoCmd.Flags().Uint64Var(&infoEntryID, "entry", 0, "show the file entry with this identifier (text only)")
	infoCmd.Flags().StringVar(&infoFilePath, "file-path", "", "show the file entry at this volume path (text only)")
}

// containerInfo is the JSON schema for apfs info.
type containerInfo struct {
	UUID        string       `json:"uuid"`
	Size        uint64       `json:"size"`
	BlockSize   uint32       `json:"blockSize"`
	VolumeCount int          `json:"volumeCount"`
	Locked      bool         `json:"locked"`
	Volumes     []volumeInfo `json:"volumes"`
}

type volumeInfo struct {
	Index           int       `json:"index"`
	Name            string    `json:"name"`
	UUID            string    `json:"uuid"`
	CaseInsensitive bool      `json:"caseInsensitive"`
	Locked          bool      `json:"locked"`
	Files           uint64    `json:"files"`
	Directories     uint64    `json:"directories"`
	Symlinks        uint64    `json:"symlinks"`
	Snapshots       uint64    `json:"snapshots"`
	Size            uint64    `json:"size"`
	LastUnmounted   time.Time `json:"lastUnmounted"`
}

func runInfo(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	// Legacy detailed report path (fsapfsinfo port)
	if infoHierarchy || infoBodyfile != "" || infoEntryID != 0 || infoFilePath != "" {
		return runLegacyInfo(imagePath)
	}

	container, closer, err := openContainer(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()
	defer container.Free()

	info, err := collectContainerInfo(container)
	if err != nil {
		return err
	}

	if opts.Output == "json" {
		return jsonOut(info)
	}

	printContainerInfo(info)
	return nil
}

func collectContainerInfo(container *apfs.Container) (*containerInfo, error) {
	uuid, err := container.GetIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unable to get container identifier: %w", err)
	}

	size, err := container.GetSize()
	if err != nil {
		return nil, fmt.Errorf("unable to get container size: %w", err)
	}

	locked, _ := container.IsLocked()

	volumes, err := container.Volumes()
	if err != nil {
		return nil, fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	info := &containerInfo{
		UUID:        formatUUIDBytes(uuid),
		Size:        size,
		BlockSize:   container.IOHandle.BlockSize,
		VolumeCount: len(volumes),
		Locked:      locked,
	}

	for index, volume := range volumes {
		vi := volumeInfo{Index: index}

		if name, err := volume.GetUTF8Name(); err == nil {
			vi.Name = name
		}
		if volUUID, err := volume.GetIdentifier(); err == nil {
			vi.UUID = formatUUIDBytes(volUUID[:])
		}
		if ci, err := volume.IsCaseInsensitive(); err == nil {
			vi.CaseInsensitive = ci
		}
		if volLocked, err := volume.IsLocked(); err == nil {
			vi.Locked = volLocked
		}

		if sb := volume.Superblock; sb != nil {
			vi.Files = sb.NumberOfFiles
			vi.Directories = sb.NumberOfDirectories
			vi.Symlinks = sb.NumberOfSymlinks
			vi.Snapshots = sb.NumberOfSnapshots
			vi.Size = sb.TotalBlocksAllocated * uint64(container.IOHandle.BlockSize)
			if sb.UnmountTime != 0 {
				vi.LastUnmounted = time.Unix(0, int64(sb.UnmountTime)).UTC()
			}
		}

		info.Volumes = append(info.Volumes, vi)
	}

	return info, nil
}

func printContainerInfo(info *containerInfo) {
	fmt.Println("Apple File System (APFS) container:")
	fmt.Println()
	fmt.Printf("  %-18s %s\n", "UUID", info.UUID)
	fmt.Printf("  %-18s %s (%d bytes)\n", "Size", formatSize(info.Size), info.Size)
	fmt.Printf("  %-18s %d bytes\n", "Block size", info.BlockSize)
	fmt.Printf("  %-18s %d\n", "Volumes", info.VolumeCount)
	if info.Locked {
		fmt.Printf("  %-18s yes\n", "Locked")
	}

	for _, vi := range info.Volumes {
		fmt.Println()
		fmt.Printf("Volume %d: %s\n", vi.Index, vi.Name)
		fmt.Printf("  %-18s %s\n", "UUID", vi.UUID)
		fmt.Printf("  %-18s %s (%d bytes)\n", "Size", formatSize(vi.Size), vi.Size)
		fmt.Printf("  %-18s %d files, %d directories, %d symlinks\n", "Contents", vi.Files, vi.Directories, vi.Symlinks)
		if vi.Snapshots > 0 {
			fmt.Printf("  %-18s %d\n", "Snapshots", vi.Snapshots)
		}
		fmt.Printf("  %-18s %v\n", "Case-insensitive", vi.CaseInsensitive)
		if vi.Locked {
			fmt.Printf("  %-18s yes\n", "Locked")
		}
		if !vi.LastUnmounted.IsZero() {
			fmt.Printf("  %-18s %s\n", "Last unmounted", vi.LastUnmounted.Format(time.RFC3339))
		}
	}
}

func formatUUIDBytes(uuid []byte) string {
	if len(uuid) != 16 {
		return fmt.Sprintf("%x", uuid)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}

// runLegacyInfo produces the detailed fsapfsinfo-style report through the
// ported InfoHandle (text only).
func runLegacyInfo(imagePath string) error {
	if opts.Output == "json" {
		return usageErrorf("--hierarchy/--bodyfile/--entry/--file-path produce text output only")
	}

	handle, err := tools.NewInfoHandle(infoMD5)
	if err != nil {
		return err
	}
	handle.NotifyStream = os.Stdout

	if opts.Volume != "" {
		if err := handle.SetFileSystemIndex(opts.Volume); err != nil {
			return usageErrorf("legacy info flags select volumes by index: %v", err)
		}
	}
	if opts.Offset != 0 {
		handle.VolumeOffset = opts.Offset
	}
	if opts.Password != "" {
		handle.SetPassword(opts.Password)
	}
	if opts.RecoveryPassword != "" {
		handle.SetRecoveryPassword(opts.RecoveryPassword)
	}
	if infoBodyfile != "" {
		if err := handle.SetBodyfile(infoBodyfile); err != nil {
			return err
		}
	}

	if err := handle.OpenInput(imagePath); err != nil {
		return withCode(ExitBadImage, err)
	}
	defer handle.CloseInput()

	switch {
	case infoEntryID != 0:
		return handle.PrintFileEntryByIdentifier(infoEntryID)
	case infoFilePath != "":
		return handle.PrintFileEntryByPath(infoFilePath)
	case infoBodyfile != "":
		return handle.PrintFileEntries()
	default:
		return handle.PrintFileSystemHierarchy()
	}
}
