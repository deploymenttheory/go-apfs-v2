package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
)

var (
	// Mount command flags
	mountVolumeIndex      string
	mountVolumeOffset     string
	mountUserPassword     string
	mountRecoveryPassword string
	mountVerbose          bool

	mountCmd = &cobra.Command{
		Use:   "mount [options] <container> <mount_point>",
		Short: "Mount an APFS container using FUSE",
		Long: `Mount an Apple File System (APFS) container using FUSE.

The mount command provides read-only access to APFS volumes with support for:
  - Password-protected volumes (user and recovery passwords)
  - Multiple volumes within a container
  - Full file system browsing via standard filesystem operations`,
		Example: `  # Mount first volume
  apfs mount /dev/disk2 /mnt/apfs

  # Mount specific volume
  apfs mount --volume 0 /dev/disk2 /mnt/apfs

  # Mount with password
  apfs mount --password "secret" /dev/disk2 /mnt/apfs

  # Verbose output
  apfs mount --verbose /dev/disk2 /mnt/apfs`,
		Args:              cobra.ExactArgs(2),
		RunE:              runMount,
		DisableAutoGenTag: true,
	}
)

func init() {
	// Mount flags
	mountCmd.Flags().StringVarP(&mountVolumeIndex, "volume", "f", "0", "volume index to mount (default: 0)")
	mountCmd.Flags().StringVarP(&mountVolumeOffset, "offset", "o", "0", "container offset in bytes")
	mountCmd.Flags().StringVarP(&mountUserPassword, "password", "p", "", "user password for encrypted volumes")
	mountCmd.Flags().StringVarP(&mountRecoveryPassword, "recovery-password", "r", "", "recovery password for encrypted volumes")

	// General flags
	mountCmd.Flags().BoolVarP(&mountVerbose, "verbose", "v", false, "verbose output to stderr")
}

func runMount(cmd *cobra.Command, args []string) error {
	containerPath := args[0]
	mountPoint := args[1]

	// Validate mount point
	if stat, err := os.Stat(mountPoint); err != nil {
		return fmt.Errorf("mount point does not exist: %w", err)
	} else if !stat.IsDir() {
		return fmt.Errorf("mount point is not a directory")
	}

	// Create mount handle
	mountHandle := tools.NewMountHandle()

	if mountVerbose {
		mountHandle.NotifyStream = os.Stderr
	}

	// Set volume index
	if mountVolumeIndex != "" {
		if err := mountHandle.SetFileSystemIndex(mountVolumeIndex); err != nil {
			return fmt.Errorf("invalid volume index: %w", err)
		}
	}

	// Set offset
	if mountVolumeOffset != "" && mountVolumeOffset != "0" {
		if err := mountHandle.SetOffset(mountVolumeOffset); err != nil {
			return fmt.Errorf("invalid offset: %w", err)
		}
	}

	// Set passwords
	if mountUserPassword != "" {
		if err := mountHandle.SetPassword(mountUserPassword); err != nil {
			return fmt.Errorf("unable to set password: %w", err)
		}
	}

	if mountRecoveryPassword != "" {
		if err := mountHandle.SetRecoveryPassword(mountRecoveryPassword); err != nil {
			return fmt.Errorf("unable to set recovery password: %w", err)
		}
	}

	// Open the container
	if err := mountHandle.Open(containerPath); err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer mountHandle.Close()

	if mountVerbose {
		fmt.Fprintf(os.Stderr, "Container opened successfully\n")
		if mountHandle.IsContainerLocked() {
			fmt.Fprintf(os.Stderr, "Warning: Container is locked\n")
		}
	}

	// Get number of volumes
	numVolumes, err := mountHandle.GetNumberOfVolumes()
	if err != nil {
		return fmt.Errorf("unable to get number of volumes: %w", err)
	}

	if mountVerbose {
		fmt.Fprintf(os.Stderr, "Number of volumes: %d\n", numVolumes)
	}

	// Determine which volume to mount
	volumeToMount := mountHandle.FileSystemIndex
	if volumeToMount < 0 || volumeToMount >= numVolumes {
		return fmt.Errorf("invalid volume index: %d (available: 0-%d)", volumeToMount, numVolumes-1)
	}

	if mountVerbose {
		volume, err := mountHandle.GetVolumeByIndex(volumeToMount)
		if err != nil {
			return fmt.Errorf("unable to get volume %d: %w", volumeToMount, err)
		}

		name, err := volume.GetUTF8Name()
		if err == nil {
			fmt.Fprintf(os.Stderr, "Mounting volume %d: %s\n", volumeToMount, string(name))
		} else {
			fmt.Fprintf(os.Stderr, "Mounting volume %d\n", volumeToMount)
		}
		fmt.Fprintf(os.Stderr, "Mount point: %s\n", mountPoint)
	}

	// Mount the filesystem using FUSE
	server, err := tools.MountAPFS(mountHandle, volumeToMount, mountPoint, mountVerbose)
	if err != nil {
		return fmt.Errorf("unable to mount filesystem: %w", err)
	}

	if mountVerbose {
		fmt.Fprintf(os.Stderr, "Filesystem mounted successfully\n")
		fmt.Fprintf(os.Stderr, "Press Ctrl+C to unmount...\n")
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	<-sigChan
	if mountVerbose {
		fmt.Fprintf(os.Stderr, "\nReceived signal, unmounting...\n")
	}

	// Unmount
	if err := tools.UnmountAPFS(server); err != nil {
		return fmt.Errorf("error during unmount: %w", err)
	}

	if mountVerbose {
		fmt.Fprintf(os.Stderr, "Unmounted successfully\n")
	}

	return nil
}
