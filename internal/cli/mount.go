// apfs mount IMAGE MOUNTPOINT — read-only FUSE mount.
package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
)

var mountCmd = &cobra.Command{
	Use:   "mount IMAGE MOUNTPOINT",
	Short: "Mount an APFS image read-only via FUSE (Linux and macOS)",
	Long: `Mount an APFS image read-only using FUSE. Available on Linux and
macOS (requires macFUSE); on other platforms this command exits with code 5.

Press Ctrl+C to unmount.

Examples:
  apfs mount image.dmg /mnt/apfs
  apfs mount -v 1 image.dmg /mnt/apfs`,
	Args: exactArgs(2, "IMAGE MOUNTPOINT"),
	RunE: runMount,
}

func runMount(cmd *cobra.Command, args []string) error {
	imagePath := args[0]
	mountPoint := args[1]

	if stat, err := os.Stat(mountPoint); err != nil {
		return usageErrorf("mount point does not exist: %v", err)
	} else if !stat.IsDir() {
		return usageErrorf("mount point is not a directory")
	}

	mountHandle := tools.NewMountHandle()

	if opts.Verbose {
		mountHandle.NotifyStream = os.Stderr
	}

	volumeIndex := 0
	if opts.Volume != "" {
		index, err := strconv.Atoi(opts.Volume)
		if err != nil {
			return usageErrorf("mount selects volumes by index: %v", err)
		}
		volumeIndex = index
	}

	if opts.Offset != 0 {
		mountHandle.VolumeOffset = opts.Offset
	}
	if opts.Password != "" {
		if err := mountHandle.SetPassword(opts.Password); err != nil {
			return err
		}
	}
	if opts.RecoveryPassword != "" {
		if err := mountHandle.SetRecoveryPassword(opts.RecoveryPassword); err != nil {
			return err
		}
	}

	if err := mountHandle.Open(imagePath); err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open container: %w", err))
	}
	defer mountHandle.Close()

	numVolumes, err := mountHandle.GetNumberOfVolumes()
	if err != nil {
		return fmt.Errorf("unable to get number of volumes: %w", err)
	}
	if volumeIndex < 0 || volumeIndex >= numVolumes {
		return usageErrorf("invalid volume index: %d (available: 0-%d)", volumeIndex, numVolumes-1)
	}

	server, err := tools.MountAPFS(mountHandle, volumeIndex, mountPoint, opts.Verbose)
	if err != nil {
		return withCode(ExitUnsupported, fmt.Errorf("unable to mount filesystem: %w", err))
	}

	if !opts.Quiet {
		fmt.Fprintf(os.Stderr, "Mounted at %s. Press Ctrl+C to unmount.\n", mountPoint)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	if !opts.Quiet {
		fmt.Fprintln(os.Stderr, "\nUnmounting...")
	}

	if err := tools.UnmountAPFS(server); err != nil {
		return fmt.Errorf("error during unmount: %w", err)
	}

	return nil
}
