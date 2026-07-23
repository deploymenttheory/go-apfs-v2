// Cat tool: stream a file from an APFS volume to stdout
package tools

import (
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/spf13/cobra"
)

var (
	catContainerPath string
	catVolumeIndex   int
)

// CatCmd represents the cat command
var CatCmd = &cobra.Command{
	Use:   "cat <path>...",
	Short: "Write file contents to standard output",
	Long: `Write the contents of one or more files from an APFS volume to
standard output, for use in pipelines.

Examples:
  apfs cat --container image.dmg /etc/hosts
  apfs cat --container image.dmg /app/Info.plist | plutil -p -`,
	Args: cobra.MinimumNArgs(1),
	RunE: runCat,
}

func init() {
	CatCmd.Flags().StringVarP(&catContainerPath, "container", "c", "", "Path to APFS container (required)")
	CatCmd.Flags().IntVarP(&catVolumeIndex, "volume", "f", 0, "Volume index (default: 0)")
	CatCmd.MarkFlagRequired("container")
}

func runCat(cmd *cobra.Command, args []string) error {
	container, closer, err := apfs.OpenImage(catContainerPath, nil)
	if err != nil {
		return fmt.Errorf("unable to open container: %w", err)
	}
	defer closer.Close()
	defer container.Free()

	volume, err := container.GetVolume(catVolumeIndex)
	if err != nil {
		return fmt.Errorf("unable to get volume: %w", err)
	}

	for _, volumePath := range args {
		name := fsNameFromVolumePath(volumePath)

		file, err := volume.Open(name)
		if err != nil {
			return fmt.Errorf("unable to open %s: %w", volumePath, err)
		}

		if info, err := file.Stat(); err == nil && info.IsDir() {
			file.Close()
			return fmt.Errorf("%s is a directory", volumePath)
		}

		if _, err := io.Copy(os.Stdout, file); err != nil {
			file.Close()
			return fmt.Errorf("unable to read %s: %w", volumePath, err)
		}
		file.Close()
	}

	return nil
}
