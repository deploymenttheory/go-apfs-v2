// apfs snapshot — inspect APFS volume snapshots.
package cli

import (
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Inspect APFS volume snapshots",
	Long: `Work with APFS snapshots.

Snapshots are created at build time with 'create --fs apfs --snapshot NAME' or
'pack <dir> --fs apfs --snapshot NAME'. This command group inspects them.`,
}

func init() {
	snapshotCmd.AddCommand(snapshotListCmd)
}

var snapshotListCmd = &cobra.Command{
	Use:   "list IMAGE",
	Short: "List the snapshots on each APFS volume in an image",
	Args:  exactArgs(1, "IMAGE"),
	RunE:  runSnapshotList,
}

// openAPFSContainer opens imagePath as an APFS container (sniffing the DMG/raw
// layout and applying --offset), returning the container and a cleanup function.
// It is APFS-only: snapshots are an APFS concept.
func openAPFSContainer(imagePath string) (*apfs.Container, func(), error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}
	base := io.ReaderAt(reader)
	if offset != 0 {
		base = io.NewSectionReader(reader, offset, math.MaxInt64-offset)
	}
	if sniffFilesystem(base) != "apfs" {
		closer.Close()
		return nil, nil, withCode(ExitUnsupported, fmt.Errorf("%s is not an APFS image; snapshots are APFS-only", imagePath))
	}

	container, err := apfs.Open(base, &apfs.OpenOptions{
		Password:         opts.Password,
		RecoveryPassword: opts.RecoveryPassword,
	})
	if err != nil {
		closer.Close()
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open APFS container: %w", err))
	}
	return container, func() { container.Free(); closer.Close() }, nil
}

// snapshotJSON is one snapshot in the JSON output.
type snapshotJSON struct {
	Volume      int       `json:"volume"`
	VolumeName  string    `json:"volumeName"`
	Name        string    `json:"name"`
	XID         uint64    `json:"xid"`
	CreatedTime time.Time `json:"created,omitempty"`
}

func runSnapshotList(cmd *cobra.Command, args []string) error {
	container, cleanup, err := openAPFSContainer(args[0])
	if err != nil {
		return err
	}
	defer cleanup()

	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	var out []snapshotJSON
	for vi, volume := range volumes {
		volName, _ := volume.GetUTF8Name()
		n, err := volume.GetNumberOfSnapshots()
		if err != nil {
			return fmt.Errorf("volume %d: unable to read snapshots: %w", vi, err)
		}
		for i := 0; i < n; i++ {
			snap, err := volume.GetSnapshot(i)
			if err != nil {
				return fmt.Errorf("volume %d snapshot %d: %w", vi, i, err)
			}
			name, _ := snap.GetUTF8Name()
			s := snapshotJSON{Volume: vi, VolumeName: volName, Name: name}
			if snap.SnapshotMetadata != nil {
				s.XID = snap.SnapshotMetadata.ObjectIdentifier
				if t := snap.SnapshotMetadata.CreationTime; t != 0 {
					s.CreatedTime = time.Unix(0, int64(t)).UTC()
				}
			}
			out = append(out, s)
		}
	}

	if opts.Output == "json" {
		return jsonOut(out)
	}
	if len(out) == 0 {
		if !opts.Quiet {
			fmt.Println("No snapshots.")
		}
		return nil
	}
	for _, s := range out {
		created := ""
		if !s.CreatedTime.IsZero() {
			created = "  " + s.CreatedTime.Format(time.RFC3339)
		}
		fmt.Printf("Volume %d (%s): %s  (xid %d)%s\n", s.Volume, s.VolumeName, s.Name, s.XID, created)
	}
	return nil
}
