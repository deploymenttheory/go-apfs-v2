// Wires APFS volume creation (create --fs apfs) into the CLI via the pure-Go
// pkg/apfswrite builder.
package cli

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func createAPFS(dstPath string, sizeBytes int64) error {
	containerUUID, volumeUUID, err := createUUIDs.resolve()
	if err != nil {
		return err
	}
	fixed, clamp := writerTimes()

	createOpts := &apfswrite.CreateOptions{
		VolumeName:    createVolName,
		CaseSensitive: createCaseSens,
		ContainerUUID: containerUUID,
		VolumeUUID:    volumeUUID,
		FixedTime:     fixed,
		ClampModTimes: clamp,
	}
	if createSnapshot != "" {
		createOpts.Snapshots = []apfswrite.SnapshotSpec{{Name: createSnapshot}}
	}
	var buf writeAtBuffer
	if err := apfswrite.CreateContainer(&buf, sizeBytes, createOpts); err != nil {
		return fmt.Errorf("unable to create APFS container: %w", err)
	}
	if err := disk.WrapRawImageDMG(dstPath, buf.Bytes(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write DMG: %w", err)
	}
	return createReport(dstPath, "apfs")
}
