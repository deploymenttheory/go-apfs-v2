// Wires APFS volume creation (create --fs apfs) into the CLI via the pure-Go
// pkg/apfswrite builder.
package cli

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func createAPFS(dstPath string, sizeBytes int64) error {
	containerUUID, volumeUUID, err := createUUIDs.resolve()
	if err != nil {
		return err
	}
	role, err := apfs.ParseVolumeRole(createRole)
	if err != nil {
		return usageErrorf("invalid --role: %v", err)
	}
	var volumeGroup [16]byte
	if createVolGroup != "" {
		if volumeGroup, err = parseUUIDFlag("--volume-group", createVolGroup); err != nil {
			return err
		}
		// A volume group is a system/data pair and this writer emits one volume
		// per container, so only the system half can be written. Catch it here
		// so it reads as a usage error rather than a container-build failure.
		if role != apfs.VolumeRoleSystem {
			return usageErrorf("--volume-group requires --role system: a volume group is a system/data pair, " +
				"and only one volume per container can be written today, so the data half cannot accompany it")
		}
	}
	fixed, clamp := writerTimes()

	createOpts := &apfswrite.CreateOptions{
		VolumeName:    createVolName,
		CaseSensitive: createCaseSens,
		ContainerUUID: containerUUID,
		VolumeUUID:    volumeUUID,
		Role:          role,
		VolumeGroupID: volumeGroup,
		FixedTime:     fixed,
		ClampModTimes: clamp,
	}
	if createSnapshot != "" {
		createOpts.Snapshots = []apfswrite.SnapshotSpec{{Name: createSnapshot}}
	}
	if err := ensureScratchSpace(scratchDir(dstPath), dstPath, uint64(sizeBytes)); err != nil {
		return err
	}

	img, err := newScratchImage(dstPath)
	if err != nil {
		return err
	}
	defer img.Close()

	if err := apfswrite.CreateContainer(img, sizeBytes, createOpts); err != nil {
		return fmt.Errorf("unable to create APFS container: %w", err)
	}
	if err := disk.WrapRawImageDMGFrom(dstPath, img, img.Size(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write DMG: %w", err)
	}
	return createReport(dstPath, "apfs")
}
