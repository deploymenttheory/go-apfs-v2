//go:build apfswrite

// This file wires APFS creation into the CLI. It imports pkg/apfswrite, which
// is a GPL-2.0 port of mkapfs, so a binary built with -tags apfswrite is
// covered by the GPL-2.0. Without the tag, the default binary is MIT and APFS
// creation is unavailable (see create_apfs_stub.go).
package cli

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func createAPFS(dstPath string, sizeBytes int64) error {
	var buf writeAtBuffer
	err := apfswrite.CreateContainer(&buf, sizeBytes, &apfswrite.CreateOptions{
		VolumeName:    createVolName,
		CaseSensitive: createCaseSens,
	})
	if err != nil {
		return fmt.Errorf("unable to create APFS container: %w", err)
	}
	if err := disk.WrapRawImageDMG(dstPath, buf.Bytes(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write DMG: %w", err)
	}
	return createReport(dstPath, "apfs")
}
