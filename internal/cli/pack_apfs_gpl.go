//go:build apfswrite

// This file wires APFS directory packing into the CLI. It imports pkg/apfswrite,
// a GPL-2.0 port of mkapfs, so a binary built with -tags apfswrite is covered by
// the GPL-2.0. Without the tag, the default binary is MIT and `pack --fs apfs`
// is unavailable (see pack_apfs_stub.go).
package cli

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// packDirectoryAPFS builds an APFS container from srcDir and wraps it in a DMG.
func packDirectoryAPFS(srcDir, dstPath, volname string, encOpts *disk.EncodeOptions) error {
	var buf writeAtBuffer
	if err := apfswrite.CreateContainerFromDir(&buf, 0, srcDir, &apfswrite.CreateOptions{VolumeName: volname}); err != nil {
		return fmt.Errorf("unable to build APFS container from %s: %w", srcDir, err)
	}

	if err := disk.WrapRawImageDMG(dstPath, buf.Bytes(), "Apple_APFS", encOpts); err != nil {
		return fmt.Errorf("unable to write DMG %s: %w", dstPath, err)
	}

	return packReport(srcDir, dstPath, int64(len(buf.Bytes())))
}
