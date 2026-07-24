//go:build !apfswrite

// Default (MIT) build: APFS directory packing is unavailable because it lives in
// the GPL-2.0 pkg/apfswrite package, which the default binary does not link.
// Build with -tags apfswrite to enable it (that binary is GPL-2.0).
package cli

import "github.com/deploymenttheory/go-apfs-v2/pkg/disk"

func packDirectoryAPFS(srcDir, dstPath, volname string, encOpts *disk.EncodeOptions) error {
	return withCode(ExitUnsupported, errAPFSPackUnavailable())
}

func errAPFSPackUnavailable() error {
	return usageErrorf("packing to APFS is not available in this build; rebuild with -tags apfswrite (GPL-2.0). HFS+ packing works with --fs hfs+")
}
