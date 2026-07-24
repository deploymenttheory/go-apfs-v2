//go:build !apfswrite

// Default (MIT) build: APFS creation is unavailable because it lives in the
// GPL-2.0 pkg/apfswrite package, which the default binary does not link.
// Build with -tags apfswrite to enable it (that binary is GPL-2.0).
package cli

func createAPFS(dstPath string, sizeBytes int64) error {
	return withCode(ExitUnsupported, errAPFSCreateUnavailable())
}

func errAPFSCreateUnavailable() error {
	return usageErrorf("APFS creation is not available in this build; rebuild with -tags apfswrite (GPL-2.0). HFS+ creation works with --fs hfs+")
}
