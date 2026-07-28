//go:build !darwin

package acceptance

import "testing"

// compressedAttributes is unavailable here: decmpfs and the
// XATTR_SHOWCOMPRESSION option that reveals it are macOS concepts, so there is
// no compressed file to read. Its only caller skips on every other platform.
func compressedAttributes(t *testing.T, path string) (attr, fork []byte, ok bool) {
	t.Helper()
	return nil, nil, false
}
