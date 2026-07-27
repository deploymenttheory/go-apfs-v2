//go:build !darwin

package hostmeta

import "os"

// Flags reports that this platform has no BSD flags field.
func Flags(fi os.FileInfo) (uint32, bool) {
	return 0, false
}
