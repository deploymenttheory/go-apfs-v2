//go:build !darwin && !linux

package hostmeta

// XattrsSupported reports whether this build can read extended attributes.
const XattrsSupported = false

// ListXattrs returns no attributes on a platform that has none this tool can
// read. It reports success rather than an error, because "there is nothing
// here" is the truth on such a platform, and a caller reporting fidelity loss
// should say attributes were unreadable, not that the walk failed.
func ListXattrs(path string) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}
