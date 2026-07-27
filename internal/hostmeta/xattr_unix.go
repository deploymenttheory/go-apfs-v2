//go:build darwin || linux

package hostmeta

import (
	"strings"

	"golang.org/x/sys/unix"
)

// XattrsSupported reports whether this build can read extended attributes.
const XattrsSupported = true

// ListXattrs returns every extended attribute on the file at path, without
// following a symbolic link — a link's own attributes are not its target's.
//
// The standard library exposes none of this: syscall has Listxattr and Getxattr
// on Linux only, has neither on darwin, and has no L-prefixed variant anywhere.
// golang.org/x/sys/unix has all of them, is pure Go, and works with cgo
// disabled.
//
// A file with no attributes returns an empty map, not an error. So does a file
// system that does not support attributes: that is an absence of data, not a
// failure to read it.
func ListXattrs(path string) (map[string][]byte, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		if isUnsupported(err) {
			return map[string][]byte{}, nil
		}
		return nil, err
	}
	if size == 0 {
		return map[string][]byte{}, nil
	}

	buf := make([]byte, size)
	size, err = unix.Llistxattr(path, buf)
	if err != nil {
		if isUnsupported(err) {
			return map[string][]byte{}, nil
		}
		return nil, err
	}

	attrs := make(map[string][]byte)
	for name := range strings.SplitSeq(string(buf[:size]), "\x00") {
		if name == "" {
			continue
		}
		value, err := getXattr(path, name)
		if err != nil {
			// An attribute that vanished between listing and reading, or that
			// this process may not see, is not a reason to fail the walk.
			continue
		}
		attrs[name] = value
	}
	return attrs, nil
}

func getXattr(path, name string) ([]byte, error) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	size, err = unix.Lgetxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:size], nil
}

// isUnsupported reports whether err means "this file system has no extended
// attributes" rather than a genuine failure.
func isUnsupported(err error) bool {
	return err == unix.ENOTSUP || err == unix.EOPNOTSUPP || err == unix.ENOSYS
}
