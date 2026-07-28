package hostmeta

import "golang.org/x/sys/unix"

// Linux has no transparent compression and no XATTR_SHOWCOMPRESSION, so there
// is nothing here that the ordinary wrappers cannot see; compare
// xattr_darwin.go, which needs the raw syscall to reach a compressed file's
// content.

func listXattrNames(path string) ([]string, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(path, buf)
	if err != nil {
		return nil, err
	}
	return splitNames(buf[:size]), nil
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
