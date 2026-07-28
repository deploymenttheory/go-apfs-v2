package hostmeta

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Options for listxattr(2) and getxattr(2) on macOS.
const (
	xattrNoFollow         = 0x0001 // XATTR_NOFOLLOW: a link's attributes, not its target's
	xattrShowCompression  = 0x0020 // XATTR_SHOWCOMPRESSION
	xattrCompressionFlags = xattrNoFollow | xattrShowCompression
)

// A transparently compressed file keeps its content in com.apple.decmpfs and,
// for the larger compression types, com.apple.ResourceFork. Those attributes
// are hidden by default — they do not appear in a listing and getxattr answers
// "attribute not found" — because they are how the content is stored rather
// than metadata about it. XATTR_SHOWCOMPRESSION reveals them, and without it a
// compressed file looks like an ordinary one whose content happens to be
// decompressed on read.
//
// golang.org/x/sys/unix cannot ask for that: its darwin wrappers hardcode the
// options argument to zero and the underlying getxattr is unexported. So these
// go through the syscall directly.
//
// syscall.Syscall is deprecated on darwin, so every call here falls back to the
// unix wrappers if the raw path fails in a way that is not an ordinary errno.
// Should a future Go break it, the result is that compression stops being
// preserved — a fidelity loss the report already knows how to describe — rather
// than pack failing outright.

// listXattrNames returns the names of every extended attribute on path,
// including the ones holding a compressed file's content.
func listXattrNames(path string) ([]string, error) {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}

	call := func(buf *byte, size uintptr) (int, syscall.Errno) {
		n, _, errno := syscall.Syscall6(syscall.SYS_LISTXATTR,
			uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(buf)), size,
			xattrCompressionFlags, 0, 0)
		return int(n), errno
	}

	size, errno := call(nil, 0)
	if errno != 0 {
		if isUnsupported(errno) {
			return nil, errno
		}
		return listXattrNamesFallback(path)
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	size, errno = call(&buf[0], uintptr(size))
	if errno != 0 {
		if isUnsupported(errno) {
			return nil, errno
		}
		return listXattrNamesFallback(path)
	}
	return splitNames(buf[:size]), nil
}

// getXattr reads one attribute, including a compressed file's content.
func getXattr(path, name string) ([]byte, error) {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}

	call := func(buf *byte, size uintptr) (int, syscall.Errno) {
		// The fifth argument is the position, which must be zero for anything
		// other than a resource fork read in pieces; this reads whole values.
		n, _, errno := syscall.Syscall6(syscall.SYS_GETXATTR,
			uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(buf)), size, 0, xattrCompressionFlags)
		return int(n), errno
	}

	size, errno := call(nil, 0)
	if errno != 0 {
		return getXattrFallback(path, name)
	}
	if size == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, size)
	size, errno = call(&buf[0], uintptr(size))
	if errno != 0 {
		return getXattrFallback(path, name)
	}
	return buf[:size], nil
}

// The fallbacks see everything except a compressed file's content.

func listXattrNamesFallback(path string) ([]string, error) {
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

func getXattrFallback(path, name string) ([]byte, error) {
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
