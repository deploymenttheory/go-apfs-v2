//go:build darwin

package acceptance

import (
	"syscall"
	"testing"
	"unsafe"
)

// xattrShowCompression is XATTR_SHOWCOMPRESSION. A compressed file's
// com.apple.decmpfs and com.apple.ResourceFork are invisible to an ordinary
// getxattr — they do not even appear in a listing — because they are how the
// content is stored rather than metadata about it. This option reveals them.
const xattrShowCompression = 0x0020

// compressedAttributes reads the two attributes a compressed file is made of.
// It reports false when the file is not compressed.
//
// golang.org/x/sys/unix cannot be used: its darwin wrappers hardcode the
// options argument to zero, so unix.Getxattr answers "attribute not found" for
// every compressed file. The raw syscall is the way to pass the option.
func compressedAttributes(t *testing.T, path string) (attr, fork []byte, ok bool) {
	t.Helper()
	attr, ok = showCompressionXattr(path, "com.apple.decmpfs")
	if !ok {
		return nil, nil, false
	}
	fork, _ = showCompressionXattr(path, "com.apple.ResourceFork")
	return attr, fork, true
}

func showCompressionXattr(path, name string) ([]byte, bool) {
	pathPtr, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, false
	}
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, false
	}

	get := func(buf *byte, size uintptr) (int, syscall.Errno) {
		n, _, errno := syscall.Syscall6(syscall.SYS_GETXATTR,
			uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(namePtr)),
			uintptr(unsafe.Pointer(buf)), size, 0, xattrShowCompression)
		return int(n), errno
	}

	size, errno := get(nil, 0)
	if errno != 0 || size <= 0 {
		return nil, false
	}
	buf := make([]byte, size)
	n, errno := get(&buf[0], uintptr(size))
	if errno != 0 || n <= 0 {
		return nil, false
	}
	return buf[:n], true
}
