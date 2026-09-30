package hostmeta

import (
	"golang.org/x/sys/unix"
	"os"
)

func openNativeResourceFork(fd int, writable bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if writable {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_CLOEXEC
	}
	fork, err := unix.Openat(fd, "..namedfork/rsrc", flags, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fork), "resource fork"), nil
}
