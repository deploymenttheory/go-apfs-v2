package hostdata

import (
	"bytes"
	"errors"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"golang.org/x/sys/unix"
)

type legacyForkCalls struct {
	path     func(int) (string, error)
	stat     func(int, *unix.Stat_t) error
	open     func(string, int, uint32) (int, error)
	truncate func(int, int64) error
	close    func(int) error
}

func nativeHeldPath(fd int) (string, error) {
	var path [unix.PathMax]byte
	if _, err := darwinabi.FcntlGetPath(int32(fd), &path); err != nil {
		return "", err
	}
	return terminatedHeldPath(path[:])
}
func terminatedHeldPath(path []byte) (string, error) {
	end := bytes.IndexByte(path, 0)
	if end < 1 || path[0] != '/' {
		return "", fs.ErrInvalid
	}
	return string(path[:end]), nil
}

func openLegacyResourceFork(fd, flags int, mode uint32) (int, error) {
	return openLegacyResourceForkUsing(fd, flags, mode, legacyForkCalls{nativeHeldPath, unix.Fstat, unix.Open, unix.Ftruncate, unix.Close})
}

// macOS 15 rejects a regular file as openat's starting descriptor. Resolve its
// current path through the held descriptor, then validate the acquired stream
// before any truncation or writes. F_GETPATH does not make namespace lookup
// atomic: unlinked files and concurrent namespace changes can fail acquisition.
// O_CREAT can open an empty native stream before identity validation; the caller
// must exclude unrelated namespace edits, just as with native path-based opens.
func openLegacyResourceForkUsing(fd, flags int, mode uint32, calls legacyForkCalls) (int, error) {
	var source unix.Stat_t
	if err := calls.stat(fd, &source); err != nil {
		return -1, err
	}
	if source.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, fs.ErrInvalid
	}
	path, err := calls.path(fd)
	if err != nil {
		return -1, err
	}
	// Never apply O_TRUNC through a pathname that may have been replaced.
	opened, err := calls.open(path+"/..namedfork/rsrc", flags&^unix.O_TRUNC, mode)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) { return -1, errors.Join(err, calls.close(opened)) }
	var fork unix.Stat_t
	if err = calls.stat(opened, &fork); err != nil {
		return fail(err)
	}
	if fork.Mode&unix.S_IFMT != unix.S_IFREG || source.Dev != fork.Dev || source.Ino != fork.Ino {
		return fail(ErrMetadataIdentity)
	}
	if flags&unix.O_TRUNC != 0 {
		if err = calls.truncate(opened, 0); err != nil {
			return fail(err)
		}
	}
	return opened, nil
}
