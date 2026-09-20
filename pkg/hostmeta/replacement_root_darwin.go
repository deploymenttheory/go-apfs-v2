package hostmeta

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func prepareReplacementAt(source *os.File, stage *os.Root, info os.FileInfo) (*os.File, error) {
	flags, _ := Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND|UFCompressed) != 0 {
		return nil, fmt.Errorf("%w: protected or compressed source", ErrUnsupportedReplacement)
	}
	dir, err := stage.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	// Setattrlist has no descriptor variant in x/sys. Darwin's fdescfs path
	// names this held directory descriptor, not any caller-controlled pathname.
	if err := clearReplacementACL(fmt.Sprintf("/dev/fd/%d", dir.Fd())); err != nil {
		return nil, err
	}
	if err := unix.Fclonefileat(int(source.Fd()), int(dir.Fd()), "replacement", cloneACL); err != nil {
		return nil, err
	}
	if err := stage.Chmod("replacement", 0600); err != nil {
		return nil, err
	}
	return stage.OpenFile("replacement", os.O_RDWR, 0)
}

func restoreReplacementMetadataAt(source, target *os.File, info os.FileInfo) error {
	return restoreReplacementMetadata(source, target, info)
}
