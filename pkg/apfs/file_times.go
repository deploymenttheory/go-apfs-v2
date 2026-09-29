package apfs

import (
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

// FileTimes reads four inode timestamps without following the final symlink or
// reading payloads/xattrs. Names use fs.ValidPath; the image must stay immutable.
// Signed nanosecond bit patterns are retained, including dates before 1970.
func (v *Volume) FileTimes(name string) (hostmeta.FileTimes, error) {
	if v == nil {
		return hostmeta.FileTimes{}, &fs.PathError{Op: "timestamps", Path: name, Err: fs.ErrInvalid}
	}
	info, err := v.Stat(name)
	if err != nil {
		return hostmeta.FileTimes{}, err
	}
	inode := info.Sys().(*Inode)
	return hostmeta.FileTimes{
		Birth:  time.Unix(0, int64(inode.CreationTime)).UTC(),
		Modify: time.Unix(0, int64(inode.ModificationTime)).UTC(),
		Change: time.Unix(0, int64(inode.InodeChangeTime)).UTC(),
		Access: time.Unix(0, int64(inode.AccessTime)).UTC(),
	}, nil
}
