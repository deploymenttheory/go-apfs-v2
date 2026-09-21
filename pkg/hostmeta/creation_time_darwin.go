package hostmeta

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func setCreationTime(file *os.File, when time.Time) error {
	var timestamp [16]byte
	binary.LittleEndian.PutUint64(timestamp[:], uint64(when.Unix()))
	binary.LittleEndian.PutUint64(timestamp[8:], uint64(when.Nanosecond()))
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_CRTIME}
	// fdescfs binds Setattrlist to the held file despite pathname replacement.
	return unix.Setattrlist(fmt.Sprintf("/dev/fd/%d", file.Fd()), &list, timestamp[:], 0)
}
