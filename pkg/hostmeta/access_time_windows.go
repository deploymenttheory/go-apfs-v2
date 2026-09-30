package hostmeta

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func copyAccessTime(target *os.File, source os.FileInfo) error {
	when := source.Sys().(*syscall.Win32FileAttributeData).LastAccessTime
	stamp := windows.Filetime{LowDateTime: when.LowDateTime, HighDateTime: when.HighDateTime}
	if when.LowDateTime == 0 && when.HighDateTime == 0 || when.HighDateTime >= 1<<31 {
		return os.ErrInvalid
	}
	return setHeldFileTimes(target, nil, &stamp, nil)
}
