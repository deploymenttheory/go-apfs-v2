package hostmeta

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func copyAccessTime(target *os.File, source os.FileInfo) error {
	when := source.Sys().(*syscall.Stat_t).Atim
	return setHeldLinuxTimes(target, []unix.Timespec{
		{Sec: when.Sec, Nsec: when.Nsec}, {Nsec: unix.UTIME_OMIT},
	})
}

func setFileTimes(target *os.File, modify, access time.Time) error {
	return setHeldLinuxTimes(target, []unix.Timespec{
		{Sec: access.Unix(), Nsec: int64(access.Nanosecond())},
		{Sec: modify.Unix(), Nsec: int64(modify.Nanosecond())},
	})
}

func setHeldLinuxTimes(target *os.File, stamps []unix.Timespec) error {
	conn, err := target.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = unix.UtimesNanoAt(int(fd), "", stamps, unix.AT_EMPTY_PATH)
	})
	if err != nil {
		return err
	}
	return setErr
}
