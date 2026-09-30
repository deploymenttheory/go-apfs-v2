package hostmeta

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func setCreationTime(file *os.File, when time.Time) error {
	ticks, err := windowsTimeTicks(when)
	if err != nil {
		return err
	}
	stamp := windows.Filetime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)}
	return setHeldFileTimes(file, &stamp, nil, nil)
}

func setFileTimes(file *os.File, modify, access time.Time) error {
	mt, err := windowsTimeTicks(modify)
	if err != nil {
		return err
	}
	at, err := windowsTimeTicks(access)
	if err != nil {
		return err
	}
	m := windows.Filetime{LowDateTime: uint32(mt), HighDateTime: uint32(mt >> 32)}
	a := windows.Filetime{LowDateTime: uint32(at), HighDateTime: uint32(at >> 32)}
	return setHeldFileTimes(file, nil, &a, &m)
}

func setHeldFileTimes(file *os.File, creation, access, modify *windows.Filetime) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = windows.SetFileTime(windows.Handle(fd), creation, access, modify)
	})
	if err != nil {
		return err
	}
	return setErr
}
