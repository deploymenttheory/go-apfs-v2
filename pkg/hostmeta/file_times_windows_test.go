package hostmeta

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type zeroAccessFileInfo struct{ os.FileInfo }

func (i zeroAccessFileInfo) Sys() any {
	s := *i.FileInfo.Sys().(*syscall.Win32FileAttributeData)
	s.LastAccessTime = syscall.Filetime{}
	return &s
}

func openTimeTestFile(name string, _ bool) (*os.File, error) {
	h, err := openXattrPath(name, windows.FILE_WRITE_ATTRIBUTES|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), name), nil
}

func TestCarrierWindowsTimePrecision(t *testing.T) {
	file := replacementSource(t, 0600)
	when := time.Unix(946684800, 0)
	for _, tc := range [][2]time.Time{{when.Add(time.Nanosecond), when}, {when, when.Add(time.Nanosecond)}} {
		if err := SetFileTimes(file, tc[0], tc[1]); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("precision: %v", err)
		}
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := copyAccessTime(file, zeroAccessFileInfo{info}); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zero access sentinel: %v", err)
	}
}
