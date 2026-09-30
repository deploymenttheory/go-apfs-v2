package hostmeta

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCarrierWindowsHeldTimes(t *testing.T) {
	source, target := replacementSource(t, 0600), replacementSource(t, 0600)
	when := time.Unix(978307200, 234567800)
	if err := os.Chtimes(source.Name(), when, when.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	from, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	before, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyAccessTime(source, target); err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(target, when); err != nil {
		t.Fatal(err)
	}
	after, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, got := *before.Sys().(*syscall.Win32FileAttributeData), *after.Sys().(*syscall.Win32FileAttributeData)
	ticks, err := windowsTimeTicks(when)
	if err != nil {
		t.Fatal(err)
	}
	if got.CreationTime.LowDateTime != uint32(ticks) || got.CreationTime.HighDateTime != uint32(ticks>>32) || got.LastAccessTime != from.Sys().(*syscall.Win32FileAttributeData).LastAccessTime {
		t.Fatal("native times differ")
	}
	want.CreationTime, want.LastAccessTime = got.CreationTime, got.LastAccessTime
	if want != got {
		t.Fatal("unrelated metadata changed")
	}
	if err := SetCreationTime(target, when.Add(time.Nanosecond)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("precision: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	stamp := windows.Filetime{LowDateTime: 1}
	if err := setHeldFileTimes(target, &stamp, nil, nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
	if err := setHeldFileTimes(nil, &stamp, nil, nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
}
