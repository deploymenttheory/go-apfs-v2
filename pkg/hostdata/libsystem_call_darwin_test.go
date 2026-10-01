package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/ebitengine/purego"
)

func TestDarwinCallCapturedErrno(t *testing.T) {
	library, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(library)
	symbol := func(name string) uintptr {
		p, e := purego.Dlsym(library, name)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	// No separate errno accessor may run on the native path. Its failure would
	// reproduce the old race rather than merely test an injected errno value.
	forbidden := func() *int32 { t.Fatal("native call used delayed errno accessor"); return nil }
	if n, e := callDarwinInt(symbol("getpid"), nil, forbidden); e != nil || int(n) != os.Getpid() {
		t.Fatal(n, e)
	}
	invalid := ^uintptr(0)
	if n, e := callDarwinInt(symbol("close"), nil, forbidden, invalid); n != -1 || !errors.Is(e, syscall.EBADF) {
		t.Fatal(n, e)
	}
	file, e := os.CreateTemp(t.TempDir(), "seek")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	// Seeking creates no data or allocation: this only checks ssize_t width.
	if n, e := callDarwinSize(symbol("lseek"), nil, forbidden, file.Fd(), 1<<33, 0); n != 1<<33 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := callDarwinSize(symbol("lseek"), nil, forbidden, invalid, 0, 0); n != 0 || !errors.Is(e, syscall.EBADF) {
		t.Fatal(n, e)
	}
	eno := int32(syscall.EACCES)
	readErrno := func() *int32 { return &eno }
	if n, e := callDarwinInt(0, func() int32 { return 7 }, readErrno); n != 7 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := callDarwinInt(0, func() int32 { return -1 }, readErrno); n != -1 || !errors.Is(e, syscall.EACCES) {
		t.Fatal(n, e)
	}
	if n, e := callDarwinSize(0, func() int64 { return 1 << 33 }, readErrno); n != 1<<33 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := callDarwinSize(0, func() int64 { return -1 }, readErrno); n != 0 || !errors.Is(e, syscall.EACCES) {
		t.Fatal(n, e)
	}
}

func TestDarwinCallMetadataErrnoUnderScheduling(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if err := os.WriteFile(existing, nil, 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "missing")
	// An absent filesec property returns ENOENT after successful statx. Under the
	// old two-call errno reader, runtime activity occasionally changed that into
	// EINTR, ETIMEDOUT or even 260, turning successful capture into a false error.
	for worker := 0; worker < 8; worker++ {
		t.Run("worker", func(t *testing.T) {
			t.Parallel()
			for iteration := 0; iteration < 500; iteration++ {
				if _, err := CapturePathMetadata(existing, true); err != nil {
					t.Fatalf("existing iteration%d: %v", iteration, err)
				}
				runtime.Gosched()
				if _, err := CapturePathMetadata(missing, true); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing iteration%d: %v", iteration, err)
				}
			}
		})
	}
}
