package darwinabi

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestTypedSecurityAndContextWrappers(t *testing.T) {
	sec := FilesecInit()
	if sec == 0 {
		t.Fatal("filesec allocation")
	}
	defer FilesecFree(sec)
	f, err := os.CreateTemp(t.TempDir(), "metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if _, err := Fstatx(int32(f.Fd()), &st, sec); err != nil {
		t.Fatal(err)
	}
	var uid uint32
	if _, err := FilesecGetProperty(sec, 1, unsafe.Pointer(&uid)); err != nil || uid != uint32(os.Getuid()) {
		t.Fatal(uid, err)
	}
	if _, err := Fstatx(-1, &st, sec); !errors.Is(err, syscall.EBADF) {
		t.Fatal(err)
	}
	process := QuarantineProcessAlloc()
	if process == 0 {
		t.Fatal("quarantine allocation")
	}
	defer QuarantineProcessFree(process)
	if _, err := QuarantineProcessInit(process); err != nil && !errors.Is(err, syscall.ENOATTR) {
		t.Fatal(err)
	}
	_ = AppSandboxed()
}

// These calls check the native -1/errno convention through each typed boundary,
// including fd and path operations whose successful calls run in hostdata tests.
func TestTypedNativeErrors(t *testing.T) {
	if n, err := Flistxattr(-1, nil, 0, 0); n != 0 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
	if n, err := FchmodExtended(-1, ^uint32(0), ^uint32(0), 0600, 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
	path, err := unix.BytePtrFromString(t.TempDir() + "/absent")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ChmodExtended(path, ^uint32(0), ^uint32(0), 0600, 0); n != -1 || !errors.Is(err, syscall.ENOENT) {
		t.Fatal(n, err)
	}
	var request [12]byte
	if n, err := Ffsctl(-1, 0xc00c4114, unsafe.Pointer(&request), 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
}
