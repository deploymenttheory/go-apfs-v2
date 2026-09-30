package hostmeta

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

func TestLibSystemXattrNative(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const name = "user.libsystem"
	if err := unix.Fsetxattr(int(f.Fd()), name, []byte("original"), 0); err != nil {
		t.Fatal(err)
	}
	value, err := getXattr(file, name)
	if err != nil || string(value) != "original" {
		t.Fatalf("%q %v", value, err)
	}
	names, err := listXattrNames(file)
	if err != nil || len(names) == 0 {
		t.Fatalf("%v %v", names, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := getXattr(link, name); !errors.Is(err, unix.ENOATTR) {
		t.Fatalf("followed symlink: %v", err)
	}
	if err := unix.Fsetxattr(int(f.Fd()), name, []byte{}, 0); err != nil {
		t.Fatal(err)
	}
	if value, err := getXattr(file, name); err != nil || value == nil || len(value) != 0 {
		t.Fatalf("empty: %v %v", value, err)
	}
	for _, path := range []string{file + "absent", "bad\x00path"} {
		if _, err := listXattrNames(path); err == nil {
			t.Fatal("missing listing error")
		}
		if _, err := getXattr(path, name); err == nil {
			t.Fatal("missing read error")
		}
	}
	if _, err := getXattr(file, "bad\x00name"); err == nil {
		t.Fatal("missing invalid-name error")
	}
	if _, err := getCaptureXattrFD(int(f.Fd()), "bad\x00name", nil); err == nil {
		t.Fatal("missing invalid-name error")
	}
	// Position and options ABI: hidden compression metadata must be seen by the
	// capture path without changing ordinary visibility. Type 1 is inline data.
	compression := []byte{0x66, 0x70, 0x6d, 0x63, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 'a', 'b', 'c'}
	if err := unix.Fsetxattr(int(f.Fd()), DecmpfsName, compression, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchflags(int(f.Fd()), unix.UF_COMPRESSED); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Fgetxattr(int(f.Fd()), DecmpfsName, nil); !errors.Is(err, unix.ENOATTR) {
		t.Fatalf("storage attribute should be hidden: %v", err)
	}
	values, err := CaptureXattrs(context.Background(), f, XattrCaptureLimits{1 << 20, 1 << 20, 2 << 20})
	if err != nil || !bytes.Equal(values[DecmpfsName], compression) {
		t.Fatalf("hidden capture: %v %v", values, err)
	}
	if err := os.Rename(file, file+"renamed"); err != nil {
		t.Fatal(err)
	}
	values, err = CaptureXattrs(context.Background(), f, XattrCaptureLimits{1 << 20, 1 << 20, 2 << 20})
	if err != nil || !bytes.Equal(values[DecmpfsName], compression) {
		t.Fatalf("held capture: %v %v", values, err)
	}
}

func TestLibSystemBindingFailures(t *testing.T) {
	fault := errors.New("symbol not found")
	if _, err := bindDarwinXattr(func(string) (uintptr, error) { return 0, fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	// Real symbol resolution independently confirms all registered ABI functions.
	h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(h)
	if _, err := bindDarwinXattr(func(n string) (uintptr, error) { return purego.Dlsym(h, n) }); err != nil {
		t.Fatal(err)
	}
	errno := int32(syscall.EACCES)
	a := &darwinXattrABI{errno: func() *int32 { return &errno }}
	if _, err := a.call(func() int64 { return -1 }); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	old := loadDarwinXattr
	loadDarwinXattr = func() (*darwinXattrABI, error) { return nil, fault }
	defer func() { loadDarwinXattr = old }()
	if _, err := darwinListXattrPath("file", nil, 0); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := darwinGetXattrPath("file", "name", nil, 0); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := listCaptureXattrFD(1, 100); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := getCaptureXattrFD(1, "name", nil); !errors.Is(err, fault) {
		t.Fatal(err)
	}
}
