package hostdata

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

// These fixed signatures come from sys/xattr.h. x/sys does not expose Darwin's
// compression visibility or resource-fork position arguments. libSystem is used
// only for host IO; all AppleDouble policy and encoding remain Go code.
type darwinXattrABI struct {
	native   map[string]uintptr
	listPath func(*byte, *byte, uintptr, int32) int64
	getPath  func(*byte, *byte, *byte, uintptr, uint32, int32) int64
	listFD   func(int32, *byte, uintptr, int32) int64
	getFD    func(int32, *byte, *byte, uintptr, uint32, int32) int64
	errno    func() *int32
}

var loadDarwinXattr = sync.OnceValues(func() (*darwinXattrABI, error) {
	// The process holds this system library for its lifetime. Closing it while
	// registered function pointers survive would invalidate those pointers.
	h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	return bindDarwinXattr(func(name string) (uintptr, error) { return purego.Dlsym(h, name) })
})

func bindDarwinXattr(symbol func(string) (uintptr, error)) (*darwinXattrABI, error) {
	a := &darwinXattrABI{native: make(map[string]uintptr)}
	for _, item := range []struct {
		name   string
		target any
	}{
		{"listxattr", &a.listPath}, {"getxattr", &a.getPath},
		{"flistxattr", &a.listFD}, {"fgetxattr", &a.getFD}, {"__error", &a.errno},
	} {
		p, err := symbol(item.name)
		if err != nil {
			return nil, err
		}
		a.native[item.name] = p
		purego.RegisterFunc(item.target, p)
	}
	return a, nil
}

func darwinListXattrPath(path string, buf []byte, flags int32) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := callDarwinSize(a.native["listxattr"], func() int64 { return a.listPath(p, unsafe.SliceData(buf), uintptr(len(buf)), flags) }, a.errno, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), uintptr(flags))
	runtime.KeepAlive(p)
	runtime.KeepAlive(buf)
	return n, err
}

func darwinGetXattrPath(path, name string, buf []byte, flags int32) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	q, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := callDarwinSize(a.native["getxattr"], func() int64 { return a.getPath(p, q, unsafe.SliceData(buf), uintptr(len(buf)), 0, flags) }, a.errno, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, uintptr(flags))
	runtime.KeepAlive(p)
	runtime.KeepAlive(q)
	runtime.KeepAlive(buf)
	return n, err
}

func listCaptureXattrFD(fd, limit int) ([]string, error) {
	a, err := loadDarwinXattr()
	if err != nil {
		return nil, err
	}
	return readXattrNames(func(buf []byte) (int, error) {
		n, err := callDarwinSize(a.native["flistxattr"], func() int64 {
			return a.listFD(int32(fd), unsafe.SliceData(buf), uintptr(len(buf)), xattrShowCompression)
		}, a.errno, uintptr(fd), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), xattrShowCompression)
		runtime.KeepAlive(buf)
		return n, err
	}, limit)
}

func getCaptureXattrFD(fd int, name string, buf []byte) (int, error) {
	q, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := callDarwinSize(a.native["fgetxattr"], func() int64 {
		return a.getFD(int32(fd), q, unsafe.SliceData(buf), uintptr(len(buf)), 0, xattrShowCompression)
	}, a.errno, uintptr(fd), uintptr(unsafe.Pointer(q)), uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), 0, xattrShowCompression)
	runtime.KeepAlive(q)
	runtime.KeepAlive(buf)
	return n, err
}
