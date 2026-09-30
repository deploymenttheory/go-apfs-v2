package hostmeta

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Only libSystem IO and filesec property access cross this boundary. The ACL,
// AppleDouble, policy and ordering algorithms remain Go implementations.
type darwinSecurityABI struct {
	native  map[string]uintptr
	init    func() uintptr
	free    func(uintptr)
	get     func(uintptr, int32, unsafe.Pointer) int32
	stat    func(int32, *unix.Stat_t, uintptr) int32
	chmod   func(int32, uint32, uint32, int32, uintptr) int32
	setattr func(int32, *unix.Attrlist, unsafe.Pointer, uintptr, uint32) int32
	fsctl   func(int32, uintptr, unsafe.Pointer, uint32) int32
	errno   func() *int32
}

var loadDarwinSecurity = sync.OnceValues(func() (*darwinSecurityABI, error) {
	h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	return bindDarwinSecurity(func(name string) (uintptr, error) { return purego.Dlsym(h, name) }, runtime.GOARCH)
})

func bindDarwinSecurity(symbol func(string) (uintptr, error), arch string) (*darwinSecurityABI, error) {
	a := &darwinSecurityABI{native: make(map[string]uintptr)}
	stat := "fstatx_np"
	if arch == "amd64" {
		stat += "$INODE64"
	}
	for _, item := range []struct {
		name   string
		target any
	}{
		{"filesec_init", &a.init}, {"filesec_free", &a.free}, {"filesec_get_property", &a.get}, {stat, &a.stat},
		{"__fchmod_extended", &a.chmod}, {"fsetattrlist", &a.setattr}, {"ffsctl", &a.fsctl}, {"__error", &a.errno},
	} {
		p, err := symbol(item.name)
		if err != nil {
			return nil, err
		}
		a.native[strings.TrimSuffix(item.name, "$INODE64")] = p
		purego.RegisterFunc(item.target, p)
	}
	return a, nil
}

func (a *darwinSecurityABI) property(sec uintptr, name int32, out unsafe.Pointer) (bool, error) {
	_, err := callDarwinInt(a.native["filesec_get_property"], func() int32 { return a.get(sec, name, out) }, a.errno, sec, uintptr(name), uintptr(out))
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

func (a *darwinSecurityABI) properties(sec uintptr) (result DarwinChmodProperties, err error) {
	for _, item := range []struct {
		name   int32
		target **uint32
	}{{1, &result.UID}, {2, &result.GID}} {
		var value uint32
		present, e := a.property(sec, item.name, unsafe.Pointer(&value))
		if e != nil {
			return result, e
		}
		if present {
			*item.target = &value
		}
	}
	var mode uint16
	present, err := a.property(sec, 4, unsafe.Pointer(&mode))
	if err != nil {
		return result, err
	}
	if present {
		value := uint32(mode)
		result.Mode = &value
	}
	for _, item := range []struct {
		name   int32
		target **[16]byte
	}{{3, &result.OwnerUUID}, {6, &result.GroupUUID}} {
		var value [16]byte
		present, e := a.property(sec, item.name, unsafe.Pointer(&value))
		if e != nil {
			return result, e
		}
		if present {
			*item.target = &value
		}
	}
	var raw unsafe.Pointer
	present, err = a.property(sec, 100, unsafe.Pointer(&raw))
	if err != nil || !present {
		return result, err
	}
	var size uintptr
	present, err = a.property(sec, 101, unsafe.Pointer(&size))
	if err != nil {
		return result, err
	}
	if !present || raw == nil || !SecurityRecordSizeValid(uint64(size)) {
		return result, appledouble.ErrFileSecurity
	}
	result.RawSecurity, err = appledouble.ParseDarwinFileSecurity(unsafe.Slice((*byte)(raw), int(size)))
	if err == nil {
		result.RawSecurity.Trailing = nil
	}
	return result, err
}
