package hostmeta

import (
	"sync"

	"github.com/ebitengine/purego"
)

var loadAppSandbox = sync.OnceValues(func() (func() bool, error) {
	return bindAppSandbox(purego.Dlopen, purego.Dlsym)
})

func bindAppSandbox(open func(string, int) (uintptr, error), symbol func(uintptr, string) (uintptr, error)) (func() bool, error) {
	h, err := open("/usr/lib/system/libxpc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	p, err := symbol(h, "_xpc_runtime_is_app_sandboxed")
	if err != nil {
		return nil, err
	}
	var query func() bool
	purego.RegisterFunc(&query, p)
	return query, nil
}

func captureAppSandbox() (bool, error) {
	query, err := loadAppSandbox()
	if err != nil {
		return false, err
	}
	return query(), nil
}
