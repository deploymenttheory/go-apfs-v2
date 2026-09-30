package hostmeta

import (
	"github.com/ebitengine/purego"
	"sync"
)

var loadAppSandbox = sync.OnceValues(func() (func() bool, error) {
	h, err := purego.Dlopen("/usr/lib/system/libxpc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	p, err := purego.Dlsym(h, "_xpc_runtime_is_app_sandboxed")
	if err != nil {
		return nil, err
	}
	var query func() bool
	purego.RegisterFunc(&query, p)
	return query, nil
})

func captureAppSandbox() (bool, error) {
	query, err := loadAppSandbox()
	if err != nil {
		return false, err
	}
	return query(), nil
}
