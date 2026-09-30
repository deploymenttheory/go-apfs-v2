package hostmeta

import (
	"errors"
	"testing"

	"github.com/ebitengine/purego"
)

func TestSandboxCaptureBindingFailures(t *testing.T) {
	marker := errors.New("native sandbox loader failure")
	if _, err := bindAppSandbox(func(string, int) (uintptr, error) { return 0, marker }, nil); !errors.Is(err, marker) {
		t.Fatal(err)
	}
	if _, err := bindAppSandbox(func(name string, flags int) (uintptr, error) {
		if name != "/usr/lib/system/libxpc.dylib" || flags != purego.RTLD_NOW|purego.RTLD_LOCAL {
			t.Fatal(name, flags)
		}
		return 123, nil
	}, func(handle uintptr, name string) (uintptr, error) {
		if handle != 123 || name != "_xpc_runtime_is_app_sandboxed" {
			t.Fatal(handle, name)
		}
		return 0, marker
	}); !errors.Is(err, marker) {
		t.Fatal(err)
	}
}
