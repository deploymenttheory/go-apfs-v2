package hostmeta

import (
	"runtime"
	"syscall"

	"github.com/ebitengine/purego"
)

// Native errno must be captured inside the foreign-call trampoline, before Go
// resumes. LockOSThread alone does not prevent Go's scheduler/syscalls changing
// the thread-local errno before a subsequent __error call. The fallback exists
// only for injected Go providers; production bindings always have a symbol.
//
//go:uintptrescapes
func callDarwinInt(pointer uintptr, fallback func() int32, errno func() *int32, args ...uintptr) (int32, error) {
	if pointer != 0 {
		result, _, captured := purego.SyscallN(pointer, args...)
		value := int32(result)
		if value == -1 {
			return value, syscall.Errno(uint32(captured))
		}
		return value, nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	value := fallback()
	if value == -1 {
		return value, syscall.Errno(*errno())
	}
	return value, nil
}

// ssize_t results use the whole 64-bit register, unlike the int wrappers above.
//
//go:uintptrescapes
func callDarwinSize(pointer uintptr, fallback func() int64, errno func() *int32, args ...uintptr) (int, error) {
	if pointer != 0 {
		result, _, captured := purego.SyscallN(pointer, args...)
		if int64(result) == -1 {
			return 0, syscall.Errno(uint32(captured))
		}
		return int(result), nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	value := fallback()
	if value == -1 {
		return 0, syscall.Errno(*errno())
	}
	return int(value), nil
}
