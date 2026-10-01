package hostdata

import (
	"context"
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

// Matches the independently measured libquarantine 217 process-info ABI in
// testdata/appledouble/native/quarantine-process-capture.h. Only the libSystem
// wrapper crosses the boundary; no numbered syscall or policy algorithm does.
type quarantineProcessInfo struct {
	agentLength    uint64
	agent          *byte
	metadataLength uint64
	metadata       *byte
	trackingLength uint64
	tracking       *byte
	flags          uint64
	pid            int32
	reserved       uint32
}

type quarantineCaptureABI struct {
	native  map[string]uintptr
	query   func(*byte, int32, *quarantineProcessInfo) int32
	getFile func(*byte, int32, *quarantineFileGet) int32
	setFile func(*byte, int32, *quarantineFileSet) int32
	errno   func() *int32
	alloc   func() uintptr
	free    func(uintptr)
	capture func(uintptr) int32
}

var loadQuarantineCapture = sync.OnceValues(func() (*quarantineCaptureABI, error) {
	system, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	q, err := purego.Dlopen("/usr/lib/system/libquarantine.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	return bindQuarantineCapture(func(name string) (uintptr, error) {
		h := system
		if strings.HasPrefix(name, "_qtn_") {
			h = q
		}
		return purego.Dlsym(h, name)
	})
})

func bindQuarantineCapture(symbol func(string) (uintptr, error)) (*quarantineCaptureABI, error) {
	a := &quarantineCaptureABI{native: map[string]uintptr{}}
	for _, item := range []struct {
		name   string
		target any
	}{
		{"__mac_syscall", &a.query}, {"__error", &a.errno}, {"_qtn_proc_alloc", &a.alloc}, {"_qtn_proc_free", &a.free}, {"_qtn_proc_init_with_self", &a.capture},
		{"__mac_syscall", &a.getFile}, {"__mac_syscall", &a.setFile},
	} {
		p, err := symbol(item.name)
		if err != nil {
			return nil, err
		}
		purego.RegisterFunc(item.target, p)
		a.native[item.name] = p
	}
	return a, nil
}

func nativeQuarantineProfile(release string) (appledouble.QuarantineProfile, error) {
	switch strings.SplitN(release, ".", 2)[0] {
	case "26":
		return appledouble.QuarantineMacOS26, nil
	case "27":
		return appledouble.QuarantineMacOS27, nil
	default:
		return 0, errors.ErrUnsupported
	}
}

func captureNativeQuarantineProcess(ctx context.Context) (*QuarantineProcessCapture, error) {
	return captureNativeQuarantineUsing(ctx, func() (string, error) { return unix.Sysctl("kern.osproductversion") }, loadQuarantineCapture)
}

func captureNativeQuarantineUsing(ctx context.Context, version func() (string, error), load func() (*quarantineCaptureABI, error)) (*QuarantineProcessCapture, error) {
	release, err := version()
	if err != nil {
		return nil, err
	}
	profile, err := nativeQuarantineProfile(release)
	if err != nil {
		return nil, err
	}
	a, err := load()
	if err != nil {
		return nil, err
	}
	return captureQuarantineProcess(ctx, func() (*QuarantineProcessCapture, error) { return a.read(profile) }, a.confirmAbsent)
}

func (a *quarantineCaptureABI) read(profile appledouble.QuarantineProfile) (*QuarantineProcessCapture, error) {
	var agent [257]byte
	var metadata [65]byte
	var tracking [64]byte
	i := quarantineProcessInfo{agent: &agent[0], metadata: &metadata[0], tracking: &tracking[0]}
	policy := []byte("Quarantine\x00")
	_, err := callDarwinInt(a.native["__mac_syscall"], func() int32 { return a.query(&policy[0], 84, &i) }, a.errno,
		uintptr(unsafe.Pointer(&policy[0])), 84, uintptr(unsafe.Pointer(&i)))
	runtime.KeepAlive(policy)
	runtime.KeepAlive(agent)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(tracking)
	if errors.Is(err, syscall.ENOATTR) {
		return &QuarantineProcessCapture{Profile: profile, Absent: true}, nil
	}
	if err != nil {
		return nil, err
	}
	if i.agentLength > 255 || i.metadataLength > 64 || i.trackingLength > 64 || i.flags > 1<<32-1 {
		return nil, appledouble.ErrQuarantineContext
	}
	return &QuarantineProcessCapture{Profile: profile, Flags: uint32(i.flags), Agent: agent[:i.agentLength], Metadata: metadata[:i.metadataLength], Tracking: tracking[:i.trackingLength]}, nil
}

func (a *quarantineCaptureABI) confirmAbsent() error {
	p := a.alloc()
	if p == 0 {
		return syscall.ENOMEM
	}
	defer a.free(p)
	_, err := callDarwinInt(a.native["_qtn_proc_init_with_self"], func() int32 { return a.capture(p) }, a.errno, p)
	if errors.Is(err, syscall.ENOATTR) {
		return nil
	}
	if err == nil {
		return ErrQuarantineCaptureChanged
	}
	return err
}
