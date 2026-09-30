//go:build native_quarantine_oracle

package hostmeta

import (
	"bytes"
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/ebitengine/purego"
)

func TestQuarantineCaptureNativeOracle(t *testing.T) {
	path := os.Getenv("APFS_QUARANTINE_ORACLE")
	if path == "" {
		t.Fatal("native oracle library path is required")
	}
	h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(h)
	var capture func(*byte, *uint64, *byte, *uint64, *byte, *uint64, *uint64, *int32) int32
	purego.RegisterLibFunc(&capture, h, "appledouble_quarantine_capture")
	var agent [257]byte
	var metadata [65]byte
	var tracking [64]byte
	var al, ml, tl, flags uint64
	var errno int32
	status := capture(&agent[0], &al, &metadata[0], &ml, &tracking[0], &tl, &flags, &errno)
	got, err := CaptureQuarantineProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		if status != -1 || errno != int32(syscall.ENOATTR) || !got.Absent {
			t.Fatalf("native capture status=%d errno=%d disagrees", status, errno)
		}
		return
	}
	if got.Absent || flags != uint64(got.Flags) || al > 255 || ml > 64 || tl > 64 || !bytes.Equal(agent[:al], got.Agent) || !bytes.Equal(metadata[:ml], got.Metadata) || !bytes.Equal(tracking[:tl], got.Tracking) {
		t.Fatal("Go capture differs from independent same-process C observation")
	}
	// Never put agent, opaque metadata or tracking payloads in evidence logs.
	t.Logf("native process capture matched; absent=%t, agentBytes=%d, metadataBytes=%d, trackingBytes=%d", got.Absent, al, ml, tl)
}
