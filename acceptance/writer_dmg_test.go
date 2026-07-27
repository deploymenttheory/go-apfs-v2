// Oracle-backed acceptance test for the DMG writer: a repacked image is
// mounted with hdiutil to prove the container is readable by the platform.
// The synthetic encode/decode round-trips stay in pkg/disk.
package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// TestRepackMountsViaHdiutil is the darwin-only correctness oracle: it repacks
// the source DMG and attaches it read-only via hdiutil to prove the output is a
// genuinely valid UDIF image. Gated on DMG_REPACK_SRC.
func TestRepackMountsViaHdiutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is only available on darwin")
	}
	src := os.Getenv("DMG_REPACK_SRC")
	if src == "" {
		t.Skip("set DMG_REPACK_SRC to a source DMG to run this test")
	}

	dst := filepath.Join(t.TempDir(), "repacked-mount.dmg")
	if err := disk.RepackDMG(src, dst, nil); err != nil {
		t.Fatalf("RepackDMG: %v", err)
	}

	out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse", "-plist", dst).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach failed: %v\n%s", err, out)
	}

	// Find the attached device node to detach it again.
	dev := parseFirstDevEntry(string(out))
	if dev == "" {
		t.Fatalf("could not determine attached device from hdiutil output:\n%s", out)
	}
	t.Cleanup(func() {
		_ = exec.Command("hdiutil", "detach", "-force", dev).Run()
	})

	t.Logf("repacked DMG mounted via hdiutil as %s", dev)
}

// parseFirstDevEntry extracts the first /dev/diskN entry from an hdiutil
// -plist attach response (or plain text as a fallback).
func parseFirstDevEntry(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<string>/dev/") {
			line = strings.TrimPrefix(line, "<string>")
			line = strings.TrimSuffix(line, "</string>")
			return line
		}
		if strings.HasPrefix(line, "/dev/disk") {
			return strings.Fields(line)[0]
		}
	}
	return ""
}
