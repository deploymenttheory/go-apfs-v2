// Helpers shared by the checker tests: attaching a raw image through hdiutil,
// detaching it again, and skipping when a platform tool is not installed.
package acceptance

import (
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

var devRe = regexp.MustCompile(`/dev/disk\d+`)

// requireTools skips the test unless every named tool is on PATH.
func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("required tool %q not found", tool)
		}
	}
}

// attachRaw attaches a raw image read-only without mounting it and returns the
// device node, so a checker can be pointed at the whole container.
func attachRaw(t *testing.T, imgPath string) string {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-nomount", "-readonly", imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := devRe.FindString(string(out))
	if dev == "" {
		t.Fatalf("could not find /dev/diskN in hdiutil output:\n%s", out)
	}
	return dev
}

// detach releases a device attached by attachRaw. Failures are logged rather
// than fatal so they cannot mask the assertion that actually matters.
func detach(t *testing.T, dev string) {
	t.Helper()
	if out, err := exec.Command("hdiutil", "detach", dev).CombinedOutput(); err != nil {
		t.Logf("hdiutil detach %s: %v\n%s", dev, err, out)
	}
}

// writeImage formats a container into path.
func writeImage(t *testing.T, path string, size int64, opts *apfswrite.CreateOptions) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	if err := apfswrite.CreateContainer(f, size, opts); err != nil {
		f.Close()
		t.Fatalf("CreateContainer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}
}

// seededBytes returns n deterministic pseudo-random bytes for the given seed,
// so a failing image can be reproduced exactly.
func seededBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// mountPointFrom extracts the mount point from hdiutil attach output.
//
// The columns are tab-separated and the mount point is the last of them, which
// is what makes splitting on whitespace wrong: a volume name may contain
// spaces, and macOS produces one whenever the name is already taken — attaching
// a second volume called Keep mounts it at "/Volumes/Keep 1". Splitting on
// spaces then yields "/Volumes/Keep", an entirely different volume that happens
// to still be mounted, and the test reads the wrong file.
func mountPointFrom(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		candidate := strings.TrimSpace(fields[len(fields)-1])
		if strings.HasPrefix(candidate, "/Volumes/") {
			return candidate
		}
	}
	return ""
}

// attachAndMount attaches a raw image read-only and mounts it, returning the
// mount point and the device to detach.
func attachAndMount(t *testing.T, imgPath string) (mountPoint, dev string) {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-imagekey", "diskimage-class=CRawDiskImage", "-readonly", imgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev = devRe.FindString(string(out))
	if mountPoint = mountPointFrom(out); mountPoint == "" {
		exec.Command("hdiutil", "detach", dev).Run()
		t.Fatalf("the image did not mount:\n%s", out)
	}
	return mountPoint, dev
}
