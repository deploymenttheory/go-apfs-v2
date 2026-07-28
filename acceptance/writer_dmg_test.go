// Checker test for the DMG writer: a repacked image is mounted with hdiutil,
// which proves macOS can read it. The synthetic encode/decode round-trips stay
// in pkg/disk.
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

// TestRepackMountsViaHdiutil repacks the source DMG and attaches it read-only
// with hdiutil, which proves macOS accepts the output as a valid UDIF image.
// Set DMG_REPACK_SRC to a source DMG to run it.
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

// TestCreatedDMGMountsViaHdiutil mounts a DMG this tool created, rather than
// one it repacked.
//
// Nothing tested that before: every other acceptance test reconstructs the raw
// file system out of the DMG and attaches that instead, stepping around the
// wrapper entirely. So a created DMG was unmountable for as long as the wrapper
// existed and no test noticed -- it declared itself a device image, which tells
// DiskImages sector 0 holds a partition map, while carrying a bare file system
// there. hdiutil refused it with "attach failed - Bad file descriptor".
//
// Unlike the repack test this needs no external fixture, so it runs on every
// macOS CI run.
func TestCreatedDMGMountsViaHdiutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is only available on darwin")
	}
	requireTools(t, "hdiutil")

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello from a created dmg\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "nested.txt"), []byte("nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, fs := range []string{"hfs+", "apfs"} {
		t.Run(fs, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "created.dmg")
			mustRun(t, "pack", source, dst, "--fs", fs, "--volname", "CREATED", "-q")

			mnt := t.TempDir()
			out, err := exec.Command("hdiutil", "attach", "-readonly", "-nobrowse",
				"-mountpoint", mnt, dst).CombinedOutput()
			if err != nil {
				t.Fatalf("hdiutil could not mount a DMG we created: %v\n%s", err, out)
			}
			// hdiutil prefixes its output with "Checksumming …" lines, so the
			// device node has to be matched rather than taken as the first
			// field -- otherwise the detach silently fails and the volume is
			// left attached.
			dev := devRe.FindString(string(out))
			if dev == "" {
				t.Fatalf("could not find the attached device in hdiutil output:\n%s", out)
			}
			t.Cleanup(func() { detach(t, dev) })

			// Mounting proves the wrapper; reading proves the file system
			// inside it survived the wrap.
			got, err := os.ReadFile(filepath.Join(mnt, "hello.txt"))
			if err != nil || string(got) != "hello from a created dmg\n" {
				t.Errorf("hello.txt through the mount = %q, %v", got, err)
			}
			if _, err := os.ReadFile(filepath.Join(mnt, "sub", "nested.txt")); err != nil {
				t.Errorf("nested path through the mount: %v", err)
			}
		})
	}
}
