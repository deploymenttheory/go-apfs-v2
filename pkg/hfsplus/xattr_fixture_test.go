package hfsplus_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFixtureXattrs reads the committed HFS+ fixture. macOS stamps
// com.apple.provenance onto files as it writes them, so every entry in the
// image carries at least that one -- which makes it a usable assertion that the
// attributes file is walked at all, against bytes macOS produced rather than
// bytes this package synthesized.
func TestFixtureXattrs(t *testing.T) {
	imagePath := filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg")
	if _, err := os.Stat(imagePath); err != nil {
		t.Skipf("fixture image missing: %v", err)
	}

	volume := openVolume(t, imagePath)

	attrs, err := volume.Xattrs("hello.txt")
	if err != nil {
		t.Fatalf("Xattrs(hello.txt): %v", err)
	}
	if len(attrs) == 0 {
		t.Fatal("hello.txt reported no extended attributes; the attributes file was not read")
	}
	if _, ok := attrs["com.apple.provenance"]; !ok {
		t.Errorf("hello.txt attributes = %v, want com.apple.provenance among them", keysOf(attrs))
	}

	// A hard link resolves to its iNode record, which is where a linked file's
	// attributes actually live.
	linked, err := volume.Xattrs("hardlink-to-hello")
	if err != nil {
		t.Fatalf("Xattrs(hardlink-to-hello): %v", err)
	}
	if len(linked) == 0 {
		t.Error("a hard link reported no extended attributes")
	}

	// Directories carry attributes too.
	if _, err := volume.Xattrs("dir1"); err != nil {
		t.Errorf("Xattrs on a directory: %v", err)
	}

	// A path that does not exist must be an error, not an empty map.
	if _, err := volume.Xattrs("no-such-file"); err == nil {
		t.Error("Xattrs on a missing path returned no error")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
