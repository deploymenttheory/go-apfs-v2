// Every DMG chunk codec the toolkit claims to read, checked against the same
// volume compressed each way.
//
// ADC and LZMA had no fixture and no test, and ADC did not work: reading a real
// UDCO image panicked with an out-of-range index. Claiming a codec without
// exercising it is how that survived, so each claimed codec now has an image
// here and must produce the same bytes as the others.
package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// codecFixtures are the same HFS+ volume written with different chunk
// compressors, produced with `hdiutil convert -format`:
//
//	UDZO  zlib   (the committed default)
//	UDCO  ADC
//	ULMO  LZMA
//
// bzip2 and LZFSE are covered by basic-bz2.dmg and basic-lzfse.dmg, which hold
// the APFS fixture instead.
var codecFixtures = map[string]string{
	"zlib": "hfs-basic.dmg",
	"adc":  "hfs-basic-adc.dmg",
	"lzma": "hfs-basic-lzma.dmg",
}

// TestDMGCodecsAgree checks each codec decodes to the same volume. Comparing
// them against each other rather than against a recorded hash is what makes a
// wrong-but-consistent decoder visible: ADC used to compute one back-reference
// distance 256 bytes too far, which would corrupt content without failing.
func TestDMGCodecsAgree(t *testing.T) {
	want := extractAll(t, filepath.Join(repoRoot, "testdata", "cli", codecFixtures["zlib"]))
	if len(want) == 0 {
		t.Fatal("the reference fixture extracted nothing")
	}

	for codec, name := range codecFixtures {
		if codec == "zlib" {
			continue
		}
		t.Run(codec, func(t *testing.T) {
			got := extractAll(t, filepath.Join(repoRoot, "testdata", "cli", name))
			if len(got) != len(want) {
				t.Fatalf("%s extracted %d files, zlib extracted %d", codec, len(got), len(want))
			}
			for path, content := range want {
				other, ok := got[path]
				if !ok {
					t.Errorf("%s is missing %s", codec, path)
					continue
				}
				if string(other) != string(content) {
					t.Errorf("%s: %s differs from the zlib original (%d bytes vs %d)",
						codec, path, len(other), len(content))
				}
			}
		})
	}
}

// extractAll extracts an image and returns every file's contents by path.
func extractAll(t *testing.T, image string) map[string][]byte {
	t.Helper()
	dest := t.TempDir()
	if _, stderr, code := run(t, "extract", image, "-C", dest); code != 0 {
		t.Fatalf("extract %s exited %d: %s", image, code, stderr)
	}

	files := map[string][]byte{}
	err := filepath.Walk(dest, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dest, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walking the extracted tree: %v", err)
	}
	return files
}

// TestAPMWholeDiskImageIsReadable covers the other partition scheme this
// toolkit claims to locate. A DMG carrying an Apple Partition Map is found
// through its blkx partition names, so the map itself was never parsed and a
// raw whole-disk image with one could not be opened at all — it fell through to
// "does not contain a recognizable APFS or HFS+ file system".
//
// The fixture is what `hdiutil create -layout SPUD -type UDIF` produces, which
// has no koly trailer and so is a raw image rather than a DMG.
func TestAPMWholeDiskImageIsReadable(t *testing.T) {
	listing := mustRun(t, "list", fixtureAPM)
	if !strings.Contains(listing, "f.txt") {
		t.Errorf("the APM image did not list its contents:\n%s", listing)
	}
	if got := mustRun(t, "cat", fixtureAPM, "f.txt"); got != "apm content\n" {
		t.Errorf("f.txt = %q, want %q", got, "apm content\n")
	}
}
