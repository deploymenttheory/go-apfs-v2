// Checker test for the DMG encoder's codecs: every DMG this tool writes must
// pass `hdiutil verify`, which decodes each chunk with Apple's own
// decompressors and checks the checksums. Reading a DMG back with this
// module's reader cannot catch a codec whose encoder and decoder agree on a
// stream Apple's decoder rejects; this test exists because two did.
//
//   - LZMA DMGs were written as LZMA1 "alone" streams, which hdiutil rejects
//     ("checksum failed with error 1000"). It writes xz-contained LZMA2.
//   - The LZFSE encoder formerly used split long literal runs with the
//     following match's distance, which can reach before the start of the
//     output; Apple's decoder rejects such a chunk. See
//     pkg/compression/lzfse.
//
// macOS only: hdiutil is the ground truth, and it exists nowhere else.
package acceptance

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// hdiutilVerify runs `hdiutil verify` on dmg and fails unless it is valid.
// hdiutil caches results by path, so dmg must be freshly named.
func hdiutilVerify(t *testing.T, dmg string) {
	t.Helper()
	out, err := exec.Command("hdiutil", "verify", dmg).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "is VALID") {
		t.Fatalf("hdiutil verify rejected %s (%v):\n%s", filepath.Base(dmg), err, out)
	}
}

// TestPackedDMGsPassHdiutilVerify packs the sample tree as APFS and as HFS+
// with every codec the encoder writes.
func TestPackedDMGsPassHdiutilVerify(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is only available on darwin")
	}
	requireTools(t, "hdiutil")
	src, _ := buildSampleTree(t)
	for _, fs := range []string{"apfs", "hfs+"} {
		for _, codec := range []string{"lzfse", "lzma", "zlib", "none"} {
			t.Run(fs+"/"+codec, func(t *testing.T) {
				dmg := filepath.Join(t.TempDir(), "packed.dmg")
				mustRun(t, "pack", src, dmg, "--fs", fs, "--compression", codec)
				hdiutilVerify(t, dmg)
			})
		}
	}
}

// TestLZFSESplitLiteralChunkPassesHdiutilVerify writes a DMG whose first chunk
// begins with a literal run too long for one LZFSE record and then repeats its
// start. The old encoder split that run into records carrying the repeat's
// distance, 1000, at output positions below 1000, and hdiutil rejected the
// DMG.
func TestLZFSESplitLiteralChunkPassesHdiutilVerify(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is only available on darwin")
	}
	requireTools(t, "hdiutil")

	r := make([]byte, 1000)
	rand.New(rand.NewSource(1)).Read(r)
	img := append(append([]byte{}, r...), r[:100]...)
	img = append(img, bytes.Repeat([]byte("compressible text "), 4000)...)
	img = append(img, make([]byte, (1<<20)-len(img))...)

	var buf bytes.Buffer
	blocks := []disk.SourceBlock{{Name: "disk image", Data: img}}
	if err := disk.EncodeUDIF(&buf, blocks, &disk.EncodeOptions{Compression: disk.CompressionLZFSE}); err != nil {
		t.Fatal(err)
	}
	dmg := filepath.Join(t.TempDir(), "split-literal.dmg")
	if err := os.WriteFile(dmg, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	hdiutilVerify(t, dmg)
}
