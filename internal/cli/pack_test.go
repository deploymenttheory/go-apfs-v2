// CLI acceptance tests for the pack (write-direction) command, exercised
// through the built binary against the committed APFS and HFS+ fixtures.
// These run on every OS in CI without any downloads.
package cli_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// packFixtures returns the fixture images that should round-trip through pack:
// the APFS basic fixture and, when present, the HFS+ fixture.
func packFixtures(t *testing.T) map[string]string {
	t.Helper()
	fixtures := map[string]string{"apfs": fixtureDMG}
	if hfsManifest.VolumeName != "" {
		fixtures["hfs+"] = fixtureHFS
	}
	return fixtures
}

// rawSHA256 reconstructs a DMG's full raw image and returns its sha256 and size.
func rawSHA256(t *testing.T, dmg string) (string, int) {
	t.Helper()
	raw, err := disk.ReconstructRawImage(dmg)
	if err != nil {
		t.Fatalf("reconstruct %s: %v", dmg, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), len(raw)
}

// TestPackRoundTripFixtures proves the fidelity invariant on both filesystems:
// pack via the CLI, then the raw filesystem image is preserved bit-for-bit.
func TestPackRoundTripFixtures(t *testing.T) {
	for fsName, src := range packFixtures(t) {
		t.Run(fsName, func(t *testing.T) {
			srcSum, srcSize := rawSHA256(t, src)

			out := filepath.Join(t.TempDir(), "repacked.dmg")
			mustRun(t, "pack", src, out)

			dstSum, dstSize := rawSHA256(t, out)
			if dstSum != srcSum || dstSize != srcSize {
				t.Fatalf("raw image not preserved: src %s (%d) != repacked %s (%d)",
					srcSum[:16], srcSize, dstSum[:16], dstSize)
			}
		})
	}
}

// TestPackCompressionModes checks both --compression zlib (default) and none
// preserve the raw image; only the container bytes differ.
func TestPackCompressionModes(t *testing.T) {
	srcSum, _ := rawSHA256(t, fixtureDMG)

	for _, mode := range []string{"zlib", "none"} {
		t.Run(mode, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "repacked.dmg")
			mustRun(t, "pack", fixtureDMG, out, "--compression", mode)
			gotSum, _ := rawSHA256(t, out)
			if gotSum != srcSum {
				t.Errorf("--compression %s did not preserve the raw image", mode)
			}
		})
	}
}

// TestPackOutputOpensWithOwnReader confirms a repacked image is a valid DMG
// that this tool reads back with identical info and listing.
func TestPackOutputOpensWithOwnReader(t *testing.T) {
	for fsName, src := range packFixtures(t) {
		t.Run(fsName, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "repacked.dmg")
			mustRun(t, "pack", src, out)

			srcInfo := infoJSON(t, src)
			dstInfo := infoJSON(t, out)
			if srcInfo.Volumes[0].Name != dstInfo.Volumes[0].Name {
				t.Errorf("volume name changed: %q -> %q", srcInfo.Volumes[0].Name, dstInfo.Volumes[0].Name)
			}
			if srcInfo.Volumes[0].Files != dstInfo.Volumes[0].Files {
				t.Errorf("file count changed: %d -> %d", srcInfo.Volumes[0].Files, dstInfo.Volumes[0].Files)
			}

			srcList := mustRun(t, "list", "-R", src)
			dstList := mustRun(t, "list", "-R", out)
			if srcList != dstList {
				t.Errorf("recursive listing differs after pack:\n--- source ---\n%s\n--- repacked ---\n%s", srcList, dstList)
			}
		})
	}
}

// TestPackReextractMatchesManifest packs a fixture, extracts from the repacked
// image, and verifies every file against the committed manifest.
func TestPackReextractMatchesManifest(t *testing.T) {
	cases := []struct {
		fs       string
		src      string
		manifest fixtureManifest
	}{
		{"apfs", fixtureDMG, manifest},
	}
	if hfsManifest.VolumeName != "" {
		cases = append(cases, struct {
			fs       string
			src      string
			manifest fixtureManifest
		}{"hfs+", fixtureHFS, hfsManifest})
	}

	for _, tc := range cases {
		t.Run(tc.fs, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "repacked.dmg")
			mustRun(t, "pack", tc.src, out)

			dest := t.TempDir()
			mustRun(t, "extract", out, "-C", dest)

			var checked int
			for path, expected := range tc.manifest.Files {
				if expected.Type != "file" {
					continue
				}
				got, err := fileSHA256(filepath.Join(dest, filepath.FromSlash(path)))
				if err != nil {
					t.Errorf("%s: missing after pack+extract: %v", path, err)
					continue
				}
				if got != expected.SHA256 {
					t.Errorf("%s: checksum mismatch after pack+extract", path)
				}
				checked++
			}
			if checked == 0 {
				t.Fatal("manifest had no files to check")
			}
		})
	}
}

// TestPackJSONSummary checks the machine-readable summary.
func TestPackJSONSummary(t *testing.T) {
	out := filepath.Join(t.TempDir(), "repacked.dmg")
	stdout := mustRun(t, "pack", "-o", "json", fixtureDMG, out)

	var summary struct {
		Source           string `json:"source"`
		Destination      string `json:"destination"`
		SourceBytes      int64  `json:"sourceBytes"`
		DestinationBytes int64  `json:"destinationBytes"`
	}
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatalf("pack -o json invalid: %v\n%s", err, stdout)
	}
	if summary.Destination != out || summary.DestinationBytes <= 0 {
		t.Errorf("unexpected pack json summary: %+v", summary)
	}
}

// TestPackExitCodes verifies the documented exit-code contract for pack.
func TestPackExitCodes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.dmg")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"missing source", []string{"pack", filepath.Join(t.TempDir(), "nope.dmg"), out}, 3},
		{"bad compression", []string{"pack", fixtureDMG, out, "--compression", "lz4"}, 2},
		{"bad chunk size", []string{"pack", fixtureDMG, out, "--chunk-size", "0"}, 2},
		{"too few args", []string{"pack", fixtureDMG}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, tc.args...)
			if code != tc.want {
				t.Errorf("%v exited %d, want %d\nstderr: %s", tc.args, code, tc.want, stderr)
			}
		})
	}
}

// infoJSON is a small helper returning parsed `info -o json` for a DMG.
func infoJSON(t *testing.T, dmg string) acceptanceInfo {
	t.Helper()
	var info acceptanceInfo
	if err := json.Unmarshal([]byte(mustRun(t, "info", "-o", "json", dmg)), &info); err != nil {
		t.Fatalf("info -o json invalid for %s: %v", dmg, err)
	}
	return info
}
