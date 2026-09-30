package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// Compare retained metadata with the independent committed native manifest,
// including values such as provenance that a receiving kernel can refuse.
func assertCarriedFixtureAttrs(t *testing.T, payload, metadata string, hfs ...bool) {
	t.Helper()
	store, err := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	actual, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	expectedFiles := manifest.Files
	if len(hfs) > 0 && hfs[0] {
		// The independently captured HFS+ fixture contains the same files and
		// attribute hashes, with its actual filesystem spellings. Do not apply
		// a generic Unicode normalizer to outputs or metadata names.
		expectedFiles = hfsManifest.Files
		if len(expectedFiles) != len(manifest.Files) {
			t.Fatal("native HFS+ fixture inventory differs")
		}
	}
	checked := 0
	for _, record := range actual.Records {
		want, ok := expectedFiles[record.Original]
		if !ok {
			continue
		}
		seen[record.Original] = true
		attrs, err := store.ReadRecordAttributes(context.Background(), record, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		for name, expected := range want.Xattrs {
			value, present := attrs[name]
			sum := sha256.Sum256(value)
			if !present || len(value) != expected.Size || hex.EncodeToString(sum[:]) != expected.SHA256 {
				t.Fatalf("%s %s was not preserved", record.Original, name)
			}
			checked++
		}
	}
	for name, entry := range expectedFiles {
		if len(entry.Xattrs) > 0 && !seen[name] {
			t.Fatalf("metadata record missing: %s", name)
		}
	}
	if checked == 0 {
		t.Fatal("fixture native metadata assertions did not execute")
	}
}

func TestExtractMetadataIntentPreflight(t *testing.T) {
	for _, flags := range [][]string{{"--xattrs"}, {"--preserve-meta"}, {"--xattrs", "--preserve-meta"}, {"--project-native"}} {
		dir := t.TempDir()
		sentinel := filepath.Join(dir, "existing")
		if err := os.WriteFile(sentinel, []byte("keep existing payload"), 0600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"extract", filepath.Join(t.TempDir(), "image-does-not-exist.dmg"), "-C", dir}, flags...)
		_, stderr, code := run(t, args...)
		if code != exitcode.Usage || !strings.Contains(stderr, "--metadata-root") {
			t.Fatalf("%v: %s %s", flags, exitcode.Name(code), stderr)
		}
		if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep existing payload" {
			t.Fatal(string(data), err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal(entries, err)
		}
	}
}

func TestExtractPreservedMetadataRepack(t *testing.T) {
	payload, metadata := t.TempDir(), t.TempDir()
	mustRun(t, "extract", fixtureDMG, "-C", payload, "--xattrs", "--preserve-meta", "--metadata-root", metadata, "-q")
	assertCarriedFixtureAttrs(t, payload, metadata)
	for _, format := range []string{"apfs", "hfs+"} {
		t.Run(format, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "repacked.dmg")
			mustRun(t, "pack", payload, image, "--fs", format, "--metadata-root", metadata, "--compression", "none", "-q")
			next, nextMetadata := t.TempDir(), t.TempDir()
			mustRun(t, "extract", image, "-C", next, "--xattrs", "--preserve-meta", "--metadata-root", nextMetadata, "-q")
			assertCarriedFixtureAttrs(t, next, nextMetadata, format == "hfs+")
		})
	}
}

func TestExtractNativeProjectionCounts(t *testing.T) {
	stdout := mustRun(t, "extract", fixtureDMG, "-C", t.TempDir(), "--xattrs", "--metadata-root", t.TempDir(), "--project-native", "-o", "json")
	var summary struct {
		Restored   int                              `json:"xattrsRestored"`
		Unwritable int                              `json:"xattrsUnwritable"`
		Carried    int                              `json:"xattrsCarried"`
		Projection []struct{ Field, Status string } `json:"nativeProjection"`
	}
	if err := json.Unmarshal([]byte(stdout), &summary); err != nil {
		t.Fatal(err, stdout)
	}
	written, unwritable := 0, 0
	for _, result := range summary.Projection {
		if !strings.HasPrefix(result.Field, "xattr:") {
			continue
		}
		switch result.Status {
		case "applied", "normalized":
			written++
		case "retained", "failed":
			unwritable++
		default:
			t.Fatal("unrecognized native attribute outcome", result)
		}
	}
	if written+unwritable == 0 || summary.Carried == 0 || summary.Restored != written || summary.Unwritable != unwritable {
		t.Fatalf("summary disagrees with real native outcomes: %+v; counted %d, %d", summary, written, unwritable)
	}
}

func TestExtractCarrierOnlyText(t *testing.T) {
	stdout := mustRun(t, "extract", fixtureDMG, "-C", t.TempDir(), "--xattrs", "--metadata-root", t.TempDir())
	if !strings.Contains(stdout, "Preserved ") || strings.Contains(stdout, "Restored ") || strings.Contains(stdout, "native extended attribute write(s)") {
		t.Fatal("carrier-only summary implies native writes", stdout)
	}
}
