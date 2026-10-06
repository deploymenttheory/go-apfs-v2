//go:build ignore

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestWriterSpecialGuards(t *testing.T) {
	base := os.Getenv("FILESYSTEM_NAME_WRITER_OUTPUT")
	if base == "" {
		t.Fatal("complete genuine writer manifest required")
	}
	manifest, err := filepath.Abs(filepath.Join(base, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"positive", "missing-extra", "duplicate-extra", "unknown-id", "created-name", "queried-name", "stored-name", "payload", "fixture-hash", "create-errno", "lookup-errno", "parent", "inode", "lookup-inode", "utf16", "raw-key", "raw-value", "missing-extra-check", "extra-check-input"} {
		t.Run(mutation, func(t *testing.T) {
			cmd := cirunner.CommandContext(t.Context(), binary, "-test.run=^TestWriterSpecialGuardChild$", "-test.v")
			cmd.Env = append(os.Environ(), "APFS_WRITER_SPECIAL_GUARD="+mutation, "APFS_WRITER_SPECIAL_MANIFEST="+manifest)
			output, err := cmd.CombinedOutput()
			if mutation == "positive" {
				if err != nil {
					t.Fatalf("positive special manifest failed: %v\n%s", err, output)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), "--- FAIL: TestWriterSpecialGuardChild") {
				t.Fatalf("special mutation was not rejected: %v\n%s", err, output)
			}
		})
	}
}
func TestWriterSpecialGuardChild(t *testing.T) {
	mutation := os.Getenv("APFS_WRITER_SPECIAL_GUARD")
	if mutation == "" {
		return
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	report := readWriterReport(t, os.Getenv("APFS_WRITER_SPECIAL_MANIFEST"))
	if len(report.Images) != 12 {
		t.Fatal("complete twelve-image producer required")
	}
	var image *nameWriterImage
	for i := range report.Images {
		if report.Images[i].Kind == "HFS+" && report.Images[i].Target == 15 {
			image = &report.Images[i]
			break
		}
	}
	if image == nil {
		t.Fatal("mandatory target15 HFS image missing")
	}
	native := readComparisonCapture(t, "testdata/appledouble/native/name-collation-macos15.json.gz")
	var source *volumeCapture
	for i := range native.Volumes {
		if native.Volumes[i].Kind == "HFS+" {
			source = &native.Volumes[i]
		}
	}
	if source == nil {
		t.Fatal("native source missing")
	}
	validateWriterImageManifest(t, *image, *source)
	if mutation == "positive" {
		return
	}
	c := &image.ExtraCases[0]
	switch mutation {
	case "missing-extra":
		image.ExtraCases = image.ExtraCases[:10]
	case "duplicate-extra":
		image.ExtraCases[1] = image.ExtraCases[0]
	case "unknown-id":
		c.ID = "unqualified"
	case "created-name":
		c.Created += "61"
	case "queried-name":
		c.Queried += "61"
	case "stored-name":
		c.Stored += "61"
	case "payload":
		c.Payload = "00"
	case "fixture-hash":
		image.ExtraFixtureSHA256 = "00"
	case "create-errno":
		c.CreateErrno = 22
	case "lookup-errno":
		c.LookupErrno = 22
	case "parent":
		c.Parent = 0
	case "inode":
		c.Inode = 0
	case "lookup-inode":
		c.QueriedInode++
	case "utf16":
		c.UTF16[0]++
	case "raw-key":
		c.Key = "00"
	case "raw-value":
		c.Value = "00"
	case "missing-extra-check", "extra-check-input":
		found := false
		for i, check := range image.Checks {
			if strings.HasPrefix(check.ID, "special-") {
				if mutation == "missing-extra-check" {
					image.Checks = append(image.Checks[:i], image.Checks[i+1:]...)
				} else {
					image.Checks[i].First += "61"
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatal("genuine special check missing before mutation")
		}
	default:
		t.Fatal("unknown special guard", mutation)
	}
	validateWriterImageManifest(t, *image, *source)
}
