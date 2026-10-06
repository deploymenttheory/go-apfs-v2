//go:build ignore

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run the actual fatal-on-invalid validators in isolated test processes. Every
// mutation starts from an independently generated complete image manifest; a
// positive control must pass before a rejected mutation is accepted as evidence.
func TestWriterManifestGuards(t *testing.T) {
	manifest := os.Getenv("FILESYSTEM_NAME_WRITER_OUTPUT")
	if manifest == "" {
		t.Fatal("FILESYSTEM_NAME_WRITER_OUTPUT is required")
	}
	manifest, err := filepath.Abs(filepath.Join(manifest, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"positive", "missing-case", "duplicate-case", "created-bytes", "query-bytes", "stored-bytes", "parent", "inode", "lookup-inode", "create-errno", "lookup-errno", "hash", "raw-key", "raw-value", "missing-check", "duplicate-check", "write-before-rejection", "check-input", "check-errno", "unknown-field", "trailing-json", "truncated-json"}
	for _, mutation := range cases {
		t.Run(mutation, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestWriterManifestGuardChild$", "-test.v")
			cmd.Env = append(os.Environ(), "APFS_WRITER_GUARD="+mutation, "APFS_WRITER_MANIFEST="+manifest)
			output, err := cmd.CombinedOutput()
			if mutation == "positive" {
				if err != nil {
					t.Fatalf("positive manifest control failed: %v\n%s", err, output)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), "--- FAIL: TestWriterManifestGuardChild") {
				t.Fatalf("mutation %s was not rejected by the validator: %v\n%s", mutation, err, output)
			}
		})
	}
}

func TestWriterManifestGuardChild(t *testing.T) {
	mutation := os.Getenv("APFS_WRITER_GUARD")
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
	path := os.Getenv("APFS_WRITER_MANIFEST")
	if mutation == "unknown-field" || mutation == "trailing-json" || mutation == "truncated-json" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		switch mutation {
		case "unknown-field":
			var object map[string]json.RawMessage
			if err = json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			object["Unexpected"] = json.RawMessage(`true`)
			raw, err = json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
		case "trailing-json":
			raw = append(raw, []byte(`{}`)...)
		case "truncated-json":
			raw = raw[:len(raw)/2]
		}
		path = filepath.Join(t.TempDir(), "manifest.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		readWriterReport(t, path)
		return
	}
	report := readWriterReport(t, path)
	if len(report.Images) != 12 {
		t.Fatal("positive manifest has incomplete image inventory")
	}
	image := report.Images[0]
	if image.Kind != "APFS" || image.Target != 15 || len(image.Cases) == 0 || len(image.Checks) == 0 {
		t.Fatal("positive manifest is not the complete APFS15 control")
	}
	native := readComparisonCapture(t, "testdata/appledouble/native/name-collation-macos15.json.gz")
	var source *volumeCapture
	for i := range native.Volumes {
		if native.Volumes[i].Kind == image.Kind {
			source = &native.Volumes[i]
			break
		}
	}
	if source == nil {
		t.Fatal("native input missing")
	}
	// Validate pristine input inside every child before applying its one mutation.
	validateWriterImageManifest(t, image, *source)
	c := &image.Cases[0]
	switch mutation {
	case "positive":
		return
	case "missing-case":
		image.Cases = image.Cases[:len(image.Cases)-1]
	case "duplicate-case":
		image.Cases[1] = image.Cases[0]
	case "created-bytes":
		c.Created += "61"
	case "query-bytes":
		c.Queried += "61"
	case "stored-bytes":
		c.Stored += "61"
	case "parent":
		c.Parent = 0
	case "inode":
		c.Inode = 0
	case "lookup-inode":
		c.QueriedInode++
	case "create-errno":
		c.CreateErrno = 22
	case "lookup-errno":
		c.LookupErrno = 22
	case "hash":
		c.Hash++
	case "raw-key":
		c.Key = "00"
	case "raw-value":
		c.Value = "00"
	case "missing-check":
		image.Checks = image.Checks[:len(image.Checks)-1]
	case "duplicate-check":
		image.Checks = append(image.Checks, image.Checks[0])
	case "write-before-rejection":
		image.Checks[0].Writes = 1
	case "check-input":
		image.Checks[0].First += "61"
	case "check-errno":
		image.Checks[0].Errno = 0
	default:
		t.Fatal("unknown guard mutation", mutation)
	}
	validateWriterImageManifest(t, image, *source)
}
