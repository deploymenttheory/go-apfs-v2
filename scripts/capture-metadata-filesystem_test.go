//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	if err := os.Chdir(".."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

const metadataFixture = "testdata/appledouble/native/metadata-filesystem-macos27.json.gz"

func metadataFixtureForTest(t *testing.T) metadataCapture {
	t.Helper()
	c, err := readMetadataCapture(metadataFixture)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMetadataFilesystemNativeInventory(t *testing.T) {
	for _, major := range []int{15, 26, 27} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			c, err := readMetadataCapture(fmt.Sprintf("testdata/appledouble/native/metadata-filesystem-macos%d.json.gz", major))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateMetadataCapture(c); err != nil {
				t.Fatal(err)
			}
			if err := captureprovenance.Verify(os.DirFS("."), c.Sources); err != nil {
				t.Fatal(err)
			}
			if len(c.Cases) != 960 {
				t.Fatal("lost filesystem cases", len(c.Cases))
			}
		})
	}
}

func TestMetadataFilesystemAttributeTargetInventory(t *testing.T) {
	c, err := readMetadataCapture("testdata/appledouble/native/metadata-filesystem-attribute-target-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMetadataCapture(c); err != nil {
		t.Fatal(err)
	}
	if c.Profile != "attribute-target" || len(c.Cases) != 192 || c.GoReadCases != 192 {
		t.Fatal("incomplete attribute-target capture")
	}
	if err := captureprovenance.Verify(os.DirFS("."), c.Sources); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataFilesystemRejectsIncompleteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*metadataCapture)
	}{
		{"schema", func(c *metadataCapture) { c.Schema++ }},
		{"unknown-profile", func(c *metadataCapture) { c.Profile = "invented" }},
		{"wrong-profile", func(c *metadataCapture) { c.Profile = "packed-empty" }},
		{"partial", func(c *metadataCapture) { c.Complete = false }},
		{"partial-go-readback", func(c *metadataCapture) { c.GoReadCases = 959 }},
		{"host", func(c *metadataCapture) { c.Host = "invalid" }},
		{"future-profile", func(c *metadataCapture) { c.Host = "ProductVersion:\t28.0\n" }},
		{"compiler", func(c *metadataCapture) { c.Compiler = "" }},
		{"sdk", func(c *metadataCapture) { c.SDK = "" }},
		{"architecture", func(c *metadataCapture) { c.Architecture = "" }},
		{"go", func(c *metadataCapture) { c.GoVersion = "" }},
		{"source-map", func(c *metadataCapture) { c.Sources = nil }},
		{"source-hash", func(c *metadataCapture) { c.Sources["oracle.bin"] = "invalid" }},
		{"seed", func(c *metadataCapture) { c.Seed[0] ^= 0xff }},
		{"missing-case", func(c *metadataCapture) { c.Cases = c.Cases[1:] }},
		{"duplicate-case", func(c *metadataCapture) { c.Cases[0] = c.Cases[1] }},
		{"unknown-case", func(c *metadataCapture) { c.Cases[0].ID = "invented" }},
		{"missing-before", func(c *metadataCapture) { c.Cases[0].Before = nil }},
		{"missing-after", func(c *metadataCapture) { c.Cases[0].After = nil }},
		{"missing-observation", func(c *metadataCapture) { c.Cases[0].Observation = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := metadataFixtureForTest(t)
			tc.change(&c)
			if validateMetadataCapture(c) == nil {
				t.Fatal("invalid native evidence accepted")
			}
		})
	}
}

func TestMetadataFilesystemRejectsOracleMutation(t *testing.T) {
	for _, field := range []string{"filesystem", "volume_flags", "open_errno", "before_path", "before_held", "result", "errno", "after_path", "after_held", "close_errno"} {
		t.Run("missing-"+field, func(t *testing.T) {
			c := metadataFixtureForTest(t)
			var m map[string]json.RawMessage
			if err := json.Unmarshal(c.Cases[0].Observation, &m); err != nil {
				t.Fatal(err)
			}
			delete(m, field)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			c.Cases[0].Observation = b
			if validateMetadataCapture(c) == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, tc := range []struct{ name, from, to string }{
		{"filesystem", `"filesystem":"exfat"`, `"filesystem":"invented"`},
		{"open", `"open_errno":0`, `"open_errno":13`},
		{"close", `"close_errno":0`, `"close_errno":5`},
		{"attribute", `com.example.phase2`, `com.example.invented`},
		{"read-size", `"read":-1`, `"read":100`},
		{"read-errno", `"read_errno":93`, `"read_errno":0`},
		{"list-size", `"list_result":0`, `"list_result":100`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := metadataFixtureForTest(t)
			old := c.Cases[0].Observation
			var compact bytes.Buffer
			if err := json.Compact(&compact, old); err != nil {
				t.Fatal(err)
			}
			old = compact.Bytes()
			if !bytes.Contains(old, []byte(tc.from)) {
				t.Fatal("mutation did not target fixture", tc.from)
			}
			c.Cases[0].Observation = bytes.Replace(old, []byte(tc.from), []byte(tc.to), 1)
			if validateMetadataCapture(c) == nil {
				t.Fatal("mutated result accepted")
			}
		})
	}
}

func TestMetadataFilesystemReaderErrors(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"missing.json", "bad.json", "bad.json.gz", "bad-compression.json.gz"} {
		path := filepath.Join(root, name)
		if name != "missing.json" {
			if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := readMetadataCapture(path); err == nil {
			t.Fatal("invalid capture accepted", name)
		}
	}
}

func TestMetadataFilesystemMountOwnership(t *testing.T) {
	for _, tc := range []struct{ filesystem, owners string }{
		{"ExFAT", "off"}, {"MS-DOS FAT32", "off"}, {"APFS", "on"}, {"HFS+", "on"},
	} {
		if got := metadataMountOwnership(tc.filesystem); got != tc.owners {
			t.Errorf("%s owners=%s, want %s", tc.filesystem, got, tc.owners)
		}
	}
}

func TestMetadataFilesystemPackedInventory(t *testing.T) {
	c, err := readMetadataCapture("testdata/appledouble/native/metadata-filesystem-packed-empty-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "packed-empty" || len(c.Cases) != 96 {
		t.Fatal("incomplete packed corpus")
	}
	if err := validateMetadataCapture(c); err != nil {
		t.Fatal(err)
	}
	if err := captureprovenance.Verify(os.DirFS("."), c.Sources); err != nil {
		t.Fatal(err)
	}
	c.Profile = ""
	if validateMetadataCapture(c) == nil {
		t.Fatal("packed profile accepted as ordinary corpus")
	}
}
