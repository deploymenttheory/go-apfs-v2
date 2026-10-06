//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func casesForTest(t *testing.T) []nameCase {
	t.Helper()
	tables := map[string][]byte{}
	root := filepath.Join("..", corpusDir)
	if _, err := os.Stat(root); err != nil {
		root = corpusDir
	}
	for _, name := range []string{"UnicodeData.txt", "CaseFolding.txt"} {
		raw, err := os.ReadFile(filepath.Join(root, name+".gz"))
		if err != nil {
			t.Fatal(err)
		}
		z, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(z)
		if err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		tables[name] = b
	}
	cases, err := makeCases(tables)
	if err != nil {
		t.Fatal(err)
	}
	return cases
}
func TestCollationCorpusInventory(t *testing.T) {
	cases := casesForTest(t)
	if len(cases) != 3753 {
		t.Fatal(len(cases))
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.ID] = true
	}
	for _, id := range []string{"sigma", "sharp-s", "post9-georgian", "post9-vithkuqi", "post9-latin", "reorder-234-240", "length-emoji-128", "length-decomposed-e-128", "length-e-acute-255", "length-ascii-256"} {
		if !seen[id] {
			t.Fatal("missing control", id)
		}
	}
	if _, err := makeCases(nil); err == nil {
		t.Fatal("accepted missing corpus")
	}
	for _, row := range []string{"broken", "110000;a;b", "0041;a;b", "0041;name;Lu;bad;L;;;"} {
		if _, err := makeCases(map[string][]byte{"UnicodeData.txt": []byte(row)}); err == nil {
			t.Fatal("accepted malformed source")
		}
	}
}
func sampleNative(t *testing.T) (nativeCapture, []nameCase) {
	t.Helper()
	cases := casesForTest(t)
	n := nativeCapture{Filesystem: "apfs", Capabilities: [4]uint32{}, Valid: [4]uint32{0x100}, Count: casesPerVolume, Retained: true}
	for i, c := range cases {
		n.Cases = append(n.Cases, nativeCase{ID: c.ID, Created: c.Created, Queried: c.Queried, Stored: c.Created, StoredInode: uint64(i + casesPerVolume + 3), Same: true, Parent: uint64(i + 3), Inode: uint64(i + casesPerVolume + 3), QueriedInode: uint64(i + casesPerVolume + 3)})
	}
	for i := range n.Cases {
		raw, e := hex.DecodeString(n.Cases[i].Created)
		if e != nil {
			t.Fatal(e)
		}
		if len(utf16.Encode([]rune(string(raw)))) > 255 {
			c := &n.Cases[i]
			c.CreateErrno = 63
			c.LookupErrno = 63
			c.Inode = 0
			c.QueriedInode = 0
			c.StoredInode = 0
			c.Stored = ""
			c.Same = false
		}
	}
	return n, cases
}
func TestCollationNativeInventoryRejectsGaps(t *testing.T) {
	original, cases := sampleNative(t)
	if err := validateNative(original, "APFS", cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*nativeCapture)
	}{
		{"filesystem", func(n *nativeCapture) { n.Filesystem = "hfs" }},
		{"case sensitivity", func(n *nativeCapture) { n.Sensitive = true }},
		{"uncaptured capability", func(n *nativeCapture) { n.Valid[0] = 0 }},
		{"contradictory capability", func(n *nativeCapture) { n.Capabilities[0] = 0x100 }},
		{"missing case", func(n *nativeCapture) { n.Cases = n.Cases[:len(n.Cases)-1] }},
		{"false count", func(n *nativeCapture) { n.Count-- }},
		{"not retained", func(n *nativeCapture) { n.Retained = false }},
		{"identity", func(n *nativeCapture) { n.Cases[0].ID = "other" }},
		{"parent", func(n *nativeCapture) { n.Cases[0].Parent = 0 }},
		{"negative errno", func(n *nativeCapture) { n.Cases[0].LookupErrno = -1 }},
		{"created inode", func(n *nativeCapture) { n.Cases[0].Inode = 0 }},
		{"failed identity", func(n *nativeCapture) { n.Cases[0].CreateErrno = 63 }},
		{"lookup inode", func(n *nativeCapture) { n.Cases[0].QueriedInode = 0 }},
		{"false equality", func(n *nativeCapture) { n.Cases[0].Same = false }},
		{"insufficient positive controls", func(n *nativeCapture) {
			for i := range n.Cases {
				n.Cases[i].CreateErrno = 63
				n.Cases[i].LookupErrno = 63
				n.Cases[i].Inode = 0
				n.Cases[i].QueriedInode = 0
				n.Cases[i].Same = false
				n.Cases[i].Stored = ""
				n.Cases[i].StoredInode = 0
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := original
			n.Cases = append([]nativeCase(nil), original.Cases...)
			tc.edit(&n)
			if err := validateNative(n, "APFS", cases); err == nil {
				t.Fatal("accepted invalid native evidence")
			}
		})
	}
	n := original
	n.Cases = append([]nativeCase(nil), original.Cases...)
	n.Cases[1].CreateErrno = 63
	n.Cases[1].LookupErrno = 63
	n.Cases[1].Inode = 0
	n.Cases[1].QueriedInode = 0
	n.Cases[1].StoredInode = 0
	n.Cases[1].Stored = ""
	n.Cases[1].Same = false
	if err := validateNative(n, "APFS", cases); err != nil {
		t.Fatal("genuine native rejection is evidence", err)
	}
	n = original
	n.Filesystem = "hfs"
	n.Sensitive = true
	n.Capabilities[0] = 0x100
	n.Cases = append([]nativeCase(nil), original.Cases...)
	n.Cases[0].LookupErrno = 2
	n.Cases[0].Same = false
	n.Cases[0].QueriedInode = 0
	if err := validateNative(n, "HFSX", cases); err != nil {
		t.Fatal(err)
	}
}
func TestCollationStableComparison(t *testing.T) {
	t.Chdir("..")
	n, cases := sampleNative(t)
	a := capture{Schema: 1, Cases: cases, Sources: map[string]string{"scripts/capture-name-collation.go": "source"}}
	harness, err := captureprovenance.Inventory(os.DirFS("."))
	if err != nil {
		t.Fatal(err)
	}
	for name, hash := range harness {
		a.Sources[name] = hash
	}
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		v := volumeCapture{Kind: kind, Native: n}
		v.Native.Cases = append([]nativeCase(nil), n.Cases...)
		if strings.HasPrefix(kind, "HFS") {
			v.Native.Filesystem = "hfs"
		}
		if strings.HasSuffix(kind, "X") {
			v.Native.Sensitive = true
			v.Native.Capabilities[0] = 0x100
			v.Native.Cases[0].LookupErrno = 2
			v.Native.Cases[0].Same = false
			v.Native.Cases[0].QueriedInode = 0
		}
		for _, c := range v.Native.Cases {
			if c.CreateErrno != 0 {
				continue
			}
			r := diskRecord{ID: c.ID, Name: c.Stored, Inode: c.Inode}
			if v.Native.Filesystem == "apfs" {
				name, e := hex.DecodeString(c.Stored)
				if e != nil {
					t.Fatal(e)
				}
				name = append(name, 0)
				key := make([]byte, 12+len(name))
				binary.LittleEndian.PutUint64(key, c.Parent|uint64(apfs.FileSystemRecordTypeDirectoryEntry)<<60)
				r.Hash = 123
				binary.LittleEndian.PutUint32(key[8:], r.Hash<<10|uint32(len(name)))
				copy(key[12:], name)
				value := make([]byte, 18)
				binary.LittleEndian.PutUint64(value, c.Inode)
				r.Key = hex.EncodeToString(key)
				r.Value = hex.EncodeToString(value)
			}
			v.Records = append(v.Records, r)
		}
		a.Volumes = append(a.Volumes, v)
	}
	if e := compareStable(a, a); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		edit func(*capture)
	}{
		{"incomplete", func(c *capture) { c.Schema = 0 }},
		{"source", func(c *capture) { c.Sources = map[string]string{} }},
		{"volume", func(c *capture) { c.Volumes = c.Volumes[:3] }},
		{"input inventory", func(c *capture) { c.Cases[0].Created = "00" }},
		{"native result", func(c *capture) { c.Volumes[0].Native.Cases[0].LookupErrno = 2 }},
		{"hash", func(c *capture) { c.Volumes[0].Records[0].Hash++ }},
		{"raw key malformed", func(c *capture) { c.Volumes[0].Records[0].Key = "00" }},
		{"raw key hex", func(c *capture) { c.Volumes[0].Records[0].Key = "xx" }},
		{"raw value malformed", func(c *capture) { c.Volumes[0].Records[0].Value = "00" }},
		{"raw value hex", func(c *capture) { c.Volumes[0].Records[0].Value = "xx" }},
		{"raw inode changed", func(c *capture) {
			raw, _ := hex.DecodeString(c.Volumes[0].Records[0].Value)
			raw[0] ^= 1
			c.Volumes[0].Records[0].Value = hex.EncodeToString(raw)
		}},
		{"raw key changed", func(c *capture) {
			raw, _ := hex.DecodeString(c.Volumes[0].Records[0].Key)
			raw[8] ^= 4
			c.Volumes[0].Records[0].Key = hex.EncodeToString(raw)
		}},
		{"duplicate", func(c *capture) { c.Volumes[0].Records[1] = c.Volumes[0].Records[0] }},
		{"missing record", func(c *capture) { c.Volumes[0].Records = c.Volumes[0].Records[1:] }},
		{"native stored spelling", func(c *capture) { c.Volumes[0].Native.Cases[0].Stored = "00" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := a
			b.Cases = append([]nameCase(nil), a.Cases...)
			b.Volumes = append([]volumeCapture(nil), a.Volumes...)
			b.Volumes[0].Native.Cases = append([]nativeCase(nil), a.Volumes[0].Native.Cases...)
			b.Volumes[0].Records = append([]diskRecord(nil), a.Volumes[0].Records...)
			tc.edit(&b)
			if e := compareStable(b, a); e == nil {
				t.Fatal("accepted changed native/raw evidence")
			}
		})
	}
}
