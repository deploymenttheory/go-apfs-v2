//go:build ignore

package main

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"
)

func TestSpecialNativeEvidenceRejectsTampering(t *testing.T) {
	f, err := os.Open("../testdata/appledouble/native/hfs-special-names-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var c specialCapture
	if err = json.NewDecoder(z).Decode(&c); err != nil {
		t.Fatal(err)
	}
	for _, volume := range c.Volumes {
		if err = validateSpecial(volume); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*specialVolume)
	}{
		{"count", func(v *specialVolume) { v.Native.Count-- }},
		{"filesystem", func(v *specialVolume) { v.Native.Filesystem = "apfs" }},
		{"sensitivity", func(v *specialVolume) { v.Native.Sensitive = !v.Native.Sensitive }},
		{"cleanup", func(v *specialVolume) { v.Detach = nil }},
		{"name", func(v *specialVolume) { v.Native.Cases[8].Name = "78" }},
		{"create", func(v *specialVolume) { v.Native.Cases[8].CreateErrno = 17 }},
		{"dot", func(v *specialVolume) { v.Native.Cases[1].LookupInode = 1 }},
		{"identity", func(v *specialVolume) { v.Native.Cases[8].LookupInode++ }},
		{"readdir", func(v *specialVolume) { v.Native.Cases[8].Stored[0].Hex = "78" }},
		{"raw-key", func(v *specialVolume) { v.Raw[0].Key = "00" }},
		{"raw-value", func(v *specialVolume) { v.Raw[0].Value = "00" }},
		{"raw-inode", func(v *specialVolume) { v.Raw[0].Inode++ }},
		{"raw-name", func(v *specialVolume) { v.Raw[0].UTF16[0]++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(c.Volumes[0])
			if err != nil {
				t.Fatal(err)
			}
			var v specialVolume
			if err = json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			tc.change(&v)
			if err = validateSpecial(v); err == nil {
				t.Fatal("accepted altered native evidence")
			}
		})
	}
}
