//go:build ignore

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func fixture() capture {
	c := capture{Schema: 1, Host: "macOS27", Compiler: "clang", SDK: "sdk", Revision: "revision", Sources: map[string]string{}}
	for _, p := range append(append([]string{}, bound...), "native-binary", "arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/mount.h", "SDK/sys/attr.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h") {
		c.Sources[p] = strings.Repeat("1", 64)
	}
	for i, kind := range []string{"APFS", "APFSX"} {
		v := volume{Kind: kind, ImageSHA256: strings.Repeat("2", 64), Results: make([]byte, 0x110000), Native: observation{Filesystem: "apfs", Sensitive: i == 1, Valid: [4]uint32{0x100}, Count: 1112062, Counts: map[int]int{0: 1112061, 92: 1}}}
		if i == 1 {
			v.Native.Capabilities[0] = 0x100
		}
		v.Results[0] = 255
		v.Results[47] = 255
		for n := 0xd800; n <= 0xdfff; n++ {
			v.Results[n] = 255
		}
		v.Results[0x378] = 92
		for j, b := range controls {
			raw, _ := hex.DecodeString(b)
			n := bytes.IndexByte(raw, 0)
			if n < 0 {
				n = len(raw)
			}
			e := 92
			if j < 4 || j == 13 {
				e = 0
			}
			if j == 14 {
				e = 2
			}
			v.Native.Controls = append(v.Native.Controls, control{j, b, n, 2, e})
		}
		c.Volumes = append(c.Volumes, v)
	}
	return c
}
func clone(c capture) capture {
	b, _ := json.Marshal(c)
	var out capture
	_ = json.Unmarshal(b, &out)
	return out
}
func TestAdmissionEvidence(t *testing.T) {
	t.Chdir("..")
	original := fixture()
	harness, err := captureprovenance.Inventory(os.DirFS("."))
	if err != nil {
		t.Fatal(err)
	}
	for name, hash := range harness {
		original.Sources[name] = hash
	}
	if e := compare(original, clone(original)); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*capture){"schema": func(c *capture) { c.Schema = 2 }, "host": func(c *capture) { c.Host = "" }, "volume": func(c *capture) { c.Volumes = c.Volumes[:1] }, "source": func(c *capture) { delete(c.Sources, bound[0]) }, "stale-source": func(c *capture) { c.Sources[bound[0]] = strings.Repeat("3", 64) }, "case-sensitivity": func(c *capture) { c.Volumes[0].Native.Sensitive = true }, "capability": func(c *capture) { c.Volumes[0].Native.Valid[0] = 0 }, "filesystem": func(c *capture) { c.Volumes[0].Native.Filesystem = "hfs" }, "image": func(c *capture) { c.Volumes[0].ImageSHA256 = "" }, "length": func(c *capture) { c.Volumes[0].Results = c.Volumes[0].Results[:100] }, "excluded": func(c *capture) { c.Volumes[0].Results[0] = 0 }, "errno": func(c *capture) { c.Volumes[0].Results[100] = 13 }, "counts": func(c *capture) { c.Volumes[0].Native.Counts[0]-- }, "missing-count": func(c *capture) { delete(c.Volumes[0].Native.Counts, 92) }, "all-rejected": func(c *capture) {
		for n, b := range c.Volumes[0].Results {
			if b != 255 {
				c.Volumes[0].Results[n] = 92
			}
		}
	}, "positive": func(c *capture) {
		c.Volumes[0].Results['A'] = 92
		c.Volumes[0].Native.Counts[0]--
		c.Volumes[0].Native.Counts[92]++
	}, "nul-boundary": func(c *capture) { c.Volumes[0].Native.Controls[13].Length = 3 }, "control-result": func(c *capture) { c.Volumes[0].Native.Controls[4].Create = 0 }, "control-inventory": func(c *capture) { c.Volumes[0].Native.Controls = c.Volumes[0].Native.Controls[:1] }, "lookup-creation-confusion": func(c *capture) { c.Volumes[0].Native.Controls[4].Lookup = 92 }, "scalar-change": func(c *capture) {
		c.Volumes[0].Results[1000] = 92
		c.Volumes[0].Native.Counts[0]--
		c.Volumes[0].Native.Counts[92]++
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := clone(original)
			mutate(&c)
			if e := compare(original, c); e == nil {
				t.Fatal("accepted changed or incomplete native evidence")
			}
			if e := compare(c, original); e == nil {
				t.Fatal("accepted invalid retained evidence")
			}
		})
	}
}
