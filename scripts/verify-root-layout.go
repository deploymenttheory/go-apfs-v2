//go:build ignore

// Verify unchanged legacy layouts and the intentional root metadata change.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

func main() {
	out := map[string]string{}
	for _, name := range []string{"empty", "plain", "nested", "sensitive", "snapshot", "child-streams", "hardlinks", "root-metadata", "hfsx", "hfsplus"} {
		func() {
			f, e := os.CreateTemp("", "root-hash-")
			must(e)
			defer os.Remove(f.Name())
			defer f.Close()
			root := &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "a", Data: []byte("payload")}}}
			opts := &apfswrite.CreateOptions{Root: root, VolumeName: "HASH"}
			switch name {
			case "empty":
				opts.Root = nil
			case "nested":
				root.Children = append(root.Children, &apfswrite.Entry{Name: "dir", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "b", Data: []byte("nested")}}})
			case "sensitive":
				opts.CaseSensitive = true
			case "snapshot":
				opts.Snapshots = []apfswrite.SnapshotSpec{{Name: "s"}}
			case "child-streams":
				root.Children[0].Xattrs = map[string][]byte{"user.big": make([]byte, 32769), "com.apple.ResourceFork": []byte{1, 2, 3}}
			case "hardlinks":
				root.Children[0].LinkGroup = 1
				root.Children = append(root.Children, &apfswrite.Entry{Name: "b", Data: []byte("payload"), LinkGroup: 1})
			case "root-metadata":
				root.UID = 42
				root.GID = 43
				root.Mode = os.ModeDir | 0711
				root.Xattrs = map[string][]byte{"user.root": []byte("metadata")}
			}
			if name == "hfsx" || name == "hfsplus" {
				must(hfsplus.CreateImage(f, 64<<20, "HASH", &hfsplus.Entry{Children: []*hfsplus.Entry{{Name: "a", Data: []byte("payload"), LinkGroup: 1}, {Name: "b", Data: []byte("payload"), LinkGroup: 1}}}, &hfsplus.CreateOptions{CaseInsensitive: name == "hfsplus"}))
			} else {
				must(apfswrite.CreateContainer(f, 64<<20, opts))
			}
			_, e = f.Seek(0, 0)
			must(e)
			h := sha256.New()
			_, e = io.Copy(h, f)
			must(e)
			out[name] = fmt.Sprintf("%x", h.Sum(nil))
		}()
	}
	var fixture struct{ Before, After map[string]string }
	b, e := os.ReadFile("testdata/appledouble/native/root-layout.json")
	must(e)
	must(json.Unmarshal(b, &fixture))
	if len(fixture.After) != len(out) {
		panic("layout fixture count")
	}
	for name, got := range out {
		if got != fixture.After[name] {
			panic("layout changed: " + name)
		}
		if (fixture.Before[name] == got) != (name != "root-metadata") {
			panic("unexpected baseline difference: " + name)
		}
	}
	result := map[string]any{"images": out, "passed": true}
	encoded, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.MkdirAll("artifacts/root-layout", 0700))
	must(os.WriteFile("artifacts/root-layout/report.json", append(bytes.Clone(encoded), '\n'), 0600))
	fmt.Println("Root layouts: nine unchanged controls and one intentional metadata change")
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
