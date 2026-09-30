//go:build ignore

// Qualify all four image sources through the production carrier into all four
// writers. macOS independently reads each result through libSystem and hdiutil.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type volume interface {
	tools.VolumeFS
	hostmeta.ImageMetadataFS
	Xattrs(string) (map[string][]byte, error)
}
type value struct {
	Size   int
	SHA256 string
}
type entry struct {
	UID, GID, Mode, Flags uint32
	Inode                 uint64
	Times                 [4]int64
	Attrs                 map[string]value
	Data                  *value
	Target                string
}
type result struct {
	Source, Destination, ImageSHA256 string
	Entries                          map[string]entry
	Native                           bool
}
type command struct {
	Args   []string
	Output string
}
type report struct {
	Revision, GOOS, GOARCH, Go, Host, Compiler, SDK string
	SDKHeaders                                      map[string]string
	SourceSHA256                                    map[string]string
	Results                                         []result
	Commands                                        []command
}

var outputRoot string
var evidence report
var oracle string
var formats = []string{"apfs", "apfs-sensitive", "hfsplus", "hfsx"}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func digest(b []byte) string  { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func read(name string) []byte { b, e := os.ReadFile(name); must(e); return b }
func writeJSON(name string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	must(e)
	must(os.WriteFile(name, append(b, '\n'), 0600))
}
func run(args ...string) []byte {
	cmd := exec.Command(args[0], args[1:]...)
	b, e := cmd.CombinedOutput()
	evidence.Commands = append(evidence.Commands, command{args, string(b)})
	if e != nil {
		panic(fmt.Errorf("%v: %w: %s", args, e, b))
	}
	return b
}

func tree() *apfswrite.Entry {
	times := &hostmeta.FileTimes{Birth: time.Unix(1400000000, 123456789).UTC(), Modify: time.Unix(1500000000, 234567890).UTC(), Change: time.Unix(1600000000, 345678901).UTC(), Access: time.Unix(1700000000, 456789012).UTC()}
	flags := uint32(0)
	root := &apfswrite.Entry{Mode: os.ModeDir | 0755, UID: 501, GID: 20, Times: times, BSDFlags: &flags, Xattrs: map[string][]byte{"org.example.root": {1, 0, 255}}}
	finder := make([]byte, 32)
	copy(finder, []byte("TEXTTEST"))
	for _, name := range []string{"ordinary", "hard-a", "hard-b", "AUX", "question?", "question_", "trailing.", "Ω", "._real-content"} {
		e := &apfswrite.Entry{Name: name, Mode: 0644, UID: 501, GID: 20, Times: times, BSDFlags: &flags, Data: []byte("payload:" + name), Xattrs: map[string][]byte{"org.example.empty": {}, "org.example.binary": {0, 1, 255}}}
		if strings.HasPrefix(name, "hard-") {
			e.LinkGroup = 1
			e.Data = []byte("shared-data")
			e.Xattrs[appledouble.FinderInfoName] = finder
			e.Xattrs[hostmeta.ResourceForkName] = []byte{9, 8, 0, 7}
		}
		if name == "ordinary" {
			e.Xattrs["org.example.Case"] = []byte{6}
			e.Xattrs["org.example.case"] = []byte{7}
			e.Xattrs[hostmeta.SecurityName] = imagesecurity.Profiles()[7].Data
			e.Xattrs["com.apple.quarantine"] = []byte("0081;65000000;Transport;12345678-1234-1234-1234-123456789ABC")

			e.Xattrs["org.example.large"] = bytes.Repeat([]byte{1, 0, 255, 17}, (16<<20)/4+1)
			e.Xattrs[hostmeta.ResourceForkName] = bytes.Repeat([]byte{9, 0, 7}, (17<<20)/3)
			e.Xattrs[appledouble.FinderInfoName] = finder
		}
		root.Children = append(root.Children, e)
	}
	root.Children = append(root.Children, &apfswrite.Entry{Name: "directory", Mode: os.ModeDir | os.ModeSticky | 0755, UID: 501, GID: 20, Times: times, BSDFlags: &flags, Xattrs: map[string][]byte{"org.example.directory": {4}}}, &apfswrite.Entry{Name: "link", Mode: os.ModeSymlink | 0755, UID: 501, GID: 20, Times: times, BSDFlags: &flags, Data: []byte("ordinary"), Xattrs: map[string][]byte{"org.example.link": {5}}})
	return root
}
func create(name, kind string, a *apfswrite.Entry, h *hfsplus.Entry) {
	f, e := os.Create(name)
	must(e)
	if strings.HasPrefix(kind, "apfs") {
		e = apfswrite.CreateContainer(f, 128<<20, &apfswrite.CreateOptions{Root: a, VolumeName: "TRANSPORT", CaseSensitive: kind == "apfs-sensitive"})
	} else {
		e = hfsplus.CreateImage(f, 128<<20, "TRANSPORT", h, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"})
	}
	closeErr := f.Close()
	must(e)
	must(closeErr)
}
func open(name, kind string) (volume, *os.File) {
	f, e := os.Open(name)
	must(e)
	if strings.HasPrefix(kind, "apfs") {
		c, e := apfs.Open(f, nil)
		must(e)
		vs, e := c.Volumes()
		must(e)
		if len(vs) != 1 {
			panic("volume count")
		}
		return vs[0], f
	}
	v, e := hfsplus.New(f)
	must(e)
	return v, f
}
func snapshot(v volume) map[string]entry {
	out := map[string]entry{}
	must(fs.WalkDir(v, ".", func(name string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		m, e := v.Metadata(name)
		if e != nil {
			return e
		}
		a, e := v.Xattrs(name)
		if e != nil {
			return e
		}
		r := entry{UID: m.UID, GID: m.GID, Mode: m.Mode, Flags: m.BSDFlags, Inode: m.LinkID, Times: [4]int64{m.Times.Birth.UnixNano(), m.Times.Modify.UnixNano(), m.Times.Change.UnixNano(), m.Times.Access.UnixNano()}, Attrs: map[string]value{}}
		for n, b := range a {
			if n == "com.apple.fs.symlink" && m.Mode&0170000 == 0120000 {
				continue
			} // Structural APFS link storage is verified through Readlink.

			r.Attrs[n] = value{len(b), digest(b)}
		}
		if d.Type()&fs.ModeSymlink != 0 {
			r.Target, e = v.Readlink(name)
		} else if !d.IsDir() {
			var b []byte
			b, e = fs.ReadFile(v, name)
			r.Data = &value{len(b), digest(b)}
		}
		if e != nil {
			return e
		}
		out[name] = r
		return nil
	}))
	return out
}
func compare(want, got map[string]entry, kind string) {
	if len(want) != len(got) {
		panic("entry count mismatch")
	}
	aliases := map[uint64]uint64{}
	reverse := map[uint64]uint64{}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			panic("lost entry " + name)
		}
		if id, ok := aliases[w.Inode]; ok && id != g.Inode {
			panic("lost hardlink identity " + name)
		}
		if sourceID, exists := reverse[g.Inode]; exists && sourceID != w.Inode {
			panic("distinct files merged into one inode")
		}
		reverse[g.Inode] = w.Inode
		aliases[w.Inode] = g.Inode
		w.Inode = g.Inode
		if strings.HasPrefix(kind, "hfs") {
			for i, n := range w.Times {
				w.Times[i] = time.Unix(0, n).Unix() * 1e9
			}
		}
		if !reflect.DeepEqual(w, g) {
			panic(fmt.Sprintf("logical metadata mismatch %s: wanted %+v got %+v", name, w, g))
		}
	}
}
func compressImage(name string) string {
	f, e := os.Open(name)
	must(e)
	defer f.Close()
	h := sha256.New()
	out, e := os.Create(name + ".gz")
	must(e)
	z := gzip.NewWriter(out)
	_, e = io.Copy(io.MultiWriter(h, z), f)
	must(e)
	must(z.Close())
	must(out.Close())
	return hex.EncodeToString(h.Sum(nil))
}
func prepareOracle() {
	evidence.Host = strings.TrimSpace(string(run("sw_vers")))
	evidence.Compiler = strings.TrimSpace(string(run("xcrun", "clang", "--version")))
	evidence.SDK = strings.TrimSpace(string(run("xcrun", "--show-sdk-version")))
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	evidence.SDKHeaders = map[string]string{}
	for _, header := range []string{"sys/stat.h", "sys/fcntl.h", "sys/xattr.h", "sys/acl.h"} {
		evidence.SDKHeaders[header] = digest(read(filepath.Join(sdk, "usr", "include", header)))
	}
	prepareFinderSource()
	oracle = filepath.Join(outputRoot, "metadata-transport-oracle")

	source := "testdata/appledouble/native/metadata-transport.c"
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", outputRoot, source, "-o", oracle)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-I", outputRoot, source)
		var ast any
		must(json.Unmarshal(b, &ast))
		calls := map[string]int{}
		var walk func(any)
		walk = func(node any) {
			switch n := node.(type) {
			case []any:
				for _, child := range n {
					walk(child)
				}
			case map[string]any:
				if n["kind"] == "DeclRefExpr" {
					if d, ok := n["referencedDecl"].(map[string]any); ok {
						if name, ok := d["name"].(string); ok {
							calls[name]++
						}
					}
				}
				for _, child := range n {
					walk(child)
				}
			}
		}
		walk(ast)
		for name, count := range map[string]int{"lstat": 2, "lstatx_np": 1, "getxattr": 3, "filesec_get_property": 2, "hfs_zero_hidden_fields": 1} {
			if calls[name] != count {
				panic("unexpected oracle AST call count: " + name)
			}
		}
		must(os.WriteFile(filepath.Join(outputRoot, arch+".ast.json"), b, 0600))

		evidence.Commands[len(evidence.Commands)-1].Output = fmt.Sprintf("AST retained: %d bytes SHA256 %s", len(b), digest(b))
	}
}
func native(image, kind string, want map[string]entry) {
	if strings.HasPrefix(kind, "apfs") {
		run("/sbin/fsck_apfs", "-n", image)
	} else {
		func() {
			attached := run("hdiutil", "attach", "-imagekey", "diskimage-class=CRawDiskImage", "-nomount", "-readonly", image)
			device := regexp.MustCompile(`/dev/disk[0-9]+`).FindString(string(attached))
			if device == "" {
				panic("missing HFS device")
			}
			defer run("hdiutil", "detach", device)
			args := []string{"/sbin/fsck_hfs", "-n", device}
			b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			evidence.Commands = append(evidence.Commands, command{args, fmt.Sprintf("%s\nexit: %v", b, err)})
			// Match the established HFS gate: ordinary users can receive an
			// extra raw-device error after the complete block-device clean verdict.
			if !strings.Contains(string(b), "appears to be OK") {
				panic("HFS filesystem check did not establish a clean volume")
			}
		}()
	}
	mount, e := os.MkdirTemp("", "apfs-transport-mount-")
	must(e)
	defer os.Remove(mount)
	run("hdiutil", "attach", image, "-readonly", "-owners", "on", "-nobrowse", "-mountpoint", mount)
	defer run("hdiutil", "detach", mount)
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w := want[name]
		p := filepath.Join(mount, filepath.FromSlash(name))
		var got entry
		must(json.Unmarshal(run(oracle, p), &got))
		if got.UID != w.UID || got.GID != w.GID || got.Mode != w.Mode || got.Flags != w.Flags || got.Inode != w.Inode || got.Times != w.Times {
			panic(fmt.Sprintf("native stat mismatch %s: %+v %+v", name, got, w))
		}
		for attr, value := range w.Attrs {
			args := []string{oracle, "--xattr", p, attr}
			if attr == hostmeta.SecurityName {
				args = []string{oracle, "--security", p}
			}
			cmd := exec.Command(args[0], args[1:]...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			b, e := cmd.Output()
			if e != nil {
				panic(fmt.Sprintf("native xattr %s/%s: %v %s", name, attr, e, stderr.String()))
			}
			if attr == hostmeta.SecurityName {
				security, e := appledouble.ParseDarwinFileSecurity(b)
				must(e)
				b, e = security.MarshalBinary()
				must(e)
			}
			if len(b) != value.Size || digest(b) != value.SHA256 {
				panic("native attribute mismatch " + name + "/" + attr)
			}
			evidence.Commands = append(evidence.Commands, command{args, fmt.Sprintf("%d bytes SHA256 %s", len(b), digest(b))})
		}
		if w.Target != "" {
			target, e := os.Readlink(p)
			must(e)
			if target != w.Target {
				panic("native link target")
			}
		} else if w.Data != nil {
			b := read(p)
			if len(b) != w.Data.Size || digest(b) != w.Data.SHA256 {
				panic("native data")
			}
		}
	}
}
func main() {
	root := flag.String("out", "artifacts/metadata-transport", "evidence directory")
	foreign := flag.String("foreign", "", "validate an existing foreign-host report/images on macOS")
	reference := flag.String("reference", "", "matching native Mac report directory for foreign image hashes")
	foreignOS := flag.String("foreign-goos", "", "required foreign operating system")
	captureFinder := flag.Bool("capture-finder", false, "retain the independently observed HFS FinderInfo portable fixture")
	flag.Parse()
	var e error
	outputRoot, e = filepath.Abs(*root)
	must(e)
	must(os.MkdirAll(outputRoot, 0755))
	evidence = report{Revision: strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Go: runtime.Version(), SourceSHA256: map[string]string{}}
	files := []string{"scripts/verify-metadata-transport.go", "testdata/appledouble/native/metadata-transport.c", "go.mod", "go.sum"}
	for _, pattern := range []string{"internal/tools/extract*.go", "internal/hostwalk/*.go", "internal/decmpfs/*.go", "internal/bsdflags/*.go", "pkg/metatransport/*.go", "pkg/hostmeta/*.go", "pkg/apfs/*.go", "pkg/apfswrite/*.go", "pkg/hfsplus/*.go"} {
		matches, err := filepath.Glob(pattern)
		must(err)
		files = append(files, matches...)
	}
	for _, name := range files {
		evidence.SourceSHA256[name] = digest(read(name))
	}
	defer func() { writeJSON(filepath.Join(outputRoot, "report.json"), evidence) }()
	if runtime.GOOS == "darwin" {
		prepareOracle()
	} else if *captureFinder {
		panic("FinderInfo capture requires native macOS")
	}
	if runtime.GOOS == "darwin" && *foreign == "" {
		qualifyFinderInfo()
	}
	if *foreign != "" {
		if runtime.GOOS != "darwin" {
			panic("foreign image oracle requires macOS")
		}
		var f report
		must(json.Unmarshal(read(filepath.Join(*foreign, "report.json")), &f))
		if f.Revision != evidence.Revision || len(f.Results) != 16 || f.GOOS != *foreignOS || (f.GOOS != "linux" && f.GOOS != "windows") {
			panic("foreign revision or case inventory")
		}
		if len(f.SourceSHA256) != len(evidence.SourceSHA256) {
			panic("foreign source inventory")
		}
		for name := range evidence.SourceSHA256 {
			b := read(name)
			lf := bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
			crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
			if f.SourceSHA256[name] != digest(b) && f.SourceSHA256[name] != digest(lf) && f.SourceSHA256[name] != digest(crlf) {
				panic("foreign source hash: " + name)
			}
		}
		var nativeReport report
		must(json.Unmarshal(read(filepath.Join(*reference, "report.json")), &nativeReport))
		if nativeReport.Revision != evidence.Revision || nativeReport.GOOS != "darwin" || len(nativeReport.Results) != 16 {
			panic("native reference inventory")
		}
		hashes := map[string]string{}
		for _, r := range nativeReport.Results {
			if !r.Native {
				panic("unqualified native reference")
			}
			hashes[r.Source+"/"+r.Destination] = r.ImageSHA256
		}
		seen := map[string]bool{}
		for _, r := range f.Results {
			key := r.Source + "/" + r.Destination
			if seen[key] || hashes[key] == "" || hashes[key] != r.ImageSHA256 {
				panic("foreign case inventory/hash: " + key)
			}
			seen[key] = true

			image := filepath.Join(outputRoot, r.Source+"-to-"+r.Destination+".img")
			in, e := os.Open(filepath.Join(*foreign, filepath.Base(image)+".gz"))
			must(e)
			z, e := gzip.NewReader(in)
			must(e)
			out, e := os.Create(image)
			must(e)
			h := sha256.New()
			_, e = io.Copy(io.MultiWriter(out, h), io.LimitReader(z, (128<<20)+1))
			must(e)
			must(z.Close())
			must(in.Close())
			must(out.Close())
			if fmt.Sprintf("%x", h.Sum(nil)) != r.ImageSHA256 {
				panic("foreign image hash")
			}
			native(image, r.Destination, r.Entries)
			r.Native = true
			evidence.Results = append(evidence.Results, r)
			must(os.Remove(image))
		}
		return
	}
	for _, source := range formats {
		workspace, e := os.MkdirTemp("", "apfs-transport-")
		must(e)
		src := filepath.Join(workspace, "source.img")
		a := tree()
		create(src, source, a, hfsTree(a))
		v, file := open(src, source)
		want := snapshot(v)
		if runtime.GOOS == "darwin" {
			native(src, source, want)
		}
		payload, metadata := filepath.Join(workspace, "payload"), filepath.Join(workspace, "metadata")
		extractor := tools.NewExtractor(v, payload)
		extractor.MetadataRoot = metadata
		extractor.Xattrs = true
		extractor.PreserveMeta = true
		extractor.SymlinkMode = tools.SymlinkFile
		extractor.Context = context.Background()
		must(extractor.ExtractAll())
		must(file.Close())
		for _, destination := range formats {
			name := filepath.Join(outputRoot, source+"-to-"+destination+".img")
			var a *apfswrite.Entry
			var h *hfsplus.Entry
			var closeTree func() error
			if strings.HasPrefix(destination, "apfs") {
				tree, err := apfswrite.OpenEntryTreeFromDir(payload, &apfswrite.WalkOptions{MetadataRoot: metadata, Xattrs: true})
				must(err)
				a, closeTree = tree.Root, tree.Close
			} else {
				tree, err := hfsplus.OpenEntryTreeFromDir(payload, &hfsplus.WalkOptions{MetadataRoot: metadata, Xattrs: true})
				must(err)
				h, closeTree = tree.Root, tree.Close
			}
			create(name, destination, a, h)
			must(closeTree())
			v, f := open(name, destination)
			got := snapshot(v)
			compare(want, got, destination)
			must(f.Close())
			r := result{Source: source, Destination: destination, ImageSHA256: compressImage(name), Entries: got}
			if runtime.GOOS == "darwin" {
				native(name, destination, got)
				r.Native = true
			}
			evidence.Results = append(evidence.Results, r)
			must(os.Remove(name))
			fmt.Println("Qualified", source, "->", destination)
		}
		must(os.RemoveAll(workspace))
	}
}

// qualifyFinderInfo compares catalog output with actual setxattr/lchflags on a
// separately formatted HFS volume. Native observations, not the Go normalizer,
// establish expected bytes and visibility.
func qualifyFinderInfo() {
	type observation struct {
		Code, Errno, Length, GetErrno int
		Flags                         uint32
		Value                         string
	}
	type probe struct {
		Kind, Form, Input, FinalFlags string
		Native                        observation
	}
	var probes []probe
	base, e := os.MkdirTemp("", "hfs-finder-oracle-")
	must(e)
	defer os.RemoveAll(base)
	for _, kind := range []string{"hfsplus", "hfsx"} {
		ref := filepath.Join(base, kind+"-reference.dmg")
		filesystem := "HFS+"
		if kind == "hfsx" {
			filesystem = "HFSX"
		}
		run("hdiutil", "create", "-quiet", "-size", "64m", "-fs", filesystem, "-volname", "FINDERREF", ref)
		mount := filepath.Join(base, kind+"-mount")
		must(os.Mkdir(mount, 0700))
		run("hdiutil", "attach", ref, "-owners", "on", "-nobrowse", "-mountpoint", mount)
		func() {
			defer run("hdiutil", "detach", mount)
			root := &hfsplus.Entry{Mode: os.ModeDir | 0755}
			expected := map[string]observation{}
			for _, object := range []string{"file", "directory", "symlink", "hardlink", "root"} {
				for _, form := range []string{"value", "zero", "hidden", "private", "explicit-clear", "explicit-set", "invalid-length", "hardlink-marker"} {
					raw := make([]byte, 32)
					finalFlags := "-"
					switch form {
					case "value":
						for i := range raw {
							raw[i] = byte(i + 1)
						}
					case "hidden", "explicit-clear":
						raw[8] = 0x40
					case "private":
						for i := 16; i < 24; i++ {
							raw[i] = 0xaa
						}
						for i := 28; i < 32; i++ {
							raw[i] = 0xbb
						}
					case "invalid-length":
						raw = raw[:31]
					case "hardlink-marker":
						copy(raw, []byte("hlnk"))
					}
					if form == "explicit-clear" {
						finalFlags = "0"
					}
					if form == "explicit-set" {
						finalFlags = "32768"
					}
					name := object + "-" + form
					p := filepath.Join(mount, name)
					if object == "root" {
						p = mount
						name = "."
					}
					entry := &hfsplus.Entry{Name: name, Mode: 0644, Xattrs: map[string][]byte{appledouble.FinderInfoName: raw}}
					if object == "root" {
						entry.Mode = os.ModeDir | 0755
					} else if object == "directory" {
						must(os.Mkdir(p, 0755))
						entry.Mode = os.ModeDir | 0755
					} else if object == "symlink" {
						must(os.Symlink("target", p))
						entry.Mode = os.ModeSymlink | 0755
						entry.Data = []byte("target")
					} else {
						must(os.WriteFile(p, []byte("payload"), 0644))
						entry.Data = []byte("payload")
					}
					if object == "hardlink" {
						must(os.Link(p, p+"-alias"))
						entry.LinkGroup = uint64(len(probes) + 1)
					}
					var native observation
					must(json.Unmarshal(run(oracle, "--apply-finder", p, hex.EncodeToString(raw), finalFlags), &native))
					probes = append(probes, probe{kind + "/" + object, form, hex.EncodeToString(raw), finalFlags, native})
					if form == "invalid-length" || (form == "hardlink-marker" && object != "symlink") {
						if native.Code == 0 {
							panic("native unexpectedly accepted forbidden FinderInfo")
						}
						continue
					}
					if native.Code != 0 {
						panic("native refused valid FinderInfo")
					}
					mode := "32768"
					if object == "directory" || object == "root" {
						mode = "16384"
					}
					if object == "symlink" {
						mode = "40960"
					}
					normalized := run(oracle, "--source-finder", mode, hex.EncodeToString(raw))
					evidence.Commands[len(evidence.Commands)-1].Output = hex.EncodeToString(normalized)
					if len(normalized) != 32 {
						panic("source normalizer output")
					}
					if object == "symlink" {
						clear(normalized[:8])
					}
					if finalFlags != "-" {
						normalized[8] &^= 0x40
						if native.Flags&0x8000 != 0 {
							normalized[8] |= 0x40
						}
					}
					if !bytes.Equal(normalized, make([]byte, 32)) && hex.EncodeToString(normalized) != native.Value {
						panic("unchanged Apple normalizer disagrees with live native setter")
					}
					if bytes.Equal(normalized, make([]byte, 32)) && (native.Length >= 0 || native.GetErrno != 93) {
						panic("native zero visibility")
					}
					if finalFlags != "-" {

						flags := native.Flags
						entry.BSDFlags = &flags
					}
					expected[name] = native
					if object == "root" {
						entry.Children = root.Children
						root = entry
					} else {
						root.Children = append(root.Children, entry)
					}
					if object == "hardlink" {
						alias := *entry
						alias.Name = name + "-alias"
						root.Children = append(root.Children, &alias)
						expected[alias.Name] = native
					}
				}
			}
			image := filepath.Join(base, kind+"-finder.img")
			create(image, kind, nil, root)
			v, f := open(image, kind)
			for name, w := range expected {
				attrs, e := v.Xattrs(name)
				must(e)
				got, ok := attrs[appledouble.FinderInfoName]
				if (w.Length >= 0) != ok || hex.EncodeToString(got) != w.Value {
					panic("FinderInfo producer comparison " + name)
				}
				m, e := v.Metadata(name)
				must(e)
				if m.BSDFlags != w.Flags {
					panic("FinderInfo flag comparison " + name)
				}
			}
			actual := snapshot(v)
			must(f.Close())
			native(image, kind, actual)
		}()
	}
	writeJSON(filepath.Join(outputRoot, "finderinfo-native.json"), probes)
	if flag.Lookup("capture-finder").Value.String() == "true" {
		b, err := json.MarshalIndent(map[string]any{"host": evidence.Host, "compiler": evidence.Compiler, "sdk": evidence.SDK, "revision": evidence.Revision, "source_sha256": evidence.SourceSHA256, "hfs_source": json.RawMessage(read(filepath.Join(outputRoot, "hfs-source-provenance.json"))), "cases": probes}, "", "  ")
		must(err)
		f, err := os.Create("testdata/appledouble/native/hfs-finderinfo.json.gz")
		must(err)
		z := gzip.NewWriter(f)
		_, err = z.Write(b)
		must(err)
		must(z.Close())
		must(f.Close())
	}
}

func hfsTree(a *apfswrite.Entry) *hfsplus.Entry {
	h := imagesecurity.HFSTree(a)
	var route func(*hfsplus.Entry)
	route = func(e *hfsplus.Entry) {
		e.Xattrs = maps.Clone(e.Xattrs)
		if fork, ok := e.Xattrs[hostmeta.ResourceForkName]; ok {
			e.ResourceFork = fork
			delete(e.Xattrs, hostmeta.ResourceForkName)
		}
		for _, c := range e.Children {
			route(c)
		}
	}
	route(h)
	return h
}

func prepareFinderSource() {
	const base = "https://raw.githubusercontent.com/apple-oss-distributions/hfs/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/"
	hashes := map[string]string{"hfs_xattr.c": "22413ad83654198946ad26797c074fc9c64500a9fe75abbfcff426731ddce117", "hfs_format.h": "114e5349032cd7169331760a5c601b5dea5d0cb9f955cc00e8f53577e74b36db"}
	data := map[string][]byte{}
	for name, hash := range hashes {
		p := filepath.Join(outputRoot, name)
		b, e := os.ReadFile(p)
		if e != nil {
			b = run("curl", "-fsSL", "--retry", "3", base+name)
			evidence.Commands[len(evidence.Commands)-1].Output = fmt.Sprintf("retained %s SHA256 %s", name, digest(b))
			must(os.WriteFile(p, b, 0600))
		}
		if digest(b) != hash {
			panic("pinned HFS source mismatch: " + name)
		}
		data[name] = b
	}
	source := string(data["hfs_xattr.c"])
	signature := "static int hfs_zero_hidden_fields (struct cnode *cp, u_int8_t *finderinfo) \n{"
	start := strings.Index(source, signature)
	if start < 0 {
		panic("missing complete HFS function")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		panic("missing HFS function end")
	}
	header := source[:strings.Index(source, "*/")+2] + "\n// Qualification shim: only the cnode mode field accessed by the unchanged function.\nstruct cnode { struct { mode_t ca_mode; } c_attr; };\n"
	for _, name := range []string{"FndrExtendedFileInfo", "FndrExtendedDirInfo"} {
		pattern := regexp.MustCompile(`(?s)struct ` + name + ` \{.*?\} __attribute__\(\(aligned\(2\), packed\)\);`)
		decl := pattern.Find(data["hfs_format.h"])
		if len(decl) == 0 {
			panic("missing complete HFS struct")
		}
		header += string(decl) + "\n"
	}
	header += source[start:start+end+3] + "\n"
	must(os.WriteFile(filepath.Join(outputRoot, "hfs-finder-source.h"), []byte(header), 0600))
	writeJSON(filepath.Join(outputRoot, "hfs-source-provenance.json"), map[string]any{"base_url": base, "source_sha256": hashes, "generated_header_sha256": digest([]byte(header)), "function": "hfs_zero_hidden_fields", "cnode_shim": "mode field only; no kernel authorization emulation"})
}
