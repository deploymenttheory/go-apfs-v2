//go:build ignore

// Qualify explicit native projection separately from complete carrier retention.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing/fstest"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

const out = "artifacts/native-projection"

type fixture struct{ fstest.MapFS }

func (v fixture) Readlink(name string) (string, error) {
	f, ok := v.MapFS[name]
	if !ok {
		return "", fs.ErrNotExist
	}
	return string(f.Data), nil
}
func (v fixture) Xattrs(string) (map[string][]byte, error) {
	return map[string][]byte{"user.projection": []byte("value"), "org.example.empty": {}, "com.apple.ResourceFork": bytes.Repeat([]byte{3}, 10000)}, nil
}
func (v fixture) Metadata(name string) (hostdata.ImageMetadata, error) {
	info, e := v.Stat(name)
	if e != nil {
		return hostdata.ImageMetadata{}, e
	}
	mode := uint32(0100640)
	if info.IsDir() {
		mode = 0040755
	}
	if info.Mode()&os.ModeSymlink != 0 {
		mode = 0120777
	}
	times := &hostdata.FileTimes{Birth: time.Unix(1500000000, 100), Modify: time.Unix(1600000000, 200), Access: time.Unix(1700000000, 300), Change: time.Unix(1650000000, 400)}
	return hostdata.ImageMetadata{UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), Mode: mode, Times: times}, nil
}

type stat struct {
	UID, GID, Mode, Flags uint32
	Times                 [4]int64
}
type observation struct {
	Path  string
	Stat  stat
	Attrs map[string]string
}
type result struct {
	Path, Field string
	Status      tools.ProjectionStatus
	Verified    bool
	Error       string
}
type report struct {
	Revision, GOOS, GOARCH, Go, Compiler, SDK string
	Headers, Sources                          map[string]string
	Results                                   []result
	Native                                    []observation
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte   { b, e := os.ReadFile(p); must(e); return b }
func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	if e != nil {
		panic(fmt.Errorf("%v: %w: %s", args, e, b))
	}
	return b
}
func main() {
	must(os.MkdirAll(out, 0755))
	evidence := report{Revision: strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Go: runtime.Version(), Sources: map[string]string{}, Headers: map[string]string{}}
	defer func() {
		b, e := json.MarshalIndent(evidence, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(out, "report.json"), append(b, '\n'), 0600))
	}()
	for _, pattern := range []string{"scripts/verify-native-projection.go", "testdata/appledouble/native/native-projection.c", "internal/tools/extract_projection*.go", "pkg/hostdata/metadata_open*.go", "pkg/hostdata/held_metadata*.go", "go.mod", "go.sum"} {
		paths, e := filepath.Glob(pattern)
		must(e)
		for _, p := range paths {
			evidence.Sources[p] = digest(read(p))
		}
	}
	workspace, e := os.MkdirTemp("", "native-projection-")
	must(e)
	defer os.RemoveAll(workspace)
	volume := fixture{fstest.MapFS{".": {Mode: os.ModeDir | 0755}, "directory": {Mode: os.ModeDir | 0755}, "directory/file": {Data: []byte("payload")}, "link": {Mode: os.ModeSymlink | 0777, Data: []byte("directory/file")}}}
	extractor := tools.NewExtractor(volume, filepath.Join(workspace, "payload"))
	extractor.MetadataRoot = filepath.Join(workspace, "metadata")
	extractor.ProjectNative = true
	extractor.PreserveMeta = true
	extractor.Xattrs = true
	extractor.SymlinkMode = tools.SymlinkAuto
	must(extractor.ExtractAll())
	for _, r := range extractor.NativeProjectionResults() {
		errText := ""
		if r.Err != nil {
			errText = r.Err.Error()
		}
		evidence.Results = append(evidence.Results, result{r.Path, r.Field, r.Status, r.Verified, errText})
	}
	store, e := metatransport.Open(extractor.Destination, extractor.MetadataRoot, metatransport.DefaultLimits())
	must(e)
	defer store.Close()
	manifest, e := store.Load(context.Background())
	must(e)
	if len(manifest.Records) != 4 {
		panic("incomplete carrier inventory")
	}
	for _, r := range manifest.Records {
		attrs, e := store.ReadRecordAttributes(context.Background(), r, 1<<20)
		must(e)
		want, e := volume.Xattrs(r.Original)
		must(e)
		if len(attrs) != len(want) {
			panic("carrier attr inventory")
		}
		for n, b := range want {
			if !bytes.Equal(attrs[n], b) {
				panic("carrier attr changed")
			}
		}
		m, e := volume.Metadata(r.Original)
		must(e)
		if r.Darwin.Mode == nil || *r.Darwin.Mode != m.Mode || r.Darwin.Change == nil || !r.Darwin.Change.Equal(m.Times.Change) {
			panic("logical stat omitted")
		}
	}
	if runtime.GOOS != "darwin" {
		return
	}
	evidence.Compiler = string(run("xcrun", "clang", "--version"))
	evidence.SDK = strings.TrimSpace(string(run("xcrun", "--show-sdk-version")))
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	for _, name := range []string{"sys/stat.h", "sys/xattr.h"} {
		evidence.Headers[name] = digest(read(filepath.Join(sdk, "usr", "include", name)))
	}
	source := "testdata/appledouble/native/native-projection.c"
	oracle := filepath.Join(out, "native-projection-oracle")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	for _, arch := range []string{"arm64", "x86_64"} {
		raw := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		var ast any
		must(json.Unmarshal(raw, &ast))
		calls := map[string]int{}
		var visit func(any)
		visit = func(n any) {
			switch v := n.(type) {
			case []any:
				for _, x := range v {
					visit(x)
				}
			case map[string]any:
				if v["kind"] == "DeclRefExpr" {
					if d, ok := v["referencedDecl"].(map[string]any); ok {
						if name, ok := d["name"].(string); ok {
							calls[name]++
						}
					}
				}
				for _, x := range v {
					visit(x)
				}
			}
		}
		visit(ast)
		if calls["lstat"] != 1 || calls["getxattr"] != 2 {
			panic("native oracle AST inventory")
		}
		must(os.WriteFile(filepath.Join(out, arch+".ast.json"), raw, 0600))
	}
	for _, r := range manifest.Records {
		p := filepath.Join(extractor.Destination, filepath.FromSlash(r.Materialized))
		var native stat
		must(json.Unmarshal(run(oracle, p), &native))
		obs := observation{Path: r.Original, Stat: native, Attrs: map[string]string{}}
		matches := map[string]bool{"mode": native.Mode&07777 == *r.Darwin.Mode&07777, "ownership": native.UID == *r.Darwin.UID && native.GID == *r.Darwin.GID, "modify": native.Times[1] == r.Darwin.Modify.UnixNano(), "access": native.Times[3] == r.Darwin.Access.UnixNano(), "birth": native.Times[0] == r.Darwin.Birth.UnixNano(), "flags": native.Flags == *r.Darwin.Flags}
		for _, a := range r.Attributes {
			for _, result := range evidence.Results {
				if result.Path == r.Original && result.Field == "xattr:"+a.Name && result.Verified {
					b := run(oracle, p, a.Name)
					if digest(b) != a.Value.SHA256 {
						panic("native verified attr differs")
					}
					obs.Attrs[a.Name] = digest(b)
				}
			}
		}
		for _, result := range evidence.Results {
			if result.Path != r.Original || !result.Verified {
				continue
			}
			if same, known := matches[result.Field]; known && !same {
				panic("native verified stat differs: " + result.Path + "/" + result.Field)
			}
		}
		evidence.Native = append(evidence.Native, obs)
	}
	sort.Slice(evidence.Native, func(i, j int) bool { return evidence.Native[i].Path < evidence.Native[j].Path })
	fmt.Printf("Native projection: %d retained records, %d outcomes, %d independent native observations\n", len(manifest.Records), len(evidence.Results), len(evidence.Native))
}
