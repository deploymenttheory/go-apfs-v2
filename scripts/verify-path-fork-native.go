//go:build ignore

// Qualify the observable path named-fork threshold through installed copyfile.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

const out = "artifacts/path-fork-native"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s: %v %s", args[0], e, b))
	}
	return b
}

type attribute struct{ Name, Value string }
type state struct {
	Mode, Flags uint32
	Mtime       int64
	Nano        int64 `json:"mtime_nano"`
	Attrs       []attribute
	ACL         *string
}

func observe(oracle, path string) state {
	var v state
	must(json.Unmarshal(run(oracle, "inspect", path), &v))
	sort.Slice(v.Attrs, func(i, j int) bool { return v.Attrs[i].Name < v.Attrs[j].Name })
	return v
}
func main() {
	if runtime.GOOS != "darwin" {
		panic("native path fork qualification requires macOS")
	}
	must(os.MkdirAll(out, 0755))
	source := "testdata/appledouble/native/appledouble-object.c"
	oracle := filepath.Join(out, "oracle")
	ast := map[string]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		must(os.WriteFile(filepath.Join(out, arch+".ast.json"), b, 0600))
		ast[arch] = hash(b)
	}
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	work, e := os.MkdirTemp("", "path-fork-native-")
	must(e)
	defer func() { must(os.RemoveAll(work)) }()
	cases := []map[string]any{}
	for _, operation := range []string{"pack", "unpack"} {
		for _, size := range []int{0, 1 << 20, (1 << 20) + 1} {
			for _, existing := range []bool{false, true} {
				name := fmt.Sprintf("%s-size%d-existing%t", operation, size, existing)
				dir := filepath.Join(work, name)
				must(os.Mkdir(dir, 0700))
				src := filepath.Join(dir, "source")
				goDest := filepath.Join(dir, "go")
				nativeDest := filepath.Join(dir, "native")
				data := []byte("source data fork")
				if operation == "unpack" {
					data, e = appledouble.FromXattrs(map[string][]byte{appledouble.ResourceForkName: []byte("incoming fork"), "user.fixed": []byte("fixed")}).Encode()
					must(e)
				}
				must(os.WriteFile(src, data, 0600))
				f, e := os.Open(src)
				must(e)
				if size != 0 {
					must(hostmeta.SetXattr(f, appledouble.ResourceForkName, bytes.Repeat([]byte{37}, size)))
				}
				must(f.Close())
				must(os.Chtimes(src, time.Unix(1700000000, 0), time.Unix(1700000001, 0)))
				if existing {
					for _, p := range []string{goDest, nativeDest} {
						must(os.WriteFile(p, []byte("old destination payload"), 0640))
						f, e := os.Open(p)
						must(e)
						must(hostmeta.SetXattr(f, appledouble.ResourceForkName, []byte("old destination resource fork suffix")))
						must(f.Close())
						must(os.Chtimes(p, time.Unix(1600000000, 0), time.Unix(1600000001, 0)))
					}
				}
				opts := hostmeta.AppleDoublePathOptions{Operation: hostmeta.PathPackAppleDouble, Pack: hostmeta.DefaultObjectPackOptions(), Unpack: hostmeta.DefaultObjectUnpackOptions(), MaxOpenAttempts: 8}
				// Copy explicit source times in both operations, so newly created
				// destinations have deterministic metadata for exact readback.
				opts.Pack.Stat, opts.Unpack.Stat = true, true
				if operation == "unpack" {
					opts.Operation = hostmeta.PathUnpackAppleDouble
				}
				got, e := hostmeta.CopyAppleDoublePath(context.Background(), src, goDest, opts)
				must(e)
				var native struct{ Code, Errno int }
				must(json.Unmarshal(run(oracle, "path-"+operation, src, nativeDest, "0", "1"), &native))
				if native.Code != 0 || got.Lifecycle.Code != native.Code {
					panic(fmt.Sprintf("%s: return mismatch Go%d native%+v", name, got.Lifecycle.Code, native))
				}
				goBytes, nativeBytes := read(goDest), read(nativeDest)
				if !bytes.Equal(goBytes, nativeBytes) {
					panic(name + ": data/AppleDouble bytes differ")
				}
				a, b := observe(oracle, goDest), observe(oracle, nativeDest)
				if !reflect.DeepEqual(a, b) {
					panic(fmt.Sprintf("%s: native metadata differs (mode%o/%o; attrs%d/%d; mtime%d/%d)", name, a.Mode, b.Mode, len(a.Attrs), len(b.Attrs), a.Mtime, b.Mtime))
				}
				var steps []string
				for _, step := range got.Lifecycle.Steps {
					if strings.Contains(step.Operation, "fork") {
						if step.Err != nil {
							panic(fmt.Sprintf("%s: unexpected fork provider failure: %v", name, step.Err))
						}
						steps = append(steps, step.Operation)
					}
				}
				expectedForks := size > 1<<20
				if expectedForks != strings.Contains(strings.Join(steps, ","), "open-destination-fork") {
					panic(name + ": threshold lifecycle differs")
				}
				cases = append(cases, map[string]any{"name": name, "data_sha256": hash(goBytes), "metadata_equal": true, "native_code": native.Code, "fork_steps": steps})
				fmt.Println("Qualified", name)
			}
		}
	}
	must(os.RemoveAll(work))
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{source, "scripts/verify-path-fork-native.go", "pkg/hostmeta/*.go", "go.mod", "go.sum"})
	must(e)
	report := map[string]any{"passed": true, "revision": strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "ast_sha256": ast, "cases": cases, "sdk": strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), "host": string(run("sw_vers")), "compiler": string(run("xcrun", "clang", "--version"))}
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(out, "report.json"), b, 0600))
}
