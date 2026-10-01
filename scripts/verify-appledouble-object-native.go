//go:build ignore

// Compare complete held object facades with live fcopyfile and C readback.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

const objectDir = "artifacts/appledouble-object-native"

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", args[0], e, b))
	}
	return b
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type nativeResult struct{ Code, Errno int }
type attribute struct{ Name, Value string }
type nativeState struct {
	Mode, Flags uint32
	Mtime       int64
	MtimeNano   int64 `json:"mtime_nano"`
	Attrs       []attribute
	ACL         *string
}

func state(oracle, path string) nativeState {
	var s nativeState
	must(json.Unmarshal(run(oracle, "inspect", path), &s))
	sort.Slice(s.Attrs, func(i, j int) bool { return s.Attrs[i].Name < s.Attrs[j].Name })
	return s
}
func main() {
	if runtime.GOOS != "darwin" {
		panic("native object qualification requires Darwin")
	}
	must(os.MkdirAll(objectDir, 0755))
	source := "testdata/appledouble/native/appledouble-object.c"
	astHashes := map[string]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		must(os.WriteFile(filepath.Join(objectDir, arch+".ast.json"), b, 0600))
		astHashes[arch] = hash(b)
	}
	oracle := filepath.Join(objectDir, "oracle")
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	work, e := os.MkdirTemp("", "appledouble-object-qualification-")
	must(e)
	defer func() { must(os.RemoveAll(work)) }()
	cases := []map[string]any{}
	for _, acl := range []bool{false, true} {
		for _, stat := range []bool{false, true} {
			for _, fork := range []bool{false, true} {
				name := fmt.Sprintf("acl-%t-stat-%t-fork-%t", acl, stat, fork)
				dir := filepath.Join(work, name)
				must(os.Mkdir(dir, 0700))
				files := map[string]*os.File{}
				objects := map[string]*hostdata.AppleDoubleObject{}
				for _, key := range []string{"source", "go-packed", "native-packed", "go-target", "native-target"} {
					f, e := os.OpenFile(filepath.Join(dir, key), os.O_CREATE|os.O_RDWR, 0600)
					must(e)
					files[key] = f
					o, e := hostdata.NewHostAppleDoubleObject(context.Background(), f)
					must(e)
					objects[key] = o
				}
				sourceFile := files["source"]
				must(hostdata.SetXattr(sourceFile, "user.object", []byte("ordinary fixed fixture")))
				must(hostdata.SetXattr(sourceFile, "user.empty", nil))
				finder := make([]byte, 32)
				copy(finder, "TEXTttxt")
				must(hostdata.SetXattr(sourceFile, appledouble.FinderInfoName, finder))
				if fork {
					must(hostdata.SetXattr(sourceFile, appledouble.ResourceForkName, []byte("source fork")))
				}
				held, e := hostdata.NewHeldMetadata(sourceFile)
				must(e)
				if acl {
					must(held.SetACL(&appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}))
				}
				must(held.Chmod(0640))
				must(held.SetTimes(time.Unix(1700000000, 0), time.Unix(1700000001, 0)))
				options := hostdata.DefaultObjectPackOptions()
				options.CopyACL = acl
				options.Stat = stat
				packed, e := hostdata.PackAppleDoubleObject(context.Background(), objects["source"], objects["go-packed"], files["go-packed"], options)
				must(e)
				aclArg, statArg := "0", "0"
				if acl {
					aclArg = "1"
				}
				if stat {
					statArg = "1"
				}
				var result nativeResult
				must(json.Unmarshal(run(oracle, "pack", sourceFile.Name(), files["native-packed"].Name(), aclArg, statArg), &result))
				if result.Code != packed.Lifecycle.Code {
					panic(name + ": native pack code mismatch")
				}
				want, e := os.ReadFile(files["native-packed"].Name())
				must(e)
				got, e := os.ReadFile(files["go-packed"].Name())
				must(e)
				if !bytes.Equal(got, want) {
					panic(fmt.Sprintf("%s: pack byte mismatch Go=%d native=%d", name, len(got), len(want)))
				}
				if !reflect.DeepEqual(state(oracle, files["go-packed"].Name()), state(oracle, files["native-packed"].Name())) {
					panic(name + ": packed metadata mismatch, including unconditional inner stat")
				}
				for _, key := range []string{"go-target", "native-target"} {
					f := files[key]
					must(hostdata.SetXattr(f, "user.stale", []byte("remove")))
					if fork {
						must(hostdata.SetXattr(f, appledouble.ResourceForkName, []byte("old fork suffix remains")))
					}
					must(f.Chmod(0400))
					must(os.Chtimes(f.Name(), time.Unix(1600000000, 0), time.Unix(1600000001, 0)))
				}
				optionsU := hostdata.DefaultObjectUnpackOptions()
				optionsU.Stat = stat
				unpacked, e := hostdata.UnpackAppleDoubleObject(context.Background(), io.NewSectionReader(files["go-packed"], 0, int64(len(got))), objects["go-packed"], objects["go-target"], optionsU)
				must(e)
				must(json.Unmarshal(run(oracle, "unpack", files["native-packed"].Name(), files["native-target"].Name(), aclArg, statArg), &result))
				if result.Code != unpacked.Lifecycle.Code {
					panic(name + ": native unpack code mismatch")
				}
				native, actual := state(oracle, files["native-target"].Name()), state(oracle, files["go-target"].Name())
				if !reflect.DeepEqual(native, actual) {
					panic(fmt.Sprintf("%s: native final metadata mismatch (mode %o/%o, attribute counts %d/%d)", name, native.Mode, actual.Mode, len(native.Attrs), len(actual.Attrs)))
				}
				for _, f := range files {
					must(f.Close())
				}
				cases = append(cases, map[string]any{"name": name, "packed_sha256": hash(got), "bytes": len(got), "metadata_equal": true, "pack_code": packed.Lifecycle.Code, "unpack_code": unpacked.Lifecycle.Code})
				fmt.Println("Qualified", name)
			}
		}
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{source, "scripts/verify-appledouble-object-native.go", "pkg/hostdata/*.go", "pkg/hostdata/*/*.go", "internal/hosttime/*.go", "internal/testutil/heldfixture/*.go", "pkg/hostdata/appledouble_pack*.go", "pkg/hostdata/appledouble_sequential*.go", "pkg/hostdata/held_lifecycle*.go", "pkg/hostdata/held_metadata*.go", "pkg/hostdata/quarantine_file*.go", "pkg/hostdata/xattrintent/xattr_intent*.go", "go.mod", "go.sum"})
	must(e)
	report := map[string]any{"revision": strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "ast_sha256": astHashes, "sdk": strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), "compiler": string(run("xcrun", "clang", "--version")), "host": string(run("sw_vers")), "cases": cases, "privacy": "controlled fixture hashes only; process identity and labels are not retained"}
	must(os.RemoveAll(work))
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(objectDir, "report.json"), b, 0600))
}
