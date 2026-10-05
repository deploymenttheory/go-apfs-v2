//go:build ignore

// Compile complete pinned Apple zlib translation units, retain both Clang ASTs,
// and compare their raw level-five output with independently captured libcompression.
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"time"
)

const revision = "06673bf7cb4066003fd14a0b87085c05739fc4ac"

type report struct {
	Revision, Host, Compiler, SDK string
	Sources                       map[string]string
	Cases                         map[string]string
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte    { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func save(p string, b []byte) { must(os.WriteFile(p, b, 0644)) }
func run(name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, e, b))
	}
	return b
}

type node struct {
	Kind, Name string
	Inner      []node
}

func hasBody(n node, name string) bool {
	if n.Kind == "FunctionDecl" && n.Name == name {
		for _, child := range n.Inner {
			if child.Kind == "CompoundStmt" {
				return true
			}
		}
	}
	for _, child := range n.Inner {
		if hasBody(child, name) {
			return true
		}
	}
	return false
}
func main() {
	out := flag.String("out", "artifacts/compression-zlib-source", "artifact directory")
	capture := flag.Bool("capture", false, "retain fresh source qualification report")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native source qualification requires macOS")
	}
	must(os.MkdirAll(*out, 0755))
	fixture := "testdata/appledouble/native/compression-zlib-source.json"
	var old report
	if !*capture {
		must(json.Unmarshal(read(fixture), &old))
		if old.Revision != revision {
			panic("source revision changed")
		}
	}
	r := report{Revision: revision, Host: string(run("sw_vers")), Compiler: string(run("xcrun", "clang", "--version")), SDK: string(run("xcrun", "--show-sdk-version")), Sources: map[string]string{}, Cases: map[string]string{}}
	defer func() { b, e := json.MarshalIndent(r, "", "  "); must(e); save(filepath.Join(*out, "report.json"), b) }()
	client := http.Client{Timeout: time.Minute}
	for _, name := range []string{"deflate.c", "deflate.h", "trees.c", "trees.h", "zutil.c", "zutil.h", "zlib.h", "zconf.h", "adler32.c", "gzguts.h"} {
		url := "https://raw.githubusercontent.com/apple-oss-distributions/zlib/" + revision + "/zlib/" + name
		response, e := client.Get(url)
		must(e)
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			panic(response.Status)
		}
		b, e := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		must(e)
		must(response.Body.Close())
		r.Sources[name] = hash(b)
		if !*capture && old.Sources[name] != r.Sources[name] {
			panic("pinned source hash changed: " + name)
		}
		save(filepath.Join(*out, name), b)
	}
	driver := "testdata/appledouble/native/compression-zlib-source.c"
	for _, path := range []string{driver, "scripts/verify-compression-zlib-source.go"} {
		r.Sources[path] = hash(read(path))
		if !*capture && old.Sources[path] != r.Sources[path] {
			panic("stale driver provenance: " + path)
		}
	}
	helper := filepath.Join(*out, "reference")
	args := []string{"clang", "-DNO_GZIP", "-Wno-deprecated-non-prototype", "-I", *out, driver}
	for _, name := range []string{"deflate.c", "trees.c", "adler32.c", "zutil.c"} {
		args = append(args, filepath.Join(*out, name))
	}
	run("xcrun", append(args, "-o", helper)...)
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, unit := range []struct {
			path   string
			bodies []string
		}{
			{filepath.Join(*out, "deflate.c"), []string{"deflate", "deflate_slow", "longest_match", "fill_window"}},
			{filepath.Join(*out, "trees.c"), []string{"_tr_flush_block", "build_tree", "send_tree"}},
			{driver, []string{"main"}},
		} {
			b := run("xcrun", "clang", "-arch", arch, "-DNO_GZIP", "-Wno-deprecated-non-prototype", "-I", *out, "-fsyntax-only", "-Xclang", "-ast-dump=json", unit.path)
			var root node
			must(json.Unmarshal(b, &root))
			for _, name := range unit.bodies {
				if !hasBody(root, name) {
					panic("missing complete C body: " + name)
				}
			}
			name := filepath.Base(unit.path) + "-" + arch + ".ast.json"
			save(filepath.Join(*out, name), b)
			r.Sources[name] = hash(b)
		}
	}
	f, e := os.Open("testdata/appledouble/native/compression-blocks.json.gz")
	must(e)
	defer f.Close()
	z, e := gzip.NewReader(f)
	must(e)
	defer z.Close()
	var corpus struct {
		Cases []struct {
			Name           string
			Algorithm      uint32
			Plain, Encoded []byte
		}
	}
	must(json.NewDecoder(z).Decode(&corpus))
	for _, c := range corpus.Cases {
		if c.Algorithm != 0x205 {
			continue
		}
		input, output := filepath.Join(*out, "input"), filepath.Join(*out, "output")
		save(input, c.Plain)
		run(helper, input, output)
		got := read(output)
		r.Cases[c.Name] = hash(got)
		if !bytes.Equal(got, c.Encoded) {
			panic("pinned source and native codec differ: " + c.Name)
		}
	}
	if len(r.Cases) != 366 {
		panic("incomplete source qualification")
	}
	if *capture {
		b, e := json.MarshalIndent(r, "", "  ")
		must(e)
		save(fixture, b)
	} else if !reflect.DeepEqual(old.Cases, r.Cases) {
		panic("source observation inventory changed")
	}
	fmt.Printf("qualified %d native zlib cases against complete pinned source bodies on both AST targets\n", len(r.Cases))
}
