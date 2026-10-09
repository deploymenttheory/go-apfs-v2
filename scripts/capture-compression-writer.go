//go:build ignore

// Capture the native compression producer's storage decisions and exact bytes.
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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type sample struct {
	Name                   string
	Requested              uint32
	Accepted               bool
	Size                   int64
	Flags                  uint32
	Plain, Attribute, Fork []byte
}
type capture struct {
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []sample
	Selections                   []sample
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	out := flag.String("out", "artifacts/compression-writer/native.json.gz", "output")
	check := flag.Bool("check", false, "require all native cases to match retained evidence")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native capture requires macOS")
	}
	if *check {
		a, e := filepath.Abs(*out)
		must(e)
		b, e := filepath.Abs("testdata/appledouble/native/compression-writer.json.gz")
		must(e)
		if a == b {
			panic("check requires separate output")
		}
	}
	dir, e := os.MkdirTemp("", "compression-writer-native-")
	must(e)
	defer os.RemoveAll(dir)
	run := func(name string, args ...string) []byte {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
		if e != nil {
			panic(fmt.Sprintf("%s %v: %v: %s", name, args, e, b))
		}
		return b
	}
	source := "testdata/appledouble/native/decmpfs-large.c"
	helper := filepath.Join(dir, "producer")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-framework", "CoreFoundation", source, "-o", helper)
	c := capture{Host: string(run("sw_vers")), Compiler: string(run("xcrun", "clang", "--version")), SDK: string(run("xcrun", "--show-sdk-version")), Sources: map[string]string{}}
	must(captureprovenance.Bind(os.DirFS("."), filepath.Dir(*out), c.Sources))
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	framework := "/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression"
	c.Library = string(run("xcrun", "dyld_info", "-uuid", framework))
	disassembly := run("xcrun", "dyld_info", "-disassemble", framework)
	for _, symbol := range []string{"_CompressFile:", "_CreateCompressionQueue:", "_FinishCompressionAndCleanUp:"} {
		if !bytes.Contains(disassembly, []byte(symbol)) {
			panic("missing framework implementation symbol " + symbol)
		}
	}
	must(os.WriteFile(filepath.Join(filepath.Dir(*out), "AppleFSCompression.disassembly.txt"), disassembly, 0644))
	c.Sources["AppleFSCompression.disassembly.txt"] = hash(disassembly)

	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	for _, path := range []string{"sys/xattr.h", "sys/stat.h"} {
		c.Sources["SDK/"+path] = hash(read(filepath.Join(sdk, "usr/include", path)))
	}

	for _, p := range []string{source, "scripts/capture-compression-writer.go", "go.mod", "go.sum"} {
		c.Sources[p] = hash(read(p))
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		c.Sources[arch+".ast.json"] = hash(ast)
		must(os.WriteFile(filepath.Join(filepath.Dir(*out), arch+".ast.json"), ast, 0644))
	}
	recipes := []struct {
		name    string
		n       int
		pattern string
	}{{"empty", 0, "text"}, {"tiny", 8, "text"}, {"inline-boundary", 3786, "text"}, {"single", 65536, "text"}, {"multi", 131195, "text"}, {"mixed", 131195, "mixed"}, {"random", 65536, "random"}}
	for _, tail := range []int{1, 7, 8, 15, 16, 31, 32, 63, 64, 77, 123, 127, 128, 129, 143, 144, 145, 146, 255, 256, 257, 511, 512, 513, 1023, 1024, 4095, 4096} {
		for _, pattern := range []string{"text", "mixed"} {
			recipes = append(recipes, struct {
				name    string
				n       int
				pattern string
			}{fmt.Sprintf("tail%d-%s", tail, pattern), 65536 + tail, pattern})
		}
	}
	produce := func(s sample) sample {
		base := filepath.Join(dir, fmt.Sprintf("%d-%s", s.Requested, s.Name))
		path := base + ".input"
		must(os.WriteFile(path, s.Plain, 0644))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		command := cirunner.CommandContext(ctx, helper, fmt.Sprint(s.Requested), path, base)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, e := command.Output()
		cancel()
		if e != nil {
			panic(fmt.Sprintf("producer %d/%s: %v: %s", s.Requested, s.Name, e, stderr.String()))
		}
		must(json.Unmarshal(output, &s))
		for suffix, target := range map[string]*[]byte{".attr": &s.Attribute, ".fork": &s.Fork} {
			b, e := os.ReadFile(base + suffix)
			if e != nil && !os.IsNotExist(e) {
				must(e)
			}
			*target = b
		}
		if !bytes.Equal(read(path), s.Plain) {
			panic("kernel readback differs")
		}
		return s
	}
	for _, kind := range []uint32{3, 4, 7, 8, 9, 10, 11, 12, 13, 14} {
		for _, recipe := range recipes {
			s := sample{Name: recipe.name, Requested: kind, Plain: make([]byte, recipe.n)}
			var rng uint32 = 0x12345678
			for i := range s.Plain {
				if recipe.pattern == "random" || recipe.pattern == "mixed" && i >= 65536 {
					rng ^= rng << 13
					rng ^= rng >> 17
					rng ^= rng << 5
					s.Plain[i] = byte(rng)
				} else {
					s.Plain[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "[i%27]
				}
			}
			s = produce(s)
			c.Cases = append(c.Cases, s)
			fmt.Printf("type=%d sample=%s flags=%#x attr=%d fork=%d\n", kind, recipe.name, s.Flags, len(s.Attribute), len(s.Fork))
		}
	}
	for requested := uint32(0); requested <= 32; requested++ {
		c.Selections = append(c.Selections, produce(sample{Name: "type-selection", Requested: requested, Plain: bytes.Repeat([]byte("ABCD"), 16384)}))
	}
	if len(c.Cases) != 630 {
		panic("incomplete native fork inventory")
	}
	b, e := json.Marshal(c)
	must(e)
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	_, e = z.Write(b)
	must(e)
	must(z.Close())
	must(os.MkdirAll(filepath.Dir(*out), 0755))
	must(os.WriteFile(*out, compressed.Bytes(), 0644))
	if *check {
		f, e := os.Open("testdata/appledouble/native/compression-writer.json.gz")
		must(e)
		defer f.Close()
		z, e := gzip.NewReader(f)
		must(e)
		defer z.Close()
		var old capture
		must(json.NewDecoder(z).Decode(&old))
		must(captureprovenance.VerifyReference(os.DirFS("."), old.Sources, source, "scripts/capture-compression-writer.go"))

		if !reflect.DeepEqual(c.Cases, old.Cases) || !reflect.DeepEqual(c.Selections, old.Selections) {
			panic("native compression writer corpus changed")
		}
	}
}
