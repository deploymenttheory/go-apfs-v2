//go:build ignore

// Capture native-produced and kernel-accepted large compressed files. The C
// constructor reuses native codec blocks; it never calls the Go implementation.
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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

type sample struct {
	Name, Origin, SHA256, ForkSHA256 string
	StoredCompressed                 bool
	Type                             uint32
	Size                             int64
	Attribute                        []byte
}
type report struct {
	Host, Compiler, SDK string
	Sources             map[string]string
	Cases               []sample
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run(name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s %v: %v: %s", name, args, e, b))
	}
	return b
}
func save(path string, b []byte) { must(os.WriteFile(path, b, 0644)) }

func logicalHash(path string, size int64, pattern []byte) string {
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	h := sha256.New()
	buffer := make([]byte, 65536)
	for offset := int64(0); offset < size; {
		p := buffer[:min(int64(len(buffer)), size-offset)]
		_, e = io.ReadFull(f, p)
		must(e)
		if !bytes.Equal(p, pattern[:len(p)]) {
			panic(fmt.Sprintf("native bytes differ at %d", offset))
		}
		_, e = h.Write(p)
		must(e)
		offset += int64(len(p))
	}
	var tail [1]byte
	n, e := f.Read(tail[:])
	if n != 0 || e != io.EOF {
		panic("native logical size differs")
	}
	return hex.EncodeToString(h.Sum(nil))
}
func saveFork(source, destination string) string {
	f, e := os.Open(source)
	must(e)
	defer f.Close()
	out, e := os.Create(destination)
	must(e)
	z := gzip.NewWriter(out)
	h := sha256.New()
	_, e = io.CopyBuffer(io.MultiWriter(z, h), f, make([]byte, 65536))
	must(e)
	must(z.Close())
	must(out.Close())
	return hex.EncodeToString(h.Sum(nil))
}
func main() {
	out := flag.String("out", "artifacts/large-compression", "artifact directory")
	capture := flag.Bool("capture", false, "replace retained native fixtures after full kernel qualification")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native qualification requires macOS")
	}
	must(os.MkdirAll(*out, 0755))
	fixture := "testdata/appledouble/native/large-compression"
	if *capture {
		must(os.MkdirAll(fixture, 0755))
	}
	r := report{Host: string(run("sw_vers")), Compiler: string(run("xcrun", "clang", "--version")), SDK: string(run("xcrun", "--show-sdk-version")), Sources: map[string]string{}}
	defer func() { b, e := json.MarshalIndent(r, "", "  "); must(e); save(filepath.Join(*out, "report.json"), b) }()
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	for _, path := range []string{"scripts/verify-large-compression.go", "testdata/appledouble/native/decmpfs-large.c", "testdata/appledouble/native/decmpfs-expand.c", filepath.Join(sdk, "usr/include/sys/xattr.h"), filepath.Join(sdk, "usr/include/sys/stat.h")} {
		r.Sources[path] = hash(read(path))
	}
	temp, e := os.MkdirTemp("", "apfs-large-compression-")
	must(e)
	defer os.RemoveAll(temp)
	producer := filepath.Join(temp, "producer")
	expand := filepath.Join(temp, "expand")
	for _, driver := range []struct{ source, output string }{{"testdata/appledouble/native/decmpfs-large.c", producer}, {"testdata/appledouble/native/decmpfs-expand.c", expand}} {
		run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-framework", "CoreFoundation", driver.source, "-o", driver.output)
		for _, arch := range []string{"arm64", "x86_64"} {
			ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", driver.source)
			for _, name := range []string{"main", "fopen"} {
				if !bytes.Contains(ast, []byte(`"name": "`+name+`"`)) {
					panic("missing native AST declaration " + name)
				}
			}
			name := filepath.Base(driver.source) + "-" + arch + ".ast.json"
			save(filepath.Join(*out, name), ast)
			r.Sources[name] = hash(ast)
		}
	}
	pattern := make([]byte, 65536)
	for i := range pattern {
		pattern[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "[i%27]
	}
	record := func(name, origin, path, prefix string, kind uint32, size int64) {
		s := sample{Name: name, Origin: origin, Type: kind, Size: size}
		s.SHA256 = logicalHash(path, size, pattern)
		attr, err := os.ReadFile(prefix + ".attr")
		if err == nil {
			s.Attribute, s.StoredCompressed = attr, true
			// Retain the actual header even if a producer unexpectedly chooses
			// inline storage and the following resource-fork read fails.
			save(filepath.Join(*out, name+".attr"), attr)
			s.ForkSHA256 = saveFork(prefix+".fork", filepath.Join(*out, name+".fork.gz"))
			if *capture {
				save(filepath.Join(fixture, name+".fork.gz"), read(filepath.Join(*out, name+".fork.gz")))
			}
		} else if !os.IsNotExist(err) {
			must(err)
		} else if _, err = os.Stat(prefix + ".fork"); !os.IsNotExist(err) {
			panic("uncompressed control retained a compression resource fork")
		}
		r.Cases = append(r.Cases, s)
		fmt.Printf("qualified %s: %d logical bytes sha256=%s\n", name, size, s.SHA256)
	}
	for _, kind := range []uint32{4, 8, 12, 14} {
		input := filepath.Join(temp, fmt.Sprintf("native-%d", kind))
		save(input, pattern)
		prefix := input + "-capture"
		run(producer, fmt.Sprint(kind), input, prefix)
		record(fmt.Sprintf("native-%d-65536", kind), "AppleFSCompression producer and complete kernel readback", input, prefix, kind, 65536)
		for _, boundary := range []int64{1 << 30, 2 << 30, 4 << 30} {
			for _, delta := range []int64{-1, 0, 1} {
				size := boundary + delta
				name := fmt.Sprintf("kernel-%d-%d", kind, size)
				base := filepath.Join(temp, name)
				run(expand, fmt.Sprint(kind), fmt.Sprint(size), prefix+".fork", base+".fork", base+".native", base+".attr")
				record(name, "C-constructed repeated native block with stored final tail; complete kernel readback", base+".native", base, kind, size)
				must(os.Remove(base + ".native"))
				must(os.Remove(base + ".fork"))
			}
		}
	}
	// Independent producer control across the zlib table's old 64 KiB ceiling.
	for _, size := range []int64{(512 << 20) - 1, 512 << 20, (512 << 20) + 1} {
		name := fmt.Sprintf("native-4-%d", size)
		path := filepath.Join(temp, name)
		f, e := os.Create(path)
		must(e)
		for remaining := size; remaining > 0; {
			p := pattern[:min(int64(len(pattern)), remaining)]
			n, e := f.Write(p)
			must(e)
			if n != len(p) {
				panic(io.ErrShortWrite)
			}
			remaining -= int64(n)
		}
		must(f.Close())
		prefix := path + "-capture"
		run(producer, "4", path, prefix)
		record(name, "AppleFSCompression producer and complete kernel readback", path, prefix, 4, size)
		must(os.Remove(path))
		if err := os.Remove(prefix + ".fork"); err != nil && !os.IsNotExist(err) {
			must(err)
		}
	}
	if len(r.Cases) != 43 {
		panic("incomplete native case inventory")
	}
	if *capture {
		b, e := json.MarshalIndent(r, "", "  ")
		must(e)
		save(filepath.Join(fixture, "manifest.json"), b)
	} else {
		var old report
		must(json.Unmarshal(read(filepath.Join(fixture, "manifest.json")), &old))
		if !reflect.DeepEqual(old.Cases, r.Cases) {
			panic("native large-compression observations changed; fresh evidence retained")
		}
	}
}
