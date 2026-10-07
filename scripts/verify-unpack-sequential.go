//go:build ignore

// Qualify sequential source reads through the existing unchanged Apple oracle.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/unpackrestore"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type command struct {
	Args                 []string
	Input, Output, Error string
}

func main() {
	capture := flag.Bool("capture", false, "record unapproved observations; never qualify")
	flag.Parse()
	const root = "artifacts/unpack-sequential"
	const native = "artifacts/unpack-restore"
	const fixturePath = "testdata/appledouble/native/unpack-sequential.json.gz"
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(root, 0700))
	var commands []command
	var f unpackrestore.Fixture
	passed := false
	hashes := map[string]string{}
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "capture": *capture, "fixture": f, "commands": commands, "sources": hashes}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(root, "report.json"), b, 0600)
		}
		if failure != nil || err != nil {
			fmt.Fprintln(os.Stderr, failure, err)
			os.Exit(1)
		}
	}()
	read := func(path string) []byte { b, err := os.ReadFile(path); must(err); return b }
	write := func(path string, b []byte) { must(os.WriteFile(path, b, 0600)) }
	sum := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	run := func(input string, args ...string) []byte {
		cmd := cirunner.Command(args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(input)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		err := cmd.Run()
		commands = append(commands, command{Args: args, Input: input, Output: out.String(), Error: stderr.String()})
		if err != nil {
			panic(fmt.Sprintf("%v: %v %s", args, err, stderr.String()))
		}
		return out.Bytes()
	}
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		panic("requires an ordinary macOS user and Command Line Tools")
	}
	// Keep the existing qualification intact. It pins/downloads source, extracts
	// the complete unchanged functions, compiles both ASTs, and verifies all
	// preceding controlled/live cases before this extension uses its oracle.
	run("", "go", "run", "scripts/verify-unpack-restore.go")
	f.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	f.Host = string(run("", "sw_vers"))
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read("testdata/appledouble/native/unpack-restore.c"))
	f.CopyfileSHA256 = sum(read(filepath.Join(native, "copyfile.c")))
	f.PolicySHA256 = sum(read(filepath.Join(native, "xattr_flags.c")))
	f.HeaderSHA256 = sum(read(filepath.Join(native, "xattr_flags.h")))
	if f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		panic("copyfile source provenance")
	}
	for _, path := range []string{
		"copyfile.c", "xattr_flags.c", "xattr_flags.h", "unpack-source.h", "unpack-layout-source.h", "xattr-restore-source.h", "xattr-policy-source.h", "arm64.ast.json", "x86_64.ast.json",
	} {
		b := read(filepath.Join(native, path))
		write(filepath.Join(root, path), b)
		hashes[path] = sum(b)
	}
	for _, path := range []string{
		"pkg/hostdata/appledouble_sequential.go", "pkg/hostdata/appledouble_restore.go", "pkg/hostdata/xattr_restore.go",
		"internal/testutil/unpackrestore/oracle.go", "internal/testutil/unpackrestore/sequential.go", "testdata/appledouble/native/unpack-restore.c", "scripts/verify-unpack-sequential.go",
	} {
		hashes[path] = sum(read(path))
	}
	f.Images = unpackrestore.SequentialImages()
	images := filepath.Join(root, "images")
	must(os.MkdirAll(images, 0700))
	for i, value := range f.Images {
		b, err := hex.DecodeString(value)
		must(err)
		write(filepath.Join(images, fmt.Sprintf("%d.ad", i)), b)
	}
	invoke := func(live bool) []unpackrestore.Case {
		cases := unpackrestore.SequentialCases(live)
		var input strings.Builder
		for _, c := range cases {
			stat := 0
			if c.StatFlag {
				stat = 1
			}
			fmt.Fprintf(&input, "%d 1 0 0 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0\n", c.Image, stat)
		}
		args := []string{filepath.Join(native, "unpack-restore"), images}
		if live {
			dir, err := os.MkdirTemp(root, "live-")
			must(err)
			defer os.RemoveAll(dir)
			args = append(args, dir)
		}
		out := run(input.String(), args...)
		decoder := json.NewDecoder(bytes.NewReader(out))
		for i := range cases {
			must(decoder.Decode(&cases[i].Native))
			if err := unpackrestore.ReplaySequential(cases[i], f.Images); err != nil {
				panic(fmt.Sprintf("live=%v case=%d: %v", live, i, err))
			}
			if live && !cases[i].Native.RemovedSeeds {
				panic("missing native cleanup readback")
			}
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			panic("extra native observations")
		}
		return cases
	}
	f.Cases = invoke(false)
	f.Live = invoke(true)
	b, err := json.MarshalIndent(f, "", "  ")
	must(err)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d sequential controlled and %d live cases; NOT approved\n", len(f.Cases), len(f.Live))
		return
	}
	file, err := os.Open(fixturePath)
	must(err)
	defer file.Close()
	z, err := gzip.NewReader(file)
	must(err)
	defer z.Close()
	var approved unpackrestore.Fixture
	must(json.NewDecoder(z).Decode(&approved))
	if approved.HelperSHA256 != f.HelperSHA256 || approved.CopyfileSHA256 != f.CopyfileSHA256 || approved.PolicySHA256 != f.PolicySHA256 || approved.HeaderSHA256 != f.HeaderSHA256 || !reflect.DeepEqual(approved.Images, f.Images) || !reflect.DeepEqual(approved.Cases, f.Cases) {
		panic("sequential controlled corpus changed; review independent recapture")
	}
	// Live observations include the real host's namespace (e.g. provenance).
	// Every unfiltered event is replayed above; no normalization is used.
	// Require identical inputs/counts and independently verified native effects.
	if len(approved.Live) != len(f.Live) {
		panic("live sequential case count changed")
	}
	for i, c := range f.Live {
		want := approved.Live[i]
		c.Native, want.Native = unpackrestore.Observation{}, unpackrestore.Observation{}
		if !reflect.DeepEqual(c, want) {
			panic("live sequential input changed")
		}
	}
	passed = true
	fmt.Printf("Qualified %d controlled and %d live sequential cases through unchanged Apple copyfile_unpack\n", len(f.Cases), len(f.Live))
}
