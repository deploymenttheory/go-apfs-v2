//go:build ignore

// Qualify AppleDouble unpack restoration; native tools are test-only.
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
	"net/http"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/unpackrestore"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type command struct {
	Args                 []string
	Input, Output, Error string
}

var commands []command

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte     { b, e := os.ReadFile(p); must(e); return b }
func write(p string, b []byte) { must(os.WriteFile(p, b, 0600)) }
func sum(b []byte) string      { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func run(input string, args ...string) []byte {
	cmd := cirunner.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(input)
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	e := cmd.Run()
	c := command{Args: args, Input: input, Output: out.String(), Error: errout.String()}
	if e != nil {
		c.Error += e.Error()
	}
	commands = append(commands, c)
	if e != nil {
		panic(fmt.Sprintf("%v: %v %s", args, e, errout.String()))
	}
	return out.Bytes()
}
func download(url, hash, target string) []byte {
	client := http.Client{Timeout: 30 * time.Second}
	r, e := client.Get(url)
	must(e)
	b, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	must(e)
	must(r.Body.Close())
	if r.StatusCode != 200 || sum(b) != hash {
		panic("source provenance")
	}
	write(target, b)
	return b
}
func extract(b []byte, start, end string) []byte {
	i := bytes.Index(b, []byte(start))
	if i < 0 {
		panic(start)
	}
	j := bytes.Index(b[i:], []byte(end))
	if j < 0 {
		panic(end)
	}
	return b[i : i+j]
}
func main() {
	capture := flag.Bool("capture", false, "record unapproved observations")
	flag.Parse()
	const root = "artifacts/unpack-restore"
	const source = "testdata/appledouble/native/unpack-restore.c"
	must(os.MkdirAll(root, 0700))
	var f unpackrestore.Fixture
	passed := false
	defer func() {
		failure := recover()
		r := map[string]any{"passed": passed, "capture": *capture, "fixture": f, "commands": commands}
		if failure != nil {
			r["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(r, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), b, 0600)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		panic("requires ordinary macOS user")
	}
	f.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	f.Host = string(run("", "sw_vers"))
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(source))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.PolicySHA256 = "991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc"
	f.HeaderSHA256 = "0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49"
	const base = "https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/"
	src := download(base+"copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "static int copyfile_unpack_xattr(copyfile_state_t s, attr_entry_t *entry, void *dataptr)", "/*\n * Given an Apple Double file in src")...)
	write(filepath.Join(root, "xattr-restore-source.h"), h)
	h = append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "#define FINDERINFOSIZE", "static int copyfile_unpack_quarantine")...)
	write(filepath.Join(root, "unpack-layout-source.h"), h)
	h = append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "static int copyfile_unpack(copyfile_state_t s)", "static int copyfile_pack_quarantine")...)
	write(filepath.Join(root, "unpack-source.h"), h)
	policy := download(base+"xattr_flags.c", f.PolicySHA256, filepath.Join(root, "xattr_flags.c"))
	download(base+"xattr_flags.h", f.HeaderSHA256, filepath.Join(root, "xattr_flags.h"))
	h = append([]byte{}, policy[:bytes.Index(policy, []byte("#include"))]...)
	h = append(h, extract(policy, "#define FLAG_DELIM_CHAR", "\nchar *\nxattr_name_with_flags")...)
	h = append(h, extract(policy, "int\nxattr_intent_with_flags", "\n#include \"xattr_properties.h\"")...)
	write(filepath.Join(root, "xattr-policy-source.h"), h)
	helper := filepath.Join(root, "unpack-restore")
	run("", "xcrun", "clang", "-fblocks", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-I", root, source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("", "xcrun", "clang", "-fblocks", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	f.Images = unpackrestore.Images()
	images := filepath.Join(root, "images")
	must(os.MkdirAll(images, 0700))
	for i, data := range f.Images {
		b, e := hex.DecodeString(data)
		must(e)
		write(filepath.Join(images, fmt.Sprintf("%d.ad", i)), b)
	}
	invoke := func(cases []unpackrestore.Case, live bool) []unpackrestore.Case {
		var input strings.Builder
		bit := func(b bool) int {
			if b {
				return 1
			}
			return 0
		}
		for _, c := range cases {
			fmt.Fprintf(&input, "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", c.Image, c.List, c.Remove, c.Ordinary, c.Finder, c.Fork, c.ForkStat, c.Times, c.Quarantine, c.ACL, c.Stat, bit(c.StatFlag), bit(c.Callback), c.Actions[0], c.Actions[1], c.Actions[2], c.Target, bit(c.Directory), c.Intent)
		}
		args := []string{helper, images}
		if live {
			dir, e := os.MkdirTemp(root, "live-")
			must(e)
			defer os.RemoveAll(dir)
			args = append(args, dir)
		}
		output := run(input.String(), args...)
		decoder := json.NewDecoder(bytes.NewReader(output))
		for i := range cases {
			must(decoder.Decode(&cases[i].Native))
			if e := unpackrestore.Replay(cases[i], f.Images); e != nil {
				panic(fmt.Sprintf("live=%v case %d: %v", live, i, e))
			}
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			panic("extra native output")
		}
		return cases
	}
	f.Cases = invoke(unpackrestore.Cases(), false)
	f.Live = invoke(unpackrestore.LiveCases(), true)
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d models and %d native application observations; NOT approved\n", len(f.Cases), len(f.Live))
		return
	}
	matched := ""
	for _, name := range []string{"unpack-restore.json.gz", "unpack-restore-ci.json.gz"} {
		z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/" + name)))
		must(e)
		var archived unpackrestore.Fixture
		must(json.NewDecoder(z).Decode(&archived))
		must(z.Close())
		archived.Revision, archived.Host = f.Revision, f.Host
		if reflect.DeepEqual(archived, f) {
			matched = name
		}
	}
	if matched == "" {
		panic("archived unpack restoration observations differ from every reviewed host profile")
	}
	fmt.Printf("Exact reviewed host profile: %s\n", matched)
	passed = true
	fmt.Printf("Qualified %d models and %d native application observations\n", len(f.Cases), len(f.Live))
}
