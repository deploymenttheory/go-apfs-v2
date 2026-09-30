//go:build ignore

// Qualify portable inner copyfile stage ordering; native tools are test-only.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/copypipeline"
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
	cmd := exec.Command(args[0], args[1:]...)
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
	const root = "artifacts/copy-pipeline"
	const helperSource = "testdata/appledouble/native/copy-pipeline.c"
	const corpus = "testdata/appledouble/native/copy-pipeline.json.gz"
	must(os.MkdirAll(root, 0700))
	var f copypipeline.Fixture
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
	if runtime.GOOS != "darwin" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		panic("requires ordinary macOS user")
	}
	f.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	f.Host = string(run("", "sw_vers"))
	run("", "uname", "-a")
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	src := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "static int copyfile_internal(copyfile_state_t s, copyfile_flags_t flags)", "/*\n * A publicly-visible routine, copyfile_state_alloc()")...)
	write(filepath.Join(root, "pipeline-source.h"), h)
	helper := filepath.Join(root, "copy-pipeline")
	run("", "xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("", "xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	f.Cases = copypipeline.Cases()
	var input strings.Builder
	bit := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	for _, c := range f.Cases {
		fmt.Fprintf(&input, "%d %d %d %d %d %d", c.Flags, bit(c.Source), bit(c.Destination), bit(c.Path), bit(c.Quarantine), c.Callback)
		for _, v := range c.Codes {
			fmt.Fprintf(&input, " %d", v)
		}
		fmt.Fprintf(&input, " %d\n", c.Cleanup)
	}
	output := run(input.String(), helper)
	write(filepath.Join(root, "observations.jsonl"), output)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for i := range f.Cases {
		must(decoder.Decode(&f.Cases[i].Native))
		must(copypipeline.Replay(f.Cases[i]))
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		panic("extra native output")
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d controlled stage-order cases; NOT approved\n", len(f.Cases))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read(corpus)))
	must(e)
	var archived copypipeline.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	archived.Revision, archived.Host = f.Revision, f.Host
	if !reflect.DeepEqual(archived, f) {
		panic("archived stage-order observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d controlled cases against complete unchanged Apple copyfile_internal\n", len(f.Cases))
}
