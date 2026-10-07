//go:build ignore

// Execute unchanged Apple packing bodies and retain independent observations.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/packnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type command struct {
	Args                 []string
	Input, Output, Error string
}

func main() {
	capture := flag.Bool("capture", false, "record unapproved observations; never qualify")
	flag.Parse()
	const root = "artifacts/appledouble-pack"
	const base = "artifacts/unpack-restore"
	const helperSource = "testdata/appledouble/native/pack.c"
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(root, 0700))
	var commands []command
	var fixture packnative.Fixture
	var live []map[string]any
	hashes := map[string]string{}
	passed := false
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "capture": *capture, "fixture": fixture, "commands": commands, "source_sha256": hashes, "live": live}
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
		commands = append(commands, command{args, input, out.String(), stderr.String()})
		if err != nil {
			panic(fmt.Sprintf("%v: %v %s", args, err, stderr.String()))
		}
		return out.Bytes()
	}
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		panic("requires ordinary macOS user and Command Line Tools")
	}
	run("", "go", "run", "scripts/verify-unpack-restore.go")
	fixture.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	fixture.Host = string(run("", "sw_vers"))
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	source := read(filepath.Join(base, "copyfile.c"))
	fixture.SourceSHA256 = sum(source)
	if fixture.SourceSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		panic("copyfile source provenance")
	}
	write(filepath.Join(root, "copyfile.c"), source)
	license := source[:bytes.Index(source, []byte("#include"))]
	start := bytes.Index(source, []byte("static int copyfile_pack_rsrcfork(copyfile_state_t s, attr_header_t *filehdr)"))
	if start < 0 {
		panic("packing source boundary")
	}
	write(filepath.Join(root, "pack-source.h"), append(bytes.Clone(license), source[start:]...))
	start = bytes.Index(source, []byte("static void\nsort_xattrname_list"))
	end := bytes.Index(source[start:], []byte("/*\n * Internally, the process"))
	if start < 0 || end < 0 {
		panic("sort source boundary")
	}
	write(filepath.Join(root, "pack-sort-source.h"), append(bytes.Clone(license), source[start:start+end]...))
	write(filepath.Join(root, "unpack-layout-source.h"), read(filepath.Join(base, "unpack-layout-source.h")))
	fixture.HelperSHA256 = sum(read(helperSource))
	helper := filepath.Join(root, "pack")
	run("", "xcrun", "clang", "-fblocks", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("", "xcrun", "clang", "-fblocks", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, arch+".ast.json"), ast)
		for _, function := range []string{"copyfile_pack", "copyfile_pack_rsrcfork", "sort_xattrname_list"} {
			if !bytes.Contains(ast, []byte(`"name": "`+function+`"`)) {
				panic("missing complete function AST")
			}
		}
	}
	for _, path := range []string{helperSource, "pkg/hostdata/appledouble_pack.go", "pkg/hostdata/appledouble_pack_values.go", "internal/testutil/packnative/oracle.go", "scripts/verify-appledouble-pack.go"} {
		hashes[path] = sum(read(path))
	}
	for _, name := range []string{"copyfile.c", "pack-source.h", "pack-sort-source.h", "unpack-layout-source.h", "arm64.ast.json", "x86_64.ast.json"} {
		hashes[name] = sum(read(filepath.Join(root, name)))
	}
	outputs := filepath.Join(root, "outputs")
	must(os.MkdirAll(outputs, 0700))
	fixture.Cases = packnative.Cases()
	var input strings.Builder
	for _, c := range fixture.Cases {
		input.WriteString(packnative.Input(c))
	}
	output := run(input.String(), helper, outputs)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for i := range fixture.Cases {
		must(decoder.Decode(&fixture.Cases[i].Native))
		b := read(filepath.Join(outputs, fmt.Sprintf("%d.ad", i)))
		fixture.Cases[i].Native.OutputLength = len(b)
		fixture.Cases[i].Native.OutputSHA256 = sum(b)
		if err := packnative.Replay(fixture.Cases[i]); err != nil {
			panic(fmt.Sprintf("case %d %+v: %v", i, fixture.Cases[i], err))
		}
	}
	// Independent public libSystem packing proves that the measured large-value
	// policies also occur on the host filesystem, outside the extracted body.
	const probeSource = "testdata/appledouble/native/probe.c"
	probe := filepath.Join(root, "probe")
	run("", "xcrun", "clang", "-Wall", "-Wextra", "-Werror", probeSource, "-o", probe)
	hashes[probeSource] = sum(read(probeSource))
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("", "xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", probeSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		name := "probe-" + arch + ".ast.json"
		write(filepath.Join(root, name), ast)
		hashes[name] = sum(ast)
	}
	for i, spec := range []struct {
		name string
		size int
	}{
		{"user.large", 16 << 20}, {"user.large", 16<<20 + 1}, {appledouble.ResourceForkName, 16<<20 + 1},
	} {
		prefix := filepath.Join(root, fmt.Sprintf("live-%d", i))
		value := make([]byte, spec.size)
		for j := range value {
			value[j] = byte('A' + j%7)
		}
		write(prefix+".value", value)
		write(prefix+".source", []byte("unchanged data"))
		run("", probe, "set", prefix+".source", spec.name, prefix+".value")
		run("", probe, "get", prefix+".source", spec.name, prefix+".readback")
		readback := read(prefix + ".readback")
		if !bytes.Equal(value, readback) {
			panic("native source setup readback differs")
		}
		run("", probe, "pack", prefix+".source", prefix+".ad")
		packed := read(prefix + ".ad")
		decoded, err := appledouble.Decode(packed)
		must(err)
		attributes := decoded.Xattrs()
		actual, present := attributes[spec.name]
		if !present {
			panic("native packed attribute missing")
		}
		preserved := spec.name == appledouble.ResourceForkName || spec.size <= 16<<20
		if preserved && !bytes.Equal(actual, value) || !preserved && len(actual) != 0 {
			panic("native live packing policy differs")
		}
		live = append(live, map[string]any{"name": spec.name, "source_size": spec.size, "source_sha256": sum(value), "source_readback_sha256": sum(readback), "packed_sha256": sum(packed), "packed_value_size": len(actual), "preserved": preserved})
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		panic("extra packing output")
	}
	b, err := json.MarshalIndent(fixture, "", "  ")
	must(err)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d native packing cases; NOT approved\n", len(fixture.Cases))
		return
	}
	file, err := os.Open("testdata/appledouble/native/pack.json.gz")
	must(err)
	defer file.Close()
	z, err := gzip.NewReader(file)
	must(err)
	defer z.Close()
	var approved packnative.Fixture
	must(json.NewDecoder(z).Decode(&approved))
	if approved.HelperSHA256 != fixture.HelperSHA256 || approved.SourceSHA256 != fixture.SourceSHA256 || !reflect.DeepEqual(approved.Cases, fixture.Cases) {
		panic("packing corpus changed; review independent recapture")
	}
	passed = true
	fmt.Printf("Qualified %d native packing cases and exact output hashes\n", len(fixture.Cases))
}
