//go:build ignore

// macOS is an independent oracle here, never a production dependency.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type commandResult struct {
	Args            []string
	Output          string
	Error           string
	ExpectedFailure bool
}
type comparison struct {
	Name                                       string
	Bytes                                      int
	SHA256                                     string
	ByteCompared, ByteEqual, NativeUnpackEqual bool
}

var commands []commandResult
var comparisons []comparison

type nameRecord struct {
	Name       string
	Raw        []byte
	Accepted   bool
	Attributes []struct{ Name, Value []byte }
}
type nameComparison struct {
	Name                                          string
	NativeAccepted, GoAccepted, CanonicalRestored bool
}

var nameComparisons []nameComparison

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(args ...string) []byte {
	b, err := observe(args...)
	if err != nil {
		panic(fmt.Errorf("%v: %w: %s", args, err, b))
	}
	return b
}
func observe(args ...string) ([]byte, error) {
	b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	r := commandResult{Args: args, Output: string(b)}
	if err != nil {
		r.Error = err.Error()
	}
	commands = append(commands, r)
	return b, err
}
func read(name string) []byte     { b, err := os.ReadFile(name); must(err); return b }
func write(name string, b []byte) { must(os.WriteFile(name, b, 0600)) }

func main() {
	const root = "artifacts/appledouble-native"
	must(os.MkdirAll(root, 0755))
	passed := false
	defer func() {
		failure := recover()
		report := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "passed": passed, "commands": commands, "comparisons": comparisons, "name_comparisons": nameComparisons}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(root, "report.json"), append(b, '\n'), 0644)
		}
		if err != nil || failure != nil {
			fmt.Fprintln(os.Stderr, failure, err)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native comparison requires macOS; portable codec tests run on every OS")
	}
	run("sw_vers")
	run("uname", "-a")
	run("git", "rev-parse", "HEAD")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	// Pin the independent source used to interpret the measurements. AST input
	// is an exact extraction of its wire structures, not a hand-written model.
	const sourceURL = "https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c"
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(sourceURL)
	must(err)
	source, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	must(err)
	must(response.Body.Close())
	if response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(source)) != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		panic("pinned Apple source hash mismatch")
	}
	write(filepath.Join(root, "copyfile.c"), source)
	start := bytes.Index(source, []byte("#define ATTR_FILE_PREFIX"))
	end := bytes.Index(source, []byte("/* Empty Resource Fork Header */"))
	if start < 0 || end <= start {
		panic("Apple wire structure extraction failed")
	}
	licenseEnd := bytes.Index(source, []byte("#include <err.h>"))
	if licenseEnd < 0 {
		panic("source license boundary missing")
	}
	layout := append(bytes.Clone(source[:licenseEnd]), []byte("#include <sys/types.h>\n#include <stddef.h>\n")...)
	layout = append(layout, source[start:end]...)
	layout = append(layout, []byte("\n_Static_assert(sizeof(attr_header_t)==120, \"header size\");\n_Static_assert(offsetof(attr_header_t, data_start)==96, \"data_start offset\");\n_Static_assert(ATTR_MAX_HDR_SIZE==65554, \"entry table buffer\");\n_Static_assert(offsetof(attr_entry_t, name)==11, \"entry name offset\");\n")...)
	write(filepath.Join(root, "layout.c"), layout)
	helper := filepath.Join(root, "probe")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/probe.c", "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", "testdata/appledouble/native/probe.c")
		// Keep AST bytes out of the command transcript's duplicate string.
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "probe-"+arch+".ast.json"), ast)
		ast = run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", filepath.Join(root, "layout.c"))
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "layout-"+arch+".ast.json"), ast)
		layouts := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-fdump-record-layouts", filepath.Join(root, "layout.c"))
		write(filepath.Join(root, "layout-"+arch+".txt"), layouts)
	}
	for _, size := range []int{0, 1, 65535, 65536, 65537, 300 * 1024, 1 << 20, 16 << 20} {
		name := fmt.Sprint(size)
		dir := filepath.Join(root, name)
		must(os.MkdirAll(dir, 0755))
		src := filepath.Join(dir, "source")
		value := bytes.Repeat([]byte{0x5a}, size)
		write(src, nil)
		write(filepath.Join(dir, "expected"), value)
		run(helper, "set", src, "com.example.large", filepath.Join(dir, "expected"))
		run(helper, "get", src, "com.example.large", filepath.Join(dir, "source-value"))
		if !bytes.Equal(read(filepath.Join(dir, "source-value")), value) {
			panic("fixture setup changed the value")
		}
		native := filepath.Join(dir, "native.ad")
		run(helper, "pack", src, native)
		raw := read(native)
		decoded, err := appledouble.Decode(raw)
		must(err)
		v, exists := decoded.Xattrs()["com.example.large"]
		if !exists || !bytes.Equal(v, value) {
			panic("native producer lost attribute")
		}
		encoded, err := decoded.Encode()
		must(err)
		goSidecar := filepath.Join(dir, "go.ad")
		write(goSidecar, encoded)
		if !bytes.Equal(encoded, raw) {
			panic("Go re-encoding differs from native bytes")
		}
		dst := filepath.Join(dir, "unpacked")
		write(dst, nil)
		run(helper, "unpack", goSidecar, dst)
		run(helper, "get", dst, "com.example.large", filepath.Join(dir, "result"))
		if !bytes.Equal(read(filepath.Join(dir, "result")), value) {
			panic("native unpack changed Go-produced value")
		}
		comparisons = append(comparisons, comparison{Name: name, Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), ByteCompared: true, ByteEqual: true, NativeUnpackEqual: true})
		fmt.Printf("native AppleDouble %s: %d bytes, exact re-encoding and native unpack passed\n", name, len(raw))
	}
	// Exercise the final aligned entry-table boundary with unique long names.
	// 467*140 + 52 + 120 = 65552. Empty values are real, named attributes.
	f := &appledouble.File{}
	for i := 0; i < 467; i++ {
		f.Attrs = append(f.Attrs, appledouble.Attr{Name: fmt.Sprintf("n%03d", i) + strings.Repeat("x", 123)})
	}
	f.Attrs = append(f.Attrs, appledouble.Attr{Name: strings.Repeat("z", 40)})
	raw, err := f.Encode()
	must(err)
	if len(raw) != 65552 {
		panic(fmt.Sprintf("table boundary size %d", len(raw)))
	}
	write(filepath.Join(root, "table.ad"), raw)
	write(filepath.Join(root, "table-unpacked"), nil)
	run(helper, "unpack", filepath.Join(root, "table.ad"), filepath.Join(root, "table-unpacked"))
	for _, a := range f.Attrs {
		run(helper, "get", filepath.Join(root, "table-unpacked"), a.Name, filepath.Join(root, "table-value"))
		if len(read(filepath.Join(root, "table-value"))) != 0 {
			panic("empty boundary attribute changed")
		}
	}
	comparisons = append(comparisons, comparison{Name: "table-65552", Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), NativeUnpackEqual: true})
	verifyNames(root, helper)
	passed = true
	fmt.Printf("%d native size comparisons and %d name comparisons passed\n", len(comparisons), len(nameComparisons))
}

func verifyNames(root, helper string) {
	var fixture struct {
		HelperSHA256 string
		Records      []nameRecord
	}
	must(json.Unmarshal(read("testdata/appledouble/native/names.json"), &fixture))
	if fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/probe.c"))) {
		panic("native name fixture helper provenance mismatch")
	}
	if len(fixture.Records) != 14 {
		panic("native name observations missing")
	}
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, "names", tc.Name)
		must(os.MkdirAll(dir, 0755))
		input, dst := filepath.Join(dir, "input.ad"), filepath.Join(dir, "restored")
		write(input, tc.Raw)
		fresh(dst)
		output, err := observe(helper, "unpack", input, dst)
		accepted := err == nil
		if accepted != tc.Accepted {
			panic(fmt.Sprintf("%s native acceptance changed: %v %s", tc.Name, err, output))
		}
		if !accepted {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.Contains(output, []byte("unpack failed: errno=22 ")) {
				panic("unexpected native failure, not an EINVAL rejection")
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		decoded, err := appledouble.Decode(tc.Raw)
		if (err == nil) != accepted {
			panic("Go/native name acceptance differs: " + tc.Name)
		}
		result := nameComparison{Name: tc.Name, NativeAccepted: accepted, GoAccepted: err == nil}
		if accepted {
			checkNameValues(helper, dir, dst, tc)
			if len(decoded.Attrs) != len(tc.Attributes) {
				panic("decoded name count differs")
			}
			for i, a := range tc.Attributes {
				if !bytes.Equal([]byte(decoded.Attrs[i].Name), a.Name) || !bytes.Equal(decoded.Attrs[i].Value, a.Value) {
					panic("decoded name/value differs")
				}
			}
			canonical, err := decoded.Encode()
			must(err)
			write(filepath.Join(dir, "go.ad"), canonical)
			dst = filepath.Join(dir, "canonical-restored")
			fresh(dst)
			run(helper, "unpack", filepath.Join(dir, "go.ad"), dst)
			checkNameValues(helper, dir, dst, tc)
			result.CanonicalRestored = true
		}
		nameComparisons = append(nameComparisons, result)
		fmt.Printf("native name %s: accepted=%t, Go agrees\n", tc.Name, accepted)
	}
}
func fresh(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	write(path, nil)
}
func checkNameValues(helper, dir, dst string, tc nameRecord) {
	for i, a := range tc.Attributes {
		valuePath := filepath.Join(dir, fmt.Sprintf("%s-value-%d", filepath.Base(dst), i))
		run(helper, "get", dst, string(a.Name), valuePath)
		if !bytes.Equal(read(valuePath), a.Value) {
			panic("native name readback changed")
		}
	}
}
