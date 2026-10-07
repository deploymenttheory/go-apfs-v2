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
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
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

type recordComparison struct {
	Name                                           string
	PolicyOnly                                     bool
	NativeAccepted, GoAccepted, CanonicalRestored  bool
	Baseline, Native, CanonicalBaseline, Canonical map[string][]byte
}

var recordComparisons []recordComparison

type specialProducerComparison struct {
	Name, Kind                                                                 string
	NativeSetAccepted, CodecEncodeAccepted, PackedByteEqual, NativeUnpackEqual bool
	Baseline, Source, RestoredBaseline, Restored                               map[string][]byte
}

var specialProducers []specialProducerComparison
var specialWire []recordComparison

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
	b, err := cirunner.Command(args[0], args[1:]...).CombinedOutput()
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
		report := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go": runtime.Version(), "passed": passed, "commands": commands, "comparisons": comparisons, "name_comparisons": nameComparisons, "record_comparisons": recordComparisons, "special_producers": specialProducers, "special_wire": specialWire}
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
	verifyRecords(root, helper)
	verifySpecial(root, helper)
	passed = true
	fmt.Printf("%d native size comparisons, %d name comparisons and %d record comparisons passed\n", len(comparisons), len(nameComparisons), len(recordComparisons))
	fmt.Printf("%d special-attribute producer probes and %d wire probes passed (four wire probes retain outstanding ACL/quarantine policy observations)\n", len(specialProducers), len(specialWire))
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

func verifyRecords(root, helper string) {
	var fixture struct {
		HelperSHA256, ListHelperSHA256 string
		Records                        []struct {
			Name, SHA256 string
			Raw          []byte
			Accepted     bool
			Expected     map[string][]byte
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/records.json"), &fixture))
	if fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/probe.c"))) || fixture.ListHelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/list.c"))) {
		panic("record fixture helper provenance mismatch")
	}
	if len(fixture.Records) != 44 {
		panic("required native record observations missing")
	}
	listHelper := filepath.Join(root, "list")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/list.c", "-o", listHelper)
	for _, tc := range fixture.Records {
		if tc.SHA256 != fmt.Sprintf("%x", sha256.Sum256(tc.Raw)) {
			panic("record fixture hash mismatch")
		}
		dir := filepath.Join(root, "records", tc.Name)
		must(os.MkdirAll(dir, 0755))
		input, dst := filepath.Join(dir, "input.ad"), filepath.Join(dir, "restored")
		write(input, tc.Raw)
		fresh(dst)
		r := recordComparison{Name: tc.Name, Baseline: attributes(helper, listHelper, dir, dst, "before")}
		output, err := observe(helper, "unpack", input, dst)
		r.NativeAccepted = err == nil
		if r.NativeAccepted != tc.Accepted {
			panic(fmt.Sprintf("%s native acceptance changed: %v %s", tc.Name, err, output))
		}
		if !r.NativeAccepted {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.Contains(output, []byte("unpack failed: errno=")) {
				panic("unexpected native record failure")
			}
			// Some copyfile header failures preserve stale errno. Do not pretend every
			// rejection is EINVAL, or accept a crash/setup error as a rejection.
			commands[len(commands)-1].ExpectedFailure = true
		}
		r.Native = attributes(helper, listHelper, dir, dst, "after")
		decoded, err := appledouble.Decode(tc.Raw)
		r.GoAccepted = err == nil
		if r.GoAccepted != r.NativeAccepted {
			panic("Go/native record acceptance differs: " + tc.Name)
		}
		if r.GoAccepted {
			checkAttributes(tc.Name, decoded.Xattrs(), tc.Expected)
			checkAttributes(tc.Name, withoutHostProvenance(r.Native, r.Baseline, tc.Expected), tc.Expected)
			canonical, err := decoded.Encode()
			must(err)
			write(filepath.Join(dir, "go.ad"), canonical)
			dst = filepath.Join(dir, "canonical-restored")
			fresh(dst)
			r.CanonicalBaseline = attributes(helper, listHelper, dir, dst, "canonical-before")
			run(helper, "unpack", filepath.Join(dir, "go.ad"), dst)
			r.Canonical = attributes(helper, listHelper, dir, dst, "canonical-after")
			checkAttributes(tc.Name, withoutHostProvenance(r.Canonical, r.CanonicalBaseline, tc.Expected), tc.Expected)
			r.CanonicalRestored = true
		}
		recordComparisons = append(recordComparisons, r)
		fmt.Printf("native record %s: accepted=%t, Go agrees\n", tc.Name, r.NativeAccepted)
	}
}

func attributes(helper, listHelper, dir, dst, label string) map[string][]byte {
	namesPath := filepath.Join(dir, label+"-names")
	run(listHelper, dst, namesPath)
	names := bytes.Split(read(namesPath), []byte{0})
	sort.Slice(names, func(i, j int) bool { return bytes.Compare(names[i], names[j]) < 0 })
	result := map[string][]byte{}
	for i, name := range names {
		if len(name) == 0 {
			continue
		}
		valuePath := filepath.Join(dir, fmt.Sprintf("%s-value-%d", label, i))
		run(helper, "get", dst, string(name), valuePath)
		result[string(name)] = read(valuePath)
	}
	return result
}
func withoutHostProvenance(actual, baseline, expected map[string][]byte) map[string][]byte {
	result := map[string][]byte{}
	for name, value := range actual {
		_, supplied := expected[name]
		before, present := baseline[name]
		if name == "com.apple.provenance" && !supplied && present && bytes.Equal(value, before) {
			continue
		}
		result[name] = value
	}
	return result
}
func checkAttributes(label string, actual, expected map[string][]byte) {
	if len(actual) != len(expected) {
		panic(fmt.Sprintf("%s attribute count differs: got %d, want %d", label, len(actual), len(expected)))
	}
	for name, want := range expected {
		got, ok := actual[name]
		if !ok || !bytes.Equal(got, want) {
			panic(fmt.Sprintf("%s attribute %q differs: present=%t got=%x want=%x", label, name, ok, got, want))
		}
	}
}

func verifySpecial(root, helper string) {
	var fixture struct {
		HelperSHA256, ListHelperSHA256 string
		Producers                      []struct {
			Name, Kind, Attribute string
			Value                 []byte
			SetAccepted           bool
			Expected              map[string][]byte
		}
		Wire []struct {
			Name, SHA256         string
			Raw                  []byte
			Accepted, PolicyOnly bool
			Expected             map[string][]byte
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/special.json"), &fixture))
	if fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/probe.c"))) || fixture.ListHelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/list.c"))) {
		panic("special fixture helper provenance mismatch")
	}
	if len(fixture.Producers) != 30 || len(fixture.Wire) != 25 {
		panic("required special observations missing")
	}
	// verifyRecords has already compiled and exercised the enumeration helper.
	listHelper := filepath.Join(root, "list")
	for _, tc := range fixture.Producers {
		dir := filepath.Join(root, "special-producers", tc.Name)
		must(os.MkdirAll(dir, 0755))
		src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "restored")
		freshKind(src, tc.Kind)
		freshKind(dst, tc.Kind)
		valuePath := filepath.Join(dir, "value")
		write(valuePath, tc.Value)
		r := specialProducerComparison{Name: tc.Name, Kind: tc.Kind, Baseline: attributes(helper, listHelper, dir, src, "before")}
		output, err := observe(helper, "set", src, tc.Attribute, valuePath)
		r.NativeSetAccepted = err == nil
		if r.NativeSetAccepted != tc.SetAccepted {
			panic(fmt.Sprintf("%s native setter changed: %v %s", tc.Name, err, output))
		}
		if !r.NativeSetAccepted {
			expectedNativeFailure(err, output, "set")
		}
		r.Source = attributes(helper, listHelper, dir, src, "source")
		checkAttributes(tc.Name, withoutHostProvenance(r.Source, r.Baseline, tc.Expected), tc.Expected)
		_, err = appledouble.FromXattrs(map[string][]byte{tc.Attribute: tc.Value}).Encode()
		r.CodecEncodeAccepted = err == nil
		invalidFinder := tc.Attribute == appledouble.FinderInfoName && len(tc.Value) != 32
		if r.CodecEncodeAccepted == invalidFinder {
			panic("FinderInfo constructor validation differs: " + tc.Name)
		}
		if r.NativeSetAccepted {
			side := filepath.Join(dir, "native.ad")
			run(helper, "pack", src, side)
			raw := read(side)
			decoded, err := appledouble.Decode(raw)
			must(err)
			checkAttributes(tc.Name, decoded.Xattrs(), r.Source)
			encoded, err := decoded.Encode()
			must(err)
			fromSource, err := appledouble.FromXattrs(r.Source).Encode()
			must(err)
			if !bytes.Equal(raw, encoded) || !bytes.Equal(raw, fromSource) {
				panic("native producer byte mismatch: " + tc.Name)
			}
			r.PackedByteEqual = true
			side = filepath.Join(dir, "go.ad")
			write(side, fromSource)
			r.RestoredBaseline = attributes(helper, listHelper, dir, dst, "restored-before")
			run(helper, "unpack", side, dst)
			r.Restored = attributes(helper, listHelper, dir, dst, "restored")
			checkAttributes(tc.Name, withoutHostProvenance(r.Restored, r.RestoredBaseline, tc.Expected), tc.Expected)
			r.NativeUnpackEqual = true
		}
		specialProducers = append(specialProducers, r)
		fmt.Printf("native special producer %s: setter accepted=%t, codec accepted=%t\n", tc.Name, r.NativeSetAccepted, r.CodecEncodeAccepted)
	}
	for _, tc := range fixture.Wire {
		if tc.SHA256 != fmt.Sprintf("%x", sha256.Sum256(tc.Raw)) {
			panic("special wire fixture hash")
		}
		dir := filepath.Join(root, "special-wire", tc.Name)
		must(os.MkdirAll(dir, 0755))
		input, dst := filepath.Join(dir, "input.ad"), filepath.Join(dir, "restored")
		write(input, tc.Raw)
		fresh(dst)
		r := recordComparison{Name: tc.Name, PolicyOnly: tc.PolicyOnly, Baseline: attributes(helper, listHelper, dir, dst, "before")}
		output, err := observe(helper, "unpack", input, dst)
		r.NativeAccepted = err == nil
		if r.NativeAccepted != tc.Accepted {
			panic("special wire native acceptance changed: " + tc.Name)
		}
		if !r.NativeAccepted {
			expectedNativeFailure(err, output, "unpack")
		}
		r.Native = attributes(helper, listHelper, dir, dst, "after")
		decoded, err := appledouble.Decode(tc.Raw)
		r.GoAccepted = err == nil
		if r.GoAccepted != r.NativeAccepted {
			panic("special wire acceptance mismatch: " + tc.Name)
		}
		checkAttributes(tc.Name, withoutHostProvenance(r.Native, r.Baseline, tc.Expected), tc.Expected)
		if r.GoAccepted {
			if !tc.PolicyOnly {
				checkAttributes(tc.Name, decoded.Xattrs(), tc.Expected)
			}
			// Policy-only records are retained verbatim, not falsely classified as
			// ordinary native attributes. Native handling is observed in both directions.
			canonical, err := decoded.Encode()
			must(err)
			if !bytes.Equal(canonical, tc.Raw) {
				panic("special wire payload changed: " + tc.Name)
			}
			side := filepath.Join(dir, "go.ad")
			write(side, canonical)
			dst = filepath.Join(dir, "canonical-restored")
			fresh(dst)
			r.CanonicalBaseline = attributes(helper, listHelper, dir, dst, "canonical-before")
			run(helper, "unpack", side, dst)
			r.Canonical = attributes(helper, listHelper, dir, dst, "canonical-after")
			checkAttributes(tc.Name, withoutHostProvenance(r.Canonical, r.CanonicalBaseline, tc.Expected), tc.Expected)
			r.CanonicalRestored = true
		}
		specialWire = append(specialWire, r)
		fmt.Printf("native special wire %s: accepted=%t, policy-only=%t\n", tc.Name, r.NativeAccepted, tc.PolicyOnly)
	}
}

func freshKind(path, kind string) {
	// Paths are fixed harness-owned children, never user-supplied destinations.
	must(os.RemoveAll(path))
	if kind == "directory" {
		must(os.Mkdir(path, 0700))
		return
	}
	if kind != "file" {
		panic("invalid fixture kind")
	}
	write(path, nil)
}
func expectedNativeFailure(err error, output []byte, operation string) {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.Contains(output, []byte(operation+" failed: errno=")) {
		panic("unexpected native " + operation + " failure")
	}
	// This must be called immediately after observe, before any further command.
	commands[len(commands)-1].ExpectedFailure = true
}
