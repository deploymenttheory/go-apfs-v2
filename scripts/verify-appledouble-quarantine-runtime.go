//go:build ignore

// Controlled native research, not a Go implementation of quarantine policy.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type processSnapshot struct {
	InitCode, InitErrno int
	Serialized          string // Exact native bytes, hex encoded (including final NUL).
}
type xattrSnapshot struct {
	Present         bool
	Errno           int
	Bytes, Envelope string
}
type runtimeResult struct {
	BaselineSetCode, BaselineSetErrno                                  int
	Start, End                                                         int64
	UID, EUID                                                          uint32
	Before, Effective                                                  processSnapshot
	Requested                                                          *string
	ProcessApplyCode, ProcessApplyErrno, FileApplyCode, FileApplyErrno int
	Prepared, Applied                                                  xattrSnapshot
}
type runtimeCase struct {
	Name, Kind, CreationOrder         string
	ProcessInput, FileInput, Baseline []byte
	Result                            runtimeResult
}
type runtimeFixture struct {
	Host, Profile, HelperSHA256, SDKExportsSHA256 string
	Records                                       []runtimeCase
}
type runtimeCommand struct {
	Args          []string
	Output, Error string
}

var runtimeCommands []runtimeCommand

func mustRuntime(err error) {
	if err != nil {
		panic(err)
	}
}
func readRuntime(path string) []byte     { b, e := os.ReadFile(path); mustRuntime(e); return b }
func writeRuntime(path string, b []byte) { mustRuntime(os.WriteFile(path, b, 0600)) }
func hashRuntime(b []byte) string        { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func runRuntime(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	c := runtimeCommand{Args: args, Output: string(b)}
	if e != nil {
		c.Error = e.Error()
	}
	runtimeCommands = append(runtimeCommands, c)
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func saveRuntime(path string, v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	mustRuntime(e)
	writeRuntime(path, append(b, '\n'))
}
func main() {
	capture := flag.Bool("capture", false, "record independent observations without claiming qualification")
	flag.Parse()
	const root = "artifacts/appledouble-quarantine-runtime"
	mustRuntime(os.MkdirAll(root, 0755))
	qualified := false
	var observed runtimeFixture
	defer func() {
		failure := recover()
		saveRuntime(filepath.Join(root, "observed.json"), observed)
		report := map[string]any{"qualified": qualified, "capture_only": *capture, "commands": runtimeCommands, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "cases": len(observed.Records)}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		saveRuntime(filepath.Join(root, "report.json"), report)
		if failure != nil {
			fmt.Fprintln(os.Stderr, failure)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native runtime oracle requires macOS")
	}
	runRuntime("git", "rev-parse", "HEAD")
	observed.Host = string(runRuntime("sw_vers"))
	switch {
	case strings.Contains(observed.Host, "ProductVersion:\t\t27."):
		observed.Profile = "macos27"
	case strings.Contains(observed.Host, "ProductVersion:\t\t26."):
		observed.Profile = "macos26"
	default:
		panic("unqualified native release: " + observed.Host)
	}
	runRuntime("uname", "-a")
	runRuntime("xcrun", "clang", "--version")
	runRuntime("xcrun", "--show-sdk-version")
	sdk := strings.TrimSpace(string(runRuntime("xcrun", "--show-sdk-path")))
	exports := readRuntime(filepath.Join(sdk, "usr/lib/system/libquarantine.tbd"))
	observed.SDKExportsSHA256 = hashRuntime(exports)
	writeRuntime(filepath.Join(root, "libquarantine.tbd"), exports)
	for _, symbol := range []string{"__qtn_proc_alloc", "__qtn_proc_free", "__qtn_proc_init_with_self", "__qtn_proc_to_data", "__qtn_proc_init_with_data", "__qtn_proc_apply_to_self", "__qtn_file_alloc", "__qtn_file_free", "__qtn_file_init_with_data", "__qtn_file_apply_to_fd", "__qtn_file_init_with_fd", "__qtn_file_to_data"} {
		if !bytes.Contains(exports, []byte(symbol)) {
			panic("missing SDK symbol: " + symbol)
		}
	}
	source := "testdata/appledouble/native/quarantine-runtime.c"
	observed.HelperSHA256 = hashRuntime(readRuntime(source))
	helper := filepath.Join(root, "quarantine-runtime")
	runRuntime("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := runRuntime("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		runtimeCommands[len(runtimeCommands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		writeRuntime(filepath.Join(root, "quarantine-runtime-"+arch+".ast.json"), ast)
	}
	for _, context := range []string{"inherited", "0000", "0001", "0002", "0004", "0040", "0200", "0201"} {
		for _, flags := range []uint32{0, 1, 2, 3, 4, 8, 0x10, 0x40, 0x41, 0x80, 0x200, 0x1fff} {
			for _, kind := range []string{"file", "directory"} {
				for _, order := range []string{"before", "after"} {
					for _, baseline := range []string{"absent", "existing"} {
						tc := runtimeCase{Name: fmt.Sprintf("%s-%04x-%s-%s-%s", context, flags, kind, order, baseline), Kind: kind, CreationOrder: order, FileInput: []byte(fmt.Sprintf("q/%04x;12345678;FileAgent;FileID\x00", flags))}
						if context != "inherited" {
							tc.ProcessInput = []byte("q/" + context + ";ContextAgent;ContextID")
						}
						if baseline == "existing" {
							tc.Baseline = []byte("0081;23456789;ExistingAgent;ExistingID")
						}
						dir, e := os.MkdirTemp(root, tc.Name+"-")
						mustRuntime(e)
						process, initial := "-", "-"
						if tc.ProcessInput != nil {
							process = filepath.Join(dir, "process-input")
							writeRuntime(process, tc.ProcessInput)
						}
						if tc.Baseline != nil {
							initial = filepath.Join(dir, "baseline-input")
							writeRuntime(initial, tc.Baseline)
						}
						input := filepath.Join(dir, "file-input")
						writeRuntime(input, tc.FileInput)
						b := runRuntime(helper, process, filepath.Join(dir, "destination"), input, kind, order, initial)
						writeRuntime(filepath.Join(dir, "native.json"), b)
						mustRuntime(json.Unmarshal(b, &tc.Result))
						validateRuntime(tc)
						observed.Records = append(observed.Records, tc)
					}
				}
			}
		}
	}
	if len(observed.Records) != 768 {
		panic("incomplete runtime matrix")
	}
	if *capture {
		fmt.Printf("Captured %d native runtime observations (%s); not yet qualified\n", len(observed.Records), observed.Profile)
		return
	}
	var fixture runtimeFixture
	mustRuntime(json.Unmarshal(readRuntime("testdata/appledouble/native/quarantine-runtime-"+observed.Profile+".json"), &fixture))
	if fixture.Profile != observed.Profile || fixture.HelperSHA256 != observed.HelperSHA256 || len(fixture.Records) != len(observed.Records) {
		panic("runtime fixture provenance or case count")
	}
	for i, want := range fixture.Records {
		got := observed.Records[i]
		validateRuntime(want)
		if want.Name != got.Name || want.Kind != got.Kind || want.CreationOrder != got.CreationOrder || !bytes.Equal(want.ProcessInput, got.ProcessInput) || !bytes.Equal(want.FileInput, got.FileInput) || !bytes.Equal(want.Baseline, got.Baseline) {
			panic("runtime inputs changed: " + want.Name)
		}
		compareRuntime(want.Name, want.Result, got.Result)
	}
	qualified = true
	fmt.Printf("Quarantine runtime (%s): %d controlled observations matched; no Go policy parity claimed\n", observed.Profile, len(observed.Records))
}
func validateRuntime(tc runtimeCase) {
	r := tc.Result
	if r.Start <= 0 || r.End < r.Start {
		panic("invalid operation interval: " + tc.Name)
	}
	if (tc.ProcessInput == nil) != (r.Requested == nil) {
		panic("missing requested process state: " + tc.Name)
	}
	for _, s := range []processSnapshot{r.Before, r.Effective} {
		b, e := hex.DecodeString(s.Serialized)
		mustRuntime(e)
		if len(b) < 9 || !bytes.HasPrefix(b, []byte("q/")) || b[len(b)-1] != 0 {
			panic("invalid captured process bytes: " + tc.Name)
		}
	}
	for _, s := range []xattrSnapshot{r.Prepared, r.Applied} {
		_, e := hex.DecodeString(s.Bytes)
		mustRuntime(e)
		if (!s.Present && (s.Errno != 93 || s.Bytes != "")) || (s.Present && s.Errno != 0) {
			panic("invalid xattr readback status: " + tc.Name)
		}
	}
	// File application errors and denied process changes are observations, not
	// harness setup failures. Their exact codes must still match the fixture.
}
func compareRuntime(name string, want, got runtimeResult) {
	if want.Before != got.Before || want.Effective != got.Effective || (want.Requested == nil) != (got.Requested == nil) {
		panic("process capture differs: " + name)
	}
	if want.Requested != nil && *want.Requested != *got.Requested {
		panic("process request differs: " + name)
	}
	if want.BaselineSetCode != got.BaselineSetCode || (want.BaselineSetCode != 0 && want.BaselineSetErrno != got.BaselineSetErrno) || want.ProcessApplyCode != got.ProcessApplyCode || (want.ProcessApplyCode != 0 && want.ProcessApplyErrno != got.ProcessApplyErrno) || want.FileApplyCode != got.FileApplyCode || (want.FileApplyCode != 0 && want.FileApplyErrno != got.FileApplyErrno) {
		panic("application result differs: " + name)
	}
	// errno is undefined after a successful native operation; it is retained in
	// raw evidence but is not a success predicate. Capture/readback clear errno.
	compareRuntimeXattr(name+"/prepared", want.Prepared, got.Prepared, want, got)
	compareRuntimeXattr(name+"/applied", want.Applied, got.Applied, want, got)
	// Independently native-imported envelopes must agree too, including NUL.
	a, b := want.Prepared, got.Prepared
	a.Bytes, b.Bytes = a.Envelope, b.Envelope
	compareRuntimeXattr(name+"/prepared-envelope", a, b, want, got)
	a, b = want.Applied, got.Applied
	a.Bytes, b.Bytes = a.Envelope, b.Envelope
	compareRuntimeXattr(name+"/applied-envelope", a, b, want, got)
}
func compareRuntimeXattr(name string, want, got xattrSnapshot, oldInterval, newInterval runtimeResult) {
	if want.Present != got.Present || want.Errno != got.Errno {
		panic("xattr presence differs: " + name)
	}
	if !want.Present {
		return
	}
	a, e := hex.DecodeString(want.Bytes)
	mustRuntime(e)
	b, e := hex.DecodeString(got.Bytes)
	mustRuntime(e)
	x, y := bytes.Split(a, []byte{';'}), bytes.Split(b, []byte{';'})
	if len(x) != 4 || len(y) != 4 {
		panic("unexpected runtime xattr form: " + name)
	}
	ts, e := strconv.ParseInt(string(x[1]), 16, 64)
	mustRuntime(e)
	if ts >= oldInterval.Start && ts <= oldInterval.End {
		actual, e := strconv.ParseInt(string(y[1]), 16, 64)
		mustRuntime(e)
		if actual < newInterval.Start || actual > newInterval.End {
			panic("timestamp outside operation interval: " + name)
		}
		y[1] = x[1]
	}
	if !bytes.Equal(bytes.Join(x, []byte{';'}), bytes.Join(y, []byte{';'})) {
		panic(fmt.Sprintf("xattr bytes differ %s: want %q got %q", name, a, b))
	}
}
