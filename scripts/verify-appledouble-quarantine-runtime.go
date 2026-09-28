//go:build ignore

// Independent native oracle for portable quarantine application policy.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
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
var applicationComparisons []applicationComparison

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
	normalization := flag.Bool("normalization", false, "qualify extended destination normalization inputs")
	capture := flag.Bool("capture", false, "record independent observations without claiming qualification")
	flag.Parse()
	root := "artifacts/appledouble-quarantine-runtime"
	if *normalization {
		root += "-normalization"
	}
	mustRuntime(os.MkdirAll(root, 0755))
	qualified := false
	var observed runtimeFixture
	defer func() {
		failure := recover()
		saveRuntime(filepath.Join(root, "observed.json"), observed)
		report := map[string]any{"qualified": qualified, "capture_only": *capture, "commands": runtimeCommands, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "cases": len(observed.Records), "application_comparisons": applicationComparisons}
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
	cases := runtimeCases(*normalization, observed.Profile)
	for _, tc := range cases {
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
		b := runRuntime(helper, process, filepath.Join(dir, "destination"), input, tc.Kind, tc.CreationOrder, initial)
		writeRuntime(filepath.Join(dir, "native.json"), b)
		mustRuntime(json.Unmarshal(b, &tc.Result))
		validateRuntime(tc)
		observed.Records = append(observed.Records, tc)
	}
	if *capture {
		fmt.Printf("Captured %d native runtime observations (%s); not yet qualified\n", len(observed.Records), observed.Profile)
		return
	}
	var fixture runtimeFixture
	fixturePath := "testdata/appledouble/native/quarantine-runtime-" + observed.Profile + ".json"
	if *normalization {
		fixturePath = "testdata/appledouble/native/quarantine-normalization-" + observed.Profile + ".json.gz"
	}
	data := readRuntime(fixturePath)
	if *normalization {
		z, e := gzip.NewReader(bytes.NewReader(data))
		mustRuntime(e)
		data, e = io.ReadAll(z)
		mustRuntime(e)
		mustRuntime(z.Close())
	}
	mustRuntime(json.Unmarshal(data, &fixture))
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
		applicationComparisons = append(applicationComparisons, verifyApplicationPlan(got, observed.Profile))
	}
	qualified = true
	fmt.Printf("Quarantine runtime (%s): %d native observations and explicit Go application outcomes verified\n", observed.Profile, len(observed.Records))
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
	x, y := bytes.SplitN(a, []byte{';'}, 4), bytes.SplitN(b, []byte{';'}, 4)
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

func runtimeCases(extended bool, profile string) []runtimeCase {
	if extended {
		return normalizationCases(profile)
	}
	var cases []runtimeCase
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
						cases = append(cases, tc)

					}
				}
			}
		}
	}
	if len(cases) != 768 {
		panic("incomplete base runtime matrix")
	}
	return cases
}

func normalizationCases(profile string) []runtimeCase {
	var cases []runtimeCase
	add := func(name, process string, flags uint32, agent, id, baseline, kind string) {
		tc := runtimeCase{Name: name, Kind: kind, CreationOrder: "before", FileInput: []byte(fmt.Sprintf("q/%04x;12345678;%s;%s\x00", flags, agent, id))}
		if process != "" {
			tc.ProcessInput = []byte(process)
		}
		if baseline != "" {
			tc.Baseline = []byte(baseline)
		}
		cases = append(cases, tc)
	}
	proc := func(flags, agent string) string { return "q/" + flags + ";" + agent + ";ContextID" }
	// Every combination of the low-byte bits, both with and without bit 0x200.
	for _, p := range []string{"0001", "0002"} {
		for f := uint32(0); f < 256; f++ {
			for _, high := range []uint32{0, 0x200} {
				add(fmt.Sprintf("flags-%s-%04x", p, f|high), proc(p, "ContextAgent"), f|high, "FileAgent", "FileID", "", "file")
			}
		}
	}
	highFlags := []uint32{0x100, 0x400, 0x800, 0x1000, 0x1fff}
	if profile == "macos27" {
		highFlags = append(highFlags, 0x2000, 0x3fff)
	}
	for _, p := range []string{"0001", "0002"} {
		for _, f := range highFlags {
			for _, kind := range []string{"file", "directory"} {
				add(fmt.Sprintf("high-%s-%04x-%s", p, f, kind), proc(p, "ContextAgent"), f, "FileAgent", "FileID", "", kind)
			}
		}
	}
	// Independent existing-state combinations, including protected flag bits.
	for _, p := range []string{"inherited", "0001", "0002", "0004"} {
		for _, old := range []uint32{1, 2, 4, 6, 0x40, 0x60, 0x80, 0x81, 0x82, 0x84, 0x86, 0x200, 0x1fff} {
			for _, f := range []uint32{1, 4, 8, 0x20, 0x40, 0x60, 0x218, 0x1fff} {
				process := ""
				if p != "inherited" {
					process = proc(p, "ContextAgent")
				}
				add(fmt.Sprintf("existing-%s-%04x-%04x", p, old, f), process, f, "FileAgent", "FileID", fmt.Sprintf("%04x;23456789;ExistingAgent;ExistingID", old), "file")
			}
		}
	}
	for b := 1; b < 256; b++ {
		escaped := fmt.Sprintf("a\\x%02xb", b)
		add(fmt.Sprintf("agent-byte-%02x", b), proc("0001", escaped), 1, "FileAgent", "FileID", "", "file")
		add(fmt.Sprintf("id-byte-%02x", b), proc("0001", "ContextAgent"), 1, "FileAgent", escaped, "", "file")
	}
	for i, agent := range []string{"", "A B", `A\x20B`, `A\x3bB`, "é", strings.Repeat("A", 255), strings.Repeat(`\x20`, 100), strings.Repeat(`\xff`, 90)} {
		for _, p := range []string{"0001", "0002"} {
			for _, f := range []uint32{1, 0x40} {
				for _, kind := range []string{"file", "directory"} {
					add(fmt.Sprintf("agent-field-%d-%s-%04x-%s", i, p, f, kind), proc(p, agent), f, `File\x20Agent`, `File\x3bID`, "", kind)
				}
			}
		}
	}
	for _, n := range []int{0, 1, 15, 16, 31, 32, 35, 36, 62, 63, 64} {
		for _, escaped := range []bool{false, true} {
			for _, f := range []uint32{1, 0x40} {
				id := strings.Repeat("I", n)
				if escaped {
					id = strings.Repeat(`\x20`, n)
				}
				add(fmt.Sprintf("id-length-%d-%t-%04x", n, escaped, f), proc("0002", "ContextAgent"), f, "FileAgent", id, "", "file")
			}
		}
	}
	// Plain canonical size, not logical length, gates application before substitution.
	for n := 89; n <= 120; n++ {
		for _, f := range []uint32{1, 0x40} {
			for _, kind := range []string{"file", "directory"} {
				add(fmt.Sprintf("size-%d-%04x-%s", n+271, f, kind), proc("0002", "ContextAgent"), f, strings.Repeat("A", n), strings.Repeat(`\x20`, 64), "", kind)
			}
		}
	}
	for _, f := range []uint32{1, 0x40} {
		for _, p := range []string{"0001", "0002"} {
			add(fmt.Sprintf("max-fields-%s-%04x", p, f), proc(p, strings.Repeat("P", 255)), f, strings.Repeat("A", 255), strings.Repeat("I", 64), "", "file")
		}
	}
	want := 2210
	if profile == "macos27" {
		want = 2218
	}
	if len(cases) != want {
		panic("incomplete normalization matrix")
	}
	return cases
}

// Preserve binary agent bytes; encoding/json replaces invalid UTF-8 in strings.
type applicationContextEvidence struct {
	Profile         appledouble.QuarantineProfile
	ProcessFlags    uint32
	ProcessAgent    []byte
	ExistingPresent bool
	Existing        []byte
	Directory       bool
	Timestamp       uint32
}

type applicationComparison struct {
	Name                    string
	ContextKnown            bool
	Context                 applicationContextEvidence
	Plan                    *appledouble.QuarantineApplication
	ErrorKind               string
	NativeCode, NativeErrno int
	BinaryEqual, Preserved  bool
}

func verifyApplicationPlan(tc runtimeCase, profileName string) applicationComparison {
	profile := appledouble.QuarantineMacOS27
	if profileName == "macos26" {
		profile = appledouble.QuarantineMacOS26
	}
	r := tc.Result
	result := applicationComparison{Name: tc.Name, ContextKnown: r.Effective.InitCode == 0, NativeCode: r.FileApplyCode, NativeErrno: r.FileApplyErrno}
	ctx := appledouble.QuarantineApplicationContext{Profile: profile, Directory: tc.Kind == "directory", Timestamp: uint32(r.Start)}
	decode := func(s string) []byte { b, e := hex.DecodeString(s); mustRuntime(e); return b }
	processModel := func(s string) *appledouble.Quarantine {
		p := decode(s)
		if len(p) < 9 {
			panic("short canonical process snapshot")
		}
		b := append(bytes.Clone(p[:7]), []byte("00000000;")...)
		b = append(b, p[7:]...)
		q, e := appledouble.ParseQuarantineWithProfile(b, profile)
		mustRuntime(e)
		return q
	}
	if result.ContextKnown {
		captured := processModel(r.Effective.Serialized)
		ctx.Process = &appledouble.QuarantineProcess{Flags: captured.Flags, Agent: captured.Agent}
		// Controlled successful requests establish the raw agent. init_with_self
		// can lossy-decode backslashes; effective flags still come from that capture.
		if r.Requested != nil && r.ProcessApplyCode == 0 {
			ctx.Process.Agent = processModel(*r.Requested).Agent
		}
	}
	before, after := decode(r.Prepared.Bytes), decode(r.Applied.Bytes)
	if r.Prepared.Present {
		q, e := appledouble.ParseQuarantineXattrWithProfile(before, profile)
		mustRuntime(e)
		ctx.Existing = q
	}
	source, e := appledouble.ParseQuarantineWithProfile(tc.FileInput, profile)
	mustRuntime(e)
	result.Context = applicationContextEvidence{Profile: profile, ExistingPresent: r.Prepared.Present, Existing: before, Directory: ctx.Directory, Timestamp: ctx.Timestamp}
	if ctx.Process != nil {
		result.Context.ProcessFlags = ctx.Process.Flags
		result.Context.ProcessAgent = []byte(ctx.Process.Agent)
	}
	plan, e := source.PlanApplication(ctx)
	result.Plan = plan
	if !result.ContextKnown {
		if !errors.Is(e, appledouble.ErrQuarantineContext) || plan != nil {
			panic("unavailable context accepted: " + tc.Name)
		}
		result.ErrorKind = "unavailable-context"
		return result
	}
	if e != nil {
		switch {
		case errors.Is(e, appledouble.ErrQuarantineApplicationSize):
			result.ErrorKind = "application-size"
			if r.FileApplyCode != 34 {
				panic("native size outcome differs: " + tc.Name)
			}
		case errors.Is(e, appledouble.ErrQuarantineMissing):
			result.ErrorKind = "missing-attribute"
			if r.FileApplyCode != -1 || r.FileApplyErrno != 93 {
				panic("native missing attribute differs: " + tc.Name)
			}
		default:
			panic(fmt.Sprintf("unexpected Go application error %s: %v", tc.Name, e))
		}
		if plan != nil {
			panic("error returned a write: " + tc.Name)
		}
	} else {
		if r.FileApplyCode != 0 || plan == nil {
			panic("native application result differs: " + tc.Name)
		}
		if plan.Write {
			if !r.Applied.Present {
				panic("Go write/native absence: " + tc.Name)
			}
			actual := bytes.Clone(after)
			if len(plan.Value) >= 13 && string(plan.Value[5:13]) == fmt.Sprintf("%08x", ctx.Timestamp) {
				if len(actual) < 13 {
					panic("short native xattr: " + tc.Name)
				}
				stamp, err := strconv.ParseInt(string(actual[5:13]), 16, 64)
				mustRuntime(err)
				if stamp < r.Start || stamp > r.End {
					panic("native timestamp outside operation: " + tc.Name)
				}
				copy(actual[5:13], plan.Value[5:13])
			}
			result.BinaryEqual = bytes.Equal(plan.Value, actual)
			if !result.BinaryEqual {
				panic(fmt.Sprintf("Go application bytes differ %s: Go %q native %q", tc.Name, plan.Value, after))
			}
			return result
		}
		if plan.Value != nil {
			panic("preservation carries write bytes: " + tc.Name)
		}
	}
	result.Preserved = r.Prepared.Present == r.Applied.Present && bytes.Equal(before, after)
	if !result.Preserved {
		panic("native destination changed on preservation/error: " + tc.Name)
	}
	return result
}
