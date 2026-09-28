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
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type rawProcessInfo struct {
	Code, Errno     int
	Flags           uint64
	Agent, Metadata string
	TrackingLength  uint64
}
type rawProcessEvidence struct{ Self, PID, InvalidPID rawProcessInfo }
type processSnapshot struct {
	InitCode, InitErrno int
	Raw                 *rawProcessEvidence `json:",omitempty"`
	Serialized          string              // Exact native bytes, hex encoded (including final NUL).
}
type xattrImport struct{ Code, Errno int }
type xattrSnapshot struct {
	Import          *xattrImport `json:",omitempty"`
	Present         bool
	Errno           int
	Bytes, Envelope string
}
type destinationSnapshot struct {
	Mode            uint32
	IdentityMatches bool
	LinkTarget      string
}
type targetSnapshot struct {
	Present       bool
	Errno         int
	Device, Inode uint64
	Mode          uint32
	Entries       int
	Content       string
	Quarantine    xattrSnapshot
}
type runtimeResult struct {
	DestinationBefore, DestinationAfter                                *destinationSnapshot `json:",omitempty"`
	TargetBefore, TargetAfter                                          *targetSnapshot      `json:",omitempty"`
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
	Host, Profile, HelperSHA256, SDKExportsSHA256                                                                string
	BaseHelperSHA256, CaptureHelperSHA256, ExistingHelperSHA256, DestinationHelperSHA256, KernelSDKExportsSHA256 string `json:",omitempty"`
	Records                                                                                                      []runtimeCase
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
	destinations := flag.Bool("destinations", false, "qualify regular, directory and symlink destination policy")
	existing := flag.Bool("existing", false, "qualify raw and malformed destination quarantine state")
	contexts := flag.Bool("contexts", false, "qualify raw process capture and confirmed absent state")
	processes := flag.Bool("processes", false, "qualify additional effective process flag combinations")
	normalization := flag.Bool("normalization", false, "qualify extended destination normalization inputs")
	fixtureOverride := flag.String("fixture", "", "explicit independently captured fixture for a qualified host preparation context")
	capture := flag.Bool("capture", false, "record independent observations without claiming qualification")
	flag.Parse()
	if (*processes && *normalization) || (*contexts && (*processes || *normalization)) || (*existing && (*contexts || *processes || *normalization)) || (*destinations && (*existing || *contexts || *processes || *normalization)) {
		panic("choose one extended matrix")
	}
	root := "artifacts/appledouble-quarantine-runtime"
	if *normalization {
		root += "-normalization"
	}
	if *processes {
		root += "-processes"
	}
	if *contexts {
		root += "-contexts"
	}
	if *existing {
		root += "-existing"
	}
	if *destinations {
		root += "-destinations"
	}
	mustRuntime(os.MkdirAll(root, 0755))
	qualified := false
	var observed runtimeFixture
	defer func() {
		failure := recover()
		saveRuntime(filepath.Join(root, "observed.json"), observed)
		report := map[string]any{"qualified": qualified, "capture_only": *capture, "commands": runtimeCommands, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "cases": len(observed.Records), "application_comparisons": applicationComparisons, "fixture_override": *fixtureOverride}
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
	if *contexts || *existing || *destinations {
		base := readRuntime(source)
		capture := readRuntime("testdata/appledouble/native/quarantine-process-capture.h")
		observed.BaseHelperSHA256 = hashRuntime(base)
		observed.CaptureHelperSHA256 = hashRuntime(capture)
		marker := []byte("static void snapshot(void) {")
		end := []byte("hex(data, length); putchar('}');")
		if bytes.Count(base, marker) != 1 || bytes.Count(base, end) != 1 {
			panic("native process capture injection points changed")
		}
		generated := bytes.Replace(base, marker, append(append(bytes.Clone(capture), '\n'), marker...), 1)
		generated = bytes.Replace(generated, end, []byte("hex(data, length); raw_process_snapshot(); putchar('}');"), 1)
		if *existing || *destinations {
			capture := readRuntime("testdata/appledouble/native/quarantine-existing-capture.h")
			observed.ExistingHelperSHA256 = hashRuntime(capture)
			start, end := bytes.Index(generated, []byte("static void xattr(int fd) {")), bytes.Index(generated, []byte("static int baseline_code, baseline_errno;"))
			if start < 0 || end <= start {
				panic("native existing capture injection points changed")
			}
			generated = append(append(append(bytes.Clone(generated[:start]), capture...), '\n'), generated[end:]...)
		}
		if *destinations {
			capture := readRuntime("testdata/appledouble/native/quarantine-destination-capture.h")
			observed.DestinationHelperSHA256 = hashRuntime(capture)
			start, end := bytes.Index(generated, []byte("static int baseline_code, baseline_errno;")), bytes.Index(generated, []byte("int main(int argc, char **argv) {"))
			if start < 0 || end <= start {
				panic("native destination injection points changed")
			}
			generated = append(append(append(bytes.Clone(generated[:start]), capture...), '\n'), generated[end:]...)
			replacements := [][2]string{
				{`int directory = !strcmp(argv[4], "directory"), before`, `int directory = destination_kind(argv[4]), before`},
				{`(!directory && strcmp(argv[4], "file"))`, `(directory < 0)`},
				{`size_t length; char *data = load(argv[3], &length);`, `printf(",\"DestinationBefore\":"); destination_snapshot(fd); printf(",\"TargetBefore\":"); target_snapshot();
    size_t length; char *data = load(argv[3], &length);`},
				{`printf(",\"End\":%lld}\n", (long long)time(NULL));`, `printf(",\"DestinationAfter\":"); destination_snapshot(fd); printf(",\"TargetAfter\":"); target_snapshot();
    printf(",\"End\":%lld}\n", (long long)time(NULL));`},
			}
			for _, replacement := range replacements {
				if bytes.Count(generated, []byte(replacement[0])) != 1 {
					panic("native destination marker changed")
				}
				generated = bytes.Replace(generated, []byte(replacement[0]), []byte(replacement[1]), 1)
			}
		}
		source = filepath.Join(root, "quarantine-runtime-context.c")
		writeRuntime(source, generated)
		kernel := readRuntime(filepath.Join(sdk, "usr/lib/system/libsystem_kernel.tbd"))
		if !bytes.Contains(kernel, []byte("___mac_syscall")) {
			panic("missing libSystem wrapper export")
		}
		observed.KernelSDKExportsSHA256 = hashRuntime(kernel)
		writeRuntime(filepath.Join(root, "libsystem_kernel.tbd"), kernel)
	}
	observed.HelperSHA256 = hashRuntime(readRuntime(source))

	helper := filepath.Join(root, "quarantine-runtime")
	runRuntime("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := runRuntime("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		runtimeCommands[len(runtimeCommands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		writeRuntime(filepath.Join(root, "quarantine-runtime-"+arch+".ast.json"), ast)
	}
	cases := runtimeCases(*normalization, observed.Profile)
	if *processes {
		cases = processCases(observed.Profile)
	}
	if *contexts {
		cases = contextCases(observed.Profile)
	}
	if *existing {
		cases = existingCases()
	}
	if *destinations {
		cases = destinationCases()
	}
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
	if *contexts || *existing || *destinations {
		absent, present := 0, 0
		for _, tc := range observed.Records {
			raw := tc.Result.Effective.Raw
			if raw == nil {
				panic("missing raw process evidence")
			}
			if raw.Self.Code == 0 {
				present++
			} else if raw.Self.Code == -1 && raw.Self.Errno == 93 {
				absent++
			}
		}
		if present == 0 || (observed.Profile == "macos26" && absent == 0) {
			panic("required process presence/absence observations missing")
		}
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
	if *processes {
		fixturePath = "testdata/appledouble/native/quarantine-processes-" + observed.Profile + ".json.gz"
	}
	if *contexts {
		fixturePath = "testdata/appledouble/native/quarantine-contexts-" + observed.Profile + ".json.gz"
	}
	if *existing {
		fixturePath = "testdata/appledouble/native/quarantine-existing-" + observed.Profile + ".json.gz"
	}
	if *destinations {
		fixturePath = "testdata/appledouble/native/quarantine-destinations-" + observed.Profile + ".json.gz"
	}
	if *fixtureOverride != "" {
		fixturePath = *fixtureOverride
	}
	data := readRuntime(fixturePath)
	if strings.HasSuffix(fixturePath, ".gz") {
		z, e := gzip.NewReader(bytes.NewReader(data))
		mustRuntime(e)
		data, e = io.ReadAll(z)
		mustRuntime(e)
		mustRuntime(z.Close())
	}
	mustRuntime(json.Unmarshal(data, &fixture))
	if fixture.Profile != observed.Profile || fixture.HelperSHA256 != observed.HelperSHA256 || fixture.BaseHelperSHA256 != observed.BaseHelperSHA256 || fixture.CaptureHelperSHA256 != observed.CaptureHelperSHA256 || fixture.ExistingHelperSHA256 != observed.ExistingHelperSHA256 || fixture.DestinationHelperSHA256 != observed.DestinationHelperSHA256 || len(fixture.Records) != len(observed.Records) {
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
	validateDestination(tc)
	if r.Start <= 0 || r.End < r.Start {
		panic("invalid operation interval: " + tc.Name)
	}
	if (tc.ProcessInput == nil) != (r.Requested == nil) {
		panic("missing requested process state: " + tc.Name)
	}
	for _, s := range []processSnapshot{r.Before, r.Effective} {
		validateRawProcess(s)
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
func validateRawProcess(s processSnapshot) {
	if s.Raw == nil {
		return
	}
	for _, info := range []rawProcessInfo{s.Raw.Self, s.Raw.PID, s.Raw.InvalidPID} {
		agent, e := hex.DecodeString(info.Agent)
		mustRuntime(e)
		metadata, e := hex.DecodeString(info.Metadata)
		mustRuntime(e)
		if len(agent) > 255 || len(metadata) > 64 || info.TrackingLength > 64 || info.Flags > 0xffffffff {
			panic("raw process capture bounds")
		}
		if info.Code != 0 && (info.Code != -1 || info.Errno == 0) {
			panic("raw process capture status")
		}
	}
	if s.Raw.InvalidPID.Code != -1 || s.Raw.InvalidPID.Errno == 93 {
		panic("invalid PID cannot confirm absent label")
	}
	self := s.Raw.Self
	if self.Code == 0 {
		if s.InitCode != 0 {
			panic("library and raw process capture disagree")
		}
		b, e := hex.DecodeString(s.Serialized)
		mustRuntime(e)
		flags, e := strconv.ParseUint(string(b[2:6]), 16, 32)
		mustRuntime(e)
		if flags != self.Flags {
			panic("raw and serialized process flags disagree")
		}
		if s.Raw.PID.Code == 0 && self != s.Raw.PID {
			panic("self and explicit PID capture disagree")
		}
	} else if self.Errno == 93 && (s.InitCode != -1 || s.InitErrno != 93) {
		panic("absence was not confirmed by both raw and library capture")
	}
}

func compareRuntime(name string, want, got runtimeResult) {
	if !reflect.DeepEqual(want.DestinationBefore, got.DestinationBefore) || !reflect.DeepEqual(want.DestinationAfter, got.DestinationAfter) {
		panic("destination proof differs: " + name)
	}
	// Inodes/devices differ between runs; identity and unchanged target evidence
	// are checked within each operation before comparing logical target state.
	target := func(s *targetSnapshot) *targetSnapshot {
		if s == nil {
			return nil
		}
		c := *s
		c.Device, c.Inode = 0, 0
		return &c
	}
	if !reflect.DeepEqual(target(want.TargetBefore), target(got.TargetBefore)) || !reflect.DeepEqual(target(want.TargetAfter), target(got.TargetAfter)) {
		panic("target proof differs: " + name)
	}
	if !reflect.DeepEqual(want.Before, got.Before) || !reflect.DeepEqual(want.Effective, got.Effective) || (want.Requested == nil) != (got.Requested == nil) {
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
	if !reflect.DeepEqual(want.Import, got.Import) {
		panic("xattr import differs: " + name)
	}
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
	if bytes.Equal(a, b) {
		return
	}
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

// contextCases records actual raw process state without deriving the agent from
// a successful request or guessing absence from a failed library snapshot.
func contextCases(profile string) []runtimeCase {
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
	for f := uint32(0); f < 256; f++ {
		for _, high := range []uint32{0, 0x200} {
			for _, kind := range []string{"file", "directory"} {
				for _, existing := range []bool{false, true} {
					baseline := ""
					if existing {
						baseline = "0006;23456789;ExistingAgent;ExistingID"
					}
					add(fmt.Sprintf("inherited-flags-%04x-%s-%t", f|high, kind, existing), "", f|high, "FileAgent", "FileID", baseline, kind)
				}
			}
		}
	}
	high := []uint32{0x100, 0x400, 0x800, 0x1000, 0x1fff}
	if profile == "macos27" {
		high = append(high, 0x2000, 0x3fff)
	}
	for _, f := range high {
		for _, kind := range []string{"file", "directory"} {
			add(fmt.Sprintf("inherited-high-%04x-%s", f, kind), "", f, "FileAgent", "FileID", "", kind)
		}
	}
	for b := 1; b < 256; b++ {
		escaped := fmt.Sprintf("a\\x%02xb", b)
		add(fmt.Sprintf("source-agent-byte-%02x", b), "", 1, escaped, "FileID", "", "file")
		add(fmt.Sprintf("source-id-byte-%02x", b), "", 1, "FileAgent", escaped, "", "file")
		for _, p := range []string{"0001", "0002"} {
			add(fmt.Sprintf("captured-agent-byte-%s-%02x", p, b), "q/"+p+";"+escaped+";ContextID", 1, "FileAgent", "FileID", "", "file")
		}
	}
	for _, p := range []string{"0000", "0001", "0002", "0003", "0004", "001f", "0200", "0201"} {
		for _, f := range []uint32{1, 0x40, 0x60, 0x218} {
			for _, kind := range []string{"file", "directory"} {
				for _, existing := range []bool{false, true} {
					baseline := ""
					if existing {
						baseline = "0081;23456789;ExistingAgent;ExistingID"
					}
					add(fmt.Sprintf("captured-%s-%04x-%s-%t", p, f, kind, existing), "q/"+p+";ContextAgent;ContextID", f, "FileAgent", "FileID", baseline, kind)
				}
			}
		}
	}
	for n := 89; n <= 120; n++ {
		for _, kind := range []string{"file", "directory"} {
			add(fmt.Sprintf("inherited-size-%d-%s", n+271, kind), "", 1, strings.Repeat("A", n), strings.Repeat(`\x20`, 64), "", kind)
		}
	}
	for _, n := range []int{0, 15, 16, 35, 36, 62, 63, 64} {
		for _, escaped := range []bool{false, true} {
			for _, kind := range []string{"file", "directory"} {
				id := strings.Repeat("I", n)
				if escaped {
					id = strings.Repeat(`\x20`, n)
				}
				add(fmt.Sprintf("inherited-id-%d-%t-%s", n, escaped, kind), "", 1, "FileAgent", id, "", kind)
			}
		}
	}
	for _, n := range []int{0, 254, 255} {
		for _, kind := range []string{"file", "directory"} {
			add(fmt.Sprintf("inherited-agent-%d-%s", n, kind), "", 1, strings.Repeat("A", n), "FileID", "", kind)
		}
	}
	for i, agent := range []string{"", strings.Repeat("P", 255), strings.Repeat(`\x5c`, 255), strings.Repeat(`\xff`, 255)} {
		for _, p := range []string{"0001", "0002"} {
			for _, f := range []uint32{1, 0x40} {
				add(fmt.Sprintf("captured-agent-limit-%d-%s-%04x", i, p, f), "q/"+p+";"+agent+";ContextID", f, "FileAgent", "FileID", "", "file")
			}
		}
	}
	want := 3324
	if profile == "macos27" {
		want = 3328

	}
	if len(cases) != want {
		panic(fmt.Sprintf("incomplete context matrix: %d", len(cases)))
	}
	return cases
}

// processCases separates requested process changes from effective captured state.
// Every low-five-bit combination is exercised; denied high-bit requests remain
// observations of the inherited state, never evidence for the requested flags.
func processCases(profile string) []runtimeCase {
	var cases []runtimeCase
	add := func(name string, p, f uint32, agent, kind, order, baseline string) {
		tc := runtimeCase{Name: name, Kind: kind, CreationOrder: order,
			ProcessInput: []byte(fmt.Sprintf("q/%04x;%s;ContextID", p, agent)),
			FileInput:    []byte(fmt.Sprintf("q/%04x;12345678;FileAgent;FileID\x00", f))}
		if baseline != "" {
			tc.Baseline = []byte(baseline)
		}
		cases = append(cases, tc)
	}
	for p := uint32(0); p < 32; p++ {
		for _, f := range []uint32{0, 1, 2, 3, 4, 6, 8, 0x10, 0x18, 0x20, 0x40, 0x60, 0x80, 0x200, 0x218, 0x1fff} {
			for _, kind := range []string{"file", "directory"} {
				for _, order := range []string{"before", "after"} {
					for _, existing := range []bool{false, true} {
						baseline := ""
						if existing {
							baseline = "0006;23456789;ExistingAgent;ExistingID"
						}
						add(fmt.Sprintf("process-%04x-%04x-%s-%s-%t", p, f, kind, order, existing), p, f, "ContextAgent", kind, order, baseline)
					}
				}
			}
		}
	}
	high := []uint32{0x20, 0x40, 0x80, 0x100, 0x200, 0x201, 0x21f, 0x400, 0x800, 0x1000, 0x1fff}
	if profile == "macos27" {
		high = append(high, 0x2000, 0x3fff)
	}
	for _, p := range high {
		for _, f := range []uint32{1, 0x218} {
			for _, kind := range []string{"file", "directory"} {
				add(fmt.Sprintf("request-%04x-%04x-%s", p, f, kind), p, f, "ContextAgent", kind, "before", "")
			}
		}
	}
	for p := uint32(1); p < 32; p++ {
		for i, agent := range []string{"", `A\x3bB\x5cC`, `\xff`, strings.Repeat("A", 255)} {
			for _, f := range []uint32{1, 0x40} {
				add(fmt.Sprintf("process-agent-%04x-%d-%04x", p, i, f), p, f, agent, "file", "before", "")
			}
		}
	}
	want := 4388
	if profile == "macos27" {
		want = 4396
	}
	if len(cases) != want {
		panic("incomplete process context matrix")
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
	Kind              appledouble.QuarantineDestinationKind
	Profile           appledouble.QuarantineProfile
	ProcessFlags      uint32
	ProcessAbsent     bool
	RawProcessCapture bool
	ProcessAgent      []byte
	ExistingPresent   bool
	Existing          []byte
	Directory         bool
	Timestamp         uint32
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
	if r.DestinationBefore != nil {
		ctx.Directory = false
		ctx.Kind = applicationDestinationKind(tc.Kind)
	}
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
	if result.ContextKnown && r.Effective.Raw == nil {
		captured := processModel(r.Effective.Serialized)
		ctx.Process = &appledouble.QuarantineProcess{Flags: captured.Flags, Agent: captured.Agent}
		// Controlled successful requests establish the raw agent. init_with_self
		// can lossy-decode backslashes; effective flags still come from that capture.
		if r.Requested != nil && r.ProcessApplyCode == 0 {
			ctx.Process.Agent = processModel(*r.Requested).Agent
		}
	}
	if raw := r.Effective.Raw; raw != nil {
		// No requested process data participates in this path. A successful raw
		// query supplies bytes directly, avoiding the library's second unescape.
		ctx.Process = nil
		result.ContextKnown = false
		if raw.Self.Code == 0 {
			ctx.Process = &appledouble.QuarantineProcess{Flags: uint32(raw.Self.Flags), Agent: string(decode(raw.Self.Agent))}
			result.ContextKnown = true
		} else if raw.Self.Code == -1 && raw.Self.Errno == 93 && r.Effective.InitCode == -1 && r.Effective.InitErrno == 93 {
			ctx.Process = &appledouble.QuarantineProcess{Absent: true}
			result.ContextKnown = profile == appledouble.QuarantineMacOS26
		}
	}
	before, after := decode(r.Prepared.Bytes), decode(r.Applied.Bytes)
	if r.Prepared.Import != nil {
		for _, snapshot := range []xattrSnapshot{r.Prepared, r.Applied} {
			if !snapshot.Present {
				continue
			}
			q, err := appledouble.ParseQuarantineXattrWithProfile(decode(snapshot.Bytes), profile)
			if (err == nil) != (snapshot.Import.Code == 0) {
				panic("native/Go existing import differs: " + tc.Name)
			}
			if err == nil {
				envelope, err := q.MarshalBinaryWithProfile(profile)
				mustRuntime(err)
				if !bytes.Equal(envelope, decode(snapshot.Envelope)) {
					panic("native/Go existing envelope differs: " + tc.Name)
				}
			} else if snapshot.Envelope != "" {
				panic("failed import has envelope: " + tc.Name)
			}
		}
		if r.Prepared.Present {
			ctx.ExistingXattr = append([]byte{}, before...)
		}
	} else if r.Prepared.Present {
		q, e := appledouble.ParseQuarantineXattrWithProfile(before, profile)
		mustRuntime(e)
		ctx.Existing = q
	}
	source, e := appledouble.ParseQuarantineWithProfile(tc.FileInput, profile)
	mustRuntime(e)
	result.Context = applicationContextEvidence{Profile: profile, ExistingPresent: r.Prepared.Present, Existing: before, Directory: ctx.Directory, Kind: ctx.Kind, Timestamp: ctx.Timestamp}
	if ctx.Process != nil {
		result.Context.ProcessAbsent = ctx.Process.Absent
		result.Context.RawProcessCapture = r.Effective.Raw != nil
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
		case errors.Is(e, appledouble.ErrQuarantineExisting):
			result.ErrorKind = "invalid-existing-header"
			if r.FileApplyCode != 22 || r.FileApplyErrno != 22 {
				panic("native existing-header outcome differs: " + tc.Name)
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

// Existing values intentionally include data rejected by full library import.
// All baseline writes happen before the helper changes its own process label.
func existingCases() []runtimeCase {
	var cases []runtimeCase
	add := func(name string, process []byte, flags uint32, baseline []byte, kind string) {
		cases = append(cases, runtimeCase{Name: name, Kind: kind, CreationOrder: "before", ProcessInput: process, Baseline: baseline, FileInput: []byte(fmt.Sprintf("q/%04x;12345678;Source;Identifier\x00", flags))})
	}
	values := [][]byte{nil, {}, []byte("garbage"), []byte("0006"), []byte("6"), []byte("0006;"), []byte("0006;invalid"), []byte("0006;0"), []byte("0006;0;"), []byte("0006;0;Agent"), []byte("0006;0;Agent;ID"), []byte("0006garbage"), []byte("00060000;0;A;B"), []byte("ffff;0;A;B"), []byte("2006;0;A;B"), []byte("0000;0;A;B"), []byte("0002;0;A;B"), []byte("0004;0;A;B"), []byte("0006\x00;0;A;B"), []byte("0006;0\x00junk"), []byte("0006;0;A\\x00B;C"), []byte("0006;0;A;B;C"), []byte("0006;0;\xff;\xfe"), []byte("q/0006;0;A;B")}
	for _, header := range []string{" 006", "\t006", "\n006", "\r006", "\v006", "\f006", "+006", "-006", "0x06", "0X06", "0x6", "06", "006", "6", "0006 ", "0x", "-0x", "+", "-", "", "ffff", "FFFF"} {
		values = append(values, []byte(header+";0;A;B"))
	}
	for _, stamp := range []string{"", "z", "+", "-", "0x", "-0x", "+1", "-1", " 0", "\t0", "\x000", "123456789", "ffffffff", "00000000junk"} {
		values = append(values, []byte("0006;"+stamp+";A;B"))
	}
	for _, length := range []int{255, 256, 381, 382, 383, 384, 511, 512, 1023, 1024, 4096} {
		for _, prefix := range []string{"0006;0;", "garbage", "0006;0\x00"} {
			values = append(values, []byte(prefix+strings.Repeat("X", length-len(prefix))))
		}
	}
	for _, n := range []int{380, 381, 382, 383, 500, 1020, 2000} {
		values = append(values, []byte(strings.Repeat(" ", n)+"6;0"), []byte("0006;"+strings.Repeat(" ", n)+"0"))
	}
	processes := [][]byte{nil, []byte("q/0001;Process;"), []byte("q/0002;Process;"), []byte("q/0004;Process;")}
	for vi, baseline := range values {
		for pi, process := range processes {
			for _, flags := range []uint32{1, 2, 4, 0x40, 0x60, 0x218} {
				for _, kind := range []string{"file", "directory"} {
					add(fmt.Sprintf("existing-%03d-p%d-%04x-%s", vi, pi, flags, kind), process, flags, baseline, kind)
				}
			}
		}
	}
	for b := 0; b <= 255; b++ {
		for i, baseline := range [][]byte{append([]byte{byte(b)}, []byte("006;0;A;B")...), append(append([]byte("0006;"), byte(b)), []byte("0;A;B")...)} {
			for _, flags := range []uint32{1, 0x40, 0x218} {
				add(fmt.Sprintf("existing-byte-%02x-field%d-%04x", b, i, flags), processes[2], flags, baseline, "file")
			}
		}
	}
	return cases
}

func applicationDestinationKind(kind string) appledouble.QuarantineDestinationKind {
	switch kind {
	case "file":
		return appledouble.QuarantineRegularFile
	case "directory":
		return appledouble.QuarantineDirectory
	case "symlink-file", "symlink-directory", "symlink-dangling":
		return appledouble.QuarantineSymlink
	default:
		panic("unrecognized destination kind")
	}
}
func validateDestination(tc runtimeCase) {
	r := tc.Result
	if r.DestinationBefore == nil {
		return
	}
	mode := uint32(0100000)
	switch applicationDestinationKind(tc.Kind) {
	case appledouble.QuarantineDirectory:
		mode = 0040000
	case appledouble.QuarantineSymlink:
		mode = 0120000
	}
	if r.DestinationBefore.Mode != mode || !r.DestinationBefore.IdentityMatches || !reflect.DeepEqual(r.DestinationBefore, r.DestinationAfter) {
		panic("destination vnode proof: " + tc.Name)
	}
	if !reflect.DeepEqual(r.TargetBefore, r.TargetAfter) {
		panic("target changed: " + tc.Name)
	}
	if mode != 0120000 {
		if r.TargetBefore != nil || r.DestinationBefore.LinkTarget != "" {
			panic("unexpected target proof: " + tc.Name)
		}
		return
	}
	if r.DestinationBefore.LinkTarget != hex.EncodeToString([]byte("target")) || r.TargetBefore == nil {
		panic("missing link target proof: " + tc.Name)
	}
	target := r.TargetBefore
	if tc.Kind == "symlink-dangling" {
		if target.Present || target.Errno != 2 {
			panic("dangling target changed: " + tc.Name)
		}
		return
	}
	targetMode, entries := uint32(0100000), 0
	if tc.Kind == "symlink-directory" {
		targetMode, entries = 0040000, 1
	}
	if !target.Present || target.Errno != 0 || target.Inode == 0 || target.Mode != targetMode || target.Entries != entries || target.Content != hex.EncodeToString([]byte("target-content\n")) || !target.Quarantine.Present || target.Quarantine.Bytes != hex.EncodeToString([]byte("0081;23456789;TargetAgent;TargetID")) || target.Quarantine.Import == nil || target.Quarantine.Import.Code != 0 {
		panic("target sentinel proof: " + tc.Name)
	}
}

func destinationCases() []runtimeCase {
	var cases []runtimeCase
	kinds := []string{"file", "directory", "symlink-file", "symlink-directory", "symlink-dangling"}
	add := func(name string, process []byte, flags uint32, agent, id string, baseline []byte, kind string) {
		cases = append(cases, runtimeCase{Name: name, Kind: kind, CreationOrder: "before", ProcessInput: process, Baseline: baseline, FileInput: []byte(fmt.Sprintf("q/%04x;12345678;%s;%s\x00", flags, agent, id))})
	}
	processes := [][]byte{nil, []byte("q/0001;Process;"), []byte("q/0002;Process;"), []byte("q/0004;Process;")}
	for pi, p := range processes {
		for bi, baseline := range [][]byte{nil, {}, []byte("garbage"), []byte("0006;0;Existing;ID"), []byte("ffff;0"), []byte("0000;0;Existing;ID")} {
			for _, flags := range []uint32{0, 1, 2, 4, 0x40, 0x60, 0x218, 0x1fff} {
				for _, kind := range kinds {
					add(fmt.Sprintf("destination-p%d-b%d-%04x-%s", pi, bi, flags, kind), p, flags, "Source", "ID", baseline, kind)
				}
			}
		}
	}
	for p := 1; p <= 31; p++ {
		for _, flags := range []uint32{1, 0x40, 0x218} {
			for bi, baseline := range [][]byte{nil, []byte("0006;0;Existing;ID")} {
				for _, kind := range kinds[2:] {
					add(fmt.Sprintf("destination-flags-%02x-%04x-b%d-%s", p, flags, bi, kind), []byte(fmt.Sprintf("q/%04x;Process;", p)), flags, "Source", "ID", baseline, kind)
				}
			}
		}
	}
	for b := 1; b <= 255; b++ {
		for _, kind := range kinds[2:] {
			add(fmt.Sprintf("destination-byte-%02x-%s", b, kind), processes[2], 1, fmt.Sprintf("\\x%02x", b), fmt.Sprintf("\\x%02x", b), nil, kind)
		}
	}
	for n := 89; n <= 120; n++ {
		for _, flags := range []uint32{1, 0x40} {
			for _, kind := range kinds[2:] {
				add(fmt.Sprintf("destination-size-%d-%04x-%s", n+271, flags, kind), processes[2], flags, strings.Repeat("A", n), strings.Repeat(`\x20`, 64), nil, kind)
			}
		}
	}
	for _, n := range []int{0, 62, 63, 64} {
		for _, flags := range []uint32{1, 0x40} {
			for _, kind := range kinds[2:] {
				add(fmt.Sprintf("destination-id-%d-%04x-%s", n, flags, kind), processes[2], flags, "Source", strings.Repeat("I", n), nil, kind)
			}
		}
	}
	return cases
}
