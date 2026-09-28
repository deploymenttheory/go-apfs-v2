//go:build ignore

// Independent macOS oracle only; the SDK never loads libquarantine.
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
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type command struct {
	Args            []string
	Output, Error   string
	ExpectedFailure bool
}
type comparison struct {
	Name                  string
	Accepted, BinaryEqual bool
	NativeAccepted        bool
	NativeSerialized      []byte
}
type application struct {
	Name, Kind          string
	Present, PolicyOnly bool
	Start, End          int64
	Restored            []byte
}

var commands []command
var comparisons []comparison
var applications []application
var flagBoundaries []comparison

type quarantineUpdateResult struct {
	Name                                                                string
	Updates                                                             []appledouble.QuarantineUpdate
	Prepared, Native, Selected                                          []byte
	PreparedPresent, Present, SelectedPresent, PolicyEqual, NativeEqual bool
	Start, End                                                          int64
}

var quarantineUpdates []quarantineUpdateResult
var quarantineXattrs []comparison
var processContexts []string
var producers []string
var nativeProfile = appledouble.QuarantineMacOS27
var profileName = "macos27"

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte     { b, e := os.ReadFile(p); must(e); return b }
func write(p string, b []byte) { must(os.WriteFile(p, b, 0600)) }
func observe(args ...string) ([]byte, error) {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	c := command{Args: args, Output: string(b)}
	if e != nil {
		c.Error = e.Error()
	}
	commands = append(commands, c)
	return b, e
}
func run(args ...string) []byte {
	b, e := observe(args...)
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func hash(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func main() {
	const root = "artifacts/appledouble-quarantine"
	must(os.MkdirAll(root, 0755))
	passed := false
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "commands": commands, "comparisons": comparisons, "applications": applications, "producers": producers, "profile": profileName, "flag_boundaries": flagBoundaries, "quarantine_updates": quarantineUpdates, "xattrs": quarantineXattrs, "process_contexts": processContexts}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), append(b, '\n'), 0644)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native quarantine oracle requires macOS")
	}
	run("git", "rev-parse", "HEAD")
	version := string(run("sw_vers"))
	switch {
	case strings.Contains(version, "ProductVersion:\t\t27."):
	case strings.Contains(version, "ProductVersion:\t\t26."):
		nativeProfile = appledouble.QuarantineMacOS26
		profileName = "macos26"
	default:
		panic("unqualified quarantine host version: " + version)
	}
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	tbd := read(filepath.Join(sdk, "usr/lib/system/libquarantine.tbd"))
	write(filepath.Join(root, "libquarantine.tbd"), tbd)
	for _, symbol := range []string{"__qtn_file_alloc", "__qtn_file_free", "__qtn_file_init_with_data", "__qtn_file_to_data", "__qtn_file_get_flags", "__qtn_error"} {
		if !bytes.Contains(tbd, []byte(symbol)) {
			panic("missing SDK export: " + symbol)
		}
	}
	var fixture struct {
		HelperSHA256 string
		Records      []struct {
			Name, InputSHA256 string
			Input, Serialized []byte
			Accepted          bool
		}
	}
	fixturePath := "testdata/appledouble/native/quarantine.json"
	if nativeProfile == appledouble.QuarantineMacOS26 {
		fixturePath = "testdata/appledouble/native/quarantine-macos26.json"
	}
	must(json.Unmarshal(read(fixturePath), &fixture))
	if len(fixture.Records) != 434 {
		panic("missing quarantine cases")
	}
	source := "testdata/appledouble/native/quarantine.c"
	if hash(read(source)) != fixture.HelperSHA256 {
		panic("quarantine helper hash")
	}
	helper := filepath.Join(root, "quarantine")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "quarantine-"+arch+".ast.json"), ast)
	}
	var differences []string
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, "serialization", tc.Name)
		must(os.MkdirAll(dir, 0700))
		input, output := filepath.Join(dir, "input"), filepath.Join(dir, "native")
		write(input, tc.Input)
		if hash(tc.Input) != tc.InputSHA256 {
			panic("input hash: " + tc.Name)
		}
		diagnostic, nativeErr := observe(helper, input, output)
		if nativeErr != nil {
			var exit *exec.ExitError
			if !errors.As(nativeErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(diagnostic), "parse refused: code=") {
				panic(fmt.Sprintf("unexpected native error %s: %v %s", tc.Name, nativeErr, diagnostic))
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		q, goErr := appledouble.ParseQuarantineWithProfile(tc.Input, nativeProfile)
		if (goErr == nil) != tc.Accepted {
			panic("Go fixture acceptance differs: " + tc.Name)
		}
		r := comparison{Name: tc.Name, Accepted: tc.Accepted, NativeAccepted: nativeErr == nil}
		if nativeErr == nil {
			r.NativeSerialized = read(output)
		}
		if r.NativeAccepted != tc.Accepted {
			differences = append(differences, tc.Name+": acceptance")
		}
		if tc.Accepted {
			b, e := q.MarshalBinaryWithProfile(nativeProfile)
			must(e)
			write(filepath.Join(dir, "go"), b)
			r.BinaryEqual = bytes.Equal(b, tc.Serialized) && bytes.Equal(b, r.NativeSerialized)
			if !r.BinaryEqual {
				differences = append(differences, tc.Name+": canonical bytes")
			}
		}
		comparisons = append(comparisons, r)
	}
	if len(differences) != 0 {
		panic(fmt.Sprintf("native quarantine differences: %v", differences))
	}
	verifyFlagBoundaries(root, helper)
	unpack := filepath.Join(root, "copyfile")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/probe.c", "-o", unpack)
	verifyProducers(root, unpack)
	verifyApplicationObservations(root, unpack)
	verifyQuarantineUpdates(root, unpack)
	verifyQuarantineXattrs(root, unpack)
	passed = true
	fmt.Printf("Quarantine (%s): %d serialization cases, %d flag boundaries, %d native producers, %d policy-only application observations passed\n", profileName, len(comparisons), len(flagBoundaries), len(producers), len(applications))
	fmt.Printf("Quarantine: %d ordered update comparisons, %d filesystem imports; contexts=%v\n", len(quarantineUpdates), len(quarantineXattrs), processContexts)
}
func verifyProducers(root, helper string) {
	extraFlag := "2000"
	if nativeProfile == appledouble.QuarantineMacOS26 {
		extraFlag = "1000"
	}
	for i, value := range []string{"0081;12345678;Probe;01234567-89AB-CDEF-0123-456789ABCDEF", "0000;00000000;;", "0001;12345678;A\\x20B;ID", "0081;12345678;é;ID", extraFlag + ";12345678;com.example;event", "0081;ffffffff;" + strings.Repeat("A", 255) + ";" + strings.Repeat("I", 64)} {
		dir, e := os.MkdirTemp(root, fmt.Sprintf("producer-%d-", i))
		must(e)
		src := filepath.Join(dir, "source")
		write(src, nil)
		write(filepath.Join(dir, "value"), []byte(value))
		run(helper, "set", src, appledouble.QuarantineName, filepath.Join(dir, "value"))
		run(helper, "get", src, appledouble.QuarantineName, filepath.Join(dir, "source-value"))
		run(helper, "pack", src, filepath.Join(dir, "native.ad"))
		f, e := appledouble.Decode(read(filepath.Join(dir, "native.ad")))
		must(e)
		payload := f.Xattrs()[appledouble.QuarantineName]
		q, e := appledouble.ParseQuarantineWithProfile(payload, nativeProfile)
		must(e)
		b, e := q.MarshalBinaryWithProfile(nativeProfile)
		must(e)
		if !bytes.Equal(b, payload) {
			panic("native producer serialization differs")
		}
		raw, e := f.Encode()
		must(e)
		write(filepath.Join(dir, "go.ad"), raw)
		if !bytes.Equal(raw, read(filepath.Join(dir, "native.ad"))) {
			panic("native producer sidecar differs")
		}
		write(filepath.Join(dir, "quarantine"), payload)
		producers = append(producers, filepath.Base(dir))
	}
}
func verifyApplicationObservations(root, helper string) {
	var fixture struct {
		CopyfileSourceSHA256, HelperSHA256 string
		PolicyOnly                         bool
		Records                            []struct {
			Name, Kind           string
			Input, Raw, Restored []byte
			Accepted, Present    bool
		}
	}
	fixturePath := "testdata/appledouble/native/quarantine-application.json"
	if nativeProfile == appledouble.QuarantineMacOS26 {
		fixturePath = "testdata/appledouble/native/quarantine-application-macos26.json"
	}
	must(json.Unmarshal(read(fixturePath), &fixture))
	if !fixture.PolicyOnly || len(fixture.Records) != 34 || hash(read("testdata/appledouble/native/probe.c")) != fixture.HelperSHA256 {
		panic("application fixture provenance")
	}
	client := http.Client{Timeout: 30 * time.Second}
	response, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c")
	must(e)
	source, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	must(e)
	must(response.Body.Close())
	if response.StatusCode != http.StatusOK || hash(source) != fixture.CopyfileSourceSHA256 {
		panic("copyfile source hash")
	}
	write(filepath.Join(root, "copyfile.c"), source)
	var differences []string
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, "application", tc.Kind+"-"+tc.Name)
		must(os.MkdirAll(dir, 0700))
		work, e := os.MkdirTemp(dir, "destination-")
		must(e)
		dst := filepath.Join(work, "item")
		if tc.Kind == "file" {
			write(dst, nil)
		} else if tc.Kind == "directory" {
			must(os.Mkdir(dst, 0700))
		} else {
			panic("fixture kind")
		}
		// Accepted envelopes are canonicalized in Go. Rejected envelopes stay raw
		// to observe native ignore behavior; all outcomes remain policy-only.
		q, e := appledouble.ParseQuarantineWithProfile(tc.Input, nativeProfile)
		payload := tc.Input
		if e == nil {
			payload, e = q.MarshalBinaryWithProfile(nativeProfile)
			must(e)
		}
		raw, e := appledouble.FromXattrs(map[string][]byte{appledouble.QuarantineName: payload}).Encode()
		must(e)
		write(filepath.Join(dir, "go.ad"), raw)
		write(filepath.Join(dir, "recorded.ad"), tc.Raw)
		start := time.Now().Unix()
		run(helper, "unpack", filepath.Join(dir, "go.ad"), dst)
		end := time.Now().Unix()
		out, getErr := observe(helper, "get", dst, appledouble.QuarantineName, filepath.Join(dir, "restored"))
		present := getErr == nil
		if getErr != nil {
			var exit *exec.ExitError
			if !errors.As(getErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(out), "get size: Attribute not found") {
				panic(fmt.Sprintf("unexpected quarantine read error: %v %s", getErr, out))
			}
			commands[len(commands)-1].ExpectedFailure = true
			_, e := os.Stat(dst)
			must(e)
		}
		if !tc.Accepted || present != tc.Present {
			differences = append(differences, tc.Kind+"-"+tc.Name+": presence")
		}
		r := application{Name: tc.Name, Kind: tc.Kind, Present: present, PolicyOnly: true, Start: start, End: end}
		if present {
			r.Restored = read(filepath.Join(dir, "restored"))
			got, want := strings.SplitN(string(r.Restored), ";", 4), strings.SplitN(string(tc.Restored), ";", 4)
			if len(got) != 4 || len(want) != 4 || got[0] != want[0] || got[2] != want[2] || got[3] != want[3] {
				differences = append(differences, tc.Kind+"-"+tc.Name+": fields")
			}
			timestamp, e := strconv.ParseUint(got[1], 16, 32)
			must(e)
			if nativeProfile == appledouble.QuarantineMacOS26 {
				if !bytes.Equal(r.Restored, tc.Restored) {
					differences = append(differences, tc.Kind+"-"+tc.Name+": preserved timestamp")
				}
			} else if tc.Kind == "directory" {
				if got[1] != "00000000" {
					differences = append(differences, tc.Kind+"-"+tc.Name+": directory timestamp")
				}
			} else if int64(timestamp) < start || int64(timestamp) > end {
				differences = append(differences, tc.Kind+"-"+tc.Name+": file timestamp")
			}
		}
		applications = append(applications, r)
	}
	if len(differences) != 0 {
		panic(fmt.Sprintf("native application differences: %v", differences))
	}
}

func verifyFlagBoundaries(root, helper string) {
	for _, flags := range []uint32{0x1ffe, 0x1fff, 0x2000, 0x2001, 0x3ffe, 0x3fff, 0x4000, 0x4001, 0x7fff, 0xffff} {
		name := fmt.Sprintf("%04x", flags)
		dir := filepath.Join(root, "flag-boundaries", name)
		must(os.MkdirAll(dir, 0700))
		input, output := filepath.Join(dir, "input"), filepath.Join(dir, "native")
		raw := []byte("q/" + name + ";12345678;Probe;ID\x00")
		write(input, raw)
		diagnostic, nativeErr := observe(helper, input, output)
		if nativeErr != nil {
			var exit *exec.ExitError
			if !errors.As(nativeErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(diagnostic), "parse refused: code=") {
				panic(fmt.Sprintf("flag boundary setup: %s %v %s", name, nativeErr, diagnostic))
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		q, err := appledouble.ParseQuarantineWithProfile(raw, nativeProfile)
		v := comparison{Name: name, Accepted: err == nil, NativeAccepted: nativeErr == nil}
		if v.Accepted != v.NativeAccepted {
			panic("flag boundary acceptance: " + name)
		}
		if v.Accepted {
			b, e := q.MarshalBinaryWithProfile(nativeProfile)
			must(e)
			write(filepath.Join(dir, "go"), b)
			v.NativeSerialized = read(output)
			v.BinaryEqual = bytes.Equal(b, v.NativeSerialized) && bytes.Equal(b, raw)
			if !v.BinaryEqual {
				panic("flag boundary serialization: " + name)
			}
		}
		flagBoundaries = append(flagBoundaries, v)
	}
}

// These comparisons prove record selection by applying the Go-selected values
// through the native library on a separately prepared destination. They do not
// claim that Go implements native destination normalization.
func verifyQuarantineUpdates(root, xattrHelper string) {
	var fixture struct {
		HelperSHA256, SourceSHA256, SerializationHelperSHA256, XattrHelperSHA256 string
		Records                                                                  []struct {
			Name, Kind, SourceMode       string
			Initial                      bool
			Raw, Source, Carrier, Before []byte
			Updates                      []struct {
				RecordIndex             int
				Invalid, SourceOverride bool
				Serialized              []byte
			}
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/quarantine-update.json"), &fixture))
	if len(fixture.Records) != 288 || hash(read("testdata/appledouble/native/quarantine-update.c")) != fixture.HelperSHA256 || hash(read(filepath.Join(root, "copyfile.c"))) != fixture.SourceSHA256 || hash(read("testdata/appledouble/native/quarantine.c")) != fixture.SerializationHelperSHA256 || hash(read("testdata/appledouble/native/probe.c")) != fixture.XattrHelperSHA256 {
		panic("quarantine update provenance")
	}
	helper := filepath.Join(root, "quarantine-update")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/quarantine-update.c", "-o", helper)
	quarantineUpdateAST(root)
	get := func(dst, output string) ([]byte, bool) {
		diagnostic, err := observe(xattrHelper, "get", dst, appledouble.QuarantineName, output)
		if err == nil {
			return read(output), true
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(diagnostic), "get size: Attribute not found") {
			panic(fmt.Sprintf("quarantine read %s: %v %s", dst, err, diagnostic))
		}
		commands[len(commands)-1].ExpectedFailure = true
		_, e := os.Stat(dst)
		must(e)
		return nil, false
	}
	for _, tc := range fixture.Records {
		name := fmt.Sprintf("%s-%t-%s-%s", tc.Kind, tc.Initial, tc.SourceMode, tc.Name)
		dir := filepath.Join(root, "updates", name)
		must(os.MkdirAll(dir, 0700))
		work, e := os.MkdirTemp(dir, "destinations-")
		must(e)
		dst, selected := filepath.Join(work, "native"), filepath.Join(work, "selected")
		for _, path := range []string{dst, selected} {
			switch tc.Kind {
			case "file":
				write(path, nil)
			case "directory":
				must(os.Mkdir(path, 0700))
			default:
				panic("update destination kind")
			}
			if tc.Initial {
				write(filepath.Join(dir, "baseline"), tc.Before)
				run(xattrHelper, "set", path, appledouble.QuarantineName, filepath.Join(dir, "baseline"))
			}
		}
		before, beforePresent := get(dst, filepath.Join(dir, "before"))
		selectedBefore, selectedBeforePresent := get(selected, filepath.Join(dir, "selected-before"))
		if beforePresent != tc.Initial || selectedBeforePresent != tc.Initial || !bytes.Equal(before, tc.Before) || !bytes.Equal(selectedBefore, tc.Before) {
			panic("update initial state: " + name)
		}
		side := filepath.Join(dir, "input.ad")
		write(side, tc.Raw)
		override := "-"
		var source *appledouble.Quarantine
		if len(tc.Source) != 0 {
			write(filepath.Join(dir, "source"), tc.Source)
			source, e = appledouble.ParseQuarantineWithProfile(tc.Source, nativeProfile)
			must(e)
		}
		switch tc.SourceMode {
		case "state":
			override = filepath.Join(dir, "source")
		case "carrier", "invalid-carrier":
			captured, err := appledouble.ParseQuarantineXattrWithProfile(tc.Carrier, nativeProfile)
			if tc.SourceMode == "carrier" {
				must(err)
				if source == nil || *captured != *source {
					panic("captured source differs")
				}
			} else if !errors.Is(err, appledouble.ErrQuarantine) {
				panic("malformed carrier import")
			}
			source = captured
			write(filepath.Join(dir, "carrier"), tc.Carrier)
			run(xattrHelper, "set", side, appledouble.QuarantineName, filepath.Join(dir, "carrier"))
			actual, present := get(side, filepath.Join(dir, "carrier-readback"))
			if !present || !bytes.Equal(actual, tc.Carrier) {
				panic("carrier setup: " + name)
			}
		case "none":
		default:
			panic("source mode")
		}
		f, e := appledouble.Decode(tc.Raw)
		must(e)
		updates, e := f.QuarantineUpdates(nativeProfile, source)
		must(e)
		if len(updates) != len(tc.Updates) {
			panic("update count: " + name)
		}
		applyArgs := []string{helper, "apply", selected}
		for i, want := range tc.Updates {
			got := updates[i]
			if got.RecordIndex != want.RecordIndex || got.Invalid != want.Invalid || got.SourceOverride != want.SourceOverride {
				panic("update decision: " + name)
			}
			if want.Invalid {
				if got.Quarantine != nil {
					panic("ignored update has value")
				}
				continue
			}
			b, e := got.Quarantine.MarshalBinaryWithProfile(nativeProfile)
			must(e)
			if !bytes.Equal(b, want.Serialized) {
				panic("update serialized value: " + name)
			}
			path := filepath.Join(dir, fmt.Sprintf("go-%d", i))
			write(path, b)
			applyArgs = append(applyArgs, path)
		}
		// Native copyfile prepares its destination before processing records. Use a
		// no-quarantine control container for the independent application destination.
		control, e := appledouble.FromXattrs(map[string][]byte{"org.example.before": []byte("before")}).Encode()
		must(e)
		write(filepath.Join(dir, "prepare.ad"), control)
		run(helper, "unpack", filepath.Join(dir, "prepare.ad"), selected, "-")
		prepared, preparedPresent := get(selected, filepath.Join(dir, "prepared"))
		start := time.Now().Unix()
		run(helper, "unpack", side, dst, override)
		run(applyArgs...)
		end := time.Now().Unix()
		actual, present := get(dst, filepath.Join(dir, "after"))
		chosen, chosenPresent := get(selected, filepath.Join(dir, "selected-after"))
		equal := present == chosenPresent
		if equal && present && !bytes.Equal(actual, chosen) {
			a, b := strings.SplitN(string(actual), ";", 4), strings.SplitN(string(chosen), ";", 4)
			equal = nativeProfile == appledouble.QuarantineMacOS27 && len(a) == 4 && len(b) == 4 && a[0] == b[0] && a[2] == b[2] && a[3] == b[3]
			if equal {
				for _, fields := range [][]string{a, b} {
					stamp, e := strconv.ParseInt(fields[1], 16, 64)
					must(e)
					if stamp < start || stamp > end {
						equal = false
					}
				}
			}
		}
		result := quarantineUpdateResult{Name: name, Updates: updates, Prepared: prepared, PreparedPresent: preparedPresent, Native: actual, Selected: chosen, Present: present, SelectedPresent: chosenPresent, Start: start, End: end, PolicyEqual: true, NativeEqual: equal}
		quarantineUpdates = append(quarantineUpdates, result)
		if !equal {
			panic(fmt.Sprintf("native selected application differs %s: native=%q selected=%q", name, actual, chosen))
		}
	}
}

func quarantineUpdateAST(root string) {
	source := read(filepath.Join(root, "copyfile.c"))
	start := bytes.Index(source, []byte("static int copyfile_unpack_quarantine("))
	end := bytes.Index(source, []byte("static int copyfile_unpack_acl("))
	entryStart := bytes.Index(source, []byte("typedef struct attr_entry\n"))
	entryEnd := bytes.Index(source, []byte("} __attribute__((aligned(2), packed)) attr_entry_t;"))
	licenseEnd := bytes.Index(source, []byte("#include"))
	if start < 0 || end <= start || entryStart < 0 || entryEnd <= entryStart || licenseEnd < 0 {
		panic("quarantine source extraction boundaries")
	}
	entryEnd += len("} __attribute__((aligned(2), packed)) attr_entry_t;")
	unit := append(bytes.Clone(source[:licenseEnd]), []byte(`
// Syntax-analysis shims only: this partial state is not an ABI layout claim.
#include <copyfile.h>
#include <sys/types.h>
#include <stddef.h>
#include <errno.h>
typedef void *qtn_file_t;
struct _copyfile_state { qtn_file_t qinfo; int dst_fd,err; copyfile_callback_t statuscb; char *xattr_name,*src,*dst; void *ctx; };
qtn_file_t qtn_file_alloc(void);
int qtn_file_init_with_data(qtn_file_t,const void *,size_t);
void qtn_file_free(qtn_file_t);
int qtn_file_apply_to_fd(qtn_file_t,int);
const char *qtn_error(int);
void copyfile_warn(const char *,...);
#define XATTR_QUARANTINE_NAME "com.apple.quarantine"
`)...)
	unit = append(unit, source[entryStart:entryEnd]...)
	unit = append(unit, '\n')
	unit = append(unit, source[start:end]...)
	path := filepath.Join(root, "copyfile_unpack_quarantine.c")
	write(path, unit)
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, item := range []struct{ name, path string }{{"quarantine-update", "testdata/appledouble/native/quarantine-update.c"}, {"copyfile_unpack_quarantine", path}} {
			ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", item.path)
			commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
			write(filepath.Join(root, item.name+"-"+arch+".ast.json"), ast)
		}
	}
}

func verifyQuarantineXattrs(root, xattrHelper string) {
	var fixture struct {
		HelperSHA256 string
		Records      []struct {
			Name, InputSHA256 string
			Input, Serialized []byte
			Accepted          bool
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/quarantine-xattr.json"), &fixture))
	source := "testdata/appledouble/native/quarantine-xattr.c"
	if len(fixture.Records) != 522 || hash(read(source)) != fixture.HelperSHA256 {
		panic("quarantine xattr provenance")
	}
	helper := filepath.Join(root, "quarantine-xattr")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "quarantine-xattr-"+arch+".ast.json"), ast)
	}
	var differences []string
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, "xattrs", tc.Name)
		must(os.MkdirAll(dir, 0700))
		work, e := os.MkdirTemp(dir, "capture-")
		must(e)
		input, output, target := filepath.Join(dir, "input"), filepath.Join(dir, "native"), filepath.Join(work, "source")
		if hash(tc.Input) != tc.InputSHA256 {
			panic("xattr input hash")
		}
		write(input, tc.Input)
		diagnostic, nativeErr := observe(helper, input, output, target)
		context, _, ok := strings.Cut(string(diagnostic), "\n")
		if !ok || !strings.HasPrefix(context, "process=q/") {
			panic("missing native process context")
		}
		seen := false
		for _, previous := range processContexts {
			if previous == context {
				seen = true
			}
		}
		if !seen {
			processContexts = append(processContexts, context)
		}
		if nativeErr != nil {
			var exit *exec.ExitError
			if !errors.As(nativeErr, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(diagnostic), "\nimport refused: code=") {
				panic(fmt.Sprintf("xattr setup failure %s: %v %s", tc.Name, nativeErr, diagnostic))
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		// Preserve an independent raw readback even for parser refusals.
		run(xattrHelper, "get", target, appledouble.QuarantineName, filepath.Join(dir, "stored"))
		if !bytes.Equal(read(filepath.Join(dir, "stored")), tc.Input) {
			panic("xattr setup bytes: " + tc.Name)
		}
		q, goErr := appledouble.ParseQuarantineXattrWithProfile(tc.Input, nativeProfile)
		expected := tc.Accepted
		// These two inputs use flags independently qualified as macOS-27-only by
		// the existing envelope corpora. All other stored-byte expectations agree.
		if nativeProfile == appledouble.QuarantineMacOS26 && (tc.Name == "0-flags-37" || tc.Name == "1-flagmore-0") {
			expected = false
		}
		v := comparison{Name: tc.Name, Accepted: expected, NativeAccepted: nativeErr == nil}
		if nativeErr == nil {
			v.NativeSerialized = read(output)
		}
		if (goErr == nil) != expected || v.NativeAccepted != expected {
			differences = append(differences, tc.Name+": acceptance")
		}
		if goErr == nil {
			b, e := q.MarshalBinaryWithProfile(nativeProfile)
			must(e)
			write(filepath.Join(dir, "go"), b)
			v.BinaryEqual = bytes.Equal(b, v.NativeSerialized) && bytes.Equal(b, tc.Serialized)
			if !v.BinaryEqual {
				differences = append(differences, tc.Name+": canonical bytes")
			}
		}
		quarantineXattrs = append(quarantineXattrs, v)
	}
	if len(differences) != 0 {
		panic(fmt.Sprintf("quarantine xattr differences: %v", differences))
	}
}
