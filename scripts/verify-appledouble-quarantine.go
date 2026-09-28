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
var producers []string

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
		report := map[string]any{"passed": passed, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "commands": commands, "comparisons": comparisons, "applications": applications, "producers": producers}
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
	run("sw_vers")
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
	must(json.Unmarshal(read("testdata/appledouble/native/quarantine.json"), &fixture))
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
		q, goErr := appledouble.ParseQuarantine(tc.Input)
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
			b, e := q.MarshalBinary()
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
	unpack := filepath.Join(root, "copyfile")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/probe.c", "-o", unpack)
	verifyProducers(root, unpack)
	verifyApplicationObservations(root, unpack)
	passed = true
	fmt.Printf("Quarantine: %d serialization cases, %d native producers, %d policy-only application observations passed\n", len(comparisons), len(producers), len(applications))
}
func verifyProducers(root, helper string) {
	for i, value := range []string{"0081;12345678;Probe;01234567-89AB-CDEF-0123-456789ABCDEF", "0000;00000000;;", "0001;12345678;A\\x20B;ID", "0081;12345678;é;ID", "2000;12345678;com.example;event", "0081;ffffffff;" + strings.Repeat("A", 255) + ";" + strings.Repeat("I", 64)} {
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
		q, e := appledouble.ParseQuarantine(payload)
		must(e)
		b, e := q.MarshalBinary()
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
	must(json.Unmarshal(read("testdata/appledouble/native/quarantine-application.json"), &fixture))
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
		// Canonical bytes come from Go; application outcomes remain native observations.
		q, e := appledouble.ParseQuarantine(tc.Input)
		must(e)
		payload, e := q.MarshalBinary()
		must(e)
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
			if tc.Present || !errors.As(getErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(out), "get size: Attribute not found") {
				panic(fmt.Sprintf("unexpected quarantine read error: %v %s", getErr, out))
			}
			commands[len(commands)-1].ExpectedFailure = true
			_, e := os.Stat(dst)
			must(e)
		}
		if !tc.Accepted || present != tc.Present {
			panic("quarantine application presence differs")
		}
		r := application{Name: tc.Name, Kind: tc.Kind, Present: present, PolicyOnly: true, Start: start, End: end}
		if present {
			r.Restored = read(filepath.Join(dir, "restored"))
			got, want := strings.SplitN(string(r.Restored), ";", 4), strings.SplitN(string(tc.Restored), ";", 4)
			if len(got) != 4 || len(want) != 4 || got[0] != want[0] || got[2] != want[2] || got[3] != want[3] {
				panic("quarantine context fields differ")
			}
			timestamp, e := strconv.ParseUint(got[1], 16, 32)
			must(e)
			if tc.Kind == "directory" {
				if got[1] != "00000000" {
					panic("directory timestamp differs")
				}
			} else if int64(timestamp) < start || int64(timestamp) > end {
				panic("file timestamp outside observed interval")
			}
		}
		applications = append(applications, r)
	}
}
