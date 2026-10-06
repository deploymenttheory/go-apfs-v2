//go:build ignore

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type rawNativeResult struct {
	Errno int
	Inode uint64
	Size  int64
	Read  int64
}
type rawNativeRecord struct {
	Type         string
	Index        int
	ID           string
	Count        int
	Error        int
	Stopped      bool
	Interrupted  bool
	CleanupErrno int `json:"cleanup_errno"`
	Results      []rawNativeResult
}

func validateRawCase(record rawNativeRecord, expected string, index int) error {
	if record.Type != "case" || record.Index != index || record.ID != expected || record.Interrupted || len(record.Results) != 2 {
		return errors.New("raw case identity/results changed")
	}
	for _, result := range record.Results {
		if result.Errno < 0 || result.Size < 0 || (result.Errno == 0 && (result.Inode == 0 || result.Read < 0)) || (result.Errno != 0 && (result.Inode != 0 || result.Size != 0 || result.Read != -1)) {
			return errors.New("invalid native result shape")
		}
	}
	return nil
}
func waitRawExit(ctx context.Context, pid int) (int, error) {
	for {
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
		if err != nil {
			return 0, err
		}
		if got == pid {
			if !status.Exited() {
				return 0, fmt.Errorf("native process did not exit normally: %v", status)
			}
			return status.ExitStatus(), nil
		}
		if got != 0 {
			return 0, fmt.Errorf("wrong child PID %d", got)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func rawSourceNames() []string {
	names := []string{"testdata/appledouble/native/name-raw-readback.c", "scripts/verify-name-native_raw_test.go", "scripts/verify-name-native_syscall_test.go", ".github/workflows/name-raw-diagnostic.yml", "raw-arm64.ast.json", "raw-x86_64.ast.json", "syscall-probe", "apfs-driver.plist", "sdk-settings.plist", "uname.txt"}
	for _, header := range rawHeaders() {
		names = append(names, "raw-SDK/"+header)
	}
	return names
}
func rawHeaders() []string {
	return append(append([]string(nil), syscallTraceHeaders...), "sys/mount.h", "sys/attr.h", "sys/utsname.h")
}
func validateRawSources(sources map[string]string) error {
	names := rawSourceNames()
	if len(sources) != len(names) {
		return errors.New("raw source inventory changed")
	}
	for _, name := range names {
		b, e := hex.DecodeString(sources[name])
		if e != nil || len(b) != 32 {
			return fmt.Errorf("missing/invalid raw source %s", name)
		}
	}
	return nil
}
func TestPrepareNativeRawTrace(t *testing.T) {
	c, out, _, _, raw := preparedSingleNameInput(t)
	if c.CaseID != "" || c.Cases != 3753 || c.Observations != 7506 {
		t.Fatal("raw trace requires complete3753-case source image")
	}
	if e := os.Mkdir(filepath.Join(out, "syscall-control"), 0700); e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	plan := syscallTracePlan{Schema: 1, DiagnosticOnly: true, Nonce: hex.EncodeToString(nonce), Checkpoint: sum(raw), Sources: map[string]string{}}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "raw-build-commands")}
	sdkRaw, e := os.ReadFile(filepath.Join(out, "sdk.txt"))
	if e != nil {
		t.Fatal(e)
	}
	sdk := strings.TrimSpace(string(sdkRaw))
	for name, path := range map[string]string{"apfs-driver.plist": "/System/Library/Extensions/apfs.kext/Contents/Info.plist", "sdk-settings.plist": filepath.Join(sdk, "SDKSettings.plist")} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	uname, e := commands.run(ctx, "uname", "-a")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, "uname.txt"), uname, 0600); e != nil {
		t.Fatal(e)
	}
	source := "testdata/appledouble/native/name-raw-readback.c"
	if _, e = commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-isysroot", sdk, source, "-o", filepath.Join(out, "syscall-probe")); e != nil {
		t.Fatal(e)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", sdk, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, "raw-"+arch+".ast.json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, header := range rawHeaders() {
		b, e := os.ReadFile(filepath.Join(sdk, "usr/include", header))
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(out, "raw-SDK", header)
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range rawSourceNames() {
		path := filepath.Join(out, name)
		if strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, ".github/") {
			path = name
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		plan.Sources[name] = sum(b)
	}
	if e = traceWriteJSON(filepath.Join(out, "syscall-plan.json"), plan); e != nil {
		t.Fatal(e)
	}
}
func loadRawTrace(t *testing.T) (singleNameCheckpoint, string, string, syscallTracePlan) {
	t.Helper()
	c, out, dir, _, raw := preparedSingleNameInput(t)
	if c.CaseID != "" || c.Cases != 3753 || c.Observations != 7506 {
		t.Fatal("full raw source inventory required")
	}
	b, e := os.ReadFile(filepath.Join(out, "syscall-plan.json"))
	if e != nil {
		t.Fatal(e)
	}
	var plan syscallTracePlan
	if e = json.Unmarshal(b, &plan); e != nil {
		t.Fatal(e)
	}
	if plan.Schema != 1 || !plan.DiagnosticOnly || plan.Checkpoint != sum(raw) || len(plan.Nonce) != 32 {
		t.Fatal("raw plan identity changed")
	}
	if e = validateRawSources(plan.Sources); e != nil {
		t.Fatal(e)
	}
	for name, want := range plan.Sources {
		path := filepath.Join(out, name)
		if strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, ".github/") {
			path = name
		}
		b, e := os.ReadFile(path)
		if e != nil || sum(b) != want {
			t.Fatal("raw source changed", name, e)
		}
	}
	return c, out, dir, plan
}
func TestNativeRawTraceCapture(t *testing.T) {
	c, out, dir, plan := loadRawTrace(t)
	mount := boundaryMount(out, c)
	boundaryAttached(t, out, mount)
	control := filepath.Join(out, "syscall-control")
	stdout, e := os.Create(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	stderr, e := os.Create(filepath.Join(out, "raw-native.stderr"))
	if e != nil {
		t.Fatal(errors.Join(e, stdout.Close()))
	}
	cmd := exec.Command(filepath.Join(out, "syscall-probe"), mount, filepath.Join(dir, "cases.tsv"), control, plan.Nonce)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	startErr := cmd.Start()
	e = errors.Join(startErr, stdout.Close(), stderr.Close())
	if e != nil {
		if startErr == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Process.Release()
		}
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	if e = traceWriteJSON(filepath.Join(out, "syscall-process.json"), map[string]any{"pid": pid, "nonce": plan.Nonce, "argv": cmd.Args}); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Process.Release()
		t.Fatal(e)
	}
	if e = cmd.Process.Release(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	var ready syscallTraceReady
	if e = waitTraceJSON(ctx, filepath.Join(control, "ready.json"), &ready); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceReady(ready, plan); e != nil || ready.PID != pid {
		t.Fatal("raw actor identity", e)
	}
	f, e := os.Open(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	caseBytes, e := os.ReadFile(filepath.Join(dir, "cases.tsv"))
	if e != nil {
		t.Fatal(e)
	}
	expectedRows := strings.Split(strings.TrimSuffix(string(caseBytes), "\n"), "\n")
	if len(expectedRows) != 3753 {
		t.Fatal("source case count changed")
	}
	reader := bufio.NewReader(f)
	if e = os.WriteFile(filepath.Join(control, "start"), []byte(plan.Nonce), 0600); e != nil {
		t.Fatal(e)
	}
	var pending []byte
	count := 0
	volumes := 0
	fatalSeen := false
	var last json.RawMessage
	finished := false
	for !finished {
		if e = ctx.Err(); e != nil {
			writeErr := traceWriteJSON(filepath.Join(out, "raw-incomplete.json"), map[string]any{"complete": false, "observed_cases": count, "last_complete_record": last, "partial_record": string(pending), "error": e.Error()})
			t.Fatal("native raw capture deadline", errors.Join(e, writeErr))
		}
		part, readErr := reader.ReadBytes('\n')
		pending = append(pending, part...)
		if len(pending) > 1<<20 {
			t.Fatal("oversized raw record")
		}
		if readErr == nil {
			line := append([]byte(nil), pending...)
			pending = nil
			var record rawNativeRecord
			if e = json.Unmarshal(line, &record); e != nil {
				t.Fatal(e)
			}
			last = append(last[:0], line...)
			fmt.Printf("NATIVE RAW %s", line)
			if record.Type == "fatal" {
				fatalSeen = true
			}
			switch record.Type {
			case "start", "case", "fatal", "finished", "volume-uuid":
			case "volume":
				volumes++
			default:
				t.Fatal("unknown raw record type", record.Type)
			}
			if record.Type == "case" {
				if count >= len(expectedRows) {
					t.Fatal("extra native case")
				}
				expected, _, _ := strings.Cut(expectedRows[count], "\t")
				if e = validateRawCase(record, expected, count); e != nil {
					t.Fatal(e)
				}
				count++
			}
			if record.Type == "finished" {
				finished = true
				if e = traceWriteJSON(filepath.Join(out, "raw-native-finished.json"), map[string]any{"diagnostic_only": true, "qualifies_full_gate": false, "observed_cases": count, "required_cases": 3753, "native": json.RawMessage(line)}); e != nil {
					t.Fatal(e)
				}
				if record.Count != 3753 || count != 3753 || volumes != 1 || fatalSeen || record.Error != 0 || record.Stopped || record.CleanupErrno != 0 {
					t.Fatal("incomplete/failed native capture", string(line))
				}
			}
			continue
		}
		if !errors.Is(readErr, io.EOF) {
			t.Fatal(readErr)
		}
		select {
		case <-ctx.Done():
			writeErr := traceWriteJSON(filepath.Join(out, "raw-incomplete.json"), map[string]any{"complete": false, "observed_cases": count, "last_complete_record": last, "partial_record": string(pending), "error": ctx.Err().Error()})
			t.Fatal("native raw capture incomplete", errors.Join(ctx.Err(), writeErr))
		case <-time.After(10 * time.Millisecond):
		}
	}
	var final struct {
		syscallTraceFinished
		Error int
	}
	if e = waitTraceJSON(ctx, filepath.Join(control, "finished.json"), &final); e != nil {
		t.Fatal(e)
	}
	if final.Schema != 1 || final.Nonce != plan.Nonce || final.PID != pid || final.Completed != 3753 || final.Stopped || final.CleanupErrno != 0 || final.Error != 0 {
		t.Fatal("native final identity/outcome", final)
	}
	exitCode, exitErr := waitRawExit(ctx, pid)
	if e = traceWriteJSON(filepath.Join(out, "raw-process-exit.json"), map[string]any{"pid": pid, "nonce": plan.Nonce, "exit_code": exitCode, "error": fmt.Sprint(exitErr)}); e != nil {
		t.Fatal(e)
	}
	if exitErr != nil || exitCode != 0 {
		t.Fatal("native process exit", exitCode, exitErr)
	}
	name := strings.ReplaceAll(c.Filesystem, "+", "plus") + ".dmg"
	imageResult := make(chan error, 1)
	go func() {
		after, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && sum(after) != c.InputSHA256[name] {
			err = errors.New("native capture changed backing image")
		}
		imageResult <- err
	}()
	hashCtx, hashCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hashCancel()
	select {
	case e = <-imageResult:
		if e != nil {
			t.Fatal(e)
		}
	case <-hashCtx.Done():
		t.Fatal("post-capture image integrity incomplete", hashCtx.Err())
	}
	if e = traceWriteJSON(filepath.Join(out, "raw-completion.json"), map[string]any{"diagnostic_only": true, "qualifies_full_gate": false, "observed_cases": 3753, "observations": 7506, "final": final, "exit_code": exitCode, "image_sha256": c.InputSHA256[name]}); e != nil {
		t.Fatal(e)
	}
}
func TestSingleNameRawTraceValidation(t *testing.T) {
	good := rawNativeRecord{Type: "case", Index: 0, ID: "ascii", Results: []rawNativeResult{{Inode: 20}, {Errno: 2, Read: -1}}}
	if e := validateRawCase(good, "ascii", 0); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*rawNativeRecord){func(r *rawNativeRecord) { r.ID = "duplicate" }, func(r *rawNativeRecord) { r.Index = 1 }, func(r *rawNativeRecord) { r.Interrupted = true }, func(r *rawNativeRecord) { r.Results = r.Results[:1] }, func(r *rawNativeRecord) { r.Results[1].Inode = 20 }, func(r *rawNativeRecord) { r.Results[0].Read = -1 }} {
		bad := good
		bad.Results = append([]rawNativeResult(nil), good.Results...)
		mutate(&bad)
		if validateRawCase(bad, "ascii", 0) == nil {
			t.Fatal("accepted invalid raw case", bad)
		}
	}
	for _, want := range []int{0, 7} {
		cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", want))
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		pid := cmd.Process.Pid
		if e := cmd.Process.Release(); e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		got, e := waitRawExit(ctx, pid)
		cancel()
		if e != nil || got != want {
			t.Fatal("actual child exit", got, e)
		}
		if _, e = waitRawExit(t.Context(), pid); !errors.Is(e, unix.ECHILD) {
			t.Fatal("must reject missing child", e)
		}
	}
	sources := map[string]string{}
	for _, name := range rawSourceNames() {
		sources[name] = strings.Repeat("ab", 32)
	}
	if e := validateRawSources(sources); e != nil {
		t.Fatal(e)
	}
	for _, name := range rawSourceNames() {
		hash := sources[name]
		delete(sources, name)
		if validateRawSources(sources) == nil {
			t.Fatal("accepted missing raw source", name)
		}
		sources[name] = hash
	}
}

// Run only after raw evidence upload and detach: a receiver difference must not
// prevent preservation or cleanup, and this diagnostic never qualifies parity.
func TestNativeRawTraceCompare(t *testing.T) {
	_, out, _, volume, _ := preparedSingleNameInput(t)
	if _, e := os.ReadFile(filepath.Join(out, "raw-completion.json")); e != nil {
		t.Fatal("complete native evidence required", e)
	}
	b, e := os.ReadFile(filepath.Join(out, "raw-native.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var cases []json.RawMessage
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r rawNativeRecord
		if e = json.Unmarshal([]byte(line), &r); e != nil {
			t.Fatal(e)
		}
		if r.Type == "case" {
			cases = append(cases, json.RawMessage(line))
		}
	}
	raw, e := json.Marshal(struct {
		Cases []json.RawMessage `json:"cases"`
		Count int               `json:"count"`
	}{cases, len(cases)})
	if e != nil {
		t.Fatal(e)
	}
	validateNativeNameResults(t, raw, volume.Native.Cases, 3753)
}
