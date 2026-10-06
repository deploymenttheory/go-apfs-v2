//go:build ignore

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var syscallTraceHeaders = []string{"sys/stat.h", "sys/fcntl.h", "unistd.h", "sys/errno.h", "stdio.h", "stdlib.h", "string.h", "signal.h", "time.h"}

func syscallTraceSourceNames() []string {
	names := []string{"testdata/appledouble/native/name-syscall-trace.c", "scripts/verify-name-native_syscall_test.go", ".github/workflows/name-syscall-diagnostic.yml", "syscall-arm64.ast.json", "syscall-x86_64.ast.json", "syscall-probe"}
	for _, header := range syscallTraceHeaders {
		names = append(names, "syscall-SDK/"+header)
	}
	return names
}
func validateTraceSources(sources map[string]string) error {
	names := syscallTraceSourceNames()
	if len(sources) != len(names) {
		return errors.New("incomplete trace source inventory")
	}
	for _, name := range names {
		raw, err := hex.DecodeString(sources[name])
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("invalid or missing source hash: %s", name)
		}
	}
	return nil
}

var syscallTraceOperations = []string{"root-open", "corpus-open", "case-open", "created-open", "created-fstat", "created-read", "created-close", "queried-open", "queried-fstat", "queried-read", "queried-close", "case-close", "corpus-close", "root-close"}

type syscallTracePlan struct {
	Schema         int               `json:"schema"`
	DiagnosticOnly bool              `json:"diagnostic_only"`
	Nonce          string            `json:"nonce"`
	Checkpoint     string            `json:"checkpoint_sha256"`
	Operations     []string          `json:"operations"`
	Sources        map[string]string `json:"source_sha256"`
}
type syscallTraceResult struct {
	Schema        int    `json:"schema"`
	Nonce         string `json:"nonce"`
	PID           int    `json:"pid"`
	Step          int    `json:"step"`
	Operation     string `json:"operation"`
	Attempted     bool   `json:"attempted"`
	Interrupted   bool   `json:"interrupted"`
	Result        int64  `json:"result"`
	Errno         int    `json:"errno"`
	Device, Inode uint64
	Size          int64
	Mode          uint32
}
type syscallTraceReady struct {
	Schema   int    `json:"schema"`
	Nonce    string `json:"nonce"`
	PID      int    `json:"pid"`
	UID, GID uint32
}
type syscallTraceFinished struct {
	Schema       int    `json:"schema"`
	Nonce        string `json:"nonce"`
	PID          int    `json:"pid"`
	Completed    int    `json:"completed"`
	Stopped      bool   `json:"stopped"`
	CleanupErrno int    `json:"cleanup_errno"`
}

func traceWriteJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}
func waitTraceJSON(ctx context.Context, path string, value any) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		b, e := os.ReadFile(path)
		if e == nil {
			return json.Unmarshal(b, value)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func validateTraceReady(ready syscallTraceReady, plan syscallTracePlan) error {
	if ready.Schema != 1 || ready.Nonce != plan.Nonce || ready.PID <= 0 || ready.UID != uint32(os.Getuid()) || ready.GID != uint32(os.Getgid()) {
		return errors.New("trace process identity mismatch")
	}
	return nil
}
func validateTraceResult(result syscallTraceResult, plan syscallTracePlan, pid, step int) error {
	if step < 1 || step > len(plan.Operations) || result.Schema != 1 || result.Nonce != plan.Nonce || result.PID != pid || result.Step != step || result.Operation != plan.Operations[step-1] {
		return errors.New("trace response identity/order mismatch")
	}
	return nil
}
func loadSyscallTrace(t *testing.T) (singleNameCheckpoint, string, syscallTracePlan) {
	t.Helper()
	c, out, _, _, raw := preparedSingleNameInput(t)
	if c.CaseID == "" || c.Cases != 1 || c.Observations != 2 {
		t.Fatal("syscall trace requires one explicit source case")
	}
	b, e := os.ReadFile(filepath.Join(out, "syscall-plan.json"))
	if e != nil {
		t.Fatal(e)
	}
	var plan syscallTracePlan
	if e = json.Unmarshal(b, &plan); e != nil {
		t.Fatal(e)
	}
	if plan.Schema != 1 || !plan.DiagnosticOnly || len(plan.Nonce) != 32 || plan.Checkpoint != sum(raw) || len(plan.Operations) != 14 {
		t.Fatal("trace plan identity changed")
	}
	for i, op := range syscallTraceOperations {
		if plan.Operations[i] != op {
			t.Fatal("trace operation order changed")
		}
	}
	if e := validateTraceSources(plan.Sources); e != nil {
		t.Fatal(e)
	}
	for name, want := range plan.Sources {
		if !fs.ValidPath(name) {
			t.Fatal("invalid trace source", name)
		}
		path := filepath.Join(out, name)
		if strings.HasPrefix(name, "scripts/") || strings.HasPrefix(name, "testdata/") || strings.HasPrefix(name, ".github/") {
			path = name
		}
		b, e := os.ReadFile(path)
		if e != nil || sum(b) != want {
			t.Fatal("trace source changed", name, e)
		}
	}
	return c, out, plan
}
func TestPrepareNativeSyscallTrace(t *testing.T) {
	c, out, _, _, raw := preparedSingleNameInput(t)
	if c.CaseID == "" {
		t.Fatal("one explicit case required")
	}
	if e := os.Mkdir(filepath.Join(out, "syscall-control"), 0700); e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		t.Fatal(e)
	}
	plan := syscallTracePlan{Schema: 1, DiagnosticOnly: true, Nonce: hex.EncodeToString(nonce), Checkpoint: sum(raw), Operations: append([]string(nil), syscallTraceOperations...), Sources: map[string]string{}}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "syscall-build-commands")}
	sdkRaw, e := os.ReadFile(filepath.Join(out, "sdk.txt"))
	if e != nil {
		t.Fatal(e)
	}
	sdk := strings.TrimSpace(string(sdkRaw))
	source := "testdata/appledouble/native/name-syscall-trace.c"
	if _, e = commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-isysroot", sdk, source, "-o", filepath.Join(out, "syscall-probe")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{source, "scripts/verify-name-native_syscall_test.go", ".github/workflows/name-syscall-diagnostic.yml"} {
		b, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		plan.Sources[name] = sum(b)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", sdk, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			t.Fatal(e)
		}
		name := "syscall-" + arch + ".ast.json"
		if e = os.WriteFile(filepath.Join(out, name), b, 0600); e != nil {
			t.Fatal(e)
		}
		plan.Sources[name] = sum(b)
	}
	for _, header := range syscallTraceHeaders {
		b, e := os.ReadFile(filepath.Join(sdk, "usr/include", header))
		if e != nil {
			t.Fatal(e)
		}
		name := "syscall-SDK/" + header
		path := filepath.Join(out, name)
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		plan.Sources[name] = sum(b)
	}
	b, e := os.ReadFile(filepath.Join(out, "syscall-probe"))
	if e != nil {
		t.Fatal(e)
	}
	plan.Sources["syscall-probe"] = sum(b)
	if e = traceWriteJSON(filepath.Join(out, "syscall-plan.json"), plan); e != nil {
		t.Fatal(e)
	}
}
func TestNativeSyscallTraceLaunch(t *testing.T) {
	c, out, plan := loadSyscallTrace(t)
	mount := boundaryMount(out, c)
	boundaryAttached(t, out, mount)
	control := filepath.Join(out, "syscall-control")
	stdout, e := os.Create(filepath.Join(out, "syscall-process.stdout"))
	if e != nil {
		t.Fatal(e)
	}
	stderr, e := os.Create(filepath.Join(out, "syscall-process.stderr"))
	if e != nil {
		t.Fatal(errors.Join(e, stdout.Close()))
	}
	// This explicitly owned process survives individual workflow steps so native
	// descriptors and process context remain unchanged until the final close.
	cmd := cirunner.Command(filepath.Join(out, "syscall-probe"), mount, filepath.Join(out, "selected-cases.tsv"), control, plan.Nonce)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	startErr := cmd.Start()
	e = errors.Join(startErr, stdout.Close(), stderr.Close())
	if e != nil {
		if startErr == nil {
			e = errors.Join(e, cmd.Process.Kill(), cmd.Wait())
		}
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	if e = traceWriteJSON(filepath.Join(out, "syscall-process.json"), map[string]any{"pid": pid, "nonce": plan.Nonce, "argv": cmd.Args}); e != nil {
		t.Fatal(errors.Join(e, cmd.Process.Kill(), cmd.Wait()))
	}
	if e = cmd.Process.Release(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var ready syscallTraceReady
	if e = waitTraceJSON(ctx, filepath.Join(control, "ready.json"), &ready); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceReady(ready, plan); e != nil || ready.PID != pid {
		t.Fatal("started trace process identity", e)
	}
}
func TestNativeSyscallTraceOperation(t *testing.T) {
	_, out, plan := loadSyscallTrace(t)
	step, e := strconv.Atoi(os.Getenv("APFS_NAME_SYSCALL_STEP"))
	if e != nil || step < 1 || step > 14 {
		t.Fatal("explicit syscall step1..14 required")
	}
	control := filepath.Join(out, "syscall-control")
	var ready syscallTraceReady
	b, e := os.ReadFile(filepath.Join(control, "ready.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &ready); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceReady(ready, plan); e != nil {
		t.Fatal(e)
	}
	for prior := 1; prior < step; prior++ {
		b, e := os.ReadFile(filepath.Join(control, fmt.Sprintf("result-%02d.json", prior)))
		if e != nil {
			t.Fatal(e)
		}
		var r syscallTraceResult
		if e = json.Unmarshal(b, &r); e != nil {
			t.Fatal(e)
		}
		if e = validateTraceResult(r, plan, ready.PID, prior); e != nil {
			t.Fatal(e)
		}
	}
	request := filepath.Join(control, fmt.Sprintf("request-%02d.txt", step))
	if _, e = os.Stat(request); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("refusing duplicate or inaccessible native request", e)
	}
	if e = os.WriteFile(request+".tmp", []byte(fmt.Sprintf("%s %d\n", plan.Nonce, step)), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(request+".tmp", request); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var result syscallTraceResult
	if e = waitTraceJSON(ctx, filepath.Join(control, fmt.Sprintf("result-%02d.json", step)), &result); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceResult(result, plan, ready.PID, step); e != nil {
		t.Fatal(e)
	}
	t.Logf("native %s: attempted=%t result=%d errno=%d inode=%d size=%d", result.Operation, result.Attempted, result.Result, result.Errno, result.Inode, result.Size)
}
func TestNativeSyscallTraceSummary(t *testing.T) {
	c, out, plan := loadSyscallTrace(t)
	control := filepath.Join(out, "syscall-control")
	var ready syscallTraceReady
	b, e := os.ReadFile(filepath.Join(control, "ready.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &ready); e != nil {
		t.Fatal(e)
	}
	var results []syscallTraceResult
	var differences []string
	for step := 1; step <= 14; step++ {
		b, e := os.ReadFile(filepath.Join(control, fmt.Sprintf("result-%02d.json", step)))
		if e != nil {
			t.Fatal(e)
		}
		var r syscallTraceResult
		if e = json.Unmarshal(b, &r); e != nil {
			t.Fatal(e)
		}
		if e = validateTraceResult(r, plan, ready.PID, step); e != nil {
			t.Fatal(e)
		}
		results = append(results, r)

	}
	if err := validateTraceSequence(results, *c.ReferenceNative); err != nil {
		differences = append(differences, err.Error())
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var finished syscallTraceFinished
	if e = waitTraceJSON(ctx, filepath.Join(control, "finished.json"), &finished); e != nil {
		t.Fatal(e)
	}
	if finished.Schema != 1 || finished.Nonce != plan.Nonce || finished.PID != ready.PID || finished.Completed != 14 || finished.Stopped || finished.CleanupErrno != 0 {
		differences = append(differences, "trace completion/cleanup mismatch")
	}
	if e = traceWriteJSON(filepath.Join(out, "syscall-summary.json"), map[string]any{"diagnostic_only": true, "qualifies_full_gate": false, "case_id": c.CaseID, "operations": results, "differences": differences, "finished": finished}); e != nil {
		t.Fatal(e)
	}
	if len(differences) > 0 {
		t.Fatal("native operation sequence or cleanup is incomplete", differences)
	}
}
func TestNativeSyscallTraceStop(t *testing.T) {
	// Cleanup avoids revalidating mounted input: a preceding failure must not
	// prevent stopping our owned process and closing any descriptors it holds.
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	control := filepath.Join(out, "syscall-control")
	b, e := os.ReadFile(filepath.Join(control, "ready.json"))
	if errors.Is(e, os.ErrNotExist) {
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	var ready syscallTraceReady
	if e = json.Unmarshal(b, &ready); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join(out, "syscall-plan.json"))
	if e != nil {
		t.Fatal(e)
	}
	var plan syscallTracePlan
	if e = json.Unmarshal(b, &plan); e != nil {
		t.Fatal(e)
	}
	if e = validateTraceReady(ready, plan); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(control, "stop"), []byte(plan.Nonce), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var finished syscallTraceFinished
	e = waitTraceJSON(ctx, filepath.Join(control, "finished.json"), &finished)
	if e != nil {
		commands := &nativeCommandRunner{Directory: filepath.Join(out, "syscall-cleanup-commands")}
		cleanup, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		actual, psErr := commands.run(cleanup, "ps", "-ww", "-p", strconv.Itoa(ready.PID), "-o", "command=")
		expectedPrefix := filepath.Join(out, "syscall-probe") + " "
		if psErr == nil && strings.HasPrefix(strings.TrimSpace(string(actual)), expectedPrefix) && strings.HasSuffix(strings.TrimSpace(string(actual)), " "+plan.Nonce) {
			process, findErr := os.FindProcess(ready.PID)
			if findErr == nil {
				e = errors.Join(e, process.Signal(syscall.SIGTERM), process.Release())
			} else {
				e = errors.Join(e, findErr)
			}
		} else {
			e = errors.Join(e, psErr, errors.New("cannot safely signal unverified trace process"))
		}
		t.Fatal(e)
	}
	if finished.Schema != 1 || finished.Nonce != plan.Nonce || finished.PID != ready.PID || finished.CleanupErrno != 0 {
		t.Fatal("trace cleanup identity/error", finished)
	}
}
func TestSingleNameSyscallTraceValidation(t *testing.T) {
	plan := syscallTracePlan{Nonce: "native", Operations: syscallTraceOperations}
	ready := syscallTraceReady{Schema: 1, Nonce: "native", PID: 123, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if e := validateTraceReady(ready, plan); e != nil {
		t.Fatal(e)
	}
	sources := map[string]string{}
	for _, name := range syscallTraceSourceNames() {
		sources[name] = strings.Repeat("ab", 32)
	}
	if err := validateTraceSources(sources); err != nil {
		t.Fatal(err)
	}
	for _, name := range syscallTraceSourceNames() {
		hash := sources[name]
		delete(sources, name)
		if validateTraceSources(sources) == nil {
			t.Fatal("accepted omitted source", name)
		}
		sources[name] = hash
	}
	sources["extra"] = strings.Repeat("ab", 32)
	if validateTraceSources(sources) == nil {
		t.Fatal("accepted unexpected source")
	}
	delete(sources, "extra")
	sources["syscall-probe"] = "not-a-hash"
	if validateTraceSources(sources) == nil {
		t.Fatal("accepted malformed hash")
	}
	actor := ready
	actor.UID++
	if validateTraceReady(actor, plan) == nil {
		t.Fatal("accepted wrong actor")
	}
	bad := ready
	bad.PID = 0
	if validateTraceReady(bad, plan) == nil {
		t.Fatal("accepted invalid process")
	}
	result := syscallTraceResult{Schema: 1, Nonce: "native", PID: 123, Step: 4, Operation: "created-open", Attempted: true, Result: -1, Errno: 2}
	if e := validateTraceResult(result, plan, 123, 4); e != nil {
		t.Fatal("real failed syscall must remain observable", e)
	}
	for _, step := range []int{0, 3, 15} {
		if validateTraceResult(result, plan, 123, step) == nil {
			t.Fatal("accepted wrong step", step)
		}
	}
	result.Nonce = "other"
	if validateTraceResult(result, plan, 123, 4) == nil {
		t.Fatal("accepted foreign response")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := waitTraceJSON(ctx, filepath.Join(t.TempDir(), "missing"), &ready); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

// The continuous route removes action/upload boundaries between native calls.
// It validates the image and actor once, then retains every actual result before
// the separate summary compares it with the producer's existing-entry record.
func TestNativeSyscallTraceContinuous(t *testing.T) {
	_, out, plan := loadSyscallTrace(t)
	control := filepath.Join(out, "syscall-control")
	b, err := os.ReadFile(filepath.Join(control, "ready.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ready syscallTraceReady
	if err = json.Unmarshal(b, &ready); err != nil {
		t.Fatal(err)
	}
	if err = validateTraceReady(ready, plan); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for step, operation := range plan.Operations {
		number := step + 1
		request := filepath.Join(control, fmt.Sprintf("request-%02d.txt", number))
		if _, err = os.Stat(request); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("duplicate or inaccessible request", err)
		}
		fmt.Printf("NATIVE START step=%d operation=%s pid=%d\n", number, operation, ready.PID)
		if err = os.WriteFile(request+".tmp", []byte(fmt.Sprintf("%s %d\n", plan.Nonce, number)), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(request+".tmp", request); err != nil {
			t.Fatal(err)
		}
		var result syscallTraceResult
		if err = waitTraceJSON(ctx, filepath.Join(control, fmt.Sprintf("result-%02d.json", number)), &result); err != nil {
			t.Fatal(err)
		}
		if err = validateTraceResult(result, plan, ready.PID, number); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("NATIVE RESULT %s\n", raw)
	}
}

func TestNativeSyscallTraceHostLog(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "syscall-host-log-commands")}
	_, err = commands.run(ctx, "/usr/bin/log", "show", "--last", "1m", "--style", "compact", "--predicate", `process == "kernel" AND eventMessage CONTAINS[c] "apfs"`)
	if err != nil {
		t.Fatal(err)
	}
}

// A diagnostic observes receiver errno; it never derives it from producer
// creation policy. Successful opens still require exact stored-object identity.
func validateTraceSequence(results []syscallTraceResult, producer nativeCase) error {
	if len(results) != 14 {
		return errors.New("incomplete native operation sequence")
	}
	opened := false
	for i, r := range results {
		step := i + 1
		if r.Interrupted || r.Errno < 0 {
			return errors.New("interrupted or invalid native operation")
		}
		switch step {
		case 1, 2, 3:
			if !r.Attempted || r.Result < 0 || r.Errno != 0 {
				return errors.New("native directory open failed")
			}
		case 4, 8:
			if !r.Attempted || (r.Result < 0 && (r.Result != -1 || r.Errno == 0)) || (r.Result >= 0 && r.Errno != 0) {
				return errors.New("invalid native file-open result")
			}
			opened = r.Result >= 0
		case 5, 6, 7, 9, 10, 11:
			if !opened {
				if r.Attempted || r.Result != 0 || r.Errno != 0 || r.Inode != 0 || r.Device != 0 || r.Size != 0 || r.Mode != 0 {
					return errors.New("operation attempted after failed open")
				}
				continue
			}
			if !r.Attempted || r.Result != 0 || r.Errno != 0 {
				return errors.New("native file operation failed")
			}
			if step == 5 || step == 9 {
				if producer.CreateErrno != 0 || producer.Inode == 0 || r.Inode != producer.Inode || r.Size != 0 || r.Device == 0 || r.Mode&syscall.S_IFMT != syscall.S_IFREG {
					return errors.New("native stored-object identity changed")
				}
			}
		case 12, 13, 14:
			if !r.Attempted || r.Result != 0 || r.Errno != 0 {
				return errors.New("native directory close failed")
			}
		}
	}
	return nil
}
func TestSingleNameSyscallReference(t *testing.T) {
	producer := nativeCase{Inode: 6511}
	results := make([]syscallTraceResult, 14)
	for i := range results {
		results[i].Attempted = true
	}
	for _, i := range []int{0, 1, 2, 3, 7} {
		results[i].Result = 6
	}
	for _, i := range []int{4, 8} {
		results[i].Inode = 6511
		results[i].Device = 1
		results[i].Mode = syscall.S_IFREG
	}
	if err := validateTraceSequence(results, producer); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{3, 7} {
		results[i] = syscallTraceResult{Attempted: true, Result: -1, Errno: 22}
		for j := i + 1; j <= i+3; j++ {
			results[j] = syscallTraceResult{}
		}
	}
	results[7].Errno = 2
	if err := validateTraceSequence(results, producer); err != nil {
		t.Fatal("receiver errno must not be inferred from producer", err)
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13} {
		bad := append([]syscallTraceResult(nil), results...)
		bad[index].Interrupted = true
		if err := validateTraceSequence(bad, producer); err == nil {
			t.Fatal("accepted interrupted operation", index)
		}
	}
	bad := append([]syscallTraceResult(nil), results...)
	bad[4].Attempted = true
	if err := validateTraceSequence(bad, producer); err == nil {
		t.Fatal("accepted stat after failed open")
	}
	if err := validateTraceSequence(results[:13], producer); err == nil {
		t.Fatal("accepted incomplete sequence")
	}
}
