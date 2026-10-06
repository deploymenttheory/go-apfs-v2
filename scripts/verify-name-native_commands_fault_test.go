//go:build ignore

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/procgroup"
)

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// Cancellation must reach a grandchild that detached into its own process
// group; otherwise an unresponsive native descendant outlives the step.
func TestNativeReadbackCommandCancelKillsTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are not used on Windows")
	}
	t.Setenv("APFS_READBACK_COMMAND_CHILD", "tree")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := &nativeCommandRunner{Directory: t.TempDir()}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go func() {
		for {
			out, _ := os.ReadFile(filepath.Join(runner.Directory, "command-001.stdout"))
			if strings.Contains(string(out), "\n") {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	out, err := runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	grandchild, e := strconv.Atoi(strings.TrimSpace(string(out)))
	if e != nil {
		t.Fatal(string(out), e)
	}
	defer func() {
		if p, err := os.FindProcess(grandchild); err == nil {
			_ = p.Kill()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(grandchild) {
		if time.Now().After(deadline) {
			t.Fatal("detached grandchild survived cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report := readNativeCommandFinish(t, runner.Directory); report.Abandoned {
		t.Fatal("killable tree was reported abandoned")
	}
}

// A child the kernel will not release: cancellation does nothing to it and no
// kill ever lands. The runner must still return, record the abandonment and
// leave the child to the kernel instead of blocking the step.
func TestNativeReadbackCommandAbandonsUnreleasedChild(t *testing.T) {
	t.Setenv("APFS_READBACK_COMMAND_CHILD", "hold")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runner := &nativeCommandRunner{Directory: t.TempDir(), progressOutput: &output, progressInterval: 20 * time.Millisecond, cancel: func(*os.Process) error { return nil }, abandonAfter: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$")
	if !errors.Is(err, errNativeAbandoned) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("abandonment did not bound the wait")
	}
	report := readNativeCommandFinish(t, runner.Directory)
	if !report.Abandoned || report.ExitCode != -1 || report.ContextError != context.DeadlineExceeded.Error() {
		t.Fatal(report)
	}
	if !strings.Contains(output.String(), "ABANDON command=") {
		t.Fatal("missing live abandonment record", output.String())
	}
	var pid struct{ PID int }
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "ABANDON command=") {
			_, _ = fmt.Sscanf(line[strings.Index(line, "pid=")+4:], "%d", &pid.PID)
		}
	}
	if pid.PID <= 0 {
		t.Fatal("abandonment record lacks pid", output.String())
	}
	if p, err := os.FindProcess(pid.PID); err == nil {
		_ = p.Kill()
	}
}

func TestNativeReadbackCommandChild(t *testing.T) {
	switch os.Getenv("APFS_READBACK_COMMAND_CHILD") {
	case "output":
		fmt.Fprint(os.Stdout, "native stdout")
		fmt.Fprint(os.Stderr, "native stderr")
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stdout, "partial output")
		fmt.Fprint(os.Stderr, "native failure")
		os.Exit(7)
	case "hold":
		fmt.Fprintln(os.Stderr, "NATIVE START case=blocked candidate=0 operation=openat-file")
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "tree":
		// A grandchild in its own process group that keeps running after its
		// parent exits unless cancellation kills the whole descendant tree.
		exe, err := os.Executable()
		if err != nil {
			os.Exit(10)
		}
		child := cirunner.Command(exe, "-test.run=^TestNativeReadbackCommandChild$")
		child.Env = append(os.Environ(), "APFS_READBACK_COMMAND_CHILD=hold")
		child.SysProcAttr = procgroup.Attr()
		if err = child.Start(); err != nil {
			os.Exit(11)
		}
		fmt.Fprintln(os.Stdout, child.Process.Pid)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "inherit":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(10)
		}
		child := cirunner.Command(exe, "-test.run=^TestNativeReadbackCommandChild$")
		child.Env = append(os.Environ(), "APFS_READBACK_COMMAND_CHILD=hold")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err = child.Start(); err != nil {
			os.Exit(11)
		}
		fmt.Fprintln(os.Stdout, child.Process.Pid)
		os.Exit(0)
	}
}

func readNativeCommandFinish(t *testing.T, dir string) nativeCommandObservation {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "command-001-finish.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report nativeCommandObservation
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Started.IsZero() || report.Finished.Before(report.Started) {
		t.Fatal("incomplete timing")
	}
	return report
}

func TestNativeReadbackCommandDiagnostics(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"output", "failure", "hold", "inherit"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv("APFS_READBACK_COMMAND_CHILD", action)
			runner := &nativeCommandRunner{Directory: t.TempDir()}
			limit := 10 * time.Second
			if action == "hold" {
				limit = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), limit)
			defer cancel()
			out, err := runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$")
			report := readNativeCommandFinish(t, runner.Directory)
			stdout, e := os.ReadFile(filepath.Join(runner.Directory, report.Stdout))
			if e != nil || string(stdout) != string(out) {
				t.Fatal("lost stdout", e)
			}
			stderr, e := os.ReadFile(filepath.Join(runner.Directory, report.Stderr))
			if e != nil {
				t.Fatal(e)
			}
			switch action {
			case "output":
				if err != nil || string(out) != "native stdout" || string(stderr) != "native stderr" || report.ExitCode != 0 || report.Error != "" {
					t.Fatal(string(out), string(stderr), report, err)
				}
			case "failure":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 || report.ExitCode != 7 || string(stderr) != "native failure" {
					t.Fatal(report, err)
				}
			case "hold":
				if !errors.Is(err, context.DeadlineExceeded) || report.ContextError != context.DeadlineExceeded.Error() {
					t.Fatal("cancellation lost", report, err)
				}
			case "inherit":
				pid, e := strconv.Atoi(strings.TrimSpace(string(out)))
				if e != nil {
					t.Fatal(string(out), e)
				}
				child, e := os.FindProcess(pid)
				if e != nil {
					t.Fatal(e)
				}
				defer func() {
					if err := child.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						t.Error(err)
					}
					if runtime.GOOS == "windows" {
						if _, err := child.Wait(); err != nil && !errors.Is(err, os.ErrProcessDone) {
							t.Error(err)
						}
					}
					_ = child.Release()
				}()

				if err != nil || ctx.Err() != nil || report.ExitCode != 0 {
					t.Fatal("inherited stdout blocked command completion", report, err)
				}
			}
		})
	}
}

func TestNativeReadbackCommandFaults(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		r := &nativeCommandRunner{Directory: t.TempDir()}
		if _, err := r.run(t.Context(), filepath.Join(t.TempDir(), "missing-program")); err == nil {
			t.Fatal("accepted missing executable")
		}
		if report := readNativeCommandFinish(t, r.Directory); report.ExitCode != -1 || report.Error == "" {
			t.Fatal(report)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		r := &nativeCommandRunner{Directory: t.TempDir()}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := r.run(ctx, "unused"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if report := readNativeCommandFinish(t, r.Directory); report.ContextError != context.Canceled.Error() {
			t.Fatal(report)
		}
	})
	for _, suffix := range []string{"-start", "-finish"} {
		t.Run("log"+suffix, func(t *testing.T) {
			t.Setenv("APFS_READBACK_COMMAND_CHILD", "output")
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			r := &nativeCommandRunner{Directory: t.TempDir()}
			if err = os.Mkdir(filepath.Join(r.Directory, "command-001"+suffix+".json"), 0700); err != nil {
				t.Fatal(err)
			}
			out, err := r.run(t.Context(), exe, "-test.run=^TestNativeReadbackCommandChild$")
			if err == nil {
				t.Fatal("lost diagnostic write failure")
			}
			if suffix == "-start" && len(out) != 0 {
				t.Fatal("executed command without start evidence")
			}
			if suffix == "-finish" && string(out) != "native stdout" {
				t.Fatal("lost successful output after diagnostic failure")
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(p, []byte("occupied"), 0600); err != nil {
			t.Fatal(err)
		}
		r := &nativeCommandRunner{Directory: p}
		if _, err := r.run(t.Context(), "unused"); err == nil {
			t.Fatal("ignored diagnostic directory failure")
		}
	})
}

func TestNativeReadbackCommandLiveProgress(t *testing.T) {
	t.Setenv("APFS_READBACK_COMMAND_CHILD", "hold")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	runner := &nativeCommandRunner{Directory: t.TempDir(), progressInterval: 20 * time.Millisecond, progressOutput: &output, liveStderr: true}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err = runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for _, text := range []string{"ACTIVITY command=", "CANCEL command=", "context deadline exceeded", "case=blocked candidate=0 operation=openat-file"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("missing %q in live progress: %s", text, output.String())
		}
	}
}

// The notification must arrive while the child is still alive. Inspecting only
// the final retained stderr would not exercise the failed live logging path.
type nativeProgressObserver struct {
	bytes.Buffer
	ready chan struct{}
}

func (w *nativeProgressObserver) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	if strings.Contains(w.Buffer.String(), "NATIVE START case=blocked candidate=0 operation=openat-file") {
		select {
		case w.ready <- struct{}{}:
		default:
		}
	}
	return n, err
}

func TestNativeReadbackCommandStreamsBeforeExit(t *testing.T) {
	t.Setenv("APFS_READBACK_COMMAND_CHILD", "hold")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output := &nativeProgressObserver{ready: make(chan struct{}, 1)}
	runner := &nativeCommandRunner{Directory: t.TempDir(), progressInterval: 20 * time.Millisecond, progressOutput: output, liveStderr: true}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$"); done <- err }()
	select {
	case <-output.ready:
		select {
		case err := <-done:
			t.Fatalf("probe exited before live record: %v", err)
		default:
		}
	case err := <-done:
		t.Fatalf("probe finished without live trace: %v", err)
	case <-ctx.Done():
		<-done
		t.Fatal("native call boundary was not streamed while child was alive")
	}
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(filepath.Join(runner.Directory, "command-001.stderr"))
	if err != nil || !strings.Contains(string(retained), "NATIVE START case=blocked candidate=0 operation=openat-file") {
		t.Fatal("lost retained trace", string(retained), err)
	}
	if !strings.Contains(output.String(), "CANCEL command=") {
		t.Fatal("missing live cancellation error")
	}
}

const nativeReadbackAttachment = `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk99</string></dict></array></dict></plist>`

func TestNativeReadbackMountCleanup(t *testing.T) {
	sentinel := errors.New("injected native failure")
	for _, phase := range []string{"success", "attach-launch", "attach-diagnostic", "operation", "cancelled", "parse", "detach", "detach-log"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			mount := filepath.Join(dir, "mount")
			if err := os.Mkdir(mount, 0700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "detach.json")
			if phase == "detach-log" {
				if err := os.Mkdir(log, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			operationCalls := 0
			run := func(callContext context.Context, name string, args ...string) ([]byte, error) {
				calls++
				if name != "hdiutil" {
					t.Fatal(name)
				}
				if args[0] == "attach" {
					if phase == "attach-launch" {
						return nil, sentinel
					}
					if phase == "cancelled" {
						cancel()
					}
					if phase == "parse" {
						return []byte("invalid plist"), nil
					}
					if phase == "attach-diagnostic" {
						return []byte(nativeReadbackAttachment), sentinel
					}
					return []byte(nativeReadbackAttachment), nil
				}
				if args[0] != "detach" || callContext.Err() != nil {
					t.Fatal("cleanup inherited cancellation", args, callContext.Err())
				}
				if deadline, ok := callContext.Deadline(); !ok || time.Until(deadline) > 45*time.Second {
					t.Fatal("unbounded cleanup")
				}
				if phase == "detach" {
					return nil, sentinel
				}
				return []byte("ejected"), nil
			}
			err := withNativeReadbackMount(ctx, run, "image", mount, log, func([]byte) error {
				operationCalls++
				if phase == "operation" {
					return sentinel
				}
				if phase == "cancelled" {
					return ctx.Err()
				}
				return nil
			})
			expectedCalls := 2
			if phase == "attach-launch" {
				expectedCalls = 1
			}
			if calls != expectedCalls {
				t.Fatal("missing independent cleanup", calls)
			}
			if phase == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("lost failure", phase)
			}
			if (phase == "attach-launch" || phase == "attach-diagnostic" || phase == "parse") && operationCalls != 0 {
				t.Fatal("ran operation after failed acquisition")
			}
			if phase == "attach-launch" || phase == "attach-diagnostic" || phase == "operation" || phase == "detach" {
				if !errors.Is(err, sentinel) {
					t.Fatal("lost original error", err)
				}
			}
			if phase == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			_, statErr := os.Stat(mount)
			if phase == "detach" {
				if statErr != nil {
					t.Fatal("removed mount after failed detach")
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatal("empty mount not cleaned", statErr)
			}
		})
	}
}
