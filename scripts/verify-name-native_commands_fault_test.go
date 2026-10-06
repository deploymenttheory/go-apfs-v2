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
	"testing"
	"time"
)

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
	case "inherit":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(10)
		}
		child := exec.Command(exe, "-test.run=^TestNativeReadbackCommandChild$")
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
	runner := &nativeCommandRunner{Directory: t.TempDir(), progressInterval: 20 * time.Millisecond, progressOutput: &output}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err = runner.run(ctx, exe, "-test.run=^TestNativeReadbackCommandChild$"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for _, text := range []string{"PROGRESS native command", "ERROR native command", "context deadline exceeded", "case=blocked candidate=0 operation=openat-file"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("missing %q in live progress: %s", text, output.String())
		}
	}
}

func TestNativeReadbackCommandBoundedTail(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	if got := nativeCommandTail(file); got != "" {
		t.Fatal(got)
	}
	data := strings.Repeat("x", 8192) + "\nNATIVE START operation=openat-file\n"
	if _, err = file.WriteString(data); err != nil {
		t.Fatal(err)
	}
	before, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := nativeCommandTail(file)
	after, err := file.Seek(0, 1)
	if err != nil || before != after || len(got) > 4096 || !strings.HasSuffix(got, "NATIVE START operation=openat-file") {
		t.Fatal("unbounded tail or changed child write offset", got, err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nativeCommandTail(file), "stderr stat:") {
		t.Fatal("lost tail read error")
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
