//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type nativeCommandRunner struct {
	Directory        string
	sequence         int
	progressInterval time.Duration
	progressOutput   io.Writer
}

// Read a bounded tail from the existing regular file. Child output remains on
// regular files, so a descendant inheriting stderr cannot hold a pipe open.
func nativeCommandTail(file *os.File) string {
	info, err := file.Stat()
	if err != nil {
		return fmt.Sprintf("<stderr stat: %v>", err)
	}
	size := min(info.Size(), int64(4096))
	data := make([]byte, int(size))
	n, err := file.ReadAt(data, info.Size()-size)
	if err != nil && err != io.EOF {
		return fmt.Sprintf("<stderr read: %v>", err)
	}
	return strings.TrimSpace(string(data[:n]))
}

func (r *nativeCommandRunner) wait(ctx context.Context, cmd *exec.Cmd, stderr *os.File, stem string) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	interval := r.progressInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	output := r.progressOutput
	if output == nil {
		output = os.Stderr
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	cancelled := ctx.Done()
	for {
		select {
		case err := <-done:
			if err != nil || ctx.Err() != nil {
				fmt.Fprintf(output, "ERROR native command %s: %v context=%v; last stderr:\n%s\n", stem, err, ctx.Err(), nativeCommandTail(stderr))
			}
			return err
		case <-cancelled:
			// Report before waiting for process exit: a blocked kernel call can
			// prevent even a killed child from being reaped immediately.
			fmt.Fprintf(output, "ERROR native command %s deadline/cancellation: %v; cancellation requested; awaiting process exit; last stderr:\n%s\n", stem, ctx.Err(), nativeCommandTail(stderr))
			cancelled = nil
		case <-ticker.C:
			fmt.Fprintf(output, "PROGRESS native command %s pid=%d elapsed=%s; last stderr:\n%s\n", stem, cmd.Process.Pid, time.Since(started).Round(time.Second), nativeCommandTail(stderr))
		}
	}
}

type nativeCommandObservation struct {
	Command      string    `json:"command"`
	Args         []string  `json:"args"`
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished,omitempty"`
	Deadline     time.Time `json:"deadline,omitempty"`
	ExitCode     int       `json:"exit_code"`
	Error        string    `json:"error,omitempty"`
	ContextError string    `json:"context_error,omitempty"`
	Stdout       string    `json:"stdout"`
	Stderr       string    `json:"stderr"`
}

// A child daemon retaining stdout cannot keep this runner waiting for pipe EOF:
// raw native streams go directly to owned regular files, with WaitDelay retained
// as a further bound if os/exec needs a cancellation wait.
func (r *nativeCommandRunner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := os.MkdirAll(r.Directory, 0755); err != nil {
		return nil, err
	}
	r.sequence++
	stem := fmt.Sprintf("command-%03d", r.sequence)
	stdoutName, stderrName := stem+".stdout", stem+".stderr"
	stdout, err := os.Create(filepath.Join(r.Directory, stdoutName))
	if err != nil {
		return nil, err
	}
	stderr, err := os.Create(filepath.Join(r.Directory, stderrName))
	if err != nil {
		return nil, errors.Join(err, stdout.Close())
	}
	observation := nativeCommandObservation{Command: name, Args: append([]string(nil), args...), Started: time.Now().UTC(), ExitCode: -1, Stdout: stdoutName, Stderr: stderrName}
	observation.Deadline, _ = ctx.Deadline()
	save := func(suffix string) error {
		data, err := json.MarshalIndent(observation, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(r.Directory, stem+suffix+".json"), append(data, '\n'), 0644)
	}
	if err = save("-start"); err != nil {
		return nil, errors.Join(err, stdout.Close(), stderr.Close())
	}
	fmt.Fprintf(os.Stderr, "START native command %s %v (%s)\n", name, args, stem)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := r.wait(ctx, cmd, stderr, stem)
	observation.Finished = time.Now().UTC()
	if cmd.ProcessState != nil {
		observation.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil {
		observation.Error = runErr.Error()
	}
	if ctx.Err() != nil {
		observation.ContextError = ctx.Err().Error()
	}
	err = errors.Join(runErr, ctx.Err(), stdout.Close(), stderr.Close())
	data, readErr := os.ReadFile(filepath.Join(r.Directory, stdoutName))
	err = errors.Join(err, readErr, save("-finish"))
	fmt.Fprintf(os.Stderr, "END native command %s exit=%d context=%s error=%v (%s)\n", name, observation.ExitCode, observation.ContextError, err, stem)
	return data, err
}

type nativeReadbackRun func(context.Context, string, ...string) ([]byte, error)

// Mount ownership is registered even when a successful attach is followed by a
// diagnostic error. Cleanup has its own context and never inherits cancellation.
func withNativeReadbackMount(ctx context.Context, run nativeReadbackRun, image, mount, detachLog string, operation func([]byte) error) (err error) {
	attached, attachErr := run(ctx, "hdiutil", "attach", "-readonly", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	device, parseErr := diskimage.AttachmentDevice(attached)
	if attachErr == nil || device != "" {
		if device == "" {
			device = mount
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			var attempts []map[string]any
			detachErr := diskimage.RetryDetach(cleanup, func() (int, error) {
				output, e := run(cleanup, "hdiutil", "detach", device)
				code := 0
				if e != nil {
					code = -1
					var exit *exec.ExitError
					if errors.As(e, &exit) {
						code = exit.ExitCode()
					}
				}
				attempts = append(attempts, map[string]any{"device": device, "exit_code": code, "output": string(output)})
				return code, e
			})
			if detachErr == nil {
				detachErr = os.Remove(mount)
			}
			data, marshalErr := json.Marshal(attempts)
			err = errors.Join(err, detachErr, marshalErr, os.WriteFile(detachLog, data, 0644))
		}()
	}
	if attachErr != nil {
		if device == "" {
			return errors.Join(attachErr, os.Remove(mount))
		}
		return attachErr
	}
	if parseErr != nil {
		return parseErr
	}
	return operation(attached)
}
