//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type nativeCommandRunner struct {
	Directory string
	sequence  int
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
	runErr := cmd.Run()
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
