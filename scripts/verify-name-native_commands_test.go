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
	"sync"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/procgroup"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type nativeCommandRunner struct {
	Directory        string
	sequence         int
	progressInterval time.Duration
	progressOutput   io.Writer
	liveStderr       bool
	// Fault injection for tests only; zero values select the real behaviour.
	cancel       func(*os.Process) error
	waitDelay    time.Duration
	abandonAfter time.Duration
}

// A cancelled native command that the kernel has not released after WaitDelay
// plus this bound is abandoned: the harness stops waiting on it, records the
// abandonment, and lets the step end so its evidence uploads still run.
const nativeAbandonAfter = 10 * time.Second

var errNativeAbandoned = errors.New("native command did not exit after cancellation; abandoned")

type nativeProgressWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *nativeProgressWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

// The image-specific manifest remains here; command lifecycle reporting is shared
// with every other CI capture and verification command. Live stderr is tailed
// from the retained regular file, so the probe inherits no pipe at all. The
// child runs in its own process group and cancellation kills the whole tree;
// a child that still does not exit is abandoned rather than awaited.
func (r *nativeCommandRunner) wait(ctx context.Context, cmd *cirunner.Cmd, stderr *os.File, stem string) (result error) {
	destination := r.progressOutput
	if destination == nil {
		destination = os.Stderr
	}
	output := &nativeProgressWriter{writer: destination}
	reporter := cirunner.DefaultReporter()
	if r.progressOutput != nil {
		reporter = cirunner.NewReporter(output, 256)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			result = errors.Join(result, reporter.Close(cleanup))
		}()
	}
	cmd.Options.Reporter = reporter
	cmd.Options.Label = stem
	cmd.Options.Heartbeat = r.progressInterval
	if r.liveStderr {
		forward := cirunner.ForwardFile(stderr, output)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			result = errors.Join(result, forward.Stop(cleanup))
		}()
	}
	kill := r.cancel
	if kill == nil {
		kill = procgroup.KillTree
	}
	cmd.SysProcAttr = procgroup.Attr()
	cmd.Cancel = func() error { return kill(cmd.Process) }
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	abandon := r.abandonAfter
	if abandon <= 0 {
		abandon = nativeAbandonAfter
	}
	timer := time.NewTimer(cmd.WaitDelay + abandon)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		fmt.Fprintf(output, "ABANDON command=%q pid=%d; process did not exit after cancellation\n", stem, pid)
		return fmt.Errorf("%w: pid %d", errNativeAbandoned, pid)
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
	Abandoned    bool      `json:"abandoned,omitempty"`
	Stdout       string    `json:"stdout"`
	Stderr       string    `json:"stderr"`
}

// Every command stream is an owned regular file: a child daemon retaining
// stdout/stderr cannot hold a pipe open. The single-process native probe opts
// into live stderr, tailed from that same retained file, and a five-second
// WaitDelay. Cancellation kills the whole descendant tree; a child that still
// does not exit is abandoned rather than awaited.
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
	cmd := cirunner.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	if r.cancel != nil {
		cmd.WaitDelay = r.waitDelay
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	runErr := r.wait(ctx, cmd, stderr, stem)
	observation.Finished = time.Now().UTC()
	if cmd.ProcessState != nil {
		observation.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil {
		observation.Error = runErr.Error()
		observation.Abandoned = errors.Is(runErr, errNativeAbandoned)
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
