//go:build ignore

// ci-run is the host-built workflow entry point. The child inherits the job's
// target GOOS/GOARCH; the runner itself always executes on the actual host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := runCICommand(ctx, os.Args[1:], os.Stdout, os.Stderr, cirunner.DefaultReporter()); err != nil {
		fmt.Fprintln(os.Stderr, "CI COMMAND FAILED:", err)
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			os.Exit(exit.ExitCode())
		}
		os.Exit(1)
	}
}

func runCICommand(parent context.Context, args []string, stdout, stderr io.Writer, reporter *cirunner.Reporter) (result error) {
	flags := flag.NewFlagSet("apfs-ci-runner", flag.ContinueOnError)
	flags.SetOutput(stderr)
	suite := flags.String("suite", "", "workflow/job/step identity")
	limit := flags.Duration("timeout", 0, "explicit workload deadline including command shutdown")
	artifacts := flags.String("artifacts", os.Getenv("APFS_CI_REPORT_DIR"), "retained command streams and manifest root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *suite == "" || *limit <= 0 || *artifacts == "" || flags.NArg() == 0 {
		return errors.New("suite, positive timeout, artifact directory and command are required")
	}
	fmt.Fprintf(stderr, "CI PREPARE suite=%q timeout=%s\n", *suite, *limit)
	root, err := filepath.Abs(*artifacts)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, "command-")
	if err != nil {
		return err
	}
	output, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, output.Close()) }()
	diagnostic, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, diagnostic.Close()) }()
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(parent, *limit)
	defer cancel()
	command := cirunner.CommandContext(ctx, flags.Arg(0), flags.Args()[1:]...)
	command.Options.Label = *suite
	command.Options.Reporter = reporter
	command.Stdout = output
	command.Stderr = diagnostic
	command.Stdin = os.Stdin
	command.WaitDelay = 5 * time.Second
	deadline, _ := ctx.Deadline()
	manifest := map[string]any{
		"schema": 1, "suite": *suite, "args": flags.Args(), "host_os": runtime.GOOS,
		"host_arch": runtime.GOARCH, "started": started, "deadline": deadline,
		"revision": os.Getenv("GITHUB_SHA"), "stdout": "stdout", "stderr": "stderr",
	}
	save := func(name string) error {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0644)
	}
	if err = save("start.json"); err != nil {
		return err
	}
	forwardOutput := cirunner.ForwardFile(output, stdout)
	forwardDiagnostic := cirunner.ForwardFile(diagnostic, stderr)
	runErr := command.Run()
	manifest["finished"] = time.Now().UTC()
	manifest["exit_code"] = -1
	if command.ProcessState != nil {
		manifest["exit_code"] = command.ProcessState.ExitCode()
	}
	if runErr != nil {
		manifest["error"] = runErr.Error()
	}
	if ctx.Err() != nil {
		manifest["context_error"] = ctx.Err().Error()
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	forwardErr := errors.Join(forwardOutput.Stop(cleanup), forwardDiagnostic.Stop(cleanup))
	reportErr := reporter.Flush(cleanup)
	result = errors.Join(runErr, ctx.Err(), forwardErr, reportErr, output.Sync(), diagnostic.Sync())
	manifest["complete"] = result == nil
	if result != nil {
		manifest["qualification_error"] = result.Error()
	}
	result = errors.Join(result, save("finish.json"))
	fmt.Fprintf(stderr, "CI FINISH suite=%q elapsed=%s artifacts=%q error=%v\n", *suite, time.Since(started).Round(time.Millisecond), dir, result)
	return result
}
