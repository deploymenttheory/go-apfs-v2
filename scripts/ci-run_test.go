//go:build ignore

package main

import (
	"bytes"
	"context"
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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestCICommandChild(t *testing.T) {
	switch os.Getenv("APFS_CI_COMMAND_CHILD") {
	case "bytes":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{0, 1, 2, 255, '\n'}, 20000))
		fmt.Fprintln(os.Stderr, "native diagnostic")
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stdout, "partial native result")
		fmt.Fprint(os.Stderr, "native failure")
		os.Exit(7)
	case "hold":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func commandReporter(t *testing.T) *cirunner.Reporter {
	t.Helper()
	r := cirunner.NewReporter(io.Discard, 256)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestCICommandPreservesBytesAndFailures(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"bytes", "failure", "hold", "missing"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("APFS_CI_COMMAND_CHILD", mode)
			root := t.TempDir()
			program := exe
			limit := "10s"
			if mode == "missing" {
				program = filepath.Join(root, "missing-program")
			}
			if mode == "hold" {
				limit = "100ms"
			}
			var stdout, stderr bytes.Buffer
			args := []string{"--suite", "unit/cli/" + mode, "--timeout", limit, "--artifacts", root, "--", program, "-test.run=^TestCICommandChild$"}
			err := runCICommand(t.Context(), args, &stdout, &stderr, commandReporter(t))
			files, globErr := filepath.Glob(filepath.Join(root, "command-*"))
			if globErr != nil || len(files) != 1 {
				t.Fatal(files, globErr)
			}
			read := func(name string) []byte {
				t.Helper()
				b, e := os.ReadFile(filepath.Join(files[0], name))
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			if !bytes.Equal(read("stdout"), stdout.Bytes()) {
				t.Fatal("raw stdout changed")
			}
			var start, finish map[string]any
			if e := json.Unmarshal(read("start.json"), &start); e != nil {
				t.Fatal(e)
			}
			if e := json.Unmarshal(read("finish.json"), &finish); e != nil {
				t.Fatal(e)
			}
			if start["suite"] != "unit/cli/"+mode || finish["suite"] != start["suite"] || finish["deadline"] != start["deadline"] {
				t.Fatal("manifest identity changed")
			}
			if !strings.Contains(stderr.String(), "CI PREPARE") || !strings.Contains(stderr.String(), "CI FINISH") {
				t.Fatal("missing lifecycle", stderr.String())
			}
			switch mode {
			case "bytes":
				if err != nil || finish["complete"] != true || !bytes.Equal(stdout.Bytes(), bytes.Repeat([]byte{0, 1, 2, 255, '\n'}, 20000)) || string(read("stderr")) != "native diagnostic\n" {
					t.Fatal("changed native bytes", err)
				}
			case "failure":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 || finish["exit_code"] != float64(7) || stdout.String() != "partial native result" || string(read("stderr")) != "native failure" {
					t.Fatal("lost native failure", finish, err)
				}
			case "hold":
				if !errors.Is(err, context.DeadlineExceeded) || finish["context_error"] != context.DeadlineExceeded.Error() {
					t.Fatal("lost deadline", finish, err)
				}
			case "missing":
				if err == nil || finish["exit_code"] != float64(-1) {
					t.Fatal("accepted missing program", finish, err)
				}
			}
			if mode != "bytes" && (finish["complete"] != false || finish["qualification_error"] == nil) {
				t.Fatal("failure marked complete", finish)
			}
		})
	}
}

func TestCICommandRejectsInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--unknown"}, {"--suite", "s", "--timeout", "bad"},
		{"--suite", "s", "--timeout", "0s", "--artifacts", "x", "go"},
		{"--timeout", "1s", "--artifacts", "x", "go"},
		{"--suite", "s", "--timeout", "1s", "--artifacts", "", "go"},
		{"--suite", "s", "--timeout", "1s", "--artifacts", "x"},
	} {
		if err := runCICommand(t.Context(), args, io.Discard, io.Discard, commandReporter(t)); err == nil {
			t.Fatal("accepted incomplete configuration", args)
		}
	}
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCICommand(t.Context(), []string{"--suite", "s", "--timeout", "1s", "--artifacts", path, "go"}, io.Discard, io.Discard, commandReporter(t)); err == nil {
		t.Fatal("accepted unwritable artifact directory")
	}
}
