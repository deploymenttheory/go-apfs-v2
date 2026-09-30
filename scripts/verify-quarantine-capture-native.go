//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native quarantine qualification requires macOS")
	}
	const dir = "artifacts/quarantine-capture-native"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var commands []map[string]any
	run := func(name string, args ...string) ([]byte, error) {
		cmd := exec.Command(name, args...)
		out, err := cmd.CombinedOutput()
		record := map[string]any{"command": append([]string{name}, args...), "output": string(out)}
		if err != nil {
			record["error"] = err.Error()
		}
		commands = append(commands, record)
		if err != nil {
			return out, fmt.Errorf("%s: %w\n%s", name, err, out)
		}
		return out, nil
	}
	sdk, err := run("xcrun", "--sdk", "macosx", "--show-sdk-path")
	if err != nil {
		return err
	}
	host, err := run("sw_vers")
	if err != nil {
		return err
	}
	compiler, err := run("xcrun", "clang", "--version")
	if err != nil {
		return err
	}
	const source = "testdata/appledouble/native/quarantine-capture.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, err := run("xcrun", "clang", "-arch", arch, "-isysroot", strings.TrimSpace(string(sdk)), "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "ast-"+arch+".json"), ast, 0600); err != nil {
			return err
		}
		// AST bytes live in their own artifact; do not duplicate them in commands.
		commands[len(commands)-1]["output"] = "retained in ast-" + arch + ".json"
	}
	library, err := filepath.Abs(filepath.Join(dir, "quarantine-capture.dylib"))
	if err != nil {
		return err
	}
	if _, err := run("xcrun", "clang", "-dynamiclib", "-O2", "-Wall", "-Wextra", "-Werror", source, "-o", library); err != nil {
		return err
	}
	cmd := exec.Command("go", "test", "-count=1", "-json", "-tags=native_quarantine_oracle", "-run=^TestQuarantine(Capture|File)NativeOracle$", "./pkg/hostmeta")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_QUARANTINE_ORACLE="+library)
	out, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(dir, "tests.jsonl"), out, 0600); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return fmt.Errorf("native Go comparison: %w\n%s", err, out)
	}
	if !strings.Contains(string(out), `"Action":"pass"`) || strings.Contains(string(out), `"Action":"skip"`) {
		return fmt.Errorf("native comparison did not complete")
	}
	hashes := map[string]string{}
	files, err := filepath.Glob("pkg/hostmeta/quarantine_capture*.go")
	if err != nil {
		return err
	}
	fileSources, err := filepath.Glob("pkg/hostmeta/quarantine_file*.go")
	if err != nil {
		return err
	}
	files = append(files, fileSources...)
	files = append(files, source, "scripts/verify-quarantine-capture-native.go", "testdata/appledouble/native/quarantine-process-capture.h", "go.mod", "go.sum")
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hashes[file] = hex.EncodeToString(sum[:])
	}
	revision, err := run("git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	report := map[string]any{"revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "host": string(host), "compiler": string(compiler), "sdk": strings.TrimSpace(string(sdk)), "source_sha256": hashes, "commands": commands, "same_process_native_comparisons": 1}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	fmt.Println("Raw quarantine capture matches independent C in the same process; both architecture ASTs retained")
	return nil
}
