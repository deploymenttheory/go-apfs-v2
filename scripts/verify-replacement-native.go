//go:build ignore

// Qualify replacement metadata on fresh APFS and HFS+ volumes against copyfile.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	capture := flag.String("capture", "", "also write a reviewed native fixture at this path")
	flag.Parse()
	if err := verify(*capture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verify(capture string) (result error) {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native qualification requires macOS; portable replay runs on every host")
	}
	const out = "artifacts/replacement-native"
	if err := os.MkdirAll(out, 0755); err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "apfs-replacement-oracle-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(temp)) }()
	commands := []map[string]any{}
	defer func() {
		b, err := json.MarshalIndent(commands, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(out, "commands.json"), append(b, '\n'), 0600)
		}
		result = errors.Join(result, err)
	}()
	run := func(name string, args ...string) ([]byte, error) {
		cmd := exec.Command(name, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		commands = append(commands, map[string]any{"argv": append([]string{name}, args...), "stdout": stdout.String(), "stderr": stderr.String(), "success": err == nil})
		if err != nil {
			return nil, fmt.Errorf("%s %v: %w\n%s\n%s", name, args, err, stdout.Bytes(), stderr.Bytes())
		}
		return stdout.Bytes(), nil
	}
	versions := map[string]string{}
	for name, args := range map[string][]string{"sw_vers": {}, "uname": {"-a"}, "xcrun": {"clang", "--version"}, "go": {"version"}} {
		data, err := run(name, args...)
		if err != nil {
			return err
		}
		versions[name] = strings.TrimSpace(string(data))
	}
	const source = "testdata/appledouble/native/replacement-copy.c"
	hashes := map[string]string{}
	hashFile := func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hashes[path] = hex.EncodeToString(sum[:])
		return nil
	}
	for _, p := range []string{source, "scripts/verify-replacement-native.go", "pkg/hostdata/replacement_copy_darwin_test.go", "pkg/hostdata/replacement_copy.go", "pkg/hostdata/replacement_copy_darwin.go", "pkg/hostdata/replacement_darwin.go", "pkg/hostdata/replacement_root_darwin.go", "go.mod", "go.sum"} {
		if err := hashFile(p); err != nil {
			return err
		}
	}
	sdk, err := run("xcrun", "--show-sdk-path")
	if err != nil {
		return err
	}
	for _, header := range []string{"copyfile.h", "sys/clonefile.h", "sys/xattr.h", "sys/acl.h", "sys/attr.h"} {
		if err := hashFile(filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header)); err != nil {
			return err
		}
	}
	helper := filepath.Join(temp, "oracle")
	if _, err := run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper); err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, err := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=replacement_copy_oracle", source)
		if err != nil {
			return err
		}
		// AST contents have their own retained file; keep the command log compact.
		commands[len(commands)-1]["stdout"] = "retained in oracle-" + arch + ".ast.json"
		if !json.Valid(ast) || !bytes.Contains(ast, []byte("fcopyfile")) || !bytes.Contains(ast, []byte("fclonefileat")) {
			return fmt.Errorf("incomplete %s oracle AST", arch)
		}
		name := filepath.Join(out, "oracle-"+arch+".ast.json")
		if err := os.WriteFile(name, ast, 0600); err != nil {
			return err
		}
		if err := hashFile(name); err != nil {
			return err
		}
	}
	records := []json.RawMessage{}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		err := func() (result error) {
			image := filepath.Join(temp, strings.ReplaceAll(filesystem, "+", "plus")+".dmg")
			mount := filepath.Join(temp, "mount")
			if err := os.Mkdir(mount, 0700); err != nil {
				return err
			}
			defer os.Remove(mount)
			if _, err := run("hdiutil", "create", "-size", "128m", "-fs", filesystem, "-volname", "ReplacementOracle", image); err != nil {
				return err
			}
			if _, err := run("hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, image); err != nil {
				return err
			}
			defer func() { _, err := run("hdiutil", "detach", mount); result = errors.Join(result, err) }()
			cmd := exec.Command("go", "test", "-count=1", "-json", "-run", "^TestReplacementCopyDarwinNative$", "./pkg/hostdata")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_REPLACEMENT_MOUNT="+mount, "APFS_REPLACEMENT_ORACLE="+helper, "APFS_REPLACEMENT_FS="+filesystem)
			data, err := cmd.CombinedOutput()
			if e := os.WriteFile(filepath.Join(out, strings.ReplaceAll(filesystem, "+", "plus")+".jsonl"), data, 0600); e != nil {
				return errors.Join(err, e)
			}
			if err != nil {
				return fmt.Errorf("%s acceptance: %w\n%s", filesystem, err, data)
			}
			scanner := bufio.NewScanner(bytes.NewReader(data))
			scanner.Buffer(make([]byte, 4096), 1<<20)
			cases := 0
			pending := map[string]string{}
			packagePass := false
			for scanner.Scan() {
				var event struct{ Action, Test, Output string }
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					return err
				}
				if event.Action == "skip" || event.Action == "fail" {
					return fmt.Errorf("%s: %s %s", filesystem, event.Action, event.Test)
				}
				if event.Action == "pass" && event.Test == "" {
					packagePass = true
				}
				if event.Action == "output" {
					pending[event.Test] += event.Output
					for {
						line, rest, complete := strings.Cut(pending[event.Test], "\n")
						if !complete {
							break
						}
						pending[event.Test] = rest
						if _, value, found := strings.Cut(line, "REPLACEMENT_NATIVE "); found {
							raw := json.RawMessage(strings.TrimSpace(value))
							if !json.Valid(raw) {
								return fmt.Errorf("invalid native record: %s", event.Test)
							}
							records = append(records, raw)
							cases++
						}
					}
					if len(pending[event.Test]) > 1<<20 {
						return fmt.Errorf("oversized native output: %s", event.Test)
					}
				}

			}
			if err := scanner.Err(); err != nil {
				return err
			}
			for name, rest := range pending {
				if rest != "" {
					return fmt.Errorf("incomplete native output: %s", name)
				}
			}
			if cases != 4 || !packagePass {
				return fmt.Errorf("incomplete %s evidence: %d cases, package pass %v", filesystem, cases, packagePass)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	report := map[string]any{"schema": 1, "purpose": "SDK replacement metadata contract, with raw native copyfile controls; not a codesign timestamp or inheritance policy claim", "versions": versions, "source_sha256": hashes, "commands": commands, "cases": records}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(out, "capture.json"), data, 0600); err != nil {
		return err
	}
	if capture != "" {
		if err := os.WriteFile(capture, data, 0644); err != nil {
			return err
		}
	}
	fmt.Printf("Replacement native qualification: %d cases across APFS and HFS+\n", len(records))
	return nil
}
