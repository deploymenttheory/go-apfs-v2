//go:build ignore

// Capture installed libcopyfile instructions from an owned, stopped probe.
// This is research evidence, not a replacement for the native behavior gates.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func main() {
	if err := capture(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func capture() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("installed binary capture requires macOS")
	}
	const directory = "artifacts/path-lifecycle-binary"
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	executable, err := filepath.Abs(filepath.Join(directory, "probe"))
	if err != nil {
		return err
	}
	source := "testdata/appledouble/native/path-copyfile.c"
	if output, err := exec.Command("xcrun", "clang", source, "-o", executable).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w: %s", err, output)
	}
	names := []string{"copyfile", "copyfile_set_dst_permissions", "copyfile_validate_dst", "copyfile_fix_perms", "copyfile_open", "reset_security", "copyfile_internal", "copyfile_state_free", "open_src_rsrc_fork", "open_dst_rsrc_fork"}
	arguments := []string{"lldb", "--batch", "-o", "breakpoint set --name main", "-o", "run"}
	for _, name := range names {
		arguments = append(arguments, "-o", "disassemble --name "+name)
	}
	arguments = append(arguments, "-o", "image list libcopyfile.dylib", "-o", "quit", "--", executable)
	output, err := exec.Command("xcrun", arguments...).CombinedOutput()
	if err != nil {
		_ = os.WriteFile(filepath.Join(directory, "debugger-error.txt"), output, 0600)
		return fmt.Errorf("owned probe disassembly: %w; see %s/debugger-error.txt", err, directory)
	}
	// Omit debugger process IDs and executable paths. Preserve each instruction
	// and actual branch address unchanged; the image base identifies its slide.
	functions := make(map[string]string, len(names))
	for _, name := range names {
		start := bytes.Index(output, []byte("libcopyfile.dylib`"+name+":"))
		if start < 0 {
			return fmt.Errorf("missing symbol %s", name)
		}
		end := bytes.Index(output[start:], []byte("\n(lldb)"))
		if end < 0 {
			return fmt.Errorf("unterminated symbol %s", name)
		}
		functions[name] = string(output[start:start+end]) + "\n"
	}
	image := regexp.MustCompile(`(?m)^\[\s*0\]\s+([A-F0-9-]+)\s+(0x[0-9a-f]+)\s+/usr/lib/system/libcopyfile\.dylib\s*$`).FindSubmatch(output)
	if len(image) != 3 {
		return fmt.Errorf("missing image UUID/base")
	}
	host, err := exec.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	probe, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	provider, err := os.ReadFile("testdata/appledouble/native/xattr-provider-context.h")
	if err != nil {
		return err
	}
	resolved, err := resolveStubs(executable, functions)
	if err != nil {
		return err
	}
	observation := map[string]any{"resolved_call_stubs": resolved, "evidence": "installed-binary-disassembly", "capture": true, "passed": false, "host": strings.TrimSpace(string(host)), "goarch": runtime.GOARCH, "revision": strings.TrimSpace(string(revision)), "image_uuid": string(image[1]), "image_base": string(image[2]), "image_path": "/usr/lib/system/libcopyfile.dylib", "source_sha256": fmt.Sprintf("%x", sha256.Sum256(probe)), "functions": functions}
	observation["provider_sha256"] = fmt.Sprintf("%x", sha256.Sum256(provider))
	encoded, err := json.MarshalIndent(observation, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err = os.WriteFile(filepath.Join(directory, "observations.json"), encoded, 0600); err != nil {
		return err
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(encoded); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, "observations.json.gz"), compressed.Bytes(), 0600); err != nil {
		return err
	}
	fmt.Printf("Captured %d complete installed functions, UUID %s; review against behavioral evidence before retaining.\n", len(functions), image[1])
	return nil
}

// Resolve shared-cache branch stubs through their actual authenticated pointer
// slots. The instruction text stays unchanged; this adds symbol attribution.
func resolveStubs(executable string, functions map[string]string) (map[string]string, error) {
	result := map[string]string{}
	if runtime.GOARCH != "arm64" {
		return result, nil
	}
	targets := map[string]bool{}
	branch := regexp.MustCompile(`(?m)^\s+0x[0-9a-f]+ <\+[0-9]+>:\s+bl\s+(0x[0-9a-f]+)\s*$`)
	for _, body := range functions {
		for _, match := range branch.FindAllStringSubmatch(body, -1) {
			targets[match[1]] = true
		}
	}
	var addresses []string
	for address := range targets {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	run := func(commands []string) ([]byte, error) {
		args := []string{"lldb", "--batch", "-o", "breakpoint set --name main", "-o", "run"}
		for _, command := range commands {
			args = append(args, "-o", command)
		}
		args = append(args, "-o", "quit", "--", executable)
		out, err := exec.Command("xcrun", args...).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("resolve native call stubs: %w", err)
		}
		return out, nil
	}
	var commands []string
	for _, address := range addresses {
		commands = append(commands, "disassemble --start-address "+address+" --count 4")
	}
	output, err := run(commands)
	if err != nil {
		return nil, err
	}
	adrp := regexp.MustCompile(`(?m)^\s+(0x[0-9a-f]+):\s+adrp\s+x17, (-?[0-9]+)\s*$`)
	add := regexp.MustCompile(`(?m)^\s+0x[0-9a-f]+:\s+add\s+x17, x17, #0x([0-9a-f]+)\s*$`)
	slots := map[string]string{}
	commands = nil
	for _, address := range addresses {
		marker := "(lldb) disassemble --start-address " + address + " --count 4\n"
		start := bytes.Index(output, []byte(marker))
		if start < 0 {
			return nil, fmt.Errorf("missing stub %s", address)
		}
		section := output[start+len(marker):]
		if end := bytes.Index(section, []byte("(lldb)")); end >= 0 {
			section = section[:end]
		}
		page := adrp.FindSubmatch(section)
		offset := add.FindSubmatch(section)
		if len(page) != 3 || len(offset) != 2 {
			continue
		}
		pc, e := strconv.ParseUint(string(page[1][2:]), 16, 64)
		if e != nil {
			return nil, e
		}
		delta, e := strconv.ParseInt(string(page[2]), 10, 64)
		if e != nil {
			return nil, e
		}
		low, e := strconv.ParseUint(string(offset[1]), 16, 64)
		if e != nil {
			return nil, e
		}
		slot := fmt.Sprintf("0x%x", uint64(int64(pc&^4095)+delta*4096)+low)
		slots[slot] = address
		commands = append(commands, "memory read --format address --size 8 --count 1 "+slot)
	}
	if len(commands) == 0 {
		return result, nil
	}
	output, err = run(commands)
	if err != nil {
		return nil, err
	}
	pointer := regexp.MustCompile("(?m)^(0x[0-9a-f]+): 0x[0-9a-f]+ (.+)$")
	for _, match := range pointer.FindAllStringSubmatch(string(output), -1) {
		if address, ok := slots[match[1]]; ok {
			result[address] = match[2]
		}
	}
	return result, nil
}
