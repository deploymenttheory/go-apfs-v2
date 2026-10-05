//go:build ignore

// Capture native recompression acquisition, reads and complete surviving failure states.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type trial struct {
	Filesystem, Scenario, Requested, Inline, Fault string
	FaultCount, FaultErrno, FaultSkip              int
	ProcessSignal                                  int
	Observation                                    json.RawMessage
	Trace                                          string
	Attribute, Fork, Data                          []byte
}

type capture struct {
	Schema                       int
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []trial
}

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", "artifacts/compression-operation/native.json.gz", "fresh observations")
	check := flag.Bool("check", false, "compare every retained native case")
	flag.Parse()
	if e := run(*out, *check); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out string, check bool) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native compression capture requires macOS")
	}
	const baseline = "testdata/appledouble/native/compression-operation.json.gz"
	if check {
		a, e := filepath.Abs(out)
		if e != nil {
			return e
		}
		b, e := filepath.Abs(baseline)
		if e != nil {
			return e
		}
		if a == b {
			return errors.New("check must retain fresh observations separately")
		}
	}
	dir, e := os.MkdirTemp("", "compression-operation-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(dir)) }()
	dir, e = filepath.EvalSymlinks(dir)
	if e != nil {
		return e
	}
	artifact := "artifacts/compression-operation"
	if e = os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	capture := capture{Schema: 1, Sources: map[string]string{}}
	for _, item := range []struct {
		name string
		args []string
		dst  *string
	}{
		{"sw_vers", nil, &capture.Host}, {"xcrun", []string{"clang", "--version"}, &capture.Compiler}, {"xcrun", []string{"--show-sdk-version"}, &capture.SDK},
	} {
		b, e := command(item.name, item.args...)
		if e != nil {
			return e
		}
		*item.dst = string(b)
	}
	digest := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	const source = "testdata/appledouble/native/compression-operation.c"
	const interposer = "testdata/appledouble/native/compression-operation-interpose.c"
	for _, path := range []string{source, interposer, "testdata/appledouble/native/compression-lifecycle-interpose.c", "testdata/appledouble/native/compression-policy.c", "scripts/capture-compression-operation.go", "go.mod", "go.sum"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		capture.Sources[path] = digest(b)
	}
	helper, library := filepath.Join(dir, "oracle"), filepath.Join(dir, "interpose.dylib")
	if _, e = command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-framework", "CoreFoundation", "-lcompression", source, "-o", helper); e != nil {
		return e
	}
	if _, e = command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-dynamiclib", interposer, "-o", library); e != nil {
		return e
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, path := range []string{source, interposer} {
			ast, e := command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", path)
			if e != nil {
				return e
			}
			if !json.Valid(ast) || !bytes.Contains(ast, []byte("CompoundStmt")) {
				return fmt.Errorf("incomplete AST %s/%s", arch, path)
			}
			name := arch + "-" + filepath.Base(path) + ".ast.json"
			capture.Sources[name] = digest(ast)
			if e = os.WriteFile(filepath.Join(artifact, name), ast, 0644); e != nil {
				return e
			}
		}
	}
	const framework = "/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression"
	uuid, e := command("xcrun", "dyld_info", "-uuid", framework)
	if e != nil {
		return e
	}
	capture.Library = string(uuid)
	disassembly, e := command("xcrun", "dyld_info", "-disassemble", framework)
	if e != nil {
		return e
	}
	for _, symbol := range []string{"_CompressFile:", "_CreateCompressionQueue:", "_fqueryCompressionInfo:"} {
		if !bytes.Contains(disassembly, []byte(symbol)) {
			return fmt.Errorf("missing native symbol %s", symbol)
		}
	}
	capture.Sources["AppleFSCompression.disassembly.txt"] = digest(disassembly)
	if e = os.WriteFile(filepath.Join(artifact, "AppleFSCompression.disassembly.txt"), disassembly, 0644); e != nil {
		return e
	}
	sdk, e := command("xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	for _, header := range []string{"sys/mount.h", "sys/stat.h", "sys/xattr.h", "sys/attr.h", "sys/time.h"} {
		path := filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header)
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		capture.Sources[path] = digest(b)
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		e = func() (result error) {
			mount := filepath.Join(dir, "mount")
			if e := os.Mkdir(mount, 0700); e != nil {
				return e
			}
			defer func() { result = errors.Join(result, os.RemoveAll(mount)) }()
			if filesystem != "host" {
				image := filepath.Join(dir, filesystem+".dmg")
				if _, e := command("hdiutil", "create", "-size", "256m", "-fs", filesystem, "-volname", "CompressionLifecycle", image); e != nil {
					return e
				}
				attached, e := command("hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
				if e != nil {
					return e
				}
				device, e := diskimage.AttachmentDevice(attached)
				if e != nil {
					_, cleanup := command("hdiutil", "detach", mount)
					return errors.Join(e, cleanup)
				}
				defer func() {
					var attempts []map[string]any
					e := diskimage.RetryDetach(context.Background(), func() (int, error) {
						output, err := command("hdiutil", "detach", device)
						code := 0
						if err != nil {
							code = -1
							var exit *exec.ExitError
							if errors.As(err, &exit) {
								code = exit.ExitCode()
							}
						}
						attempts = append(attempts, map[string]any{"device": device, "exit": code, "output": string(output)})
						return code, err
					})
					b, encode := json.MarshalIndent(attempts, "", "  ")
					result = errors.Join(result, e, encode, os.WriteFile(filepath.Join(artifact, filesystem+"-detach.json"), b, 0600))
				}()
				if e = os.WriteFile(filepath.Join(artifact, filesystem+"-attach.plist"), attached, 0600); e != nil {
					return e
				}

			}
			var cases []trial
			for _, inline := range []string{"default", "no"} {
				for _, scenario := range []string{"ordinary", "size-0", "size-16384", "size-16385", "incompressible", "subsecond", "already-compressed", "already-compressed-fork", "mode-000", "mode-200", "mode-400", "mode-444", "mode-755", "directory", "fifo", "hardlink", "symlink", "fork", "empty-fork", "stale-attribute", "immutable", "append", "hidden", "deny-write", "deny-read", "deny-writeattr", "deny-writexattr", "deny-readxattr", "appledouble-name"} {
					cases = append(cases, trial{Scenario: scenario, Inline: inline, Requested: "default"})
				}
				for _, fault := range []string{"open-data", "open-fork", "fstat", "dup", "fstatfs", "write"} {
					cases = append(cases, trial{Scenario: "ordinary", Fault: fault, Inline: inline, Requested: "default", FaultCount: 1, FaultErrno: 5})
				}
				cases = append(cases, trial{Scenario: "ordinary", Fault: "fstat", FaultSkip: 1, Inline: inline, Requested: "default", FaultCount: 1, FaultErrno: 5})
				for _, fault := range []string{"pread", "pread-short", "pread-zero"} {
					for skip := 0; skip < 3; skip++ {
						cases = append(cases, trial{Scenario: "multi-block", Fault: fault, FaultSkip: skip, Inline: inline, Requested: "default", FaultCount: 1, FaultErrno: 5})
					}
				}
			}
			for _, kind := range []string{"3", "7", "9", "11", "13"} {
				for _, scenario := range []string{"ordinary", "multi-block"} {
					for _, inline := range []string{"default", "no"} {
						cases = append(cases, trial{Scenario: scenario, Requested: kind, Inline: inline})
					}
				}
			}
			for index, c := range cases {
				c.Filesystem = filesystem
				root := filepath.Join(mount, fmt.Sprint(index))
				if e := os.Mkdir(root, 0700); e != nil {
					return e
				}
				base := "target"
				if c.Scenario == "appledouble-name" {
					base = "._target"
				}
				path, prefix := filepath.Join(root, base), filepath.Join(root, "observed")
				var stdout, stderr bytes.Buffer
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				cmd := exec.CommandContext(ctx, helper, c.Scenario, path, prefix, c.Requested, c.Inline)
				cmd.Env = append(os.Environ(), "DYLD_INSERT_LIBRARIES="+library, "APFS_NATIVE_FAULT_TARGET="+path, "APFS_NATIVE_FAULT_STAGE="+c.Fault, fmt.Sprintf("APFS_NATIVE_FAULT_COUNT=%d", c.FaultCount), fmt.Sprintf("APFS_NATIVE_FAULT_ERRNO=%d", c.FaultErrno), fmt.Sprintf("APFS_NATIVE_FAULT_SKIP=%d", c.FaultSkip))
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				e := cmd.Run()
				cancel()
				if e != nil {
					var exit *exec.ExitError
					if !errors.As(e, &exit) {
						return e
					}
					status, ok := exit.Sys().(syscall.WaitStatus)
					if !ok || !status.Signaled() || c.Fault != "fstatfs" {
						return fmt.Errorf("%s/%d: %w\n%s\n%s", filesystem, index, e, &stdout, &stderr)
					}
					c.ProcessSignal = int(status.Signal())
					if c.ProcessSignal != 11 {
						return fmt.Errorf("unexpected native termination: %d", c.ProcessSignal)
					}
					// Retain the complete surviving inode state in a separate,
					// non-interposed process. A crash never counts as acceptance.
					state, e := command(helper, "observe", path, prefix)
					if e != nil {
						return e
					}
					stdout.Reset()
					stdout.Write(state)
				}

				if !json.Valid(stdout.Bytes()) {
					return fmt.Errorf("invalid observation %s", &stdout)
				}
				c.Observation = append([]byte(nil), stdout.Bytes()...)
				c.Trace = stderr.String()
				for _, item := range []struct {
					suffix string
					target *[]byte
				}{{"attr", &c.Attribute}, {"fork", &c.Fork}, {"data", &c.Data}} {
					b, e := os.ReadFile(prefix + "." + item.suffix)
					if e != nil && !os.IsNotExist(e) {
						return e
					}
					*item.target = b
				}
				capture.Cases = append(capture.Cases, c)
				if e := os.RemoveAll(root); e != nil {
					return e
				}
			}
			return nil
		}()
		if e != nil {
			return e
		}
	}
	if len(capture.Cases) != 330 {
		return fmt.Errorf("incomplete lifecycle inventory: %d", len(capture.Cases))
	}
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	e = json.NewEncoder(z).Encode(capture)
	e = errors.Join(e, z.Close(), f.Close())
	if e != nil {
		return e
	}
	if check {
		f, e := os.Open(baseline)
		if e != nil {
			return e
		}
		defer f.Close()
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		var prior struct {
			Schema int
			Cases  []trial
		}
		if e = json.NewDecoder(z).Decode(&prior); e != nil {
			return e
		}
		if prior.Schema != capture.Schema || len(prior.Cases) != len(capture.Cases) {
			return errors.New("native lifecycle inventory changed")
		}
		for i, fresh := range capture.Cases {
			old := prior.Cases[i]
			// Host APFS and attached APFS share storage policy when their observed
			// MNT_CPROTECT bit agrees. Select this retained native volume context;
			// keep every outcome and trace comparison after that selection.
			var before, after struct {
				Volume     uint32 `json:"volume_flags"`
				Filesystem string `json:"filesystem_type"`
			}
			if e = json.Unmarshal(old.Observation, &before); e != nil {
				return e
			}
			if e = json.Unmarshal(fresh.Observation, &after); e != nil {
				return e
			}
			if before.Volume&0x80 != after.Volume&0x80 && fresh.Filesystem == "host" && after.Filesystem == "apfs" && after.Volume&0x80 == 0 {
				found := false
				for _, candidate := range prior.Cases {
					if candidate.Filesystem == "APFS" && candidate.Scenario == fresh.Scenario && candidate.Requested == fresh.Requested && candidate.Inline == fresh.Inline && candidate.Fault == fresh.Fault && candidate.FaultCount == fresh.FaultCount && candidate.FaultErrno == fresh.FaultErrno && candidate.FaultSkip == fresh.FaultSkip {
						old = candidate
						old.Filesystem = "host"
						found = true
						break
					}
				}
				if !found {
					return errors.New("unqualified host APFS compression volume context")
				}
			}
			a, e := comparison(old)
			if e != nil {
				return e
			}
			b, e := comparison(fresh)
			if e != nil {
				return e
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("native lifecycle differs at %d (%s/%s/%s/%s/%s): fresh evidence retained at %s", i, fresh.Filesystem, fresh.Scenario, fresh.Requested, fresh.Inline, fresh.Fault, out)
			}
		}
	}
	fmt.Printf("Native recompression operation: %d cases across host/APFS/HFS+, complete storage/readback and confined native failure traces\n", len(capture.Cases))
	return nil
}

// Full observed mount flags stay in the artifact. Only MNT_CPROTECT participates
// in the compressor's inline-storage decision; other mount bits describe runner
// attachment context rather than a changed operation outcome.
func comparison(c trial) ([]byte, error) {
	var observation map[string]any
	if e := json.Unmarshal(c.Observation, &observation); e != nil {
		return nil, e
	}
	flags, ok := observation["volume_flags"].(float64)
	if !ok && c.ProcessSignal == 0 {
		return nil, errors.New("missing volume context")
	}
	observation["volume_flags"] = uint32(flags) & 0x80
	b, e := json.Marshal(observation)
	if e != nil {
		return nil, e
	}
	c.Observation = b
	var trace strings.Builder
	var initialModify, initialAccess, initialModifySec, initialAccessSec float64
	var haveInitial bool
	for _, line := range strings.Split(strings.TrimSpace(c.Trace), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if e := json.Unmarshal([]byte(line), &event); e != nil {
			return nil, e
		}
		if event["operation"] == "stat-state" {
			modify, mok := event["modify_nsec"].(float64)
			access, aok := event["access_nsec"].(float64)
			modifySec, msok := event["modify_sec"].(float64)
			accessSec, asok := event["access_sec"].(float64)
			if !mok || !aok || !msok || !asok {
				return nil, errors.New("missing native timestamp observation")
			}
			if !haveInitial {
				initialModify, initialAccess, initialModifySec, initialAccessSec, haveInitial = modify, access, modifySec, accessSec, true
			}
			event["modify_matches_initial"] = modify == initialModify && modifySec == initialModifySec
			event["access_matches_initial"] = access == initialAccess && accessSec == initialAccessSec
			// Keep exact timestamps in retained evidence. Compare relationships
			// to the held snapshot, because write-open/truncate use wall time.
			delete(event, "modify_nsec")
			delete(event, "access_nsec")
			delete(event, "modify_sec")
			delete(event, "access_sec")
		}
		if event["operation"] == "futimes" {
			seconds, ok := event["argument"].(float64)
			if !ok || !haveInitial {
				return nil, errors.New("timestamp restoration without source snapshot")
			}
			event["argument"] = seconds - initialModifySec
		}

		if event["operation"] == "fstatfs" && event["result"] == float64(0) {
			flags, ok := event["argument"].(float64)
			if !ok {
				return nil, errors.New("missing volume trace")
			}
			event["argument"] = uint32(flags) & 0x80
		}
		b, e := json.Marshal(event)
		if e != nil {
			return nil, e
		}
		trace.Write(b)
		trace.WriteByte('\n')
	}
	c.Trace = trace.String()
	return json.Marshal(c)
}
