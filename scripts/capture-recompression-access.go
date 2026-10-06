//go:build ignore

// Retain independent native regular-file authorization observations and both ASTs.
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
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type accessCapture struct {
	Schema              int
	Host, SDK, Compiler string
	Sources             map[string]string
	Cases               []json.RawMessage
	OpenCases           []accessOpenCase
}

type accessOpenCase struct {
	Name                   string
	Type                   uint32
	Attribute, Fork, Plain []byte
	Observation            json.RawMessage
}

func accessCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := cirunner.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return data, fmt.Errorf("%s %v: %w: %s", name, args, err, stderr.Bytes())
	}
	return data, nil
}
func accessHash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
func main() {
	out := flag.String("out", "artifacts/recompression-access/native.json.gz", "fresh native evidence")
	check := flag.Bool("check", false, "compare independently retained native outcomes")
	flag.Parse()
	if err := accessRun(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func accessRun(out string, check bool) (err error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native access capture requires macOS")
	}
	host, e := accessCommand("sw_vers", "-productVersion")
	if e != nil {
		return e
	}
	version := strings.TrimSpace(string(host))
	major := strings.Split(version, ".")[0]
	if major != "15" && major != "26" && major != "27" {
		return fmt.Errorf("unqualified host %s", version)
	}
	baseline := "testdata/appledouble/native/recompression-access-macos" + major + ".json.gz"
	actual, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	for _, v := range []string{"15", "26", "27"} {
		path, e := filepath.Abs("testdata/appledouble/native/recompression-access-macos" + v + ".json.gz")
		if e != nil {
			return e
		}
		if check && actual == path {
			return errors.New("check cannot replace retained evidence")
		}
	}
	if e = os.MkdirAll(filepath.Dir(out), 0700); e != nil {
		return e
	}
	directory, e := os.MkdirTemp("", "recompression-access-")
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()
	sdk, e := accessCommand("xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	compiler, e := accessCommand("xcrun", "clang", "--version")
	if e != nil {
		return e
	}
	capture := accessCapture{Schema: 1, Host: version, SDK: strings.TrimSpace(string(sdk)), Compiler: string(compiler), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), filepath.Dir(out), capture.Sources); err != nil {
		return err
	}
	source := "testdata/appledouble/native/recompression-access.c"
	for _, name := range []string{source, "scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/compression-lz4.json.gz", "testdata/appledouble/native/recompression-access-source/sources.json", "testdata/appledouble/native/recompression-access-source/vfs_subr.c.gz", "testdata/appledouble/native/recompression-access-source/vfs_syscalls.c.gz", "testdata/appledouble/native/recompression-access-source/kern_authorization.c.gz", "testdata/appledouble/native/recompression-access-source/kern_credential.c.gz"} {
		data, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		capture.Sources[name] = accessHash(data)
	}
	for _, name := range []string{"sys/acl.h", "sys/kauth.h", "sys/stat.h", "sys/mount.h", "sys/fcntl.h", "sys/xattr.h", "membership.h"} {
		data, e := os.ReadFile(filepath.Join(capture.SDK, "usr/include", name))
		if e != nil {
			return e
		}
		capture.Sources["SDK/"+name] = accessHash(data)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := accessCommand("xcrun", "clang", "-target", arch+"-apple-macos15", "-isysroot", capture.SDK, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			return e
		}
		name := "recompression-access." + arch + ".ast.json"
		if e = os.WriteFile(filepath.Join(filepath.Dir(out), name), ast, 0600); e != nil {
			return e
		}
		capture.Sources[name] = accessHash(ast)
	}
	binary := filepath.Join(directory, "probe")
	if _, e = accessCommand("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", binary); e != nil {
		return e
	}
	scenarios := []string{"ordinary", "mode-000", "mode-200", "mode-400", "mode-444", "mode-755", "immutable", "append", "deny-read", "deny-write", "deny-readxattr", "deny-writexattr", "deny-writeattr", "deny-writesecurity", "deny-inherit-only", "deny-generic-read", "deny-wellknown-12", "deny-wellknown-10", "deny-wellknown-16", "deny-wellknown-4294967294", "allow-all-before-deny", "allow-part-then-deny", "split-allow", "generic-allow"}
	operations := []string{"open-data", "open-fork", "attribute", "truncate", "chmod", "times", "flags"}
	for _, scenario := range scenarios {
		for _, operation := range operations {
			data, e := accessCommand(binary, scenario, operation, filepath.Join(directory, "file"), major)
			if e != nil {
				return e
			}
			if !json.Valid(data) {
				return fmt.Errorf("invalid native observation %s/%s", scenario, operation)
			}
			capture.Cases = append(capture.Cases, json.RawMessage(bytes.TrimSpace(data)))
		}
	}
	openSource := "testdata/appledouble/native/recompression-open.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := accessCommand("xcrun", "clang", "-target", arch+"-apple-macos15", "-isysroot", capture.SDK, "-Xclang", "-ast-dump=json", "-fsyntax-only", openSource)
		if e != nil {
			return e
		}
		name := "recompression-open." + arch + ".ast.json"
		if e = os.WriteFile(filepath.Join(filepath.Dir(out), name), ast, 0600); e != nil {
			return e
		}
		capture.Sources[name] = accessHash(ast)
	}
	openBinary := filepath.Join(directory, "open-probe")
	if _, e = accessCommand("xcrun", "clang", "-Wall", "-Wextra", "-Werror", openSource, "-o", openBinary); e != nil {
		return e
	}
	encoded, e := os.ReadFile("testdata/appledouble/native/compression-lz4.json.gz")
	if e != nil {
		return e
	}
	native, e := gzip.NewReader(bytes.NewReader(encoded))
	if e != nil {
		return e
	}
	var storage struct {
		Kernel []struct {
			Name, Filesystem       string
			Type                   uint32
			Attribute, Fork, Plain []byte
			Exit                   int
		}
	}
	if e = errors.Join(json.NewDecoder(native).Decode(&storage), native.Close()); e != nil {
		return e
	}
	for _, input := range storage.Kernel {
		if input.Filesystem != "APFS" || input.Exit != 0 || (input.Name != "inline-text-16" && input.Name != "fork-text-65537") {
			continue
		}
		attr, fork := filepath.Join(directory, "attribute"), "-"
		if e = os.WriteFile(attr, input.Attribute, 0600); e != nil {
			return e
		}
		if input.Fork != nil {
			fork = filepath.Join(directory, "fork")
			if e = os.WriteFile(fork, input.Fork, 0600); e != nil {
				return e
			}
		}
		data, e := accessCommand(openBinary, attr, fork, filepath.Join(directory, "compressed"))
		if e != nil {
			return e
		}
		if !json.Valid(data) {
			return errors.New("invalid compressed-open observation")
		}
		capture.OpenCases = append(capture.OpenCases, accessOpenCase{Name: input.Name, Type: input.Type, Attribute: input.Attribute, Fork: input.Fork, Plain: input.Plain, Observation: json.RawMessage(bytes.TrimSpace(data))})
	}
	if len(capture.OpenCases) != 2 {
		return errors.New("incomplete compressed-open inventory")
	}

	file, e := os.Create(out)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(file)
	encodeErr := json.NewEncoder(z).Encode(capture)
	if e = errors.Join(encodeErr, z.Close(), file.Close()); e != nil {
		return e
	}
	if check {
		file, e := os.Open(baseline)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		z, e := gzip.NewReader(file)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, z.Close()) }()
		var old accessCapture
		if e = json.NewDecoder(z).Decode(&old); e != nil {
			return e
		}
		if !reflect.DeepEqual(old.OpenCases, capture.OpenCases) {
			return fmt.Errorf("native compressed-open observations differ; fresh %s", out)
		}
		if old.Schema != 1 || len(old.Cases) != len(capture.Cases) || len(old.OpenCases) != 2 {
			return errors.New("native access inventory differs")
		}
		if err := captureprovenance.Verify(os.DirFS("."), old.Sources); err != nil {
			return err
		}
		for _, name := range []string{source, "scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/compression-lz4.json.gz", "testdata/appledouble/native/recompression-access-source/sources.json", "testdata/appledouble/native/recompression-access-source/vfs_subr.c.gz", "testdata/appledouble/native/recompression-access-source/vfs_syscalls.c.gz", "testdata/appledouble/native/recompression-access-source/kern_authorization.c.gz", "testdata/appledouble/native/recompression-access-source/kern_credential.c.gz"} {
			if old.Sources[name] != capture.Sources[name] {
				return fmt.Errorf("stale access source %s", name)
			}
		}
		for i, data := range capture.Cases {
			var got, want struct {
				Scenario, Operation string
				Errno               int
			}
			if e = json.Unmarshal(data, &got); e != nil {
				return e
			}
			if e = json.Unmarshal(old.Cases[i], &want); e != nil {
				return e
			}
			if got != want {
				return fmt.Errorf("native access mismatch %d: got %+v want %+v; retained %s", i, got, want, out)
			}
		}
	}
	fmt.Printf("Native recompression access: %d cases on macOS %s; evidence %s\n", len(capture.Cases), version, out)
	return nil
}
