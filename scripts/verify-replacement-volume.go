//go:build ignore

// Qualify held replacement against actual volume capabilities and native time
// precision on each supported macOS runner. No filesystem is emulated here.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	if err := verifyVolume(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verifyVolume() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native replacement volume qualification requires macOS")
	}
	const dir = "artifacts/replacement-volume"
	const source = "testdata/appledouble/native/replacement-volume.c"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	sources := map[string]string{}
	bind := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		sources[path] = hex.EncodeToString(sum[:])
		return nil
	}
	for _, path := range []string{source, "scripts/verify-replacement-volume.go", "scripts/generate-darwin-wrappers.go", "internal/darwinabi/zsyscall_darwin_arm64.go", "internal/darwinabi/zsyscall_darwin_arm64.s", "internal/darwinabi/zsyscall_darwin_amd64.go", "internal/darwinabi/zsyscall_darwin_amd64.s", "pkg/hostdata/filesystem_metadata_storage.go", "pkg/hostdata/filesystem_metadata_storage_darwin.go", "pkg/hostdata/filesystem_metadata_storage_test.go", "pkg/hostdata/filesystem_metadata_storage_darwin_test.go", "pkg/hostdata/replacement_volume_darwin.go", "pkg/hostdata/replacement_volume_darwin_test.go", "pkg/hostdata/replacement_darwin.go", "pkg/hostdata/replacement_root_darwin.go", "pkg/hostdata/replacement_copy_darwin.go", "go.mod", "go.sum"} {
		if err := bind(path); err != nil {
			return err
		}
	}
	versions := map[string]string{}
	for name, argv := range map[string][]string{"host": {"sw_vers"}, "compiler": {"xcrun", "clang", "--version"}, "sdk": {"xcrun", "--show-sdk-path"}} {
		data, err := cirunner.Command(argv[0], argv[1:]...).Output()
		if err != nil {
			return err
		}
		versions[name] = string(data)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		data, err := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", source).Output()
		if err != nil {
			return err
		}
		if !json.Valid(data) || !bytes.Contains(data, []byte("fgetattrlist")) || !bytes.Contains(data, []byte("fsetattrlist")) {
			return fmt.Errorf("incomplete %s AST", arch)
		}
		path := filepath.Join(dir, arch+".ast.json.gz")
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		zipped := gzip.NewWriter(file)
		_, err = zipped.Write(data)
		if err = errors.Join(err, zipped.Close(), file.Close()); err != nil {
			return err
		}
		if err := bind(path); err != nil {
			return err
		}
	}
	oracle, err := filepath.Abs(filepath.Join(dir, "native-observer"))
	if err != nil {
		return err
	}
	if out, err := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", oracle).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w: %s", err, out)
	}
	if err := bind(oracle); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	profile := filepath.Join(dir, "coverage.out")
	cmd := cirunner.Command("go", "test", "-count=1", "-json", "-run", "^Test(ReplacementVolume|FilesystemMetadataStorage)", "-coverprofile="+profile, "./pkg/hostdata")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_REPLACEMENT_VOLUME_ORACLE="+oracle)
	var transcript bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	if err := errors.Join(cmd.Run(), log.Close()); err != nil {
		return err
	}
	passed := map[string]bool{}
	decoder := json.NewDecoder(&transcript)
	for {
		var event struct{ Action, Test string }
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("incomplete volume suite: %s %s", event.Action, event.Test)
		}
		if event.Action == "pass" {
			passed[event.Test] = true
		}
	}
	for _, filesystem := range []string{"APFS", "HFS+", "MS-DOS_FAT32", "ExFAT"} {
		for _, api := range []string{"path", "root"} {
			name := "TestReplacementVolumeDarwinNative/" + filesystem + "/" + api
			if !passed[name] {
				return fmt.Errorf("missing native outcome: %s", name)
			}
		}
	}
	if !passed["TestReplacementVolumeCapabilityFailures"] || !passed[""] {
		return fmt.Errorf("missing capability failure or package pass")
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		return err
	}
	covered, total := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], "/replacement_volume_darwin.go:") {
			continue
		}
		n, e := strconv.Atoi(fields[1])
		if e != nil {
			return e
		}
		hits, e := strconv.Atoi(fields[2])
		if e != nil {
			return e
		}
		total += n
		if hits > 0 {
			covered += n
		}
	}
	if total == 0 || covered*100 <= total*95 {
		return fmt.Errorf("volume capability coverage must exceed 95%%: %d/%d", covered, total)
	}
	report := map[string]any{"schema": 1, "complete": true, "versions": versions, "sources": sources, "native_cases": 8, "covered": covered, "statements": total, "purpose": "held filesystem xattr storage and ACL capability, metadata preservation and native creation-time precision"}
	data, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.json"), append(data, '\n'), 0600)
}
