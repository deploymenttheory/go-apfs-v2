//go:build ignore

// Qualify held Go compression installation on actual host/APFS/HFS+ volumes.
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
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"golang.org/x/sys/unix"
	"howett.net/plist"
)

const artifact = "artifacts/compression-installation-native"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func command(name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	code := 0
	if e != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			code = exit.ExitCode()
		}
	}
	return data, code, errors.Join(e, ctx.Err())
}
func run() (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native installation qualification requires macOS")
	}
	if e := os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	root, e := os.MkdirTemp("", "compression-installed-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(root)) }()
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return e
	}
	report := map[string]any{}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		counts, e := qualify(root, filesystem)
		if e != nil {
			return e
		}
		report[filesystem] = counts
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{"pkg/hostdata/compression_*.go", "pkg/osversion/*.go", "pkg/hostdata/resource_fork*.go", "internal/darwinabi/*.go", "internal/darwinabi/*.s", "testdata/appledouble/native/resource-fork-open*", "scripts/capture-resource-fork-open.go", "testdata/appledouble/native/compression-operation*.json.gz", "scripts/verify-compression-installation-native.go", "testdata/appledouble/native/compression-lifecycle.json.gz", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	revision, _, e := command("git", "rev-parse", "HEAD")
	if e != nil {
		return e
	}
	report["source_sha256"] = hashes
	report["revision"] = strings.TrimSpace(string(revision))
	report["go"] = runtime.Version()
	report["goarch"] = runtime.GOARCH
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(artifact, "report.json"), b, 0600); e != nil {
		return e
	}
	fmt.Println("Native Go installation: 492 complete held-file installation/recompression/resource-fork kernel-readback cases across host/APFS/HFS+; all cases required")
	return nil
}
func qualify(root, filesystem string) (counts map[string]int, result error) {
	dir := filepath.Join(artifact, filesystem)
	if e := os.MkdirAll(dir, 0755); e != nil {
		return nil, e
	}
	mount := filepath.Join(root, filesystem)
	if e := os.Mkdir(mount, 0700); e != nil {
		return nil, e
	}
	if filesystem != "host" {
		image := filepath.Join(root, filesystem+".dmg")
		out, _, e := command("hdiutil", "create", "-size", "256m", "-fs", filesystem, "-volname", "CompressionInstalled", image)
		if e != nil {
			return nil, fmt.Errorf("create %s: %w: %s", filesystem, e, out)
		}
		out, _, e = command("hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
		if e != nil {
			return nil, fmt.Errorf("attach %s: %w: %s", filesystem, e, out)
		}
		device, e := diskimage.AttachmentDevice(out)
		if e != nil {
			_, _, cleanup := command("hdiutil", "detach", mount)
			return nil, errors.Join(e, cleanup)
		}
		defer func() {
			var attempts []map[string]any
			e := diskimage.RetryDetach(context.Background(), func() (int, error) {
				out, code, e := command("hdiutil", "detach", device)
				attempts = append(attempts, map[string]any{"device": device, "exit": code, "output": string(out)})
				return code, e
			})
			b, encode := json.MarshalIndent(attempts, "", "  ")
			result = errors.Join(result, e, encode, os.WriteFile(filepath.Join(dir, "detach.json"), b, 0600))
		}()
		if e = os.WriteFile(filepath.Join(dir, "attach.plist"), out, 0600); e != nil {
			return nil, e
		}
	}
	var mounted unix.Statfs_t
	if e := unix.Statfs(mount, &mounted); e != nil {
		return nil, e
	}
	volume, _, e := command("diskutil", "info", "-plist", unix.ByteSliceToString(mounted.Mntonname[:]))
	if e != nil {
		return nil, fmt.Errorf("volume: %w: %s", e, volume)
	}
	if e = os.WriteFile(filepath.Join(dir, "volume.plist"), volume, 0600); e != nil {
		return nil, e
	}
	var info struct {
		Type string `plist:"FilesystemType"`
	}
	if _, e = plist.Unmarshal(volume, &info); e != nil {
		return nil, e
	}
	if info.Type == "" || filesystem == "APFS" && info.Type != "apfs" || filesystem == "HFS+" && info.Type != "hfs" {
		return nil, fmt.Errorf("unexpected mounted filesystem %s: %s", filesystem, info.Type)
	}
	log, e := os.Create(filepath.Join(dir, "tests.jsonl"))
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run=^Test((Install|Commit)HeldCompressionNativeReadback|RecompressNativeFiles|CompressionResourceForkOpeningNative)$", "./pkg/hostdata")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APFS_COMPRESSION_MOUNT="+mount, "APFS_COMPRESSION_FILESYSTEM="+filesystem)
	var transcript bytes.Buffer
	cmd.Stdout = io.MultiWriter(log, &transcript)
	cmd.Stderr = io.MultiWriter(os.Stderr, log)
	runErr := cmd.Run()
	if e = errors.Join(runErr, log.Close(), ctx.Err()); e != nil {
		return nil, e
	}
	counts = map[string]int{"TestInstallHeldCompressionNativeReadback": 0, "TestCommitHeldCompressionNativeReadback": 0, "TestRecompressNativeFiles": 0, "TestCompressionResourceForkOpeningNative": 0}
	top := map[string]bool{}
	for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if e = json.Unmarshal(line, &event); e != nil {
			return nil, e
		}
		if event.Action == "skip" || event.Action == "fail" {
			return nil, fmt.Errorf("native installation skipped/failed: %s", event.Test)
		}
		if event.Action != "pass" || event.Test == "" {
			continue
		}
		name, _, child := strings.Cut(event.Test, "/")
		if _, ok := counts[name]; !ok {
			return nil, fmt.Errorf("unexpected native installation suite: %s", event.Test)
		}
		if child {
			counts[name]++
		} else {
			top[name] = true
		}
	}
	for name, n := range counts {
		want := 66
		if name == "TestRecompressNativeFiles" {
			want = 22
		}
		if name == "TestCompressionResourceForkOpeningNative" {
			want = 10
		}
		if n != want || !top[name] {
			return nil, fmt.Errorf("incomplete %s/%s: %d/%d", filesystem, name, n, want)
		}
	}
	return counts, nil
}
