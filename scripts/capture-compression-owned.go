//go:build ignore

// Capture independent native rooted acquisition and held volume observations.
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
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type capture struct {
	Schema              int
	Host, Compiler, SDK string
	Sources             map[string]string
	Cases               []trial
}
type trial struct {
	Filesystem  string
	Observation json.RawMessage
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", "artifacts/compression-owned/native.json.gz", "fresh observations")
	check := flag.Bool("check", false, "compare the complete retained profile")
	flag.Parse()
	if err := run(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(out string, check bool) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native capture requires macOS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	host, e := command(ctx, "sw_vers")
	if e != nil {
		return e
	}
	version, e := osversion.ParseProductVersion(string(host))
	if e != nil {
		return e
	}
	if _, e = osversion.ProfileForMacOS(version); e != nil {
		return e
	}
	baseline := fmt.Sprintf("testdata/appledouble/native/compression-owned-macos%d.json.gz", version.Major)
	absolute, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	retained, e := filepath.Abs(baseline)
	if e != nil {
		return e
	}
	if check && absolute == retained {
		return errors.New("fresh capture must not overwrite retained evidence")
	}
	artifact := filepath.Dir(out)
	if e = os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	directory, e := os.MkdirTemp("", "compression-owned-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(directory)) }()
	directory, e = filepath.EvalSymlinks(directory)
	if e != nil {
		return e
	}
	report := capture{Schema: 1, Host: string(host), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), artifact, report.Sources); err != nil {
		return err
	}
	hashFile := func(name, key string) error {
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		report.Sources[key] = fmt.Sprintf("%x", sha256.Sum256(b))
		return nil
	}
	const source = "testdata/appledouble/native/compression-owned.c"
	for _, name := range []string{source, "scripts/capture-compression-owned.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
		if e = hashFile(name, name); e != nil {
			return e
		}
	}
	helper := filepath.Join(artifact, "native")
	if _, e = command(ctx, "xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-lz", "-o", helper); e != nil {
		return e
	}
	if e = hashFile(helper, "native-binary"); e != nil {
		return e
	}
	b, e := command(ctx, "xcrun", "clang", "--version")
	if e != nil {
		return e
	}
	report.Compiler = string(b)
	b, e = command(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	report.SDK = strings.TrimSpace(string(b))
	for _, header := range []string{"sys/stat.h", "sys/mount.h", "sys/xattr.h", "fcntl.h", "unistd.h", "zlib.h"} {
		name := filepath.Join(report.SDK, "usr/include", header)
		if e = hashFile(name, name); e != nil {
			return e
		}
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e = command(ctx, "xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("CompoundStmt")) {
			return errors.New("incomplete AST")
		}
		name := arch + "-compression-owned.ast.json"
		if e = os.WriteFile(filepath.Join(artifact, name), b, 0644); e != nil {
			return e
		}
		report.Sources[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		e = func() (err error) {
			base := directory
			if filesystem != "host" {
				var cleanup func() error
				base, cleanup, err = mount(ctx, directory, filesystem, artifact)
				if err != nil {
					return err
				}
				defer func() { err = errors.Join(err, cleanup()) }()
			}
			for _, compressed := range []string{"0", "1", "2"} {
				for _, route := range []string{"direct", "root"} {
					for _, mutation := range []string{"none", "root-before", "root-after", "leaf-after"} {
						path := filepath.Join(base, "case-"+compressed+"-"+route+"-"+mutation)
						b, e := command(ctx, helper, path, route, mutation, compressed)
						if e != nil {
							return e
						}
						if !json.Valid(b) {
							return errors.New("invalid native observation")
						}
						report.Cases = append(report.Cases, trial{filesystem, json.RawMessage(b)})
					}
				}
			}

			mounted := report
			mounted.Cases = report.Cases[len(report.Cases)-24:]
			observed, e := json.Marshal(mounted)
			if e != nil {
				return e
			}
			capturedPath, e := filepath.Abs(filepath.Join(artifact, strings.ReplaceAll(filesystem, "+", "plus")+"-cases.json"))
			if e != nil {
				return e
			}
			if e = os.WriteFile(capturedPath, observed, 0644); e != nil {
				return e
			}
			replay := cirunner.CommandContext(ctx, "go", "test", "-count=1", "-json", "./pkg/hostdata", "-run", "^TestNativeCompressionOwnedMounted$")
			replay.Env = append(os.Environ(), "APFS_COMPRESSION_OWNED_MOUNT="+base, "APFS_COMPRESSION_OWNED_CAPTURE="+capturedPath)
			transcript, replayErr := replay.CombinedOutput()
			writeErr := os.WriteFile(filepath.Join(artifact, strings.ReplaceAll(filesystem, "+", "plus")+"-replay.jsonl"), transcript, 0644)
			if replayErr != nil || writeErr != nil {
				return errors.Join(fmt.Errorf("mounted native API replay %s: %w: %s", filesystem, replayErr, transcript), writeErr)
			}
			return nil
		}()
		if e != nil {
			return e
		}
	}
	b, e = json.Marshal(report)
	if e != nil {
		return e
	}
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	_, e = z.Write(b)
	if e = errors.Join(e, z.Close(), f.Close()); e != nil {
		return e
	}
	if len(report.Cases) != 72 {
		return fmt.Errorf("incomplete inventory %d", len(report.Cases))
	}
	if check {
		previous, e := readCapture(baseline)
		if e != nil {
			return e
		}
		if e = compare(previous, report); e != nil {
			return e
		}
	}
	fmt.Printf("72 native held-input cases across host/APFS/HFS+; macOS %s\n", version)
	return nil
}
func mount(ctx context.Context, directory, kind, artifact string) (string, func() error, error) {
	name := strings.ReplaceAll(kind, "+", "plus")
	image := filepath.Join(directory, name+".dmg")
	root := filepath.Join(directory, name+"-mount")
	if e := os.Mkdir(root, 0700); e != nil {
		return "", nil, e
	}
	if _, e := command(ctx, "hdiutil", "create", "-size", "64m", "-fs", kind, "-volname", "OwnedCompression", image); e != nil {
		return "", nil, e
	}
	attached, e := command(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", root, image)
	if e != nil {
		return "", nil, e
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = root
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var attempts []map[string]any
		e := diskimage.RetryDetach(cleanupCtx, func() (int, error) {
			b, e := cirunner.CommandContext(cleanupCtx, "hdiutil", "detach", device).CombinedOutput()
			code := 0
			if e != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(e, &exit) {
					code = exit.ExitCode()
				}
			}
			attempts = append(attempts, map[string]any{"device": device, "output": string(b), "exit_code": code})
			return code, e
		})
		b, marshalErr := json.Marshal(attempts)
		return errors.Join(e, marshalErr, os.WriteFile(filepath.Join(artifact, name+"-detach.json"), b, 0644))
	}
	if e = os.WriteFile(filepath.Join(artifact, name+"-attach.plist"), attached, 0644); e != nil || parseErr != nil {
		return "", nil, errors.Join(e, parseErr, cleanup())
	}
	return root, cleanup, nil
}
func readCapture(name string) (capture, error) {
	var c capture
	f, e := os.Open(name)
	if e != nil {
		return c, e
	}
	z, e := gzip.NewReader(f)
	if e != nil {
		return c, errors.Join(e, f.Close())
	}
	e = json.NewDecoder(z).Decode(&c)
	return c, errors.Join(e, z.Close(), f.Close())
}

// Compare stable native results, retaining the full timestamp/identity snapshots
// in both archives. Absolute inode numbers and operation-clock times are not
// reproducible across independent files; relationships are checked by replay.
func compare(before, after capture) error {
	for _, sources := range []map[string]string{before.Sources, after.Sources} {
		if err := captureprovenance.Verify(os.DirFS("."), sources); err != nil {
			return err
		}
	}
	if before.Schema != 1 || len(before.Cases) != 72 || len(after.Cases) != 72 {
		return errors.New("incomplete retained capture")
	}
	for _, name := range []string{"testdata/appledouble/native/compression-owned.c", "scripts/capture-compression-owned.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
		if before.Sources[name] != after.Sources[name] {
			return fmt.Errorf("stale source %s", name)
		}
	}
	normalize := func(raw json.RawMessage) ([]byte, error) {
		var v map[string]any
		if e := json.Unmarshal(raw, &v); e != nil {
			return nil, e
		}
		for _, key := range []string{"before", "after_open", "after_duplicate", "after_zero_write", "after_close"} {
			if state, ok := v[key].(map[string]any); ok {
				for _, name := range []string{"dev", "inode", "mtime", "atime", "ctime", "birth", "mount_flags"} {
					delete(state, name)
				}
			}
		}
		return json.Marshal(v)
	}
	for i, old := range before.Cases {
		fresh := after.Cases[i]
		if old.Filesystem != fresh.Filesystem {
			return fmt.Errorf("filesystem inventory %d", i)
		}
		a, e := normalize(old.Observation)
		if e != nil {
			return e
		}
		b, e := normalize(fresh.Observation)
		if e != nil {
			return e
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("native case differs %d/%s", i, old.Filesystem)
		}
	}
	return nil
}
