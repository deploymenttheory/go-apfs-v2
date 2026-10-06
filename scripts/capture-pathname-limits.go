//go:build ignore

// Capture independent native pathname length, symlink and error-order controls.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type mountedImage struct {
	image, root, device, name, artifact string
	attaches, detaches                  int
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (i *mountedImage) attach(ctx context.Context, readonly bool) error {
	args := []string{"attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", i.root}
	if readonly {
		args = append(args, "-readonly")
	}
	args = append(args, i.image)
	b, e := runCommand(ctx, "hdiutil", args...)
	i.attaches++
	recordErr := os.WriteFile(filepath.Join(i.artifact, fmt.Sprintf("%s-attach-%d.plist", i.name, i.attaches)), b, 0644)
	if e != nil {
		return errors.Join(e, recordErr)
	}
	device, parseErr := diskimage.AttachmentDevice(b)
	if device == "" {
		device = i.root
	}
	i.device = device
	return errors.Join(parseErr, recordErr)
}
func (i *mountedImage) detach() error {
	if i.device == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var attempts []map[string]any
	e := diskimage.RetryDetach(ctx, func() (int, error) {
		b, e := exec.CommandContext(ctx, "hdiutil", "detach", i.device).CombinedOutput()
		code := 0
		if e != nil {
			code = -1
			var exit *exec.ExitError
			if errors.As(e, &exit) {
				code = exit.ExitCode()
			}
		}
		attempts = append(attempts, map[string]any{"device": i.device, "exit_code": code, "output": string(b)})
		return code, e
	})
	i.detaches++
	recordErr := writeJSON(filepath.Join(i.artifact, fmt.Sprintf("%s-detach-%d.json", i.name, i.detaches)), attempts)
	if e == nil {
		i.device = ""
	}
	return errors.Join(e, recordErr)
}
func makeImage(ctx context.Context, dir, kind string) (*mountedImage, error) {
	name := strings.ReplaceAll(kind, "+", "plus")
	i := &mountedImage{image: filepath.Join(dir, name+".dmg"), root: filepath.Join(dir, name+"-mount"), name: name, artifact: dir}
	if e := os.Mkdir(i.root, 0700); e != nil {
		return nil, e
	}
	nativeKind := kind
	if kind == "APFSX" {
		nativeKind = "Case-sensitive APFS"
	}
	if kind == "HFSX" {
		nativeKind = "Case-sensitive HFS+"
	}
	if _, e := runCommand(ctx, "hdiutil", "create", "-size", "64m", "-fs", nativeKind, "-volname", "PathnameAuthority", i.image); e != nil {
		return nil, e
	}
	return i, i.attach(ctx, false)
}

func main() {
	out := flag.String("out", "artifacts/pathname-limits", "new capture directory")
	flag.Parse()
	if err := captureLimits(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func captureLimits(out string) (result error) {
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		return errors.New("requires ordinary Darwin actor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	out, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	source, err := os.ReadFile("testdata/appledouble/native/pathname-limits.c")
	if err != nil {
		return err
	}
	script, err := os.ReadFile("scripts/capture-pathname-limits.go")
	if err != nil {
		return err
	}
	oracle := filepath.Join(out, "probe.c")
	if err = os.WriteFile(oracle, source, 0644); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "capture.go"), script, 0644); err != nil {
		return err
	}
	sdkBytes, err := runCommand(ctx, "xcrun", "--sdk", "macosx", "--show-sdk-path")
	if err != nil {
		return err
	}
	sdk := strings.TrimSpace(string(sdkBytes))
	compiler, err := runCommand(ctx, "xcrun", "clang", "--version")
	if err != nil {
		return err
	}
	binary := filepath.Join(out, "probe")
	if _, err = runCommand(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", oracle, "-o", binary); err != nil {
		return err
	}
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	sources := map[string]string{"probe.c": hash(source), "capture.go": hash(script), "probe": hash(binaryBytes)}
	for _, target := range []string{"arm64-apple-macos15", "x86_64-apple-macos15"} {
		ast, err := runCommand(ctx, "xcrun", "clang", "-target", target, "-isysroot", sdk, "-std=c11", "-Xclang", "-ast-dump=json", "-fsyntax-only", oracle)
		if err != nil {
			return err
		}
		name := target + ".ast.json"
		if err = os.WriteFile(filepath.Join(out, name), ast, 0644); err != nil {
			return err
		}
		sources[name] = hash(ast)
	}
	for _, header := range []string{"sys/stat.h", "sys/mount.h", "sys/attr.h", "sys/acl.h", "sys/fcntl.h", "sys/resource.h", "sys/param.h"} {
		raw, err := os.ReadFile(filepath.Join(sdk, "usr/include", header))
		if err != nil {
			return err
		}
		name := "SDK/" + header
		if err = os.MkdirAll(filepath.Dir(filepath.Join(out, name)), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(out, name), raw, 0644); err != nil {
			return err
		}
		sources[name] = hash(raw)
	}
	for _, header := range []string{"resource_private.h", "param.h", "syslimits.h"} {
		compressed, err := os.ReadFile("testdata/appledouble/native/pathname-authorization-source/headers/" + header + ".gz")
		if err != nil {
			return err
		}
		z, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return err
		}
		raw, readErr := io.ReadAll(z)
		if err = errors.Join(readErr, z.Close()); err != nil {
			return err
		}
		name := "XNU/" + header
		if err = os.MkdirAll(filepath.Dir(filepath.Join(out, name)), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(out, name), raw, 0644); err != nil {
			return err
		}
		sources[name] = hash(raw)
	}
	host, err := runCommand(ctx, "sw_vers")
	if err != nil {
		return err
	}
	rows := []map[string]any{}
	observe := func(label, root string) error {
		raw, err := runCommand(ctx, binary, root)
		if err != nil {
			return err
		}
		var native map[string]any
		if err = json.Unmarshal(raw, &native); err != nil {
			return err
		}
		cases, ok := native["cases"].([]any)
		if !ok || len(cases) != 26 || native["cleanup_complete"] != true || native["fixture_acl_observed_empty"] != true {
			return errors.New("incomplete native path-limit oracle")
		}
		rows = append(rows, map[string]any{"volume": label, "native": native})
		return writeJSON(filepath.Join(out, "observations.json"), rows)
	}
	if err = observe("host", os.TempDir()); err != nil {
		return err
	}
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		image, err := makeImage(ctx, out, kind)
		if err != nil {
			if image != nil {
				err = errors.Join(err, image.detach())
			}
			return err
		}
		if err = observe(kind, image.root); err != nil {
			return errors.Join(err, image.detach())
		}
		if err = image.detach(); err != nil {
			return err
		}
	}
	report := map[string]any{"schema": 1, "host": string(host), "compiler": string(compiler), "sdk": sdk, "source_sha256": sources, "expected_volumes": 5, "expected_cases": 130, "volumes": rows, "mounts_detached": true, "scope": "Native ordinary-process path limits, link traversal and error ordering. Failed private long-path enable setters are retained and do not qualify enabled policy."}
	if err = writeJSON(filepath.Join(out, "capture.json"), report); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(out, "capture.json"))
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(out, "capture.json.gz"))
	if err != nil {
		return err
	}
	z := gzip.NewWriter(f)
	_, writeErr := z.Write(raw)
	return errors.Join(writeErr, z.Close(), f.Close())
}
