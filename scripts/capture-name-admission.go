//go:build ignore

// Capture native APFS admission by creating every Unicode scalar name.
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
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type control struct {
	Index  int
	Bytes  string
	Length int `json:"native_length"`
	Lookup int `json:"lookup_errno"`
	Create int `json:"create_errno"`
}
type observation struct {
	Filesystem          string
	Flags               uint32
	Sensitive           bool `json:"case_sensitive"`
	Capabilities, Valid [4]uint32
	Count               int `json:"scalar_count"`
	Seconds             float64
	Counts              map[int]int
	Controls            []control
}
type volume struct {
	Kind        string
	Native      observation
	Results     []byte
	ImageSHA256 string
}
type capture struct {
	Schema                        int
	Host, Compiler, SDK, Revision string
	Sources                       map[string]string
	Volumes                       []volume
}

const source = "testdata/appledouble/native/name-admission.c"

var bound = []string{source, "scripts/capture-name-admission.go", "scripts/capture-name-admission_test.go", ".github/workflows/name-admission.yml", "go.mod", "go.sum"}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w\n%s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", "artifacts/name-admission", "artifact directory")
	check := flag.Bool("check", false, "require exact native-version baseline")
	flag.Parse()
	if e := run(*out, *check); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out string, check bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native admission requires Darwin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	out, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
	c := capture{Schema: 1, Sources: map[string]string{}}
	for _, q := range []struct {
		dest *string
		name string
		args []string
	}{{&c.Host, "sw_vers", nil}, {&c.Compiler, "xcrun", []string{"clang", "--version"}}, {&c.SDK, "xcrun", []string{"--show-sdk-path"}}, {&c.Revision, "git", []string{"rev-parse", "HEAD"}}} {
		b, e := command(ctx, q.name, q.args...)
		if e != nil {
			return e
		}
		*q.dest = strings.TrimSpace(string(b))
	}
	v, e := osversion.ParseProductVersion(c.Host)
	if e != nil {
		return e
	}
	if _, e = osversion.ProfileForMacOS(v); e != nil {
		return e
	}
	for _, p := range bound {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		c.Sources[p] = sum(b)
	}
	binary := filepath.Join(out, "probe")
	if _, e = command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); e != nil {
		return e
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	c.Sources["native-binary"] = sum(b)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", c.SDK, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			return e
		}
		name := arch + ".ast.json"
		c.Sources[name] = sum(ast)
		if e = os.WriteFile(filepath.Join(out, name), ast, 0644); e != nil {
			return e
		}
	}
	for _, h := range []string{"sys/stat.h", "sys/mount.h", "sys/attr.h", "sys/fcntl.h", "unistd.h", "sys/errno.h"} {
		b, e := os.ReadFile(filepath.Join(c.SDK, "usr/include", h))
		if e != nil {
			return e
		}
		p := "SDK/" + h
		c.Sources[p] = sum(b)
		dest := filepath.Join(out, p)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			return e
		}
	}
	for _, kind := range []string{"APFS", "APFSX"} {
		v, e := captureVolume(ctx, out, kind, binary)
		if e != nil {
			return e
		}
		c.Volumes = append(c.Volumes, v)
	}
	if e = validate(c); e != nil {
		return e
	}
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	e = json.NewEncoder(z).Encode(c)
	if e = errors.Join(e, z.Close()); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "native.json.gz"), encoded.Bytes(), 0644); e != nil {
		return e
	}
	if check {
		prior, e := read(fmt.Sprintf("testdata/appledouble/native/name-admission-macos%d.json.gz", v.Major))
		if e != nil {
			return fmt.Errorf("required admission baseline: %w", e)
		}
		if e = compare(prior, c); e != nil {
			return e
		}
	}
	fmt.Printf("2224124 actual native scalar creations plus30 interface controls; macOS%s\n", v)
	return nil
}
func read(path string) (c capture, err error) {
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	z, e := gzip.NewReader(f)
	if e != nil {
		return c, e
	}
	defer func() { err = errors.Join(err, z.Close()) }()
	err = json.NewDecoder(z).Decode(&c)
	return c, err
}
func captureVolume(ctx context.Context, out, kind, binary string) (v volume, err error) {
	v.Kind = kind
	mount := filepath.Join(out, kind+"-mount")
	image := filepath.Join(out, kind+".dmg")
	if err = os.Mkdir(mount, 0700); err != nil {
		return v, err
	}
	fs := kind
	if kind == "APFSX" {
		fs = "Case-sensitive APFS"
	}
	if _, err = command(ctx, "hdiutil", "create", "-size", "128m", "-fs", fs, "-volname", "Admission", image); err != nil {
		return v, err
	}
	attached, e := command(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	if e != nil {
		return v, e
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = mount
	}
	detached := false
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var attempts []map[string]any
		e := diskimage.RetryDetach(cleanupCtx, func() (int, error) {
			b, e := exec.CommandContext(cleanupCtx, "hdiutil", "detach", device).CombinedOutput()
			code := 0
			if e != nil {
				code = -1
				var x *exec.ExitError
				if errors.As(e, &x) {
					code = x.ExitCode()
				}
			}
			attempts = append(attempts, map[string]any{"device": device, "exit_code": code, "output": string(b)})
			return code, e
		})
		b, j := json.Marshal(attempts)
		return errors.Join(e, j, os.WriteFile(filepath.Join(out, kind+"-detach.json"), b, 0644))
	}
	defer func() {
		if !detached {
			err = errors.Join(err, cleanup())
		}
	}()
	if e = os.WriteFile(filepath.Join(out, kind+"-attach.plist"), attached, 0644); e != nil || parseErr != nil {
		return v, errors.Join(e, parseErr)
	}
	results := filepath.Join(out, kind+"-scalars.bin")
	b, e := command(ctx, binary, mount, results)
	if e != nil {
		return v, e
	}
	if e = os.WriteFile(filepath.Join(out, kind+"-native.json"), b, 0644); e != nil {
		return v, e
	}
	if e = json.Unmarshal(b, &v.Native); e != nil {
		return v, e
	}
	v.Results, e = os.ReadFile(results)
	if e != nil {
		return v, e
	}
	if e = cleanup(); e != nil {
		return v, e
	}
	detached = true
	f, e := os.Open(image)
	if e != nil {
		return v, e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	if e = errors.Join(e, f.Close()); e != nil {
		return v, e
	}
	v.ImageSHA256 = hex.EncodeToString(h.Sum(nil))
	return v, nil
}

var controls = []string{"784179", "78c3a979", "78f09f988079", "78efbfbd79", "78cdb879", "78efb79079", "78f48fbfbf79", "788079", "78c0af79", "78e080af79", "78eda08079", "78f490808079", "78c3", "78007a", "782f79"}

func validate(c capture) error {
	if c.Schema != 1 || c.Host == "" || c.Compiler == "" || c.SDK == "" || c.Revision == "" || len(c.Volumes) != 2 {
		return errors.New("incomplete native admission capture")
	}
	for _, p := range append(append([]string{}, bound...), "native-binary", "arm64.ast.json", "x86_64.ast.json", "SDK/sys/stat.h", "SDK/sys/mount.h", "SDK/sys/attr.h", "SDK/sys/fcntl.h", "SDK/unistd.h", "SDK/sys/errno.h") {
		h, e := hex.DecodeString(c.Sources[p])
		if e != nil || len(h) != 32 {
			return fmt.Errorf("missing admission source %s", p)
		}
	}
	for i, v := range c.Volumes {
		want := []string{"APFS", "APFSX"}[i]
		if v.Kind != want || v.Native.Filesystem != "apfs" || v.Native.Sensitive != (i == 1) || v.Native.Valid[0]&0x100 == 0 || (v.Native.Capabilities[0]&0x100 != 0) != v.Native.Sensitive || v.Native.Count != 1112062 || len(v.Results) != 0x110000 || len(v.Native.Controls) != len(controls) {
			return errors.New("incorrect admission volume inventory")
		}
		h, e := hex.DecodeString(v.ImageSHA256)
		if e != nil || len(h) != 32 {
			return errors.New("missing image hash")
		}
		counts := map[int]int{}
		for scalar, status := range v.Results {
			excluded := scalar == 0 || scalar == 47 || (scalar >= 0xd800 && scalar <= 0xdfff)
			if excluded {
				if status != 255 {
					return errors.New("interface scalar was included")
				}
				continue
			}
			if status != 0 && status != 92 {
				return fmt.Errorf("unexpected native scalar errno %d at U+%04X", status, scalar)
			}
			counts[int(status)]++
		}
		if counts[0] < 100000 || len(counts) != len(v.Native.Counts) {
			return errors.New("missing admission positive controls")
		}
		for e, n := range counts {
			if v.Native.Counts[e] != n {
				return errors.New("incorrect admission counts")
			}
		}
		for _, r := range []rune{'A', 0xe9, 0x1f600, 0xfffd} {
			if v.Results[r] != 0 {
				return errors.New("native positive scalar rejected")
			}
		}
		for j, control := range v.Native.Controls {
			raw, _ := hex.DecodeString(controls[j])
			n := bytes.IndexByte(raw, 0)
			if n < 0 {
				n = len(raw)
			}
			if control.Index != j || control.Bytes != controls[j] || control.Length != n || control.Lookup != 2 {
				return errors.New("native interface control changed")
			}
			want := 92
			if j < 4 || j == 13 {
				want = 0
			}
			if j == 14 {
				want = 2
			}
			if control.Create != want {
				return fmt.Errorf("native interface outcome changed at%d: %d", j, control.Create)
			}
		}
	}
	return nil
}
func compare(a, b capture) error {
	if e := validate(a); e != nil {
		return e
	}
	if e := validate(b); e != nil {
		return e
	}
	for _, p := range bound {
		if a.Sources[p] != b.Sources[p] {
			return fmt.Errorf("stale admission source %s", p)
		}
	}
	for i, v := range a.Volumes {
		if !bytes.Equal(v.Results, b.Volumes[i].Results) {
			return fmt.Errorf("native scalar admission changed on%s", v.Kind)
		}
		for j, c := range v.Native.Controls {
			if c != b.Volumes[i].Native.Controls[j] {
				return errors.New("native admission interface changed")
			}
		}
	}
	return nil
}
