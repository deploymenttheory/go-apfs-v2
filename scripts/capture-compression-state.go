//go:build ignore

// Retain native images and exact readback for active and inactive decmpfs storage.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

const fixture = "testdata/appledouble/native/compression-state.json.gz"
const artifact = "artifacts/compression-state"

type observation struct {
	Flags          uint32 `json:"flags"`
	Size           int64  `json:"size"`
	Mode           uint32 `json:"mode"`
	AttributeSize  int64  `json:"attr_size"`
	AttributeErrno int    `json:"attr_errno"`
	ForkSize       int64  `json:"fork_size"`
	ForkErrno      int    `json:"fork_errno"`
	ReadErrno      int    `json:"read_errno"`
	ReadSize       int64  `json:"read_size"`
}
type sample struct {
	Filesystem, Name, State string
	Attribute, Fork, Data   []byte
	Observation             observation
}
type corpus struct {
	Schema              int
	Host, Compiler, SDK string
	Sources, Images     map[string]string
	Cases               []sample
}

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, ctx.Err()
}
func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func load(path string, v any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer z.Close()
	return json.NewDecoder(z).Decode(v)
}
func save(path string, v any) error {
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	e = json.NewEncoder(z).Encode(v)
	return errors.Join(e, z.Close(), f.Close())
}
func main() {
	out := flag.String("out", artifact+"/observed.json.gz", "fresh observation file")
	check := flag.Bool("check", false, "compare every retained case without overwriting the baseline")
	foreign := flag.String("foreign", "", "verify all producer images in this directory instead of creating native images")
	flag.Parse()
	if e := run(*out, *check, *foreign); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out string, check bool, foreign string) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native compression state requires macOS")
	}
	if check {
		a, e := filepath.Abs(out)
		if e != nil {
			return e
		}
		b, e := filepath.Abs(fixture)
		if e != nil {
			return e
		}
		if a == b {
			return errors.New("check cannot overwrite baseline")
		}
	}
	if e := os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	root, e := os.MkdirTemp("", "compression-state-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(root)) }()
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return e
	}
	c := corpus{Schema: 1, Sources: map[string]string{}, Images: map[string]string{}}
	for _, item := range []struct {
		name string
		args []string
		dst  *string
	}{{"sw_vers", nil, &c.Host}, {"xcrun", []string{"clang", "--version"}, &c.Compiler}, {"xcrun", []string{"--show-sdk-version"}, &c.SDK}} {
		b, e := command(item.name, item.args...)
		if e != nil {
			return e
		}
		*item.dst = string(b)
	}
	const source = "testdata/appledouble/native/compression-state.c"
	for _, path := range []string{source, "scripts/capture-compression-state.go", "testdata/appledouble/native/compression-lifecycle.json.gz", "go.mod", "go.sum"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		c.Sources[path] = digest(b)
	}
	helper := filepath.Join(root, "oracle")
	if _, e = command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper); e != nil {
		return e
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("CompoundStmt")) {
			return errors.New("incomplete C AST")
		}
		name := arch + "-compression-state.ast.json"
		c.Sources[name] = digest(b)
		if e = os.WriteFile(filepath.Join(artifact, name), b, 0644); e != nil {
			return e
		}
	}
	sdk, e := command("xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	for _, name := range []string{"sys/stat.h", "sys/xattr.h", "fcntl.h"} {
		path := filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", name)
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		c.Sources[path] = digest(b)
	}
	if foreign != "" {
		return verifyForeign(root, helper, foreign, c)
	}
	var lifecycle struct {
		Cases []struct {
			Filesystem, Scenario, Requested, Inline, Fault string
			Attribute, Fork, Data                          []byte
		}
	}
	if e = load("testdata/appledouble/native/compression-lifecycle.json.gz", &lifecycle); e != nil {
		return e
	}
	for _, fs := range []string{"APFS", "HFS+"} {
		image := filepath.Join(root, fs+".dmg")
		if _, e = command("hdiutil", "create", "-size", "256m", "-fs", fs, "-volname", "CompressionState", image); e != nil {
			return e
		}
		mount := filepath.Join(root, fs)
		if e = os.Mkdir(mount, 0700); e != nil {
			return e
		}
		e = mounted(image, mount, false, func() error {
			templates := 0
			for _, base := range lifecycle.Cases {
				if base.Filesystem != fs || base.Scenario != "ordinary" || base.Fault != "" || base.Requested == "default" {
					continue
				}
				if base.Requested != "3" && base.Requested != "7" && base.Requested != "9" && base.Requested != "11" && base.Requested != "13" {
					continue
				}
				templates++
				for _, state := range []string{"active", "full", "empty", "edit", "bad-header", "short-header", "unknown-type", "no-fork"} {
					name := fmt.Sprintf("codec-%s-%s-%s", base.Requested, base.Inline, state)
					s := sample{Filesystem: fs, Name: name, State: state, Attribute: bytes.Clone(base.Attribute), Fork: bytes.Clone(base.Fork), Data: bytes.Clone(base.Data)}
					flags := uint32(0x8000)
					mutate := "keep"
					switch state {
					case "active":
						flags |= 0x20
					case "empty":
						s.Data = nil
					case "edit":
						mutate = "edit"
					case "bad-header":
						s.Attribute = []byte("stale")
					case "short-header":
						s.Attribute = s.Attribute[:8]
					case "unknown-type":
						binary.LittleEndian.PutUint32(s.Attribute[4:], 0xdeadbeef)
					case "no-fork":
						s.Fork = nil
					}
					data := s.Data
					if state == "active" {
						data = nil
					}
					prefix := filepath.Join(root, "input")
					for suffix, b := range map[string][]byte{"attr": s.Attribute, "fork": s.Fork, "data": data} {
						if e := os.WriteFile(prefix+"."+suffix, b, 0600); e != nil {
							return e
						}
					}
					fork := prefix + ".fork"
					if len(s.Fork) == 0 {
						fork = "-"
					}
					path := filepath.Join(mount, name)
					if _, e := command(helper, "create", path, prefix+".attr", fork, prefix+".data", fmt.Sprint(flags), mutate); e != nil {
						return e
					}
					if state == "edit" {
						copy(s.Data, "WXYZ")
					}
					observed, e := observe(helper, path, filepath.Join(root, "observed"))
					if e != nil {
						return e
					}
					if observed.Observation.Flags != flags || observed.Observation.Size != int64(len(s.Data)) || observed.Observation.ReadErrno != 0 || !bytes.Equal(observed.Data, s.Data) || !bytes.Equal(observed.Attribute, s.Attribute) || !bytes.Equal(observed.Fork, s.Fork) {
						return fmt.Errorf("native state changed unexpectedly: %s/%s: %+v", fs, name, observed.Observation)
					}
					s.Observation = observed.Observation
					c.Cases = append(c.Cases, s)
				}
			}
			if templates != 10 {
				return fmt.Errorf("%s template inventory %d != 10", fs, templates)
			}
			return nil
		})
		if e != nil {
			return e
		}
		dst := filepath.Join(artifact, fs+".dmg")
		if _, e = command("hdiutil", "convert", image, "-format", "UDZO", "-o", dst, "-ov"); e != nil {
			return e
		}
		b, e := os.ReadFile(dst)
		if e != nil {
			return e
		}
		c.Images[fs+".dmg"] = digest(b)
	}
	if len(c.Cases) != 160 {
		return fmt.Errorf("case inventory %d != 160", len(c.Cases))
	}
	if e = save(out, c); e != nil {
		return e
	}
	if check {
		var retained corpus
		if e = load(fixture, &retained); e != nil {
			return e
		}
		if !reflect.DeepEqual(c.Cases, retained.Cases) {
			return errors.New("native state differs from retained 160 cases")
		}
	}
	fmt.Println("160 native compression-state cases, APFS and HFS+, exact storage/data/flags and retained images")
	return nil
}
func mounted(image, mount string, readonly bool, fn func() error) (result error) {
	args := []string{"attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount}
	if readonly {
		args = append(args, "-readonly")
	}
	args = append(args, image)
	out, e := command("hdiutil", args...)
	if e != nil {
		return e
	}
	device, e := diskimage.AttachmentDevice(out)
	if e != nil {
		_, cleanup := command("hdiutil", "detach", mount)
		return errors.Join(e, cleanup)
	}
	logPrefix := filepath.Join(artifact, filepath.Base(image))
	defer func() {
		var attempts []map[string]any
		result = errors.Join(result, diskimage.RetryDetach(context.Background(), func() (int, error) {
			out, e := command("hdiutil", "detach", device)
			code := 0
			if e != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(e, &exit) {
					code = exit.ExitCode()
				}
			}
			attempts = append(attempts, map[string]any{"device": device, "exit": code, "output": string(out)})
			if e == nil {
				return 0, nil
			}
			var exit *exec.ExitError
			if errors.As(e, &exit) {
				return exit.ExitCode(), e
			}
			return -1, e
		}))
		b, encode := json.MarshalIndent(attempts, "", "  ")
		result = errors.Join(result, encode, os.WriteFile(logPrefix+".detach.json", b, 0600))
	}()
	if e = os.WriteFile(logPrefix+".attach.plist", out, 0600); e != nil {
		return e
	}
	return fn()
}
func observe(helper, path, prefix string) (sample, error) {
	var s sample
	b, e := command(helper, "observe", path, prefix)
	if e != nil {
		return s, e
	}
	if e = json.Unmarshal(b, &s.Observation); e != nil {
		return s, e
	}
	if e = os.WriteFile(prefix+".json", b, 0600); e != nil {
		return s, e
	}
	for suffix, dst := range map[string]*[]byte{"attr": &s.Attribute, "fork": &s.Fork, "data": &s.Data} {
		*dst, e = os.ReadFile(prefix + "." + suffix)
		if e != nil {
			return s, e
		}
	}
	return s, nil
}
func verifyForeign(root, helper, foreign string, observed corpus) error {
	var c corpus
	if e := load(fixture, &c); e != nil {
		return e
	}
	images, e := filepath.Glob(filepath.Join(foreign, "*.dmg"))
	if e != nil {
		return e
	}
	if len(images) != 2 {
		return fmt.Errorf("foreign image inventory %d != 2", len(images))
	}
	total := 0
	for _, image := range images {
		fs := strings.TrimSuffix(filepath.Base(image), ".dmg")
		if fs != "APFS" && fs != "HFS+" {
			return fmt.Errorf("unknown foreign image %s", fs)
		}
		mount := filepath.Join(root, fs)
		if e = os.Mkdir(mount, 0700); e != nil {
			return e
		}
		if e = mounted(image, mount, true, func() error {
			for _, want := range c.Cases {
				if want.Filesystem != fs {
					continue
				}
				got, e := observe(helper, filepath.Join(mount, want.Name), filepath.Join(root, "foreign"))
				if e != nil {
					return e
				}
				if got.Observation != want.Observation || !bytes.Equal(got.Data, want.Data) || !bytes.Equal(got.Attribute, want.Attribute) || !bytes.Equal(got.Fork, want.Fork) {
					return fmt.Errorf("foreign native mismatch %s/%s: %+v != %+v", fs, want.Name, got.Observation, want.Observation)
				}
				got.Filesystem, got.Name, got.State = want.Filesystem, want.Name, want.State
				observed.Cases = append(observed.Cases, got)
				total++
			}
			return nil
		}); e != nil {
			return e
		}
		for _, suffix := range []string{".attach.plist", ".detach.json"} {
			b, e := os.ReadFile(filepath.Join(artifact, filepath.Base(image)+suffix))
			if e != nil {
				return e
			}
			if e = os.WriteFile(image+suffix, b, 0600); e != nil {
				return e
			}
		}
		b, e := os.ReadFile(image)
		if e != nil {
			return e
		}
		observed.Images[filepath.Base(image)] = digest(b)
	}
	if total != 160 {
		return fmt.Errorf("foreign inventory %d != 160", total)
	}
	if e = save(filepath.Join(foreign, "native-readback.json.gz"), observed); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(foreign, "native-readback.txt"), []byte("160 complete native readbacks passed\n"), 0644)
}
