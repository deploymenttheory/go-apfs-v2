//go:build ignore

// Independently mount every foreign producer image and compare native C/kernel
// observations to the complete portable result, whose bytes were qualified
// against retained native operation profiles during production.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type expectedCase struct {
	Name, Scenario, Requested, Inline string
	IdentityGroup                     string
	Links                             uint32
	Attribute, Fork, Data             []byte
	Mode, Flags                       uint32
	Birth, Modify, Change, Access     time.Time
}
type expectedImage struct {
	Schema                                          int
	Profile, Filesystem, ImageSHA256, FixtureSHA256 string
	Cases                                           []expectedCase
}
type observedCase struct {
	BirthSec   int64  `json:"birth_sec"`
	BirthNsec  int64  `json:"birth_nsec"`
	ChangeSec  int64  `json:"change_sec"`
	ChangeNsec int64  `json:"change_nsec"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Flags      uint32 `json:"flags"`
	Mode       uint32 `json:"mode"`
	Links      uint32 `json:"links"`
	Inode      uint64 `json:"inode"`
	ModifySec  int64  `json:"modify_sec"`
	ModifyNsec int64  `json:"modify_nsec"`
	AccessSec  int64  `json:"access_sec"`
	AccessNsec int64  `json:"access_nsec"`
	ReadSize   int64  `json:"read_size"`
}

func main() {
	foreign := flag.String("foreign", "", "producer artifact directory")
	flag.Parse()
	if e := run(*foreign); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func digest(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil)), errors.Join(e, f.Close())
}
func run(foreign string) (err error) {
	if runtime.GOOS != "darwin" || foreign == "" {
		return errors.New("native carrier readback requires macOS and explicit producer artifact directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	foreign, e := filepath.Abs(foreign)
	if e != nil {
		return e
	}
	// The producer evidence binds each image to this exact PR merge checkout,
	// source set and a no-skip transcript with >95 percent production coverage.
	producerReport, e := os.ReadFile(filepath.Join(foreign, "coverage.json"))
	if e != nil {
		return e
	}
	var producer struct{ Revision, GOOS string }
	if e = json.Unmarshal(producerReport, &producer); e != nil {
		return e
	}
	revision, e := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if e != nil {
		return e
	}
	if e = evidenceaudit.Coverage(os.DirFS("."), os.DirFS(filepath.Dir(foreign)), filepath.Base(foreign), strings.TrimSpace(string(revision)), producer.GOOS); e != nil {
		return e
	}
	artifact := filepath.Join(foreign, "native-readback")
	if e = os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	root, e := os.MkdirTemp("", "carrier-native-")
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, os.RemoveAll(root)) }()
	const source = "testdata/appledouble/native/carrier-recompression-readback.c"
	helper := filepath.Join(root, "observer")
	if _, e = command(ctx, "xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper); e != nil {
		return e
	}
	sources, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{source, "scripts/verify-carrier-recompression-native.go", "scripts/verify-carrier-recompression.go", "acceptance/carrier_recompression_test.go", "acceptance/carrier_replacement_test.go", "pkg/metatransport/*.go", "pkg/hostdata/*.go", "pkg/recompression/*.go", "pkg/authorization/*.go", "pkg/compression/decmpfs/*.go", "internal/decmpfs/*.go", "testdata/appledouble/native/compression-operation*.json.gz", "scripts/capture-recompression-access.go", "testdata/appledouble/native/recompression-access*.json.gz", "testdata/appledouble/native/recompression-access.c", "testdata/appledouble/native/recompression-open.c", "testdata/appledouble/native/recompression-access-source/*", ".github/workflows/carrier-recompression.yml", "go.mod", "go.sum"})
	if e != nil {
		return e
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := command(ctx, "xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("CompoundStmt")) {
			return errors.New("incomplete native readback AST")
		}
		name := arch + "-carrier-readback.ast.json"
		if e = os.WriteFile(filepath.Join(artifact, name), b, 0644); e != nil {
			return e
		}
		sources[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	host, e := command(ctx, "sw_vers")
	if e != nil {
		return e
	}
	compiler, e := command(ctx, "xcrun", "clang", "--version")
	if e != nil {
		return e
	}
	sdk, e := command(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	for _, header := range []string{"sys/stat.h", "sys/xattr.h", "fcntl.h"} {
		name := filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header)
		h, e := digest(name)
		if e != nil {
			return e
		}
		sources[name] = h
	}
	var results []map[string]any
	for _, major := range []int{15, 26, 27} {
		for _, filesystem := range []string{"host", "APFS", "HFS+"} {
			name := fmt.Sprintf("macos%d-%s.dmg", major, filesystem)
			path := filepath.Join(foreign, name)
			f, e := os.Open(path + ".json.gz")
			if e != nil {
				return e
			}
			z, e := gzip.NewReader(f)
			if e != nil {
				return errors.Join(e, f.Close())
			}
			var expected expectedImage
			e = json.NewDecoder(z).Decode(&expected)
			if e = errors.Join(e, z.Close(), f.Close()); e != nil {
				return e
			}
			wantProfile := map[int]string{15: "compression-operation-macos15", 26: "compression-operation-macos26", 27: "compression-operation"}[major]
			if expected.Schema != 1 || expected.Profile != wantProfile || expected.Filesystem != filesystem || len(expected.Cases) != 94 {
				return fmt.Errorf("incomplete producer case manifest %s", name)
			}
			h, e := digest(path)
			if e != nil {
				return e
			}
			if h != expected.ImageSHA256 {
				return fmt.Errorf("producer image digest differs %s", name)
			}
			h, e = digest(filepath.Join("testdata/appledouble/native", expected.Profile+".json.gz"))
			if e != nil {
				return e
			}
			if h != expected.FixtureSHA256 {
				return fmt.Errorf("producer native fixture differs %s", name)
			}
			result, e := verifyImage(ctx, root, helper, artifact, path, expected)
			if e != nil {
				return e
			}
			results = append(results, result)
		}
	}
	report := map[string]any{"host": string(host), "compiler": string(compiler), "sources": sources, "images": results, "image_count": len(results), "native_cases": 846}
	b, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(artifact, "report.json"), b, 0644); e != nil {
		return e
	}
	fmt.Println("9 foreign carrier images; 846 complete native payload, storage and metadata observations passed")
	return nil
}
func verifyImage(ctx context.Context, root, helper, artifact, path string, expected expectedImage) (result map[string]any, err error) {
	name := filepath.Base(path)
	mount := filepath.Join(root, "mount")
	if e := os.MkdirAll(mount, 0700); e != nil {
		return nil, e
	}
	output := filepath.Join(artifact, name)
	if e := os.MkdirAll(output, 0755); e != nil {
		return nil, e
	}
	attached, e := command(ctx, "hdiutil", "attach", "-readonly", "-nobrowse", "-owners", "off", "-mountpoint", mount, "-plist", path)
	if e != nil {
		return nil, e
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = mount
	}
	defer func() {
		detachCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var attempts []map[string]any
		detachErr := diskimage.RetryDetach(detachCtx, func() (int, error) {
			b, e := exec.CommandContext(detachCtx, "hdiutil", "detach", device).CombinedOutput()
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
		b, marshalErr := json.MarshalIndent(attempts, "", "  ")
		writeErr := os.WriteFile(filepath.Join(output, "detach.json"), b, 0644)
		err = errors.Join(err, detachErr, marshalErr, writeErr)
	}()
	if e = os.WriteFile(filepath.Join(output, "attach.plist"), attached, 0644); e != nil {
		return nil, e
	}
	if parseErr != nil {
		return nil, parseErr
	}
	var input strings.Builder
	names := map[string]bool{}
	for _, c := range expected.Cases {
		if !fs.ValidPath(c.Name) || strings.ContainsAny(c.Name, "/\\\n\r") || names[c.Name] {
			return nil, errors.New("unsafe or duplicate case name")
		}
		names[c.Name] = true
		input.WriteString(c.Name + "\n")
	}
	cmd := exec.CommandContext(ctx, "sudo", "-n", helper, mount, output)
	cmd.Stdin = strings.NewReader(input.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	e = cmd.Run()
	if writeErr := os.WriteFile(filepath.Join(output, "observed.jsonl"), stdout.Bytes(), 0644); writeErr != nil {
		return nil, errors.Join(e, writeErr)
	}
	if e != nil {
		return nil, fmt.Errorf("native observe %s: %w: %s", name, e, stderr.String())
	}
	observations := map[string]observedCase{}
	scan := bufio.NewScanner(&stdout)
	for scan.Scan() {
		var c observedCase
		if e = json.Unmarshal(scan.Bytes(), &c); e != nil {
			return nil, e
		}
		if _, exists := observations[c.Name]; exists {
			return nil, errors.New("duplicate native observation")
		}
		observations[c.Name] = c
	}
	if e = scan.Err(); e != nil {
		return nil, e
	}
	if len(observations) != len(expected.Cases) {
		return nil, errors.New("incomplete native observations")
	}
	for _, c := range expected.Cases {
		got, ok := observations[c.Name]
		if !ok || got.Flags != c.Flags || got.Mode != c.Mode || got.Size != int64(len(c.Data)) || got.ReadSize != got.Size || !time.Unix(got.BirthSec, got.BirthNsec).Equal(c.Birth) || !time.Unix(got.ChangeSec, got.ChangeNsec).Equal(c.Change) || !time.Unix(got.ModifySec, got.ModifyNsec).Equal(c.Modify) || !time.Unix(got.AccessSec, got.AccessNsec).Equal(c.Access) {
			return nil, fmt.Errorf("native metadata differs %s/%s: %+v; want mode=%o flags=%x size=%d birth=%s modify=%s change=%s access=%s", name, c.Name, got, c.Mode, c.Flags, len(c.Data), c.Birth, c.Modify, c.Change, c.Access)
		}
		for _, part := range []struct {
			suffix string
			want   []byte
		}{{".data", c.Data}, {".attr", c.Attribute}, {".fork", c.Fork}} {
			b, e := os.ReadFile(filepath.Join(output, c.Name+part.suffix))
			if e != nil {
				return nil, e
			}
			if !bytes.Equal(b, part.want) {
				return nil, fmt.Errorf("native complete bytes differ %s/%s%s", name, c.Name, part.suffix)
			}
		}
		if c.Scenario == "replacement-composition" {
			if c.IdentityGroup == "" || c.Links == 0 || got.Links != c.Links {
				return nil, fmt.Errorf("replacement link count differs %s/%s: %d want %d", name, c.Name, got.Links, c.Links)
			}
			for _, other := range expected.Cases {
				if other.Scenario != "replacement-composition" {
					continue
				}
				if (observations[other.Name].Inode == got.Inode) != (other.IdentityGroup == c.IdentityGroup) {
					return nil, fmt.Errorf("replacement inode grouping differs %s/%s/%s", name, c.Name, other.Name)
				}
			}
		}
		if c.Scenario == "hardlink" {
			other := strings.TrimSuffix(c.Name, "-alias")
			if other == c.Name {
				other += "-alias"
			}
			if got.Links != 2 || observations[other].Inode != got.Inode {
				return nil, fmt.Errorf("native hardlink identity differs %s/%s", name, c.Name)
			}
		}
	}
	return map[string]any{"image": name, "image_sha256": expected.ImageSHA256, "cases": len(expected.Cases)}, nil
}
