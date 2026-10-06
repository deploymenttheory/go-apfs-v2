//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeCrossVersionNameImages(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Fatal("native cross-version qualification requires Darwin")
	}
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chdir(root); e != nil {
		t.Fatal(e)
	}
	base := os.Getenv("APFS_NAME_IMAGE_ARTIFACTS")
	if base == "" {
		t.Fatal("missing allthree native image producers")
	}
	out, e := filepath.Abs("artifacts/name-native-readback")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(out, 0755); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	source := "testdata/appledouble/native/name-readback.c"
	binary := filepath.Join(out, "probe")
	if _, e = command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); e != nil {
		t.Fatal(e)
	}
	sdk, e := command(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		t.Fatal(e)
	}
	hashes := map[string]string{}
	for _, p := range []string{source, "scripts/verify-name-native_readback_test.go", "scripts/verify-name-comparison_test.go", "scripts/capture-name-collation.go", "go.mod", "go.sum"} {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		hashes[p] = sum(b)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", strings.TrimSpace(string(sdk)), "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if e != nil {
			t.Fatal(e)
		}
		name := arch + ".ast.json"
		hashes[name] = sum(ast)
		if e = os.WriteFile(filepath.Join(out, name), ast, 0644); e != nil {
			t.Fatal(e)
		}
	}
	for _, h := range []string{"sys/stat.h", "sys/fcntl.h", "unistd.h", "sys/errno.h"} {
		b, e := os.ReadFile(filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", h))
		if e != nil {
			t.Fatal(e)
		}
		name := "SDK/" + h
		hashes[name] = sum(b)
		dest := filepath.Join(out, name)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	hashes["native-binary"] = sum(b)
	checked := 0
	for _, p := range []struct {
		major    int
		artifact string
	}{{15, "name-collation-macos-15"}, {26, "name-collation-macos-latest"}, {27, "name-collation-xcode-27"}} {
		dir := filepath.Join(base, p.artifact)
		fresh := readComparisonCapture(t, filepath.Join(dir, "native.json.gz"))
		prior := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", p.major))
		if e = compareStable(prior, fresh); e != nil {
			t.Fatal(e)
		}
		for _, v := range fresh.Volumes {
			t.Run(fmt.Sprintf("%d/%s", p.major, v.Kind), func(t *testing.T) {
				nativeImageReadback(t, ctx, out, dir, binary, p.major, v)
				checked += len(v.Native.Cases) * 2
			})
		}
	}
	if checked != 90072 {
		t.Fatalf("native readbacks%d want90072", checked)
	}
	host, e := command(ctx, "sw_vers")
	if e != nil {
		t.Fatal(e)
	}
	compiler, e := command(ctx, "xcrun", "clang", "--version")
	if e != nil {
		t.Fatal(e)
	}
	revision, e := command(ctx, "git", "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	report := map[string]any{"schema": 1, "host": string(host), "compiler": string(compiler), "sdk": string(sdk), "revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "observations": checked, "producer_profiles": 3, "volumes": 12}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, "report.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func nativeImageReadback(t *testing.T, ctx context.Context, out, dir, binary string, major int, v volumeCapture) {
	t.Helper()
	stem := fmt.Sprintf("%d-%s", major, strings.ReplaceAll(v.Kind, "+", "plus"))
	image := filepath.Join(dir, strings.ReplaceAll(v.Kind, "+", "plus")+".dmg")
	b, e := os.ReadFile(image)
	if e != nil || sum(b) != v.ImageSHA256 {
		t.Fatal("native image hash", e)
	}
	mount := filepath.Join(out, stem+"-mount")
	if e = os.Mkdir(mount, 0700); e != nil {
		t.Fatal(e)
	}
	attached, e := command(ctx, "hdiutil", "attach", "-readonly", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	if e != nil {
		t.Fatal(e)
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = mount
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var attempts []map[string]any
		e := diskimage.RetryDetach(cleanup, func() (int, error) {
			b, e := exec.CommandContext(cleanup, "hdiutil", "detach", device).CombinedOutput()
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
		if err := errors.Join(e, j, os.WriteFile(filepath.Join(out, stem+"-detach.json"), b, 0644)); err != nil {
			t.Error(err)
		}
	}()
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if e = os.WriteFile(filepath.Join(out, stem+"-attach.plist"), attached, 0644); e != nil {
		t.Fatal(e)
	}
	raw, e := command(ctx, binary, mount, filepath.Join(dir, "cases.tsv"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, stem+"-readback.json"), raw, 0644); e != nil {
		t.Fatal(e)
	}
	var observed struct {
		Count int
		Cases []struct {
			ID      string
			Results []struct {
				Errno      int
				Inode      uint64
				Size, Read int64
			}
		}
	}
	if e = json.Unmarshal(raw, &observed); e != nil {
		t.Fatal(e)
	}
	if observed.Count != 3753 || len(observed.Cases) != 3753 {
		t.Fatal("incomplete native readback")
	}
	for i, c := range observed.Cases {
		want := v.Native.Cases[i]
		if c.ID != want.ID || len(c.Results) != 2 {
			t.Fatal("readback case inventory")
		}
		for j, r := range c.Results {
			expected := want.LookupErrno
			inode := want.QueriedInode
			if j == 0 {
				inode = want.Inode
				if want.CreateErrno == 0 {
					expected = 0
				}
			}
			if r.Errno != expected {
				t.Fatalf("%s candidate%d errno%d want%d", c.ID, j, r.Errno, expected)
			}
			if expected == 0 {
				if r.Inode != inode || r.Size != 0 || r.Read != 0 {
					t.Fatalf("%s candidate%d identity/contentchanged:%+v wantinode%d", c.ID, j, r, inode)
				}
			} else if r.Inode != 0 || r.Read != -1 {
				t.Fatalf("%s unexpected failed-read identity", c.ID)
			}
		}
	}
	after, e := os.ReadFile(image)
	if e != nil || sum(after) != v.ImageSHA256 {
		t.Fatal("read-only verification changed native image", e)
	}
}
