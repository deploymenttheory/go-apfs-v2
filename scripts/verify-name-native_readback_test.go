//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	original, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Error(err)
		}
	})
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
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "commands")}
	source := "testdata/appledouble/native/name-readback.c"
	binary := filepath.Join(out, "probe")
	if _, e = commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary); e != nil {
		t.Fatal(e)
	}
	sdk, e := commands.run(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		t.Fatal(e)
	}
	hashes := map[string]string{}
	for _, p := range []string{source, "scripts/verify-name-native_readback_test.go", "scripts/verify-name-native_commands_test.go", "scripts/verify-name-comparison_test.go", "scripts/capture-name-collation.go", "go.mod", "go.sum"} {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		hashes[p] = sum(b)
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := commands.run(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", strings.TrimSpace(string(sdk)), "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
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
	inputs := map[string]string{}
	checked := 0
	for _, p := range []struct {
		major    int
		artifact string
	}{{15, "name-collation-macos-15"}, {26, "name-collation-macos-latest"}, {27, "name-collation-xcode-27"}} {
		dir := filepath.Join(base, p.artifact)
		capturePath := filepath.Join(dir, "native.json.gz")
		input, err := os.ReadFile(capturePath)
		if err != nil {
			t.Fatal(err)
		}
		inputs[p.artifact+"/native.json.gz"] = sum(input)
		fresh := readComparisonCapture(t, capturePath, p.major)
		prior := readComparisonCapture(t, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", p.major))
		if e = compareStable(prior, fresh); e != nil {
			t.Fatal(e)
		}
		for _, v := range fresh.Volumes {
			inputs[p.artifact+"/"+strings.ReplaceAll(v.Kind, "+", "plus")+".dmg"] = v.ImageSHA256
			t.Run(fmt.Sprintf("%d/%s", p.major, v.Kind), func(t *testing.T) {
				nativeImageReadback(t, ctx, commands, out, dir, binary, p.major, v)
				checked += len(v.Native.Cases) * 2
			})
		}
	}
	if checked != 90072 {
		t.Fatalf("native readbacks%d want90072", checked)
	}
	host, e := commands.run(ctx, "sw_vers")
	if e != nil {
		t.Fatal(e)
	}
	compiler, e := commands.run(ctx, "xcrun", "clang", "--version")
	if e != nil {
		t.Fatal(e)
	}
	revision, e := commands.run(ctx, "git", "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	rawEvidence := map[string]string{}
	err := filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "report.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		rawEvidence[filepath.ToSlash(relative)] = sum(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"schema": 1, "host": string(host), "compiler": string(compiler), "sdk": string(sdk), "revision": strings.TrimSpace(string(revision)), "source_sha256": hashes, "input_sha256": inputs, "evidence_sha256": rawEvidence, "observations": checked, "producer_profiles": 3, "volumes": 12}
	b, e = json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, "report.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func nativeImageReadback(t *testing.T, ctx context.Context, commands *nativeCommandRunner, out, dir, binary string, major int, v volumeCapture) {
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
	var raw []byte
	e = withNativeReadbackMount(ctx, commands.run, image, mount, filepath.Join(out, stem+"-detach.json"), func(attached []byte) error {
		if err := os.WriteFile(filepath.Join(out, stem+"-attach.plist"), attached, 0644); err != nil {
			return err
		}
		var err error
		raw, err = commands.run(ctx, binary, mount, filepath.Join(dir, "cases.tsv"))
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, stem+"-readback.json"), raw, 0644)
	})
	if e != nil {
		t.Fatal(e)
	}
	validateNativeNameReadback(t, raw, v)
	after, e := os.ReadFile(image)
	if e != nil || sum(after) != v.ImageSHA256 {
		t.Fatal("read-only verification changed native image", e)
	}
}

// Shared without changing the native oracle's required inventory or assertions.
func validateNativeNameReadback(t *testing.T, raw []byte, v volumeCapture) {
	t.Helper()
	if len(v.Native.Cases) != 3753 {
		t.Fatal("incomplete native source readback inventory")
	}
	validateNativeNameResults(t, raw, v.Native.Cases, 3753)
}

func validateNativeNameResults(t *testing.T, raw []byte, expected []nativeCase, required int) {
	t.Helper()
	if required <= 0 || len(expected) != required {
		t.Fatal("invalid explicit native readback inventory")
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
	if e := json.Unmarshal(raw, &observed); e != nil {
		t.Fatal(e)
	}
	if observed.Count != required || len(observed.Cases) != required {
		t.Fatal("incomplete native readback")
	}
	for i, c := range observed.Cases {
		want := expected[i]
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
}
