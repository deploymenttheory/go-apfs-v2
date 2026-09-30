//go:build ignore

// Compare held Go writes with direct libSystem calls and independent native readback.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type native struct {
	WriteError, ReadError, Size int
	ValueHex                    string
}
type observation struct {
	Name, Attribute, InputHex string
	Native, GoReadback        native
	GoError                   string
}
type command struct {
	Args   []string
	Output string
}

var commands []command

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	commands = append(commands, command{args, string(b)})
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func main() {
	if runtime.GOOS != "darwin" {
		panic("native write qualification requires macOS")
	}
	root := "artifacts/held-xattr-write"
	must(os.MkdirAll(root, 0755))
	helper := filepath.Join(root, "xattr-write")
	source := "testdata/appledouble/native/xattr-write.c"
	passed := false
	observations := []observation{}
	hashes := map[string]string{}
	paths, e := filepath.Glob("pkg/hostmeta/xattr_strict*.go")
	must(e)
	paths = append(paths, source, "scripts/verify-xattr-write-native.go", "go.mod", "go.sum")
	for _, p := range paths {
		b, e := os.ReadFile(p)
		must(e)
		hashes[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	revision := strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	host := string(run("sw_vers"))
	clang := string(run("xcrun", "clang", "--version"))
	sdk := string(run("xcrun", "--show-sdk-version"))
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "revision": revision, "host": host, "clang": clang, "sdk": sdk, "source_sha256": hashes, "observations": observations, "commands": commands}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(report, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(root, "report.json"), b, 0600))
		if failure != nil {
			fmt.Fprintln(os.Stderr, failure)
			os.Exit(1)
		}
	}()
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		args := []string{"clang", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", source}
		b, e := exec.Command("xcrun", args...).Output()
		must(e)
		var ast map[string]any
		must(json.Unmarshal(b, &ast))
		calls := 0
		var walk func(any)
		walk = func(v any) {
			switch n := v.(type) {
			case map[string]any:
				if n["kind"] == "DeclRefExpr" {
					if d, ok := n["referencedDecl"].(map[string]any); ok && d["name"] == "fsetxattr" {
						calls++
					}
				}
				for _, c := range n {
					walk(c)
				}
			case []any:
				for _, c := range n {
					walk(c)
				}
			}
		}
		walk(ast)
		if calls != 1 {
			panic(fmt.Sprintf("%s fsetxattr call count %d", arch, calls))
		}
		path := filepath.Join(root, arch+".ast.json")
		must(os.WriteFile(path, b, 0600))
		commands = append(commands, command{append([]string{"xcrun"}, args...), "see " + path})
	}
	dir, e := os.MkdirTemp(root, "live-")
	must(e)
	defer os.RemoveAll(dir)
	capture := func(label, name string, value []byte, reference, actual string, f *os.File, link bool) {
		kind := "file"
		if link {
			kind = "link"
		}
		encoded := hex.EncodeToString(value)
		var expected, got native
		must(json.Unmarshal(run(helper, "set", reference, kind, name, encoded), &expected))
		err := hostmeta.SetXattr(f, name, value)
		must(json.Unmarshal(run(helper, "read", actual, kind, name, ""), &got))
		o := observation{Name: label, Attribute: name, InputHex: encoded, Native: expected, GoReadback: got}
		if err != nil {
			o.GoError = err.Error()
		}
		observations = append(observations, o)
		if (expected.WriteError == 0 && err != nil) || (expected.WriteError != 0 && !errors.Is(err, syscall.Errno(expected.WriteError))) {
			panic(fmt.Sprintf("%s native write=%d Go=%v", label, expected.WriteError, err))
		}
		if expected.ReadError != got.ReadError || expected.Size != got.Size || expected.ValueHex != got.ValueHex {
			panic(fmt.Sprintf("%s native=%+v Go readback=%+v", label, expected, got))
		}
	}
	reference := filepath.Join(dir, "reference")
	actual := filepath.Join(dir, "go")
	for _, p := range []string{reference, actual} {
		must(os.WriteFile(p, []byte("payload"), 0600))
	}
	f, e := os.Open(actual)
	must(e)
	defer f.Close()
	for _, step := range []struct {
		label, name string
		value       []byte
	}{
		{"ordinary-create", "user.write", []byte{0, 1, 255}},
		{"ordinary-shrink", "user.write", []byte{7}},
		{"ordinary-empty", "user.write", nil},
		{"unicode", "user.世界", []byte{42}},
		{"finder-invalid", "com.apple.FinderInfo", []byte{1}},
		{"finder-present", "com.apple.FinderInfo", append([]byte{1}, make([]byte, 31)...)},
		{"finder-zero", "com.apple.FinderInfo", make([]byte, 32)},
		{"fork-fresh-empty", hostmeta.ResourceForkName, nil},
		{"fork-present", hostmeta.ResourceForkName, []byte{7, 8, 9}},
		{"fork-short-overwrite", hostmeta.ResourceForkName, []byte{4}},
		{"fork-empty-overwrite", hostmeta.ResourceForkName, nil},
		{"security-invalid", hostmeta.SecurityName, []byte{1}},
	} {
		capture(step.label, step.name, step.value, reference, actual, f, false)
	}
	// Write denial is measured on already-open descriptors; no permission bypass.
	for _, p := range []string{reference, actual} {
		run("/bin/chmod", "+a", "everyone deny writeextattr", p)
	}
	capture("acl-write-denied", "user.write", []byte{99}, reference, actual, f, false)
	for _, p := range []string{reference, actual} {
		run("/bin/chmod", "-N", p)
	}
	// A reader-denied descriptor still permits writes. The native reader records
	// the permission error rather than pretending the value is absent.
	for _, p := range []string{reference, actual} {
		run("/bin/chmod", "+a", "everyone deny readextattr", p)
	}
	capture("acl-read-denied-write-allowed", "user.write", []byte{88}, reference, actual, f, false)
	for _, p := range []string{reference, actual} {
		run("/bin/chmod", "-N", p)
	}
	for _, p := range []string{reference, actual} {
		var read native
		must(json.Unmarshal(run(helper, "read", p, "file", "user.write", ""), &read))
		if read.ReadError != 0 || read.ValueHex != "58" {
			panic("write with read denied did not persist")
		}
	}
	moved := actual + "-moved"
	must(os.Rename(actual, moved))
	must(os.WriteFile(actual, []byte("decoy"), 0600))
	capture("renamed-file", "user.write", []byte{55}, reference, moved, f, false)
	var absent native
	must(json.Unmarshal(run(helper, "read", actual, "file", "user.write", ""), &absent))
	if absent.ReadError != int(syscall.ENOATTR) {
		panic("old pathname mutated")
	}
	alias := actual + "-alias"
	must(os.Link(moved, alias))
	capture("hard-link", "user.write", []byte{44}, reference, alias, f, false)
	b, e := os.ReadFile(moved)
	must(e)
	if string(b) != "payload" {
		panic("file data changed")
	}
	position, e := f.Seek(0, 1)
	must(e)
	if position != 0 {
		panic("file position changed")
	}
	for _, kind := range []string{"directory", "link"} {
		rp := filepath.Join(dir, kind+"-reference")
		gp := filepath.Join(dir, kind+"-go")
		for _, p := range []string{rp, gp} {
			if kind == "directory" {
				must(os.Mkdir(p, 0700))
			} else {
				must(os.Symlink(actual, p))
			}
		}
		flags := syscall.O_RDONLY
		if kind == "link" {
			flags |= syscall.O_SYMLINK
		}
		fd, e := syscall.Open(gp, flags, 0)
		must(e)
		held := os.NewFile(uintptr(fd), gp)
		capture(kind+"-create", "user.write", []byte{1, 2}, rp, gp, held, kind == "link")
		capture(kind+"-empty", "user.write", nil, rp, gp, held, kind == "link")
		gm := gp + "-moved"
		must(os.Rename(gp, gm))
		must(os.WriteFile(gp, []byte("decoy"), 0600))
		capture(kind+"-renamed", "user.write", []byte{3}, rp, gm, held, kind == "link")
		must(held.Close())
	}
	if len(observations) != 22 {
		panic("incomplete fixture selection")
	}
	passed = true
	fmt.Printf("Qualified %d native writes with full independent readback, both Clang ASTs and held identities\n", len(observations))
}
