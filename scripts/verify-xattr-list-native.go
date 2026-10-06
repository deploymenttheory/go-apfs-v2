//go:build ignore

// Compare held Go listing with direct libSystem calls; retain both Clang ASTs.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type native struct {
	Size, Read, Error int
	NamesHex          string
}
type observation struct {
	Name   string
	Native native
	Names  []string
	Error  string
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
	b, e := cirunner.Command(args[0], args[1:]...).CombinedOutput()
	commands = append(commands, command{args, string(b)})
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func main() {
	if runtime.GOOS != "darwin" {
		panic("native listing qualification requires macOS")
	}
	root := "artifacts/held-xattr-list"
	must(os.MkdirAll(root, 0755))
	helper := filepath.Join(root, "xattr-list")
	source := "testdata/appledouble/native/xattr-list.c"
	passed := false
	observations := []observation{}
	hashes := map[string]string{}
	paths, e := filepath.Glob("pkg/hostdata/xattr_strict*.go")
	must(e)
	paths = append(paths, source, "scripts/verify-xattr-list-native.go", "go.mod", "go.sum")
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
		b, e := cirunner.Command("xcrun", args...).Output()
		must(e)
		var ast map[string]any
		must(json.Unmarshal(b, &ast))
		calls := 0
		var walk func(any)
		walk = func(v any) {
			switch n := v.(type) {
			case map[string]any:
				if n["kind"] == "DeclRefExpr" {
					if d, ok := n["referencedDecl"].(map[string]any); ok && d["name"] == "flistxattr" {
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
		if calls != 2 {
			panic(fmt.Sprintf("%s flistxattr call count %d", arch, calls))
		}
		path := filepath.Join(root, arch+".ast.json")
		must(os.WriteFile(path, b, 0600))
		commands = append(commands, command{append([]string{"xcrun"}, args...), "see " + path})
	}
	dir, e := os.MkdirTemp(root, "live-")
	must(e)
	defer os.RemoveAll(dir)
	capture := func(name, path string, f *os.File, link bool) {
		kind := "file"
		if link {
			kind = "link"
		}
		var n native
		must(json.Unmarshal(run(helper, path, kind), &n))
		names, e := hostdata.ListXattrNames(f, hostdata.MaxXattrListSize)
		o := observation{Name: name, Native: n, Names: names}
		if e != nil {
			o.Error = e.Error()
		}
		observations = append(observations, o)
		if n.Error != 0 {
			if names != nil || !errors.Is(e, syscall.Errno(n.Error)) {
				panic(fmt.Sprintf("%s: native error %d vs %v/%v", name, n.Error, names, e))
			}
			return
		}
		must(e)
		raw, e := hex.DecodeString(n.NamesHex)
		must(e)
		var actual []byte
		for _, v := range names {
			actual = append(actual, []byte(v)...)
			actual = append(actual, 0)
		}
		if !bytes.Equal(raw, actual) || len(raw) != n.Size || n.Read != n.Size {
			panic(fmt.Sprintf("%s: native %+v vs Go %q", name, n, names))
		}
		exact, e := hostdata.ListXattrNames(f, n.Size)
		must(e)
		if !reflect.DeepEqual(exact, names) {
			panic("exact budget differs")
		}
		if n.Size > 0 {
			got, e := hostdata.ListXattrNames(f, n.Size-1)
			if got != nil || !errors.Is(e, hostdata.ErrXattrTooLarge) {
				panic("budget refusal lost")
			}
		}
	}
	set := func(path, name string, b []byte) {
		run("/usr/bin/xattr", "-s", "-wx", name, hex.EncodeToString(b), path)
	}
	path := filepath.Join(dir, "file")
	must(os.WriteFile(path, []byte("payload"), 0600))
	f, e := os.Open(path)
	must(e)
	defer f.Close()
	capture("file-initial", path, f, false)
	set(path, "user.z", nil)
	set(path, "user.a", []byte{1})
	set(path, "user.世界", []byte{2})
	capture("ordinary-empty-unicode", path, f, false)
	fi := make([]byte, 32)
	fi[0] = 1
	set(path, "com.apple.FinderInfo", fi)
	capture("finder-present", path, f, false)
	clear(fi)
	set(path, "com.apple.FinderInfo", fi)
	capture("finder-zero", path, f, false)
	set(path, hostdata.ResourceForkName, nil)
	capture("fork-empty-absent", path, f, false)
	set(path, hostdata.ResourceForkName, []byte{7, 8})
	capture("fork-present", path, f, false)
	set(path, hostdata.ResourceForkName, nil)
	capture("fork-empty-overwrite", path, f, false)
	forkHex := strings.Join(strings.Fields(string(run("/usr/bin/xattr", "-px", hostdata.ResourceForkName, path))), "")
	retained, e := hex.DecodeString(forkHex)
	must(e)
	if !bytes.Equal(retained, []byte{7, 8}) {
		panic("empty assignment changed existing fork bytes")
	}
	run("/usr/bin/xattr", "-d", hostdata.ResourceForkName, path)
	capture("fork-removed", path, f, false)
	run("/bin/chmod", "+a", "everyone allow read", path)
	defer cirunner.Command("/bin/chmod", "-N", path).Run()
	capture("security-hidden", path, f, false)
	run("/bin/chmod", "+a", "everyone deny readextattr", path)
	capture("list-denied", path, f, false)
	run("/bin/chmod", "-N", path)
	moved := path + "-moved"
	must(os.Rename(path, moved))
	must(os.WriteFile(path, []byte("decoy"), 0600))
	set(path, "user.decoy", []byte{3})
	capture("renamed-held-file", moved, f, false)
	alias := filepath.Join(dir, "alias")
	must(os.Link(moved, alias))
	set(alias, "user.alias", []byte{4})
	capture("hard-link-update", alias, f, false)
	directory := filepath.Join(dir, "directory")
	must(os.Mkdir(directory, 0700))
	df, e := os.Open(directory)
	must(e)
	defer df.Close()
	capture("directory-initial", directory, df, false)
	set(directory, "user.directory", []byte{5})
	capture("directory-seeded", directory, df, false)
	link := filepath.Join(dir, "link")
	must(os.Symlink(path, link))
	set(link, "user.link", []byte{6})
	fd, e := syscall.Open(link, syscall.O_RDONLY|syscall.O_SYMLINK, 0)
	must(e)
	lf := os.NewFile(uintptr(fd), link)
	defer lf.Close()
	capture("held-symlink", link, lf, true)
	movedLink := link + "-moved"
	must(os.Rename(link, movedLink))
	must(os.Symlink(path, link))
	set(link, "user.decoy", []byte{7})
	capture("renamed-held-symlink", movedLink, lf, true)
	if len(observations) != 16 {
		panic("incomplete fixture selection")
	}
	passed = true
	fmt.Printf("Qualified %d native listing observations, exact budgets, both Clang ASTs and held identities\n", len(observations))
}
