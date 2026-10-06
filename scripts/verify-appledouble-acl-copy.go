//go:build ignore

// Native COPYFILE_ACL policy qualification. Never linked into production.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type profile struct {
	Name string
	ACL  *appledouble.ACL
}
type modelResult struct {
	Code, Errno, Captures, Writes int
	ACL, SourceCache              *string
}
type metadata struct {
	ACL                   *string
	UID, GID, Mode, Flags uint32
}
type applicationResult struct {
	Filesystem                               string
	Code, Errno                              int
	SourceBefore, SourceAfter, Before, After metadata
	IdentityUnchanged, PayloadUnchanged      bool
}
type modelCase struct {
	Name                string
	Source, Destination []byte
	Native              modelResult
}
type applicationCase struct {
	Name, Kind, Source, Destination string
	Native                          applicationResult
}
type fixture struct {
	Revision, Host, HelperSHA256, SourceSHA256 string
	Models                                     []modelCase
	Applications                               []applicationCase
}
type command struct {
	Args          []string
	Output, Error string
}

var commands []command

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte     { b, e := os.ReadFile(p); must(e); return b }
func write(p string, b []byte) { must(os.WriteFile(p, b, 0600)) }
func sum(b []byte) string      { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func run(args ...string) []byte {
	b, e := cirunner.Command(args[0], args[1:]...).CombinedOutput()
	c := command{Args: args, Output: string(b)}
	if e != nil {
		c.Error = e.Error()
	}
	commands = append(commands, c)
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func extract(b []byte, start, end string) []byte {
	i := bytes.Index(b, []byte(start))
	if i < 0 {
		panic(start)
	}
	j := bytes.Index(b[i:], []byte(end))
	if j < 0 {
		panic(end)
	}
	return b[i : i+j]
}
func decode(v *string) *appledouble.ACL {
	if v == nil {
		return nil
	}
	b, e := hex.DecodeString(*v)
	must(e)
	a, e := appledouble.ParseACLBinary(b)
	must(e)
	return a
}
func encoded(a *appledouble.ACL) *string {
	if a == nil {
		return nil
	}
	b, e := a.MarshalBinary()
	must(e)
	s := hex.EncodeToString(b)
	return &s
}
func binaryACL(a *appledouble.ACL) []byte {
	if a == nil {
		return nil
	}
	b, e := a.MarshalBinary()
	must(e)
	return b
}
func parseBinary(b []byte) *appledouble.ACL {
	if b == nil {
		return nil
	}
	a, e := appledouble.ParseACLBinary(b)
	must(e)
	return a
}
func profiles() []profile {

	makeACL := func(n int, inherited bool) *appledouble.ACL {
		a := &appledouble.ACL{}
		for i := 0; i < n; i++ {
			flags := uint32(1)
			if inherited {
				flags |= 16
			}
			a.Entries = append(a.Entries, appledouble.ACLEntry{Principal: [16]byte{0x11, 0x23, byte(i + 1)}, Flags: flags, Rights: 1})
		}
		return a
	}
	mixed := makeACL(3, false)
	mixed.Entries[1].Flags = 18
	propagation := makeACL(1, false)
	propagation.Entries[0].Flags = 1 | 32 | 64 | 128 | 256
	unknown := makeACL(2, false)
	unknown.Flags = 0x80060000
	unknown.Entries[0].Flags = 0x8000000f
	unknown.Entries[0].Rights = 0xffffffff
	unknown.Entries[1].Flags = 0x80000012
	mixed128 := makeACL(128, false)
	for i := range mixed128.Entries {
		if i%2 == 1 {
			mixed128.Entries[i].Flags |= 16
		}
	}
	deny := makeACL(1, false)
	deny.Entries[0].Flags = 2
	return []profile{{"none", nil}, {"empty", &appledouble.ACL{}}, {"global", &appledouble.ACL{Flags: 1 << 17}}, {"allow", makeACL(1, false)}, {"deny", deny}, {"inherited", makeACL(1, true)}, {"mixed", mixed}, {"propagation", propagation}, {"unknown", unknown}, {"explicit127", makeACL(127, false)}, {"explicit128", makeACL(128, false)}, {"inherited127", makeACL(127, true)}, {"inherited128", makeACL(128, true)}, {"mixed128", mixed128}, {"explicit64", makeACL(64, false)}, {"inherited64", makeACL(64, true)}}
}
func main() {
	capture := flag.Bool("capture", false, "record unapproved native observations")
	flag.Parse()
	const root = "artifacts/appledouble-acl-copy"
	const archivedPath = "testdata/appledouble/native/acl-copy.json.gz"
	const helperSource = "testdata/appledouble/native/acl-copy.c"
	must(os.MkdirAll(root, 0700))
	var f fixture
	passed := false
	defer func() {
		failure := recover()
		r := map[string]any{"passed": passed, "capture": *capture, "fixture": f, "commands": commands}
		if failure != nil {
			r["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(r, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), b, 0600)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native qualification requires macOS")
	}
	f.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	f.Host = string(run("sw_vers"))
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	f.SourceSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	client := http.Client{Timeout: 30 * time.Second}
	resp, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c")
	must(e)
	src, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	must(e)
	must(resp.Body.Close())
	if resp.StatusCode != 200 || sum(src) != f.SourceSHA256 {
		panic("source provenance")
	}
	write(filepath.Join(root, "copyfile.c"), src)
	header := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	for _, p := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static int\ncopyfile_unset_posix_fsec", "/*\n * Used to remove acl information"}, {"static int copyfile_security(copyfile_state_t s)", "/*\n * Attempt to set the destination"}} {
		header = append(header, extract(src, p[0], p[1])...)
	}
	write(filepath.Join(root, "acl-copy-source.h"), header)
	helper := filepath.Join(root, "acl-copy")
	// Apple's unchanged function increments a counter that it never reads.
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-Wno-unused-but-set-variable", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	inputs := profiles()
	paths := map[string]string{}
	for _, p := range inputs {
		paths[p.Name] = "-"
		if p.ACL != nil {
			b, e := p.ACL.MarshalBinary()
			must(e)
			path := filepath.Join(root, p.Name+".bin")
			write(path, b)
			paths[p.Name] = path
		}
	}
	real := map[string]bool{}
	for _, n := range []string{"none", "empty", "global", "allow", "deny", "inherited", "mixed", "propagation", "explicit128", "inherited128", "explicit64", "inherited64"} {
		real[n] = true
	}
	for _, s := range inputs {
		for _, d := range inputs {
			name := s.Name + "-" + d.Name
			tc := modelCase{Name: name, Source: binaryACL(s.ACL), Destination: binaryACL(d.ACL)}
			must(json.Unmarshal(run(helper, "model", paths[s.Name], paths[d.Name]), &tc.Native))
			f.Models = append(f.Models, tc)
			if !real[s.Name] || !real[d.Name] {
				continue
			}
			for _, kind := range []string{"file", "directory"} {
				name := kind + "-" + name
				dir := filepath.Join(root, name)
				must(os.RemoveAll(dir))
				must(os.MkdirAll(dir, 0700))
				a := applicationCase{Name: name, Kind: kind, Source: s.Name, Destination: d.Name}
				must(json.Unmarshal(run(helper, kind, paths[s.Name], paths[d.Name], dir), &a.Native))
				f.Applications = append(f.Applications, a)
			}
		}
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d policy cases and %d actual copies; NOT approved\n", len(f.Models), len(f.Applications))
		return
	}
	for _, tc := range f.Models {
		got, e := appledouble.CopyACL(parseBinary(tc.Source), parseBinary(tc.Destination))
		if (e != nil) != (tc.Native.Code != 0) || tc.Native.Captures != 1 {
			panic("policy result: " + tc.Name)
		}
		if e == nil {
			if tc.Native.Writes != 1 || !reflect.DeepEqual(encoded(got), tc.Native.ACL) || !reflect.DeepEqual(tc.Native.ACL, tc.Native.SourceCache) {
				panic("policy bytes: " + tc.Name)
			}
		} else if tc.Native.Writes != 0 || tc.Native.ACL != nil || !reflect.DeepEqual(tc.Native.SourceCache, encoded(parseBinary(tc.Source))) {
			panic("failed policy: " + tc.Name)
		}
	}
	for _, tc := range f.Applications {
		n := tc.Native
		got, e := appledouble.CopyACL(decode(n.SourceBefore.ACL), decode(n.Before.ACL))
		if (e != nil) != (n.Code != 0) || n.Filesystem != "apfs" || !n.IdentityUnchanged || !n.PayloadUnchanged || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) {
			panic("copy outcome: " + tc.Name)
		}
		after := n.After
		after.ACL = n.Before.ACL
		if !reflect.DeepEqual(after, n.Before) {
			panic("copy metadata: " + tc.Name)
		}
		if e != nil {
			if !reflect.DeepEqual(n.After, n.Before) {
				panic("failed copy mutated ACL: " + tc.Name)
			}
		} else {
			want := encoded(got)
			if got != nil && len(got.Entries) == 0 && n.After.ACL == nil {
				want = nil
			}
			if !reflect.DeepEqual(want, n.After.ACL) {
				panic("copy ACL: " + tc.Name)
			}
		}
	}
	z, e := gzip.NewReader(bytes.NewReader(read(archivedPath)))
	must(e)
	var archived fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if len(archived.Models) != len(f.Models) || len(archived.Applications) != len(f.Applications) {
		panic("corpus counts differ")
	}
	archived.Revision = f.Revision
	archived.Host = f.Host
	for i := range archived.Applications {
		a, b := &archived.Applications[i].Native, &f.Applications[i].Native
		for _, pair := range [][2]*metadata{{&a.SourceBefore, &b.SourceBefore}, {&a.SourceAfter, &b.SourceAfter}, {&a.Before, &b.Before}, {&a.After, &b.After}} {
			pair[0].UID = pair[1].UID
			pair[0].GID = pair[1].GID
		}
	}
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d policy cases and %d actual file/directory copies\n", len(f.Models), len(f.Applications))
}
