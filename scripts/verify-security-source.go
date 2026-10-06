//go:build ignore

// Qualify portable copyfile security execution; native tools are test-only.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitysource"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type command struct {
	Args                 []string
	Input, Output, Error string
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
func run(input string, args ...string) []byte {
	cmd := cirunner.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(input)
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	e := cmd.Run()
	c := command{Args: args, Input: input, Output: out.String(), Error: errout.String()}
	if e != nil {
		c.Error += e.Error()
	}
	commands = append(commands, c)
	if e != nil {
		panic(fmt.Sprintf("%v: %v %s", args, e, errout.String()))
	}
	return out.Bytes()
}
func download(url, hash, target string) []byte {
	client := http.Client{Timeout: 30 * time.Second}
	r, e := client.Get(url)
	must(e)
	b, e := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	must(e)
	must(r.Body.Close())
	if r.StatusCode != 200 || sum(b) != hash {
		panic("source provenance")
	}
	write(target, b)
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
func main() {
	capture := flag.Bool("capture", false, "record unapproved observations")
	flag.Parse()
	const root = "artifacts/security-source"
	const helperSource = "testdata/appledouble/native/security-source.c"
	const corpus = "testdata/appledouble/native/security-source.json.gz"
	must(os.MkdirAll(root, 0700))
	var f securitysource.Fixture
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
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		panic("requires ordinary user")
	}
	f.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	f.Host = string(run("", "sw_vers"))
	run("", "uname", "-a")
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	f.ParentSHA256 = sum(read("testdata/appledouble/native/security-copy.c"))
	parent := read("testdata/appledouble/native/security-copy.c")
	if bytes.Count(parent, []byte("unsigned internal_flags;")) != 1 {
		panic("helper state layout")
	}
	write(filepath.Join(root, "source-copy-helper.h"), bytes.Replace(parent, []byte("unsigned internal_flags;"), []byte("unsigned internal_flags; int err;"), 1))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.LibcSHA256 = "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff"
	src := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	for _, p := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static int\ncopyfile_unset_posix_fsec", "/*\n * Used to remove acl information"}, {"static int copyfile_security(copyfile_state_t s)", "/*\n * Attempt to set the destination"}} {
		h = append(h, extract(src, p[0], p[1])...)
	}
	write(filepath.Join(root, "acl-copy-source.h"), h)
	fh := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	fh = append(fh, extract(src, "int fcopyfile(int src_fd", "/*\n * This routine implements the clonefileat functionality")...)
	write(filepath.Join(root, "source-fcopyfile.h"), fh)
	libc := download("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c", f.LibcSHA256, filepath.Join(root, "chmodx_np.c"))
	h = append([]byte{}, libc[:bytes.Index(libc, []byte("#include"))]...)
	h = append(h, libc[bytes.Index(libc, []byte("static int\nchmodx1(")):]...)
	write(filepath.Join(root, "acl-chmod-source.h"), h)
	helper := filepath.Join(root, "security-source")
	run("", "xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-Wno-unused-but-set-variable", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("", "xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	profiles := map[string]*appledouble.ACL{"none": nil, "empty": {}, "allow": {Entries: []appledouble.ACLEntry{{Principal: [16]byte{0x11, 0x23}, Flags: 1, Rights: 1}}}, "inherited": {Entries: []appledouble.ACLEntry{{Principal: [16]byte{0x11, 0x23}, Flags: 17, Rights: 1}}}, "explicit128": {}, "inherited128": {}}
	for i := 0; i < 128; i++ {
		profiles["explicit128"].Entries = append(profiles["explicit128"].Entries, appledouble.ACLEntry{Principal: [16]byte{0x11, 0x23, byte(i + 1)}, Flags: 1, Rights: 1})
		profiles["inherited128"].Entries = append(profiles["inherited128"].Entries, appledouble.ACLEntry{Principal: [16]byte{0x11, 0x23, byte(i + 1)}, Flags: 17, Rights: 1})
	}
	paths := map[string]string{}
	for name, acl := range profiles {
		paths[name] = "-"
		if acl != nil {
			b, e := acl.MarshalBinary()
			must(e)
			paths[name] = filepath.Join(root, name+".bin")
			write(paths[name], b)
		}
	}
	pairs := [][2]string{{"none", "none"}, {"allow", "none"}, {"none", "inherited"}, {"allow", "inherited"}}
	for _, pair := range pairs {
		for _, flags := range []int{1, 2, 3} {
			for _, kind := range []uint32{0, 0100000, 0040000, 0120000, 0010000, 0140000} {
				for _, sourceError := range []int{0, 1, 45, 13, 5} {
					for statBehavior := 0; statBehavior < 3; statBehavior++ {
						for _, presence := range []int{0, 31} {
							tc := securitysource.Case{Name: fmt.Sprintf("model-%s-%s-f%d-t%o-e%d-b%d-p%d", pair[0], pair[1], flags, kind, sourceError, statBehavior, presence), Flags: flags, SourceACL: pair[0], DestinationACL: pair[1], Mode: kind | 06755, SourceError: sourceError, StatBehavior: statBehavior, Presence: presence}
							b := run("", helper, "model", fmt.Sprint(flags), paths[pair[0]], paths[pair[1]], fmt.Sprint(presence), fmt.Sprint(sourceError), fmt.Sprint(statBehavior), fmt.Sprint(tc.Mode))
							must(json.Unmarshal(b, &tc.Native))
							f.Models = append(f.Models, tc)
							if _, _, e := securitysource.Replay(tc); e != nil {
								panic(e)
							}
						}
					}
				}
			}
		}
	}
	for _, pair := range pairs {
		for _, flags := range []int{1, 2, 3} {
			for _, kind := range []string{"file", "directory", "symlink"} {
				for _, mode := range []uint32{0, 0644, 06755} {
					tc := securitysource.Case{Name: fmt.Sprintf("live-%s-%s-%s-f%d-m%o", kind, pair[0], pair[1], flags, mode), Kind: kind, Flags: flags, SourceACL: pair[0], DestinationACL: pair[1], Mode: mode}
					invoke := func(op, input string) securitysource.Observation {
						folder := filepath.Join(root, tc.Name+"-"+op)
						if kind != "symlink" {
							for _, name := range []string{"source", "target"} {
								if err := os.Chmod(filepath.Join(folder, name), 0700); err != nil && !os.IsNotExist(err) {
									must(err)
								}
							}
						}
						must(os.RemoveAll(folder))
						must(os.MkdirAll(folder, 0700))
						b := run(input, helper, "live", fmt.Sprint(flags), paths[pair[0]], paths[pair[1]], folder, kind, fmt.Sprint(mode), op)
						write(filepath.Join(root, tc.Name+"-"+op+".json"), b)
						write(filepath.Join(root, tc.Name+"-"+op+".stdin"), []byte(input))
						var n securitysource.Observation
						must(json.Unmarshal(b, &n))
						if kind != "symlink" {
							must(os.Chmod(filepath.Join(folder, "source"), 0700))
						}
						must(os.RemoveAll(folder))
						return n
					}
					tc.Native = invoke("native", "")
					_, events, e := securitysource.Replay(tc)
					must(e)
					direct := invoke("go", securitycopy.Protocol(events))
					if !reflect.DeepEqual(direct.Events, tc.Native.Events) || !reflect.DeepEqual(direct.Before, tc.Native.Before) || !reflect.DeepEqual(direct.After, tc.Native.After) || direct.Code != tc.Native.Code {
						panic("direct mismatch: " + tc.Name)
					}
					for _, n := range []securitysource.Observation{tc.Native, direct} {
						if !n.IdentityUnchanged || !n.PayloadUnchanged || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) || n.Before.Flags != n.After.Flags {
							panic("preservation: " + tc.Name)
						}
					}
					f.Applications = append(f.Applications, tc)
				}
			}
		}
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d model cases and %d actual pairs; NOT approved\n", len(f.Models), len(f.Applications))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read(corpus)))
	must(e)
	var archived securitysource.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	archived.Revision, archived.Host = f.Revision, f.Host
	// Normalize only host-actor IDs; modeled values and all security bytes stay exact.
	if len(archived.Applications) != len(f.Applications) {
		panic("application count")
	}
	for i := range archived.Applications {
		a, b := &archived.Applications[i].Native, &f.Applications[i].Native
		oldUID, oldGID := a.SourceBefore.UID, a.SourceBefore.GID
		uid, gid := b.SourceBefore.UID, b.SourceBefore.GID
		if uid != uint32(os.Getuid()) || gid != uint32(os.Getegid()) {
			panic("actor setup")
		}
		property := func(p *securitycopy.Properties) {
			if p.UID != nil && *p.UID == oldUID {
				v := uid
				p.UID = &v
			}
			if p.GID != nil && *p.GID == oldGID {
				v := gid
				p.GID = &v
			}
		}
		normalizeSource := func(s *securitycopy.Source) {
			if s.UID != oldUID || s.GID != oldGID {
				panic("source actor")
			}
			s.UID, s.GID = uid, gid
			property(&s.Properties)
		}
		normalizeSource(&a.FinalSource)
		property(&a.Cache)
		for _, m := range []*securitycopy.Metadata{&a.SourceBefore, &a.SourceAfter, &a.Before, &a.After} {
			if m.UID != oldUID || m.GID != oldGID {
				panic("metadata actor")
			}
			m.UID, m.GID = uid, gid
			property(&m.Properties)
		}
		for j := range a.Events {
			e := &a.Events[j]
			if e.Source != nil {
				normalizeSource(e.Source)
			}
			if e.UID == oldUID {
				e.UID = uid
			}
			if e.GID == oldGID {
				e.GID = gid
			}
		}
	}
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d controlled cases, %d actual stage pairs with complete fcopyfile source acquisition\n", len(f.Models), len(f.Applications))
}
