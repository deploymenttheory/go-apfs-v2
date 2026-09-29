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
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
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
	cmd := exec.Command(args[0], args[1:]...)
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
	const root = "artifacts/security-copy"
	const helperSource = "testdata/appledouble/native/security-copy.c"
	const corpus = "testdata/appledouble/native/security-copy.json.gz"
	must(os.MkdirAll(root, 0700))
	var f securitycopy.Fixture
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
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.LibcSHA256 = "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff"
	src := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	for _, p := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static int\ncopyfile_unset_posix_fsec", "/*\n * Used to remove acl information"}, {"static int copyfile_security(copyfile_state_t s)", "/*\n * Attempt to set the destination"}} {
		h = append(h, extract(src, p[0], p[1])...)
	}
	write(filepath.Join(root, "acl-copy-source.h"), h)
	libc := download("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c", f.LibcSHA256, filepath.Join(root, "chmodx_np.c"))
	h = append([]byte{}, libc[:bytes.Index(libc, []byte("#include"))]...)
	h = append(h, libc[bytes.Index(libc, []byte("static int\nchmodx1(")):]...)
	write(filepath.Join(root, "acl-chmod-source.h"), h)
	helper := filepath.Join(root, "security-copy")
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
	pairs := [][2]string{{"none", "none"}, {"allow", "none"}, {"none", "inherited"}, {"allow", "inherited"}, {"empty", "empty"}, {"explicit128", "inherited128"}}
	for _, pair := range pairs {
		for _, flags := range []int{1, 2, 3} {
			for filter := 0; filter < 5; filter++ {
				for _, presence := range []int{0, 4, 24, 31} {
					for fault := 0; fault < 6; fault++ {
						tc := securitycopy.Case{Name: fmt.Sprintf("model-%s-%s-f%d-p%d-m%d-e%d", pair[0], pair[1], flags, filter, presence, fault), SourceACL: pair[0], DestinationACL: pair[1], Flags: flags, Filter: filter, Presence: presence, Fault: fault}
						b := run("", helper, "model", fmt.Sprint(flags), fmt.Sprint(filter), paths[pair[0]], paths[pair[1]], fmt.Sprint(presence), fmt.Sprint(fault))
						must(json.Unmarshal(b, &tc.Native))
						f.Models = append(f.Models, tc)
						if _, _, e := securitycopy.Replay(tc); e != nil {
							panic(tc.Name + ": " + e.Error())
						}
					}
				}
			}
		}
	}
	for _, pair := range pairs[:4] {
		for _, flags := range []int{1, 2, 3} {
			for _, filter := range []int{0, 1, 2} {
				for _, kind := range []string{"file", "directory"} {
					for _, targetFlags := range []int{0, 2, 4} {
						tc := securitycopy.Case{Name: fmt.Sprintf("live-%s-%s-%s-f%d-p%d-b%d", kind, pair[0], pair[1], flags, filter, targetFlags), Kind: kind, SourceACL: pair[0], DestinationACL: pair[1], Flags: flags, Filter: filter, TargetFlags: targetFlags}
						dir := filepath.Join(root, tc.Name)
						must(os.RemoveAll(dir))
						must(os.MkdirAll(dir, 0700))
						invoke := func(op, input string) securitycopy.Observation {
							folder := filepath.Join(dir, op)
							must(os.MkdirAll(folder, 0700))
							b := run(input, helper, "live", fmt.Sprint(flags), fmt.Sprint(filter), paths[pair[0]], paths[pair[1]], folder, kind, fmt.Sprint(targetFlags), op)
							write(filepath.Join(dir, op+".json"), b)
							write(filepath.Join(dir, op+".stdin"), []byte(input))
							var out securitycopy.Observation
							must(json.Unmarshal(b, &out))
							return out
						}
						tc.Native = invoke("native", "")
						_, events, e := securitycopy.Replay(tc)
						if e != nil {
							panic(tc.Name + ": " + e.Error())
						}
						direct := invoke("go", securitycopy.Protocol(events))
						if !reflect.DeepEqual(direct.Events, events) || !reflect.DeepEqual(direct.Source, tc.Native.Source) || !reflect.DeepEqual(direct.Before, tc.Native.Before) || !reflect.DeepEqual(direct.After, tc.Native.After) || direct.Code != 0 {
							panic("direct mismatch: " + tc.Name)
						}
						for _, n := range []securitycopy.Observation{tc.Native, direct} {
							if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) || n.Before.Flags != n.After.Flags {
								panic("live preservation: " + tc.Name)
							}
						}
						if flags == 1 && filter == 0 {
							public := invoke("public", "")
							if public.Code != tc.Native.Code || !reflect.DeepEqual(public.Before, tc.Native.Before) || !reflect.DeepEqual(public.After, tc.Native.After) || !reflect.DeepEqual(public.SourceBefore, public.SourceAfter) || !public.IdentityUnchanged || !public.PayloadUnchanged {
								panic("public copy mismatch: " + tc.Name)
							}
						}
						f.Applications = append(f.Applications, tc)
					}
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
	var archived securitycopy.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	archived.Revision, archived.Host = f.Revision, f.Host
	// UID/GID normalization is restricted to the captured host actor values.
	if len(archived.Applications) != len(f.Applications) {
		panic("application count")
	}
	for i := range archived.Applications {
		a, b := &archived.Applications[i].Native, &f.Applications[i].Native
		oldUID, oldGID := a.Source.UID, a.Source.GID
		if b.Source.UID != uint32(os.Getuid()) || b.Source.GID != uint32(os.Getegid()) {
			panic("actor setup")
		}
		normalize := func(p *securitycopy.Properties) {
			if p.UID != nil && *p.UID == oldUID {
				v := b.Source.UID
				p.UID = &v
			}
			if p.GID != nil && *p.GID == oldGID {
				v := b.Source.GID
				p.GID = &v
			}
		}
		normalize(&a.Source.Properties)
		normalize(&a.Cache)
		a.Source.UID, a.Source.GID = b.Source.UID, b.Source.GID
		for _, m := range []*securitycopy.Metadata{&a.SourceBefore, &a.SourceAfter, &a.Before, &a.After} {
			if m.UID != oldUID || m.GID != oldGID {
				panic("unexpected archived identity")
			}
			m.UID, m.GID = b.Source.UID, b.Source.GID
			normalize(&m.Properties)
		}
		for j := range a.Events {
			v := &a.Events[j]
			if v.UID == oldUID {
				v.UID = b.Source.UID
			}
			if v.GID == oldGID {
				v.GID = b.Source.GID
			}
		}
	}
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d controlled cases, %d actual stage pairs and 24 public ACL copies\n", len(f.Models), len(f.Applications))
}
