//go:build ignore

// Qualify portable copyfile stat execution; native tools are test-only.
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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/statcopy"
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
	const root = "artifacts/stat-copy"
	const helperSource = "testdata/appledouble/native/stat-copy.c"
	const corpus = "testdata/appledouble/native/stat-copy.json.gz"
	must(os.MkdirAll(root, 0700))
	var f statcopy.Fixture
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
	if runtime.GOOS != "darwin" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		panic("requires ordinary macOS user")
	}
	f.Revision = strings.TrimSpace(string(run("", "git", "rev-parse", "HEAD")))
	f.Host = string(run("", "sw_vers"))
	run("", "uname", "-a")
	run("", "xcrun", "clang", "--version")
	run("", "xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.PrivateSHA256 = "8ac427e2c1dbe0ca92cfe2fbf114df90fd747f3fbe25c2a4919ff941a1be81c5"
	f.FSCTLSHA256 = "dae81f19610f25fb7905b5c725f728fec4b8b4978f6214374415d420ffac258d"
	src := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h", f.PrivateSHA256, filepath.Join(root, "copyfile_private.h"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	for _, p := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static errno_t copyfile_set_bsdflags", "/*\n * Attempt to copy the data section"}, {"static int copyfile_stat(copyfile_state_t s)", "/*\n * Copy the resource fork in pieces"}} {
		h = append(h, extract(src, p[0], p[1])...)
	}
	write(filepath.Join(root, "stat-source.h"), h)
	xnu := download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fsctl.h", f.FSCTLSHA256, filepath.Join(root, "fsctl.h"))
	h = append([]byte{}, xnu[:bytes.Index(xnu, []byte("#ifndef"))]...)
	h = append(h, extract(xnu, "struct fsioc_cas_bsdflags {", "#define FSIOC_GRAFT_VERSION")...)
	h = append(h, extract(xnu, "#define FSIOC_CAS_BSDFLAGS", "/* Check if a file is only open once")...)
	write(filepath.Join(root, "stat-fsctl.h"), h)
	helper := filepath.Join(root, "stat-copy")
	run("", "xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("", "xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	// Every native branch, including each independently omitted flag and every
	// compression/protection gate. Faults and races use complete Apple bodies.
	for _, sf := range []uint32{0, 1, 0x40, 0x80, 0x80000, 0x100000, 0x8000, 0x20, 0x22, 0x24, 0x20020, 0x40020, 0xffffffff} {
		for _, options := range []int{0, 1, 2, 3, 4, 8, 12} {
			for _, policy := range [][2]int{{0, 0}, {1, 0}, {0, 1}, {-5, 1}, {-5, -13}} {
				tc := statcopy.Case{Name: fmt.Sprintf("policy-%x-%d-%d-%d", sf, options, policy[0], policy[1]), SourceFlags: sf, TargetFlags: 0x1800c0, Options: options, SourcePolicy: policy[0], TargetPolicy: policy[1]}
				f.Models = append(f.Models, model(helper, tc))
			}
		}
	}
	for _, sf := range []uint32{0, 0x20, 0x22} {
		for _, tf := range []uint32{0, 0x1800c0} {
			for _, o := range []int{0, 8} {
				for fault := 0; fault <= 7; fault++ {
					for cas := 0; cas <= 5; cas++ {
						tc := statcopy.Case{Name: fmt.Sprintf("fault-%x-%x-%d-%d-%d", sf, tf, o, fault, cas), SourceFlags: sf, TargetFlags: tf, Options: o, Fault: fault, CAS: cas}
						f.Models = append(f.Models, model(helper, tc))
					}
				}
			}
		}
	}
	for _, kind := range []string{"file", "directory"} {
		for _, sf := range []uint32{0, 1, 0x8000, 0x40, 2, 4} {
			for _, tf := range []uint32{0, 2, 4, 0x40} {
				for _, options := range []int{0, 2, 4, 8} {
					tc := statcopy.Case{Name: fmt.Sprintf("live-%s-%x-%x-%d", kind, sf, tf, options), Kind: kind, SourceFlags: sf, TargetFlags: tf, Options: options}
					invoke := func(op, input string) statcopy.Observation {
						folder, e := os.MkdirTemp(root, "live-")
						must(e)
						defer os.RemoveAll(folder)
						b := run(input, helper, "live", fmt.Sprint(sf), fmt.Sprint(tf), fmt.Sprint(options), folder, kind, "0", op)
						write(filepath.Join(root, tc.Name+"-"+op+".json"), b)
						write(filepath.Join(root, tc.Name+"-"+op+".stdin"), []byte(input))
						var n statcopy.Observation
						must(json.Unmarshal(b, &n))
						if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) || n.Before.ACL != n.After.ACL || n.Before.Xattr != n.After.Xattr {
							panic("live preservation: " + tc.Name)
						}
						return n
					}
					tc.Native = invoke("native", "")
					_, events, e := statcopy.Replay(tc)
					must(e)
					direct := invoke("go", statcopy.Protocol(events))
					if !reflect.DeepEqual(direct, tc.Native) {
						panic("direct mismatch: " + tc.Name)
					}
					// Public COPYFILE_STAT includes a preceding mode write. Compare ordinary,
					// unprotected destinations where that extra write does not alter failures.
					if (options == 0 || options == 8) && tf == 0 {
						public := invoke("public", "")
						if public.Code != 0 || !reflect.DeepEqual(public.After, tc.Native.After) {
							panic("public stat mismatch: " + tc.Name)
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
		fmt.Printf("Captured %d models and %d native/Go application pairs; NOT approved\n", len(f.Models), len(f.Applications))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read(corpus)))
	must(e)
	var archived statcopy.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	archived.Revision, archived.Host = f.Revision, f.Host
	if len(archived.Applications) != len(f.Applications) {
		panic("application count")
	}
	for i := range archived.Applications {
		a, b := &archived.Applications[i].Native, &f.Applications[i].Native
		oldUID, oldGID := a.Source.UID, a.Source.GID
		if b.Source.UID != uint32(os.Getuid()) || b.Source.GID != uint32(os.Getegid()) {
			panic("actor setup")
		}
		a.Source.UID, a.Source.GID = b.Source.UID, b.Source.GID
		for _, m := range []*statcopy.Metadata{&a.SourceBefore, &a.SourceAfter, &a.Before, &a.After} {
			if m.UID != oldUID || m.GID != oldGID {
				panic("archived actor")
			}
			m.UID, m.GID = b.Source.UID, b.Source.GID
		}
		for j := range a.Events {
			v := &a.Events[j]
			if v.Operation == "ownership" {
				if v.UID != oldUID || v.GID != oldGID {
					panic("archived ownership request")
				}
				v.UID, v.GID = b.Source.UID, b.Source.GID
			}
		}
	}
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d controlled cases, %d actual native/Go stage pairs\n", len(f.Models), len(f.Applications))
}
func model(helper string, tc statcopy.Case) statcopy.Case {
	b := run("", helper, "model", fmt.Sprint(tc.SourceFlags), fmt.Sprint(tc.TargetFlags), fmt.Sprint(tc.Options), fmt.Sprint(tc.SourcePolicy), fmt.Sprint(tc.TargetPolicy), fmt.Sprint(tc.Fault), fmt.Sprint(tc.CAS))
	must(json.Unmarshal(b, &tc.Native))
	_, _, e := statcopy.Replay(tc)
	if e != nil {
		panic(tc.Name + ": " + e.Error())
	}
	return tc
}
