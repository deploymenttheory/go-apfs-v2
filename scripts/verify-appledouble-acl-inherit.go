//go:build ignore

// Native ACL creation and AppleDouble replacement oracle, not a production dependency.
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

type observation struct {
	Parent, ParentAfter, Created, Restored           *string
	CreateCode, CreateErrno, UnpackCode, UnpackErrno int
	DestinationUnchanged                             bool
}
type record struct {
	Name                     string
	Directory                bool
	Parent, Initial, Sidecar []byte
	Native                   observation
}
type fixture struct {
	HelperSHA256, SourceSHA256, Host, Revision string
	Records                                    []record
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
func sum(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func main() {
	capture := flag.Bool("capture", false, "capture independent native observations without qualifying Go policy")
	flag.Parse()
	const root = "artifacts/appledouble-acl-inherit"
	const fixturePath = "testdata/appledouble/native/acl-inherit.json.gz"
	const helperSource = "testdata/appledouble/native/acl-inherit.c"
	must(os.MkdirAll(root, 0700))
	passed := false
	var f fixture
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "capture": *capture, "fixture": f, "commands": commands}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), append(b, '\n'), 0600)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native ACL oracle requires macOS")
	}
	f.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	f.Host = string(run("sw_vers"))
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	const sourceURL = "https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_authorization.c"
	client := http.Client{Timeout: 30 * time.Second}
	response, e := client.Get(sourceURL)
	must(e)
	source, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	must(e)
	must(response.Body.Close())
	if response.StatusCode != 200 {
		panic("pinned XNU source download failed")
	}
	f.SourceSHA256 = sum(source)
	if f.SourceSHA256 != "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249" {
		panic("pinned XNU source hash mismatch")
	}
	write(filepath.Join(root, "kern_authorization.c"), source)
	start := bytes.Index(source, []byte("int\nkauth_acl_inherit("))
	end := bytes.Index(source, []byte("/*\n * Optimistically copy in a kauth_filesec structure"))
	licenseEnd := bytes.Index(source, []byte("#include"))
	if start < 0 || end <= start || licenseEnd < 0 {
		panic("XNU extraction boundaries changed")
	}
	// Retain the complete unchanged function. Minimal declarations stand in for
	// kernel-only vnode services; this unit is syntax analysis, not an executable.
	unit := append(bytes.Clone(source[:licenseEnd]), []byte(`#include <sys/types.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <errno.h>
#include <stddef.h>
typedef void *vnode_t;
typedef void *vfs_context_t;
typedef struct kauth_acl *kauth_acl_t;
struct vnode_attr { kauth_acl_t va_acl; };
#define VATTR_INIT(p) ((p)->va_acl = NULL)
#define VATTR_WANTED(p,field) ((void)(p))
#define VATTR_IS_SUPPORTED(p,field) (1)
#define KAUTH_DEBUG(...) ((void)0)
extern void *vnode_mount(vnode_t);
extern int vfs_authopaque(void *);
extern int vnode_getattr(vnode_t, struct vnode_attr *, vfs_context_t);
extern kauth_acl_t kauth_acl_alloc(int);
extern void kauth_acl_free(kauth_acl_t);
`)...)
	unit = append(unit, source[start:end]...)
	unitPath := filepath.Join(root, "kauth_acl_inherit.c")
	write(unitPath, unit)
	helper := filepath.Join(root, "acl-inherit")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, path := range []string{helperSource, unitPath} {
			ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", path)
			commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
			write(filepath.Join(root, filepath.Base(path)+"-"+arch+".ast.json"), ast)
		}
	}
	for _, tc := range cases() {
		dir, e := os.MkdirTemp(root, tc.Name+"-")
		must(e)
		parent := filepath.Join(dir, "parent.txt")
		write(parent, tc.Parent)
		initial := "-"
		if tc.Initial != nil {
			initial = filepath.Join(dir, "initial.txt")
			write(initial, tc.Initial)
		}
		ad := "-"
		if tc.Sidecar != nil {
			ad = filepath.Join(dir, "input.ad")
			write(ad, tc.Sidecar)
		}
		kind := "file"
		if tc.Directory {
			kind = "directory"
		}
		out := run(helper, dir, parent, initial, kind, ad)
		write(filepath.Join(dir, "native.json"), out)
		must(json.Unmarshal(out, &tc.Native))
		f.Records = append(f.Records, tc)
		if !*capture {
			verify(tc)
		}
	}
	output, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), append(output, '\n'))
	if *capture {
		fmt.Printf("Captured %d native cases; Go policy NOT qualified\n", len(f.Records))
		return
	}
	var archived fixture
	z, e := gzip.NewReader(bytes.NewReader(read(fixturePath)))
	must(e)
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.SourceSHA256 != f.SourceSHA256 || !reflect.DeepEqual(archived.Records, f.Records) {
		panic("native observations differ from reviewed fixture")
	}
	passed = true
	fmt.Printf("Qualified %d creation and restoration cases\n", len(f.Records))
}

func cases() []record {
	var records []record
	entry := func(flags string) string {
		return "user:01234567-89AB-CDEF-0123-456789ABCDEF:::" + flags + ":read,readattr\n"
	}
	initials := []struct{ name, text string }{
		{"absent", ""}, {"empty", "!#acl 1\n"},
		{"explicit", "!#acl 1\n" + entry("deny")},
		{"inherited", "!#acl 1\n" + entry("allow,inherited")},
		{"no-inherit", "!#acl 1 no_inherit\n" + entry("allow")},
		{"defer", "!#acl 1 defer_inherit\n" + entry("deny")},
	}
	for _, directory := range []bool{false, true} {
		// Distinct principals and mixed entries make ordering/removal observable;
		// parent-wide no_inherit does not suppress a child's eligible entries.
		for pi, parent := range []string{
			"!#acl 1\n",
			"!#acl 1 no_inherit\n" + entry("allow,file_inherit,directory_inherit"),
			"!#acl 1 defer_inherit\n" + entry("deny,file_inherit,directory_inherit"),
			"!#acl 1\n" + entry("allow,file_inherit") + strings.ReplaceAll(entry("deny,directory_inherit"), "01234567-89AB-CDEF-0123-456789ABCDEF", "11234567-89AB-CDEF-0123-456789ABCDEF") + entry("allow,file_inherit,directory_inherit,only_inherit"),
		} {
			for _, initial := range initials {
				tc := record{Name: fmt.Sprintf("mixed-%t-%d-%s", directory, pi, initial.name), Directory: directory, Parent: []byte(parent)}
				if initial.text != "" {
					tc.Initial = []byte(initial.text)
				}
				records = append(records, tc)
			}
		}
		for bits := 0; bits < 32; bits++ {
			for _, action := range []string{"allow", "deny"} {
				flags := action
				for i, name := range []string{"inherited", "file_inherit", "directory_inherit", "limit_inherit", "only_inherit"} {
					if bits&(1<<i) != 0 {
						flags += "," + name
					}
				}
				for _, initial := range initials {
					tc := record{Name: fmt.Sprintf("dir-%t-flags-%02x-%s-%s", directory, bits, action, initial.name), Directory: directory, Parent: []byte("!#acl 1\n" + entry(flags))}
					if initial.text != "" {
						tc.Initial = []byte(initial.text)
					}
					records = append(records, tc)
				}
			}
		}
		// Restore every representative selection over a genuinely inherited ACL.
		for _, texts := range [][]string{nil, {""}, {"INVALID"}, {"!#acl 1\n"}, {"!#acl 1\n" + entry("deny")}, {"!#acl 1\n" + entry("allow,inherited")}, {"!#acl 1 no_inherit\n" + entry("allow")}, {"!#acl 1 defer_inherit\n" + entry("allow")}, {"!#acl 1\n", "INVALID"}, {"INVALID", "!#acl 1\n"}, {"!#acl 1\n" + entry("deny"), ""}} {
			f := &appledouble.File{}
			for _, text := range texts {
				f.Attrs = append(f.Attrs, appledouble.Attr{Name: appledouble.ACLTextName, Value: []byte(text)})
			}
			ad, e := f.Encode()
			must(e)
			records = append(records, record{Name: fmt.Sprintf("restore-%t-%d", directory, len(records)), Directory: directory, Parent: []byte("!#acl 1\n" + entry("allow,file_inherit,directory_inherit")), Sidecar: ad})
		}
		for _, n := range []int{0, 127, 128} {
			for _, inherited := range []bool{false, true} {
				flags := "allow"
				if inherited {
					flags += ",inherited"
				}
				records = append(records, record{Name: fmt.Sprintf("limit-%t-%d-%t", directory, n, inherited), Directory: directory, Parent: []byte("!#acl 1\n" + entry("allow,file_inherit,directory_inherit")), Initial: []byte("!#acl 1\n" + strings.Repeat(entry(flags), n))})
			}
		}
	}
	return records
}

func decode(p *string) *appledouble.ACL {
	if p == nil {
		return nil
	}
	b, e := hex.DecodeString(*p)
	must(e)
	a, e := appledouble.ParseACLBinary(b)
	must(e)
	return a
}
func equal(a *appledouble.ACL, b *string) bool {
	if b == nil {
		return a == nil || (a.Flags == 0 && len(a.Entries) == 0)
	}
	if a == nil {
		return false
	}
	raw, e := a.MarshalBinary()
	must(e)
	return hex.EncodeToString(raw) == *b
}
func verify(tc record) {
	var initial *appledouble.ACL
	if tc.Initial != nil {
		var e error
		initial, e = appledouble.ParseACLText(tc.Initial, nil)
		must(e)
	}
	parent, e := appledouble.ParseACLText(tc.Parent, nil)
	must(e)
	if !equal(parent, tc.Native.Parent) {
		panic("parent input differs: " + tc.Name)
	}
	created, e := appledouble.InheritACL(initial, decode(tc.Native.Parent), tc.Directory)
	if e != nil {
		if tc.Native.CreateCode != -1 || tc.Native.CreateErrno != 12 {
			panic("unexpected creation refusal: " + tc.Name)
		}
		return
	}
	if tc.Native.CreateCode != 0 || tc.Native.CreateErrno != 0 || !tc.Native.DestinationUnchanged || !reflect.DeepEqual(tc.Native.Parent, tc.Native.ParentAfter) || !equal(created, tc.Native.Created) {
		panic("creation policy differs: " + tc.Name)
	}
	if tc.Sidecar != nil {
		f, e := appledouble.Decode(tc.Sidecar)
		must(e)
		update, e := f.ACLUpdate(nil)
		must(e)
		want := decode(tc.Native.Created)
		if update.ACL != nil {
			want = update.ACL
		}
		if tc.Native.UnpackCode != 0 || tc.Native.UnpackErrno != 0 || !equal(want, tc.Native.Restored) {
			panic("replacement policy differs: " + tc.Name)
		}
	}
}
