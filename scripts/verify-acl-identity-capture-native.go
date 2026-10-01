//go:build ignore

// Compare pure-Go libSystem capture with an independent C directory-service observer.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

const out = "artifacts/acl-identity-capture-native"

type forward struct {
	Query appledouble.ACLIdentity
	UUID  [16]byte
}
type reverse struct {
	UUID      [16]byte
	Principal appledouble.ACLPrincipal
	Found     bool
}
type native struct {
	UUID, Name                   string
	ID                           uint32
	Group, Found                 bool
	AccountErrno, MembershipCode int
}
type command struct {
	Args   []string
	Output string
}
type report struct {
	Revision, Host, Compiler, SDK string
	SourceSHA256                  map[string]string
	Commands                      []command
	Forward                       []forward                       `json:"-"`
	Reverse                       []reverse                       `json:"-"`
	Snapshot                      appledouble.ACLIdentitySnapshot `json:"-"`
	ForwardChecks, ReverseChecks  int
}

var evidence report

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	evidence.Commands = append(evidence.Commands, command{args, string(b)})
	if e != nil {
		panic(fmt.Sprintf("%v: %v %s", args, e, b))
	}
	return b
}
func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func uuidText(u [16]byte) string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
}
func decode(s string) []byte { b, e := hex.DecodeString(s); must(e); return b }
func main() {
	capture := flag.Bool("capture", false, "replace retained portable source identity snapshot")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("native identity capture requires Darwin directory services")
	}
	must(os.MkdirAll(out, 0755))
	defer func() {
		b, e := json.MarshalIndent(evidence, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(out, "report.json"), b, 0600))
	}()
	evidence.SourceSHA256 = map[string]string{}
	evidence.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	evidence.Host = string(run("sw_vers"))
	evidence.Compiler = string(run("xcrun", "clang", "--version"))
	evidence.SDK = string(run("xcrun", "--show-sdk-version"))
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	for _, name := range []string{"pwd.h", "grp.h", "membership.h"} {
		p := filepath.Join(sdk, "usr/include", name)
		evidence.SourceSHA256[p] = sha(read(p))
	}
	for _, pattern := range []string{"pkg/hostdata/acl/acl_identity_capture*.go", "pkg/appledouble/acl_identity*.go", "scripts/verify-acl-identity-capture-native.go", "testdata/appledouble/native/acl-identity.c", "testdata/appledouble/native/acl-identity-capture.c", "go.mod", "go.sum"} {
		paths, e := filepath.Glob(pattern)
		must(e)
		for _, p := range paths {
			evidence.SourceSHA256[p] = sha(read(p))
		}
	}
	source := "testdata/appledouble/native/acl-identity-capture.c"
	oracle := filepath.Join(out, "oracle")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		must(os.WriteFile(filepath.Join(out, arch+".ast.json"), b, 0600))
		evidence.Commands[len(evidence.Commands)-1].Output = fmt.Sprintf("AST %d bytes SHA256 %s", len(b), sha(b))
		for _, name := range []string{"mbr_uid_to_uuid", "mbr_gid_to_uuid", "mbr_uuid_to_id", "getpwuid", "getpwnam", "getgrgid", "getgrnam"} {
			if !bytes.Contains(b, []byte(`"name": "`+name+`"`)) {
				panic("missing AST function " + name)
			}
		}
	}
	c, e := aclmeta.NewNativeACLIdentityCapture(context.Background())
	must(e)
	query := func(args ...string) native {
		var n native
		// Account identifiers remain in process memory. Published command
		// observations carry only the lookup family and successful comparison.
		b, err := exec.Command(oracle, args...).Output()
		if err != nil {
			panic("native identity observer failed")
		}
		must(json.Unmarshal(b, &n))
		evidence.Commands = append(evidence.Commands, command{[]string{"identity-observer", args[0]}, "lookup completed; account identifiers not retained"})
		if n.AccountErrno != 0 || n.MembershipCode != 0 && n.MembershipCode != 2 {
			panic(fmt.Sprintf("directory service failure: account errno=%d membership code=%d", n.AccountErrno, n.MembershipCode))
		}
		return n
	}
	checkReverse := func(u [16]byte, public bool) {
		n := query("reverse", "uuid", uuidText(u))
		p, found, e := c.Lookup(u)
		must(e)
		want := appledouble.ACLPrincipal{Group: n.Group, Name: string(decode(n.Name)), ID: n.ID}
		if !n.Found {
			want = appledouble.ACLPrincipal{}
		}
		if found != n.Found || p != want {
			panic("native reverse identity mismatch")
		}
		evidence.ReverseChecks++
		if public {
			evidence.Reverse = append(evidence.Reverse, reverse{u, p, found})
		}
	}
	for _, group := range []bool{false, true} {
		kind := "user"
		current := os.Getuid()
		names := []string{"root", "daemon", "nobody", "appledouble-no-such-account-01234567"}
		if group {
			kind = "group"
			current = os.Getgid()
			names[0] = "wheel"
		}
		var identities []appledouble.ACLIdentity
		for _, name := range names {
			identities = append(identities, appledouble.ACLIdentity{Group: group, Name: name})
		}
		for _, number := range []uint32{0, uint32(current), ^uint32(0)} {
			id := number
			identities = append(identities, appledouble.ACLIdentity{Group: group, ID: &id})
		}
		for i, q := range identities {
			public := i != 5 // index5 is the running process's UID/GID.
			mode, value := "name", q.Name
			if q.ID != nil {
				mode, value = "id", strconv.FormatUint(uint64(*q.ID), 10)
			}
			n := query(kind, mode, value)
			var want [16]byte
			copy(want[:], decode(n.UUID))
			u, e := c.Resolve(q)
			must(e)
			if u != want {
				panic("native forward identity mismatch")
			}
			evidence.ForwardChecks++
			if public {
				evidence.Forward = append(evidence.Forward, forward{q, u})
			}
			if n.Found {
				checkReverse(u, public)
			}
		}
	}
	checkReverse([16]byte{1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239}, true)
	resolve, lookup, e := c.Snapshot().Resolvers()
	must(e)
	for _, f := range evidence.Forward {
		u, e := resolve(f.Query)
		must(e)
		if u != f.UUID {
			panic("snapshot forward mismatch")
		}
	}
	for _, r := range evidence.Reverse {
		p, found, e := lookup(r.UUID)
		must(e)
		if p != r.Principal || found != r.Found {
			panic("snapshot reverse mismatch")
		}
	}
	// A retained fixture contains only explicitly selected public system
	// accounts and fixed negative queries, never the running user's records.
	evidence.Snapshot = appledouble.ACLIdentitySnapshot{Version: 1}
	for _, f := range evidence.Forward {
		evidence.Snapshot.Identities = append(evidence.Snapshot.Identities, appledouble.ACLIdentityBinding{Group: f.Query.Group, Name: []byte(f.Query.Name), ID: f.Query.ID, UUID: f.UUID})
	}
	seen := map[[16]byte]bool{}
	for _, r := range evidence.Reverse {
		if seen[r.UUID] {
			continue
		}
		seen[r.UUID] = true
		evidence.Snapshot.Principals = append(evidence.Snapshot.Principals, appledouble.ACLPrincipalBinding{UUID: r.UUID, Found: r.Found, Group: r.Principal.Group, Name: []byte(r.Principal.Name), ID: r.Principal.ID})
	}
	_, _, e = evidence.Snapshot.Resolvers()
	must(e)
	if *capture {
		f, e := os.Create("testdata/appledouble/native/acl-identity-capture.json.gz")
		must(e)
		z := gzip.NewWriter(f)
		must(json.NewEncoder(z).Encode(map[string]any{"Host": evidence.Host, "SDK": evidence.SDK, "Compiler": evidence.Compiler, "Revision": evidence.Revision, "SourceSHA256": evidence.SourceSHA256, "Forward": evidence.Forward, "Reverse": evidence.Reverse, "Snapshot": evidence.Snapshot, "Scope": "fixed public system accounts and negative queries only"}))
		must(z.Close())
		must(f.Close())
	}
	fmt.Printf("Qualified %d forward and %d reverse native account comparisons; no personal account identifiers retained\n", evidence.ForwardChecks, evidence.ReverseChecks)
}
