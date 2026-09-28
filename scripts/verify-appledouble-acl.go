//go:build ignore

// Independent macOS ACL oracle; production code remains pure Go on every OS.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type command struct {
	Args            []string
	Output, Error   string
	ExpectedFailure bool
}
type result struct {
	Name                             string
	Accepted, BinaryEqual, TextEqual bool
}

var commands []command
var results []result
var roundTrips []string
var externalResults []result
var identityResults []string
var updateResults []aclUpdateResult
var snapshotResults []identitySnapshotCase

type identitySnapshotCase struct {
	Name                                string
	Input, External, Canonical, Sidecar []byte
	Snapshot                            appledouble.ACLIdentitySnapshot
	RestoredKinds                       []string
}

type identitySnapshotFixture struct {
	HelperSHA256, ACLHelperSHA256, SourceSHA256, Host, Revision string
	Records                                                     []identitySnapshotCase
}

type aclUpdateResult struct {
	Name, Kind                                     string
	RecordIndex                                    int
	Invalid, AfterAbsent, NativeEqual, PolicyEqual bool
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(p string) []byte     { b, e := os.ReadFile(p); must(e); return b }
func write(p string, b []byte) { must(os.WriteFile(p, b, 0600)) }
func observe(args ...string) ([]byte, error) {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	c := command{Args: args, Output: string(b)}
	if e != nil {
		c.Error = e.Error()
	}
	commands = append(commands, c)
	return b, e
}
func run(args ...string) []byte {
	b, e := observe(args...)
	if e != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, e, b))
	}
	return b
}
func main() {
	const root = "artifacts/appledouble-acl"
	must(os.MkdirAll(root, 0755))
	passed := false
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "commands": commands, "comparisons": results, "round_trips": roundTrips, "external_comparisons": externalResults, "identity_comparisons": identityResults, "acl_updates": updateResults}
		report["identity_snapshots"] = snapshotResults
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), append(b, '\n'), 0644)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native ACL oracle requires macOS")
	}
	run("git", "rev-parse", "HEAD")
	run("sw_vers")
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	var fixture struct {
		SourceSHA256, HelperSHA256 string
		Records                    []struct {
			Name                      string
			Text, External, Canonical []byte
			Accepted                  bool
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/acl.json"), &fixture))
	if len(fixture.Records) != 59 {
		panic("missing ACL fixture cases")
	}
	helperSource := "testdata/appledouble/native/acl.c"
	if fmt.Sprintf("%x", sha256.Sum256(read(helperSource))) != fixture.HelperSHA256 {
		panic("ACL helper hash mismatch")
	}
	const sourceURL = "https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/acl_translate.c"
	client := http.Client{Timeout: 30 * time.Second}
	response, e := client.Get(sourceURL)
	must(e)
	source, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	must(e)
	must(response.Body.Close())
	if response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(source)) != fixture.SourceSHA256 {
		panic("pinned Libc source hash mismatch")
	}
	write(filepath.Join(root, "acl_translate.c"), source)
	// Extract the complete native parser and its token tables unchanged. Only
	// public SDK includes are supplied; do not compile a reimplementation.
	licenseEnd := bytes.Index(source, []byte("#include <sys/appleapiopts.h>"))
	tablesStart := bytes.Index(source, []byte("#define ACL_TYPE_DIR"))
	tablesEnd := bytes.Index(source, []byte("/*\n * reallocing snprintf"))
	parserStart := bytes.Index(source, []byte("acl_t\nacl_from_text("))
	parserEnd := bytes.Index(source, []byte("\nchar *\nacl_to_text("))
	if licenseEnd < 0 || tablesStart < 0 || tablesEnd <= tablesStart || parserStart < 0 || parserEnd <= parserStart {
		panic("Libc parser extraction boundaries changed")
	}
	parserSource := append(bytes.Clone(source[:licenseEnd]), []byte("#include <sys/types.h>\n#include <sys/acl.h>\n#include <errno.h>\n#include <stdlib.h>\n#include <string.h>\n#include <strings.h>\n#include <membership.h>\n#include <uuid/uuid.h>\n#include <pwd.h>\n#include <grp.h>\n")...)
	parserSource = append(parserSource, source[tablesStart:tablesEnd]...)
	parserSource = append(parserSource, source[parserStart:parserEnd]...)
	parserPath := filepath.Join(root, "acl_from_text.c")
	write(parserPath, parserSource)

	helper := filepath.Join(root, "acl")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "acl-"+arch+".ast.json"), ast)
		parserAST := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", parserPath)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(parserAST))
		write(filepath.Join(root, "acl_from_text-"+arch+".ast.json"), parserAST)

		layout := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-fdump-record-layouts", helperSource)
		write(filepath.Join(root, "acl-"+arch+".layout.txt"), layout)
	}
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, tc.Name)
		must(os.MkdirAll(dir, 0700))
		input, external, canonical := filepath.Join(dir, "input.txt"), filepath.Join(dir, "native.bin"), filepath.Join(dir, "canonical.txt")
		write(input, tc.Text)
		output, nativeErr := observe(helper, "parse", input, external, canonical)
		if nativeErr != nil {
			var exit *exec.ExitError
			if tc.Accepted || !errors.As(nativeErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(output), "parse failed: errno=") {
				panic(fmt.Sprintf("unexpected native failure %s: %v %s", tc.Name, nativeErr, output))
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		a, goErr := appledouble.ParseACLText(tc.Text, nil)
		if (nativeErr == nil) != tc.Accepted || (goErr == nil) != tc.Accepted {
			panic("ACL acceptance differs: " + tc.Name)
		}
		r := result{Name: tc.Name, Accepted: tc.Accepted}
		if tc.Accepted {
			b, e := a.MarshalBinary()
			must(e)
			write(filepath.Join(dir, "go.bin"), b)
			r.BinaryEqual = bytes.Equal(b, read(external)) && bytes.Equal(b, tc.External)
			text, e := a.MarshalText()
			must(e)
			write(filepath.Join(dir, "go.txt"), text)
			r.TextEqual = bytes.Equal(text, read(canonical)) && bytes.Equal(text, tc.Canonical)
			if !r.TextEqual {
				panic("ACL canonical text differs: " + tc.Name)
			}
			if !r.BinaryEqual {
				panic("ACL binary differs: " + tc.Name)
			}
		}
		results = append(results, r)
	}
	verifyExternal(root, source)
	verifyIdentities(root, helper)
	// Exercise ACL application in both directions with an explicit, unknown UUID:
	// no account database or host-specific principal mapping can affect the result.
	unpack := filepath.Join(root, "copyfile")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/probe.c", "-o", unpack)
	verifyACLUpdates(root, helper, unpack)
	verifyIdentitySnapshots(root, helper, unpack)
	for _, kind := range []string{"file", "directory"} {
		dir, e := os.MkdirTemp(root, "roundtrip-"+kind+"-")
		must(e)
		text := []byte("!#acl 1\nuser:01234567-89AB-CDEF-0123-456789ABCDEF:::allow:read,readattr,readsecurity\n")
		input, src, dst := filepath.Join(dir, "input.txt"), filepath.Join(dir, "source"), filepath.Join(dir, "restored")
		write(input, text)
		if kind == "directory" {
			must(os.Mkdir(src, 0700))
			must(os.Mkdir(dst, 0700))
		} else {
			write(src, nil)
			write(dst, nil)
		}
		run(helper, "set", input, src)
		run(helper, "get", src, filepath.Join(dir, "source.bin"), filepath.Join(dir, "source.txt"))
		run(helper, "pack", src, filepath.Join(dir, "native.ad"))
		f, e := appledouble.Decode(read(filepath.Join(dir, "native.ad")))
		must(e)
		a, e := appledouble.ParseACLText(f.Xattrs()[appledouble.ACLTextName], nil)
		must(e)
		b, e := a.MarshalBinary()
		must(e)
		if !bytes.Equal(b, read(filepath.Join(dir, "source.bin"))) {
			panic("native packed ACL differs: " + kind)
		}
		// Import actual native bytes and format the ACL, including copyfile's NUL.
		imported, e := appledouble.ParseACLBinary(read(filepath.Join(dir, "source.bin")))
		must(e)
		text, e = imported.MarshalText()
		must(e)
		text = append(text, 0)
		if !bytes.Equal(text, f.Xattrs()[appledouble.ACLTextName]) {
			panic("packed ACL payload differs: " + kind)
		}
		encoded, e := appledouble.FromXattrs(map[string][]byte{appledouble.ACLTextName: text}).Encode()
		must(e)
		write(filepath.Join(dir, "go.ad"), encoded)
		run(unpack, "unpack", filepath.Join(dir, "go.ad"), dst)
		run(helper, "get", dst, filepath.Join(dir, "restored.bin"), filepath.Join(dir, "restored.txt"))
		if !bytes.Equal(b, read(filepath.Join(dir, "restored.bin"))) {
			panic("Go ACL native application differs: " + kind)
		}
		roundTrips = append(roundTrips, kind)
	}
	passed = true
	fmt.Printf("ACL oracle: %d parser, %d external, %d identity cases, %d filesystem round trips and %d ACL updates passed\n", len(results), len(externalResults), len(identityResults), len(roundTrips), len(updateResults))
	fmt.Printf("Source identity snapshots: %d live capture/replay cases and %d native restorations passed\n", len(snapshotResults), 2*len(snapshotResults))
}

func verifyIdentitySnapshots(root, aclHelper, unpack string) {
	const source = "testdata/appledouble/native/acl-identity.c"
	helper := filepath.Join(root, "acl-identity")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "acl-identity-"+arch+".ast.json"), ast)
	}
	decode := func(s string) []byte { b, e := hex.DecodeString(s); must(e); return b }
	uuidText := func(u [16]byte) string { return fmt.Sprintf("%X-%X-%X-%X-%X", u[:4], u[4:6], u[6:8], u[8:10], u[10:]) }
	type nativeLookup struct {
		UUID, Name                   string
		ID                           uint32
		Group, Found                 bool
		AccountErrno, MembershipCode int
	}
	query := func(args ...string) nativeLookup {
		var result nativeLookup
		must(json.Unmarshal(run(append([]string{helper}, args...)...), &result))
		if result.AccountErrno != 0 || (result.MembershipCode != 0 && (args[0] != "reverse" || result.MembershipCode != 2)) {
			panic(fmt.Sprintf("source identity service failure: %v: %+v", args, result))
		}
		return result
	}
	entry := func(fields string) string { return fields + ":allow:read,readattr\n" }
	bodies := []string{
		entry("user::root:"), entry("user:::0"), entry("group::wheel:"), entry("group:::0"),
		entry("user::daemon:"), entry("group::daemon:"), entry("user::nobody:"), entry("group::nobody:"),
		entry("user:::" + strconv.Itoa(os.Getuid())), entry("group:::" + strconv.Itoa(os.Getgid())),
		entry("user::appledouble-no-such-account-01234567:"), entry("group::appledouble-no-such-account-01234567:"),
		entry("user:::4294967295"), entry("group:::4294967295"),
		entry("user:01234567-89AB-CDEF-0123-456789ABCDEF::"), entry("group:01234567-89AB-CDEF-0123-456789ABCDEF:wheel:0"),
		entry("user:not-a-uuid:root:0"), entry("user::root:4294967295"), entry("group::wheel:4294967295"),
		entry("user:::0trailing"), entry("group::: -0"), entry("user:::18446744073709551616"),
		"user::root::,inherited:read\n",
		entry("user::root:") + entry("user::root:") + entry("group::wheel:") + entry("user:::0"),
		entry("user::root:") + entry("user::appledouble-no-such-account-01234567:") + entry("group::wheel:") + entry("group:::4294967295"),
	}
	for i, body := range bodies {
		name := fmt.Sprintf("source-identities-%02d", i)
		dir, e := os.MkdirTemp(root, name+"-")
		must(e)
		tc := identitySnapshotCase{Name: name, Input: []byte("!#acl 1\n" + body)}
		input := filepath.Join(dir, "input.txt")
		write(input, tc.Input)
		run(aclHelper, "parse", input, filepath.Join(dir, "native.bin"), filepath.Join(dir, "native.txt"))
		tc.External = read(filepath.Join(dir, "native.bin"))
		tc.Canonical = read(filepath.Join(dir, "native.txt"))
		capture := appledouble.NewACLIdentityCapture(func(id appledouble.ACLIdentity) ([16]byte, error) {
			kind, mode, value := "user", "name", id.Name
			if id.Group {
				kind = "group"
			}
			if id.ID != nil {
				mode = "id"
				value = strconv.FormatUint(uint64(*id.ID), 10)
			}
			n := query(kind, mode, value)
			var uuid [16]byte
			b := decode(n.UUID)
			if len(b) != len(uuid) {
				panic("native UUID size")
			}
			copy(uuid[:], b)
			return uuid, nil
		}, func(uuid [16]byte) (appledouble.ACLPrincipal, bool, error) {
			n := query("reverse", "uuid", uuidText(uuid))
			if !n.Found {
				return appledouble.ACLPrincipal{}, false, nil
			}
			return appledouble.ACLPrincipal{Group: n.Group, Name: string(decode(n.Name)), ID: n.ID}, true, nil
		})
		a, e := appledouble.ParseACLText(tc.Input, capture.Resolve)
		must(e)
		external, e := a.MarshalBinary()
		must(e)
		if !bytes.Equal(external, tc.External) {
			panic("native source identity parse differs: " + name)
		}
		canonical, e := a.FormatText(capture.Lookup)
		must(e)
		if !bytes.Equal(canonical, tc.Canonical) {
			panic("native source identity formatting differs: " + name)
		}
		// The superseded account record must not trigger a source lookup.
		f := &appledouble.File{Attrs: []appledouble.Attr{
			{Name: appledouble.ACLTextName, Value: []byte("!#acl 1\nuser::discarded-source-identity::deny:read\n")},
			{Name: appledouble.ACLTextName, Value: tc.Input}, {Name: appledouble.ACLTextName},
		}}
		u, e := f.ACLUpdate(capture.Resolve)
		must(e)
		if u.RecordIndex != 1 || u.Invalid || u.ACL == nil {
			panic("source ACL selection differs")
		}
		tc.Sidecar, e = f.Encode()
		must(e)
		write(filepath.Join(dir, "input.ad"), tc.Sidecar)
		// Serialize before replay to exercise the transport boundary, then replay
		// without any source callbacks or receiving-host account lookup.
		snapshot, e := json.Marshal(capture.Snapshot())
		must(e)
		write(filepath.Join(dir, "snapshot.json"), snapshot)
		must(json.Unmarshal(snapshot, &tc.Snapshot))
		r, l, e := tc.Snapshot.Resolvers()
		must(e)
		decoded, e := appledouble.Decode(tc.Sidecar)
		must(e)
		update, e := decoded.ACLUpdate(r)
		must(e)
		external, e = update.ACL.MarshalBinary()
		must(e)
		canonical, e = update.ACL.FormatText(l)
		must(e)
		if !bytes.Equal(external, tc.External) || !bytes.Equal(canonical, tc.Canonical) {
			panic("snapshot replay differs: " + name)
		}
		if _, e := r(appledouble.ACLIdentity{Name: "discarded-source-identity"}); !errors.Is(e, appledouble.ErrACLIdentityUncaptured) {
			panic("discarded record resolved")
		}
		write(filepath.Join(dir, "go.bin"), external)
		write(filepath.Join(dir, "go.txt"), canonical)
		for _, kind := range []string{"file", "directory"} {
			destination := filepath.Join(dir, kind)
			if kind == "file" {
				write(destination, nil)
			} else {
				must(os.Mkdir(destination, 0700))
			}
			run(unpack, "unpack", filepath.Join(dir, "input.ad"), destination)
			run(aclHelper, "get", destination, filepath.Join(dir, kind+".bin"), filepath.Join(dir, kind+".txt"))
			if !bytes.Equal(read(filepath.Join(dir, kind+".bin")), tc.External) || !bytes.Equal(read(filepath.Join(dir, kind+".txt")), tc.Canonical) {
				panic("native source-identity restoration differs: " + name + "/" + kind)
			}
			tc.RestoredKinds = append(tc.RestoredKinds, kind)
		}
		snapshotResults = append(snapshotResults, tc)
	}
	f := identitySnapshotFixture{HelperSHA256: fmt.Sprintf("%x", sha256.Sum256(read(source))), ACLHelperSHA256: fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/acl.c"))), SourceSHA256: "929b16ba8d52527c1bb4812ed7ed25f3e43f315516898d1bd777a10ca690e4c2", Host: string(run("sw_vers")), Revision: strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), Records: snapshotResults}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed-identities.json"), append(b, '\n'))
	// Real account UUIDs, IDs and names may differ between hosts. The archived
	// fixture is portable source evidence, not a receiving-host account baseline.
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/acl-identities.json.gz")))
	must(e)
	var archived identitySnapshotFixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.ACLHelperSHA256 != f.ACLHelperSHA256 || archived.SourceSHA256 != f.SourceSHA256 || len(archived.Records) != len(f.Records) {
		panic("source identity fixture provenance differs")
	}
	for i, tc := range archived.Records {
		if tc.Name != f.Records[i].Name {
			panic("source identity fixture case missing")
		}
	}
}

func verifyExternal(root string, source []byte) {
	var fixture struct {
		SourceSHA256, HelperSHA256 string
		Records                    []struct {
			Name, InputSHA256     string
			Input, External, Text []byte
			Accepted              bool
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/acl-external.json"), &fixture))
	if len(fixture.Records) != 34 || fmt.Sprintf("%x", sha256.Sum256(source)) != fixture.SourceSHA256 {
		panic("external fixture provenance")
	}
	helperSource := "testdata/appledouble/native/acl-external.c"
	if fmt.Sprintf("%x", sha256.Sum256(read(helperSource))) != fixture.HelperSHA256 {
		panic("external helper hash mismatch")
	}
	helper := filepath.Join(root, "acl-external")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", helperSource, "-o", helper)
	// Supply the pinned private type declarations, not guessed substitute structs.
	client := http.Client{Timeout: 30 * time.Second}
	response, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/posix1e/aclvar.h")
	must(e)
	header, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	must(e)
	must(response.Body.Close())
	if response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(header)) != "74711afda9818508af93ec472db57243ed45b13908a22e2bff35af9d6a8f7fd7" {
		panic("pinned ACL declarations hash mismatch")
	}
	write(filepath.Join(root, "aclvar.h"), header)
	licenseEnd := bytes.Index(source, []byte("#include <sys/appleapiopts.h>"))
	tableStart := bytes.Index(source, []byte("#define ACL_TYPE_DIR"))
	formatEnd := bytes.Index(source, []byte("\nssize_t\nacl_size("))
	importStart := bytes.Index(source, []byte("acl_t\nacl_copy_int("))
	importEnd := bytes.Index(source, []byte("/*\n * external representation, native system endianity"))
	if licenseEnd < 0 || tableStart < 0 || formatEnd <= tableStart || importStart < 0 || importEnd <= importStart {
		panic("ACL conversion extraction failed")
	}
	conversion := append(bytes.Clone(source[:licenseEnd]), []byte("#include <sys/types.h>\n#include <sys/acl.h>\n#include <stdint.h>\n#include <errno.h>\n#include <stdio.h>\n#include <stdarg.h>\n#include <stdlib.h>\n#include <string.h>\n#include <strings.h>\n#include <membership.h>\n#include <uuid/uuid.h>\n#include <pwd.h>\n#include <grp.h>\n#include <libkern/OSByteOrder.h>\n#include \"aclvar.h\"\n")...)
	conversion = append(conversion, source[importStart:importEnd]...)
	conversion = append(conversion, source[tableStart:formatEnd]...)
	conversionPath := filepath.Join(root, "acl_conversion.c")
	write(conversionPath, conversion)
	for _, arch := range []string{"arm64", "x86_64"} {
		for _, unit := range []struct{ name, path string }{{"acl-external", helperSource}, {"acl_conversion", conversionPath}} {
			ast := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", unit.path)
			commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
			write(filepath.Join(root, unit.name+"-"+arch+".ast.json"), ast)
		}
	}
	for _, tc := range fixture.Records {
		dir := filepath.Join(root, "external", tc.Name)
		must(os.MkdirAll(dir, 0700))
		input, external, text := filepath.Join(dir, "input.bin"), filepath.Join(dir, "native.bin"), filepath.Join(dir, "native.txt")
		write(input, tc.Input)
		if fmt.Sprintf("%x", sha256.Sum256(tc.Input)) != tc.InputSHA256 {
			panic("external input hash mismatch")
		}
		output, nativeErr := observe(helper, input, external, text)
		if nativeErr != nil {
			var exit *exec.ExitError
			if tc.Accepted || !errors.As(nativeErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(output), "import failed: errno=") {
				panic(fmt.Sprintf("unexpected external failure: %s: %v: %s", tc.Name, nativeErr, output))
			}
			commands[len(commands)-1].ExpectedFailure = true
		}
		a, goErr := appledouble.ParseACLBinary(tc.Input)
		if (nativeErr == nil) != tc.Accepted || (goErr == nil) != tc.Accepted {
			panic("external acceptance differs: " + tc.Name)
		}
		r := result{Name: tc.Name, Accepted: tc.Accepted}
		if tc.Accepted {
			b, e := a.MarshalBinary()
			must(e)
			write(filepath.Join(dir, "go.bin"), b)
			canonical, e := a.MarshalText()
			must(e)
			write(filepath.Join(dir, "go.txt"), canonical)
			r.BinaryEqual = bytes.Equal(b, read(external)) && bytes.Equal(b, tc.External)
			r.TextEqual = bytes.Equal(canonical, read(text)) && bytes.Equal(canonical, tc.Text)
			if !r.BinaryEqual || !r.TextEqual {
				panic("external conversion differs: " + tc.Name)
			}
		}
		externalResults = append(externalResults, r)
	}
}

func verifyIdentities(root, helper string) {
	// Native host lookup supplies source identity evidence; production lookup is
	// exclusively caller supplied. Do not assume a fixed UUID for either account.
	for _, tc := range []struct {
		kind, name string
		group      bool
	}{{"user", "root", false}, {"group", "wheel", true}} {
		dir := filepath.Join(root, "identity-"+tc.kind)
		must(os.MkdirAll(dir, 0700))
		input, external, native := filepath.Join(dir, "input.txt"), filepath.Join(dir, "native.bin"), filepath.Join(dir, "native.txt")
		write(input, []byte(fmt.Sprintf("!#acl 1\n%s::%s::allow:read\n", tc.kind, tc.name)))
		run(helper, "parse", input, external, native)
		a, e := appledouble.ParseACLBinary(read(external))
		must(e)
		if len(a.Entries) != 1 || a.Entries[0].Principal == [16]byte{} {
			panic("source identity lookup failed")
		}
		b, e := a.FormatText(func(uuid [16]byte) (appledouble.ACLPrincipal, bool, error) {
			if uuid != a.Entries[0].Principal {
				panic("unexpected source UUID")
			}
			return appledouble.ACLPrincipal{Group: tc.group, Name: tc.name, ID: 0}, true, nil
		})
		must(e)
		write(filepath.Join(dir, "go.txt"), b)
		if !bytes.Equal(b, read(native)) {
			panic("source identity text differs: " + tc.kind)
		}
		identityResults = append(identityResults, tc.kind)
	}
}

func verifyACLUpdates(root, helper, unpack string) {
	var fixture struct {
		SourceSHA256, ACLHelperSHA256, CopyfileHelperSHA256 string
		Records                                             []struct {
			Name, Kind            string
			Raw, Before, After    []byte
			Accepted, AfterAbsent bool
		}
	}
	must(json.Unmarshal(read("testdata/appledouble/native/acl-update.json"), &fixture))
	if len(fixture.Records) != 42 || fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/acl.c"))) != fixture.ACLHelperSHA256 || fmt.Sprintf("%x", sha256.Sum256(read("testdata/appledouble/native/probe.c"))) != fixture.CopyfileHelperSHA256 {
		panic("ACL update fixture provenance")
	}
	// Pinned copyfile source is independently fetched by the preceding native
	// pack/unpack CI step; this script also fetches it for standalone execution.
	client := http.Client{Timeout: 30 * time.Second}
	response, e := client.Get("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c")
	must(e)
	source, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	must(e)
	must(response.Body.Close())
	if response.StatusCode != http.StatusOK || fmt.Sprintf("%x", sha256.Sum256(source)) != fixture.SourceSHA256 {
		panic("ACL update copyfile source hash")
	}
	write(filepath.Join(root, "copyfile.c"), source)
	for _, tc := range fixture.Records {
		if !tc.Accepted {
			panic("fixture contains failed unpack")
		}
		dir := filepath.Join(root, "updates", tc.Kind+"-"+tc.Name)
		must(os.MkdirAll(dir, 0700))
		work, e := os.MkdirTemp(dir, "destination-")
		must(e)
		dst := filepath.Join(work, "item")
		if tc.Kind == "directory" {
			must(os.Mkdir(dst, 0700))
		} else if tc.Kind == "file" {
			write(dst, nil)
		} else {
			panic("unknown destination kind")
		}
		// Restore the independently captured baseline and check native setup exactly.
		before, e := appledouble.ParseACLBinary(tc.Before)
		must(e)
		text, e := before.MarshalText()
		must(e)
		write(filepath.Join(dir, "before.txt"), text)
		run(helper, "set", filepath.Join(dir, "before.txt"), dst)
		run(helper, "get", dst, filepath.Join(dir, "before.bin"), filepath.Join(dir, "before-canonical.txt"))
		if !bytes.Equal(read(filepath.Join(dir, "before.bin")), tc.Before) {
			panic("ACL baseline differs")
		}
		write(filepath.Join(dir, "input.ad"), tc.Raw)
		run(unpack, "unpack", filepath.Join(dir, "input.ad"), dst)
		output, getErr := observe(helper, "get", dst, filepath.Join(dir, "after.bin"), filepath.Join(dir, "after.txt"))
		absent := getErr != nil
		if absent {
			var exit *exec.ExitError
			if !tc.AfterAbsent || !errors.As(getErr, &exit) || exit.ExitCode() != 1 || !strings.HasPrefix(string(output), "get failed: errno=2 ") {
				panic(fmt.Sprintf("unexpected ACL read failure: %v %s", getErr, output))
			}
			commands[len(commands)-1].ExpectedFailure = true
			_, e := os.Stat(dst)
			must(e)
		}
		nativeEqual := absent == tc.AfterAbsent
		if !absent {
			nativeEqual = nativeEqual && bytes.Equal(read(filepath.Join(dir, "after.bin")), tc.After)
		}
		if !nativeEqual {
			panic("native ACL update differs: " + tc.Name)
		}
		f, e := appledouble.Decode(tc.Raw)
		must(e)
		update, e := f.ACLUpdate(nil)
		must(e)
		policyEqual := false
		switch {
		case update.ACL == nil:
			policyEqual = !absent && bytes.Equal(tc.Before, tc.After)
		case absent:
			policyEqual = update.ACL.Flags == 0 && len(update.ACL.Entries) == 0
		default:
			b, e := update.ACL.MarshalBinary()
			must(e)
			write(filepath.Join(dir, "go.bin"), b)
			policyEqual = bytes.Equal(b, tc.After)
		}
		if !policyEqual {
			panic("portable ACL update differs: " + tc.Name)
		}
		updateResults = append(updateResults, aclUpdateResult{Name: tc.Name, Kind: tc.Kind, RecordIndex: update.RecordIndex, Invalid: update.Invalid, AfterAbsent: absent, NativeEqual: nativeEqual, PolicyEqual: policyEqual})
	}
}
