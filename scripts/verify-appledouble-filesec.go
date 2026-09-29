//go:build ignore

// Native security record and ACL application oracle; not linked into production.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

type metadata struct {
	Security              string
	UID, GID, Mode, Flags uint32
}
type result struct {
	Code, Errno       int
	After             metadata
	IdentityUnchanged bool
}
type conversion struct {
	Name         string
	Disk, Darwin []byte
	Owner, Group string
}
type application struct {
	Name, Kind  string
	Mode, Flags uint32
	Text        []byte
	Before      metadata
	Request     string
	Native      result
}
type fixture struct {
	NonOwner                                                *nonOwnerFixture
	Chmod                                                   *chmodFixture
	Attributes                                              *attributeFixture
	Restoration                                             *restorationFixture
	HelperSHA256, CopyfileSHA256, XNUSHA256, Host, Revision string
	Conversions                                             []conversion
	Applications                                            []application
}
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
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
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
func download(url, hash, path string) []byte {
	client := http.Client{Timeout: 30 * time.Second}
	resp, e := client.Get(url)
	must(e)
	b, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	must(e)
	must(resp.Body.Close())
	if resp.StatusCode != 200 || sum(b) != hash {
		panic("pinned source mismatch: " + url)
	}
	write(path, b)
	return b
}
func extract(b []byte, start, end string) []byte {
	i := bytes.Index(b, []byte(start))
	if i < 0 {
		panic("missing function start")
	}
	j := bytes.Index(b[i:], []byte(end))
	if j < 0 {
		panic("missing function end")
	}
	return bytes.Clone(b[i : i+j])
}
func main() {
	capture := flag.Bool("capture", false, "capture native evidence without approving fixture")
	flag.Parse()
	const root = "artifacts/appledouble-filesec"
	const helperSource = "testdata/appledouble/native/filesec.c"
	must(os.MkdirAll(root, 0700))
	var f fixture
	passed := false
	defer func() {
		failure := recover()
		report := map[string]any{"passed": passed, "capture": *capture, "fixture": f, "commands": commands}
		if failure != nil {
			report["failure"] = fmt.Sprint(failure)
		}
		b, e := json.MarshalIndent(report, "", "  ")
		if e == nil {
			e = os.WriteFile(filepath.Join(root, "report.json"), b, 0600)
		}
		if failure != nil || e != nil {
			fmt.Fprintln(os.Stderr, failure, e)
			os.Exit(1)
		}
	}()
	if runtime.GOOS != "darwin" {
		panic("native oracle requires macOS")
	}
	f.Host = string(run("sw_vers"))
	f.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	f.HelperSHA256 = sum(read(helperSource))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.XNUSHA256 = "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249"
	copyfile := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	xnu := download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_authorization.c", f.XNUSHA256, filepath.Join(root, "kern_authorization.c"))
	header := append(bytes.Clone(copyfile[:bytes.Index(copyfile, []byte("#include"))]), extract(copyfile, "static int copyfile_unset_acl(copyfile_state_t s)\n{", "\n/*")...)
	header = append(header, extract(copyfile, "static int copyfile_unpack_acl(copyfile_state_t s, uint32_t entry_length, void *dataptr)\n{", "\nstatic int copyfile_unpack_xattr")...)
	header = append(header, xnu[:bytes.Index(xnu, []byte("#include"))]...)
	header = append(header, extract(xnu, "void\nkauth_filesec_acl_setendian(", "\n/*\n * Allocate an ACL buffer.")...)
	write(filepath.Join(root, "filesec-source.h"), header)
	helper := filepath.Join(root, "filesec")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, arch+".ast.json"), ast)
	}
	for _, tc := range conversions() {
		dir := filepath.Join(root, tc.Name)
		must(os.MkdirAll(dir, 0700))
		in, out := filepath.Join(dir, "disk.bin"), filepath.Join(dir, "darwin.bin")
		write(in, tc.Disk)
		observation := run(helper, "convert", in, out)
		var fields struct{ Owner, Group string }
		must(json.Unmarshal(observation, &fields))
		tc.Owner, tc.Group = fields.Owner, fields.Group
		tc.Darwin = read(out)
		disk, e := appledouble.ParseFileSecurity(tc.Disk)
		must(e)
		native, e := disk.MarshalDarwinBinary()
		must(e)
		if !bytes.Equal(native, tc.Darwin) || hex.EncodeToString(disk.OwnerUUID[:]) != tc.Owner || hex.EncodeToString(disk.GroupUUID[:]) != tc.Group {
			panic("conversion differs: " + tc.Name)
		}
		f.Conversions = append(f.Conversions, tc)
	}
	texts := [][]byte{nil, []byte("invalid ACL"), []byte("!#acl 1\n"), []byte("!#acl 1\nuser:21234567-89AB-CDEF-0123-456789ABCDEF:::allow:read,write\n")}
	for _, kind := range []string{"file", "directory"} {
		for _, mode := range []uint32{0, 0640, 0755, 02755, 04755, 06755} {
			for _, flags := range []uint32{0, 2, 4, 0x8000, 1} {
				for i, text := range texts {
					tc := application{Name: fmt.Sprintf("%s-%04o-%04x-%d", kind, mode, flags, i), Kind: kind, Mode: mode, Flags: flags, Text: text}
					dir, e := os.MkdirTemp(root, tc.Name+"-")
					must(e)
					input := filepath.Join(dir, "acl.txt")
					write(input, text)
					var goBefore metadata
					var goResult result
					tc.Before, tc.Native, _ = apply(helper, dir, input, tc, "native")
					goBefore, goResult, tc.Request = apply(helper, dir, input, tc, "go")
					if tc.Before != goBefore || tc.Native != goResult || !tc.Native.IdentityUnchanged {
						panic("application differs: " + tc.Name)
					}
					if tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags {
						panic("fixture mode/flags not established: " + tc.Name)
					}
					after := tc.Native.After
					if after.UID != tc.Before.UID || after.GID != tc.Before.GID || after.Mode != tc.Before.Mode || after.Flags != tc.Before.Flags {
						panic("destination metadata changed: " + tc.Name)
					}
					if tc.Native.Code != 0 && after != tc.Before {
						panic("failed write changed ACL: " + tc.Name)
					}
					f.Applications = append(f.Applications, tc)
				}
			}
		}
	}
	f.Restoration = &restorationFixture{Revision: f.Revision, Host: f.Host, HelperSHA256: sum(read("testdata/appledouble/native/acl-restore.c")), ParentHelperSHA256: f.HelperSHA256, CopyfileSHA256: f.CopyfileSHA256, XNUSHA256: f.XNUSHA256}
	verifyRestoration(root, f.Restoration, *capture)
	f.Attributes = &attributeFixture{Revision: f.Revision, Host: f.Host, HelperSHA256: sum(read("testdata/appledouble/native/acl-attributes.c")), ParentHelperSHA256: f.HelperSHA256}
	verifyAttributes(root, f.Attributes, *capture)
	f.Chmod = &chmodFixture{Revision: f.Revision, Host: f.Host, HelperSHA256: sum(read("testdata/appledouble/native/acl-chmod.c")), ParentHelperSHA256: f.HelperSHA256}
	verifyChmod(root, f.Chmod, f.Attributes, *capture)
	f.NonOwner = &nonOwnerFixture{Revision: f.Revision, Host: f.Host, HelperSHA256: sum(read("testdata/appledouble/native/acl-nonowner.c")), ParentHelperSHA256: f.HelperSHA256, CopyfileSHA256: f.CopyfileSHA256}
	verifyNonOwner(root, f.NonOwner, *capture)
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d conversions and %d application pairs; fixture NOT approved\n", len(f.Conversions), len(f.Applications))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/filesec.json.gz")))
	must(e)
	var archived fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.CopyfileSHA256 != f.CopyfileSHA256 || archived.XNUSHA256 != f.XNUSHA256 || !reflect.DeepEqual(archived.Conversions, f.Conversions) || len(archived.Applications) != len(f.Applications) {
		panic("reviewed fixture provenance/cases differ")
	}
	for i, a := range archived.Applications {
		b := f.Applications[i] // Account IDs belong to the capture host, never the codec.
		a.Before.UID = b.Before.UID
		a.Before.GID = b.Before.GID
		a.Native.After.UID = b.Native.After.UID
		a.Native.After.GID = b.Native.After.GID
		if !reflect.DeepEqual(a, b) {
			panic("reviewed application differs: " + b.Name)
		}
	}
	passed = true
	fmt.Printf("Qualified %d security conversions and %d native/Go application pairs\n", len(f.Conversions), len(f.Applications))
}
func apply(helper, dir, input string, tc application, kind string) (metadata, result, string) {
	args := []string{filepath.Join(dir, kind), tc.Kind, fmt.Sprintf("%o", tc.Mode), fmt.Sprint(tc.Flags), input, kind}
	cmd := exec.Command(helper, args...)
	stdin, e := cmd.StdinPipe()
	must(e)
	stdout, e := cmd.StdoutPipe()
	must(e)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	scan := bufio.NewScanner(stdout)
	var raw bytes.Buffer
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("missing native before: " + stderr.String())
	}
	raw.Write(scan.Bytes())
	raw.WriteByte('\n')
	var before struct{ Before metadata }
	must(json.Unmarshal(scan.Bytes(), &before))
	request := ""
	if kind == "go" {
		b, e := hex.DecodeString(before.Before.Security)
		must(e)
		dst, e := appledouble.ParseDarwinFileSecurity(b)
		must(e)
		f := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
		update, e := f.ACLUpdate(nil)
		must(e)
		record, e := update.FileSecurity(dst)
		must(e)
		request = "-"
		if record != nil {
			b, e = record.MarshalDarwinBinary()
			must(e)
			request = hex.EncodeToString(b)
		}
		_, e = io.WriteString(stdin, request+"\n")
		must(e)
	}
	must(stdin.Close())
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("missing native after: " + stderr.String())
	}
	raw.Write(scan.Bytes())
	raw.WriteByte('\n')
	var after result
	must(json.Unmarshal(scan.Bytes(), &after))
	if scan.Scan() {
		panic("extra native output")
	}
	must(scan.Err())
	e = cmd.Wait()
	c := command{Args: append([]string{helper}, args...), Input: request, Output: raw.String(), Error: stderr.String()}
	commands = append(commands, c)
	write(filepath.Join(dir, kind+".jsonl"), raw.Bytes())
	write(filepath.Join(dir, kind+".stdin"), []byte(request))
	if e != nil {
		panic(fmt.Sprintf("native application: %v %s", e, stderr.String()))
	}
	return before.Before, after, request
}
func conversions() []conversion {
	var cases []conversion
	for pattern := 0; pattern < 3; pattern++ {
		for _, count := range []int{-1, 0, 1, 2, 127, 128} {
			for _, flags := range []uint32{0, 1, 0x20000, 0xffffffff} {
				s := appledouble.FileSecurity{Trailing: []byte{0xde, 0xad, 0, 0xbe, 0xef}}
				if pattern != 0 {
					for i := range s.OwnerUUID {
						s.OwnerUUID[i] = byte(i + pattern*17)
						s.GroupUUID[i] = byte(255 - i - pattern)
					}
				}
				if count < 0 {
					s.NoACLFlags = [4]byte{byte(flags), byte(flags >> 8), byte(flags >> 16), byte(flags >> 24)}
				} else {
					s.ACL = &appledouble.ACL{Flags: flags}
					for i := 0; i < count; i++ {
						var a appledouble.ACLEntry
						for j := range a.Principal {
							a.Principal[j] = byte(i + j)
						}
						a.Flags = uint32(i%4+1) | 0x80000000 | uint32(i<<4)
						a.Rights = 0xff000001 | uint32(i<<1)
						s.ACL.Entries = append(s.ACL.Entries, a)
					}
				}
				b, e := s.MarshalBinary()
				must(e)
				cases = append(cases, conversion{Name: fmt.Sprintf("convert-%d-%d-%08x", pattern, count, flags), Disk: b})
			}
		}
	}
	return cases
}

type restoreObservation struct {
	Filesystem                                 string
	Code, Errno                                int
	Applied                                    bool
	After                                      metadata
	IdentityUnchanged, SourceMetadataUnchanged bool
	SourceMask                                 int
	Events                                     []string
	Requests                                   []metadata
}
type restorationCase struct {
	Name, Kind, Filesystem string
	Mode, Flags            uint32
	Text                   []byte
	Before                 metadata
	Native                 restoreObservation
	GoResult               hostmeta.ACLRestoreResult
}
type restorationFixture struct {
	Revision, Host, HelperSHA256, ParentHelperSHA256, CopyfileSHA256, XNUSHA256 string
	Cases                                                                       []restorationCase
}
type restorePipe struct {
	in            io.Writer
	scan          *bufio.Scanner
	input, output *bytes.Buffer
}

func (p restorePipe) exchange(request string) []byte {
	p.input.WriteString(request + "\n")
	_, e := io.WriteString(p.in, request+"\n")
	must(e)
	if !p.scan.Scan() {
		panic("native restoration protocol ended early")
	}
	b := bytes.Clone(p.scan.Bytes())
	p.output.Write(b)
	p.output.WriteByte('\n')
	return b
}
func (p restorePipe) CaptureACL() (hostmeta.ACLMetadata, error) {
	var r struct{ Captured metadata }
	must(json.Unmarshal(p.exchange("C"), &r))
	b, e := hex.DecodeString(r.Captured.Security)
	must(e)
	sec, e := appledouble.ParseDarwinFileSecurity(b)
	return hostmeta.ACLMetadata{Security: sec, UID: r.Captured.UID, GID: r.Captured.GID, Mode: r.Captured.Mode}, e
}
func nativeRestoreError(b []byte) error {
	var r struct{ Errno int }
	must(json.Unmarshal(b, &r))
	if r.Errno == 0 {
		return nil
	}
	err := syscall.Errno(r.Errno)
	if errors.Is(err, syscall.ENOTSUP) {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return err
}
func (p restorePipe) WriteACL(m hostmeta.ACLMetadata) error {
	b, e := m.Security.MarshalDarwinBinary()
	if e != nil {
		return e
	}
	return nativeRestoreError(p.exchange(fmt.Sprintf("W %d %d %d %x", m.UID, m.GID, m.Mode, b)))
}
func (p restorePipe) ClearSourceSecurity() error { return nativeRestoreError(p.exchange("R")) }
func verifyRestoration(root string, f *restorationFixture, capture bool) {
	const source = "testdata/appledouble/native/acl-restore.c"
	helper := filepath.Join(root, "acl-restore")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, "acl-restore-"+arch+".ast.json"), b)
	}
	image := filepath.Join(root, "acl-retry.dmg")
	volume, e := os.MkdirTemp("", "apfs-acl-fat-")
	must(e)
	defer os.Remove(volume)
	// hdiutil's default for a blank image is writable; specifying -format is not
	// accepted for blank creation on macOS 27. Never reuse an earlier image.
	if _, e := os.Stat(image); e == nil {
		must(os.Remove(image))
	} else if !os.IsNotExist(e) {
		must(e)
	}
	run("hdiutil", "create", "-size", "32m", "-fs", "MS-DOS", "-volname", "ACLRETRY", image)
	run("hdiutil", "attach", image, "-mountpoint", volume, "-nobrowse")
	attached := true
	defer func() {
		if attached {
			run("hdiutil", "detach", volume)
		}
	}()
	texts := [][]byte{nil, []byte("invalid ACL"), []byte("!#acl 1\n"), []byte("!#acl 1\nuser:21234567-89AB-CDEF-0123-456789ABCDEF:::allow:read,write\n")}
	for _, fs := range []string{"apfs", "msdos"} {
		for _, kind := range []string{"file", "directory"} {
			modes := []uint32{0, 0640, 0755, 02755, 04755, 06755}
			flags := []uint32{0, 2, 4, 0x8000, 1}
			if fs == "msdos" {
				modes = []uint32{0}
				flags = []uint32{0}
			}
			for _, mode := range modes {
				for _, flag := range flags {
					for i, text := range texts {
						tc := restorationCase{Name: fmt.Sprintf("restore-%s-%s-%04o-%04x-%d", fs, kind, mode, flag, i), Kind: kind, Filesystem: fs, Mode: mode, Flags: flag, Text: text}
						dir, e := os.MkdirTemp(root, tc.Name+"-")
						must(e)
						input := filepath.Join(dir, "acl.txt")
						write(input, text)
						destination := dir
						if fs == "msdos" {
							destination = filepath.Join(volume, tc.Name)
							must(os.Mkdir(destination, 0700))
						}
						var goBefore metadata
						var goNative restoreObservation
						tc.Before, tc.Native, _ = restoreRun(helper, dir, destination, input, tc, "native")
						goBefore, goNative, tc.GoResult = restoreRun(helper, dir, destination, input, tc, "go")
						if tc.Before != goBefore || !reflect.DeepEqual(tc.Native, goNative) || !tc.Native.IdentityUnchanged || !tc.Native.SourceMetadataUnchanged || tc.Native.Filesystem != fs {
							panic("restoration differs: " + tc.Name)
						}
						if fs == "apfs" && (tc.Before.Mode&07777 != tc.Mode || tc.Before.Flags != tc.Flags) {
							panic("restoration setup differs: " + tc.Name)
						}
						after := tc.Native.After
						if after.UID != tc.Before.UID || after.GID != tc.Before.GID || after.Mode != tc.Before.Mode || after.Flags != tc.Before.Flags {
							panic("restoration changed metadata: " + tc.Name)
						}
						if tc.Native.Code != 0 && after != tc.Before {
							panic("refusal changed ACL: " + tc.Name)
						}
						if tc.GoResult.Applied != tc.Native.Applied || tc.GoResult.Attempts != len(tc.Native.Requests) || tc.GoResult.Retried != (len(tc.Native.Requests) == 2) {
							panic("restoration result differs: " + tc.Name)
						}
						if len(tc.Native.Requests) == 2 && (tc.Native.Requests[0] != tc.Native.Requests[1] || tc.Native.SourceMask != 0) {
							panic("retry request or source state differs: " + tc.Name)
						}
						f.Cases = append(f.Cases, tc)
					}
				}
			}
		}
	}
	run("hdiutil", "detach", volume)
	attached = false
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed-restoration.json"), b)
	if capture {
		fmt.Printf("Captured %d restoration pairs; fixture NOT approved\n", len(f.Cases))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/acl-restore.json.gz")))
	must(e)
	var archived restorationFixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.ParentHelperSHA256 != f.ParentHelperSHA256 || archived.CopyfileSHA256 != f.CopyfileSHA256 || archived.XNUSHA256 != f.XNUSHA256 || len(archived.Cases) != len(f.Cases) {
		panic("restoration fixture provenance differs")
	}
	for i, a := range archived.Cases {
		b := f.Cases[i]
		a.Before.UID = b.Before.UID
		a.Before.GID = b.Before.GID
		a.Native.After.UID = b.Native.After.UID
		a.Native.After.GID = b.Native.After.GID
		if len(a.Native.Requests) != len(b.Native.Requests) {
			panic("request count differs")
		}
		for j := range a.Native.Requests {
			a.Native.Requests[j].UID = b.Native.Requests[j].UID
			a.Native.Requests[j].GID = b.Native.Requests[j].GID
		}
		if !reflect.DeepEqual(a, b) {
			panic("restoration fixture differs: " + b.Name)
		}
	}
	fmt.Printf("Qualified %d actual filesystem restoration pairs\n", len(f.Cases))
}
func restoreRun(helper, dir, destination, input string, tc restorationCase, kind string) (metadata, restoreObservation, hostmeta.ACLRestoreResult) {
	setup := "baseline"
	if tc.Filesystem == "msdos" {
		setup = "plain"
	}
	args := []string{filepath.Join(destination, kind), tc.Kind, fmt.Sprintf("%o", tc.Mode), fmt.Sprint(tc.Flags), input, kind, setup}
	cmd := exec.Command(helper, args...)
	stdin, e := cmd.StdinPipe()
	must(e)
	stdout, e := cmd.StdoutPipe()
	must(e)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer stdin.Close()
	scan := bufio.NewScanner(stdout)
	var output, requests bytes.Buffer
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("restoration before: " + stderr.String())
	}
	output.Write(scan.Bytes())
	output.WriteByte('\n')
	var before struct{ Before metadata }
	must(json.Unmarshal(scan.Bytes(), &before))
	var result hostmeta.ACLRestoreResult
	var restoreErr error
	if kind == "go" {
		f := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
		u, e := f.ACLUpdate(nil)
		must(e)
		result, restoreErr = hostmeta.RestoreACL(u, restorePipe{stdin, scan, &requests, &output})
		requests.WriteString("D\n")
		_, e = io.WriteString(stdin, "D\n")
		must(e)
	}
	must(stdin.Close())
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("restoration after: " + stderr.String())
	}
	output.Write(scan.Bytes())
	output.WriteByte('\n')
	var observed restoreObservation
	must(json.Unmarshal(scan.Bytes(), &observed))
	if scan.Scan() {
		panic("extra restoration output")
	}
	must(scan.Err())
	must(cmd.Wait())
	commands = append(commands, command{Args: append([]string{helper}, args...), Input: requests.String(), Output: output.String(), Error: stderr.String()})
	write(filepath.Join(dir, kind+"-restore.jsonl"), output.Bytes())
	write(filepath.Join(dir, kind+"-restore.stdin"), requests.Bytes())
	if kind == "go" && ((observed.Errno == 0 && restoreErr != nil) || (observed.Errno != 0 && !errors.Is(restoreErr, syscall.Errno(observed.Errno)))) {
		panic("restoration error lost native cause")
	}
	return before.Before, observed, result
}

type attributeConversion struct {
	Name                     string
	Input, Response, Request []byte
	Expected                 metadata
}
type attributeApplication struct {
	Reference                        result
	ReferenceAfterResponse           []byte
	Name, Kind                       string
	Initial                          int
	Mode, Flags                      uint32
	Text                             []byte
	Before                           metadata
	Response, Request, AfterResponse []byte
	Native                           result
}
type attributeFixture struct {
	Revision, Host, HelperSHA256, ParentHelperSHA256, SourceSHA256 string
	Conversions                                                    []attributeConversion
	Applications                                                   []attributeApplication
}

func verifyAttributes(root string, f *attributeFixture, capture bool) {
	const helperSource = "testdata/appledouble/native/acl-attributes.c"
	f.SourceSHA256 = "3fcbca58e2d63963115ecd4aa1e27c3d1f7dc21f124897c8bdfdf9916b503c06"
	source := download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_attrlist.c", f.SourceSHA256, filepath.Join(root, "vfs_attrlist.c"))
	header := bytes.Clone(source[:bytes.Index(source, []byte("#include"))])
	for _, part := range [][2]string{{"struct _attrlist_buf {", "\n#define _ATTRLIST_BUF_INIT"}, {"static void\nattrlist_pack_fixed(", "\n/*\n * Attempt to pack one"}, {"static void\nattrlist_pack_variable2(", "\n/*\n * Packing a single"}, {"static void\nattrlist_pack_variable(", "\n/*\n * Attempt to pack a string"}} {
		header = append(header, extract(source, part[0], part[1])...)
	}
	write(filepath.Join(root, "acl-attributes-source.h"), header)
	helper := filepath.Join(root, "acl-attributes")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "acl-attributes-"+arch+".ast.json"), ast)
	}
	for pattern := 0; pattern < 3; pattern++ {
		for _, count := range []int{-2, -1, 0, 1, 2, 127, 128} {
			for _, flags := range []uint32{0, 1, 0x20000, 0xffffffff} {
				name := fmt.Sprintf("attributes-pack-%d-%d-%08x", pattern, count, flags)
				dir := filepath.Join(root, name)
				must(os.MkdirAll(dir, 0700))
				sec := &appledouble.FileSecurity{}
				if pattern != 0 {
					for i := range sec.OwnerUUID {
						sec.OwnerUUID[i] = byte(pattern*17 + i)
						sec.GroupUUID[i] = byte(255 - i - pattern)
					}
				}
				if count < 0 {
					sec.NoACLFlags = [4]byte{byte(flags), byte(flags >> 8), byte(flags >> 16), byte(flags >> 24)}
				} else {
					sec.ACL = &appledouble.ACL{Flags: flags}
					for i := 0; i < count; i++ {
						sec.ACL.Entries = append(sec.ACL.Entries, appledouble.ACLEntry{Principal: [16]byte{byte(i), byte(i + 1)}, Flags: uint32(i%4+1) | 0x80000000, Rights: 0xff000001 | uint32(i<<1)})
					}
				}
				input, e := sec.MarshalDarwinBinary()
				must(e)
				in, get, set := filepath.Join(dir, "input.bin"), filepath.Join(dir, "get.bin"), filepath.Join(dir, "set.bin")
				write(in, input)
				ids := [][3]uint32{{0, 0, 0}, {501, 20, 0106755}, {0xffffffff, 0xfffffffe, 0xffffffff}}
				values := ids[pattern]
				absent := "0"
				if count == -2 {
					absent = "1"
				}
				out := run(helper, "pack", in, get, set, fmt.Sprint(values[0]), fmt.Sprint(values[1]), fmt.Sprint(values[2]), absent)
				var expected metadata
				must(json.Unmarshal(out, &expected))
				tc := attributeConversion{Name: name, Input: input, Response: read(get), Request: read(set), Expected: expected}
				m, e := hostmeta.ParseDarwinACLAttributes(tc.Response)
				must(e)
				verifyAttributeMetadata(m, expected)
				encoded, e := m.MarshalDarwinACLAttributes()
				must(e)
				if !bytes.Equal(encoded, tc.Request) {
					panic("native attribute packing differs: " + name)
				}
				f.Conversions = append(f.Conversions, tc)
			}
		}
	}
	texts := [][]byte{nil, []byte("invalid ACL"), []byte("!#acl 1\n"), []byte("!#acl 1\nuser:21234567-89AB-CDEF-0123-456789ABCDEF:::allow:read,write\n")}
	for _, kind := range []string{"file", "directory"} {
		for _, initial := range []int{-1, 0, 1, 128} {
			for _, mode := range []uint32{0, 06755} {
				for _, flags := range []uint32{0, 2, 4} {
					for i, text := range texts {
						tc := attributeApplication{Name: fmt.Sprintf("attributes-%s-%d-%04o-%d-%d", kind, initial, mode, flags, i), Kind: kind, Initial: initial, Mode: mode, Flags: flags, Text: text}
						dir, e := os.MkdirTemp(root, tc.Name+"-")
						must(e)
						input := filepath.Join(dir, "acl.txt")
						write(input, text)
						before, nativeResponse, native, nativeAfter, _ := attributeRun(helper, dir, input, tc, "native", attributeWriteRequest)
						referenceBefore, referenceResponse, reference, referenceAfter, _ := attributeRun(helper, dir, input, tc, "reference", attributeWriteRequest)
						if referenceBefore != before || !bytes.Equal(referenceResponse, nativeResponse) || !reference.IdentityUnchanged {
							panic("reference setup differs")
						}
						tc.Reference = reference
						tc.ReferenceAfterResponse = referenceAfter
						if reference.Code != 0 && (reference.After != before || !bytes.Equal(referenceResponse, referenceAfter)) {
							panic("failed reference write changed metadata")
						}
						goBefore, goResponse, goNative, goAfter, request := attributeRun(helper, dir, input, tc, "go", attributeWriteRequest)
						if before != goBefore || native != goNative || !bytes.Equal(nativeResponse, goResponse) || !bytes.Equal(nativeAfter, goAfter) || !native.IdentityUnchanged {
							panic("native attribute write differs: " + tc.Name)
						}
						if before.Mode&07777 != mode || before.Flags != flags {
							panic("attribute setup differs: " + tc.Name)
						}
						after := native.After
						if before.UID != after.UID || before.GID != after.GID || before.Mode != after.Mode || before.Flags != after.Flags {
							panic("attribute write lost metadata: " + tc.Name)
						}
						if native.Code != 0 && (after != before || !bytes.Equal(nativeResponse, nativeAfter)) {
							panic("failed attribute write changed metadata")
						}
						tc.Before = before
						tc.Response = goResponse
						tc.Request = request
						tc.Native = native
						tc.AfterResponse = goAfter
						f.Applications = append(f.Applications, tc)
					}
				}
			}
		}
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed-attributes.json"), b)
	if capture {
		fmt.Printf("Captured %d attribute conversions and %d actual write pairs; fixture NOT approved\n", len(f.Conversions), len(f.Applications))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/acl-attributes.json.gz")))
	must(e)
	var archived attributeFixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.ParentHelperSHA256 != f.ParentHelperSHA256 || archived.SourceSHA256 != f.SourceSHA256 || !reflect.DeepEqual(archived.Conversions, f.Conversions) || len(archived.Applications) != len(f.Applications) {
		panic("attribute fixture provenance/conversions differ")
	}
	for i, a := range archived.Applications {
		b := f.Applications[i]
		// Numeric account IDs belong to the observation host. All three attribute
		// frames must agree after only those two fields are adjusted.
		a.Before.UID = b.Before.UID
		a.Before.GID = b.Before.GID
		a.Native.After.UID = b.Native.After.UID
		a.Native.After.GID = b.Native.After.GID
		a.Reference.After.UID = b.Reference.After.UID
		a.Reference.After.GID = b.Reference.After.GID
		for _, pair := range [][2][]byte{{a.Response, b.Response}, {a.AfterResponse, b.AfterResponse}, {a.ReferenceAfterResponse, b.ReferenceAfterResponse}} {
			if len(pair[0]) < 12 || len(pair[1]) < 12 {
				panic("short captured frame")
			}
			copy(pair[0][4:12], pair[1][4:12])
		}
		if len(a.Request) != 0 {
			if len(b.Request) < 8 {
				panic("short write request")
			}
			copy(a.Request[:8], b.Request[:8])
		}
		if !reflect.DeepEqual(a, b) {
			panic("attribute observations differ: " + b.Name)
		}
	}
	fmt.Printf("Qualified %d attribute conversions and %d native write pairs\n", len(f.Conversions), len(f.Applications))
}
func verifyAttributeMetadata(m hostmeta.ACLMetadata, want metadata) {
	// fgetattrlist may return a present empty ACL where fstatx_np reports NOACL.
	// fstatx_np also hides no_inherit on an empty ACL. This comparison only
	// checks the common view; raw attribute frames (including flags) are compared
	// separately and retained. The two responses are not losslessly equivalent.
	expectedBytes, e := hex.DecodeString(want.Security)
	must(e)
	expected, e := appledouble.ParseDarwinFileSecurity(expectedBytes)
	must(e)
	if expected.ACL == nil && expected.NoACLFlags == [4]byte{} && m.Security.ACL != nil && (m.Security.ACL.Flags == 0 || m.Security.ACL.Flags == 0x20000) && len(m.Security.ACL.Entries) == 0 {
		copySecurity := *m.Security
		copySecurity.ACL = nil
		m.Security = &copySecurity
	}

	b, e := m.Security.MarshalDarwinBinary()
	must(e)
	if hex.EncodeToString(b) != want.Security || m.UID != want.UID || m.GID != want.GID || m.Mode != want.Mode {
		panic(fmt.Sprintf("attribute capture differs: %+v vs %+v security=%x", m, want, b))
	}
}
func attributeRun(helper, dir, input string, tc attributeApplication, kind string, encode func(hostmeta.ACLMetadata) ([]byte, string, error)) (metadata, []byte, result, []byte, []byte) {
	args := []string{filepath.Join(dir, kind), tc.Kind, fmt.Sprintf("%o", tc.Mode), fmt.Sprint(tc.Flags), input, kind, fmt.Sprint(tc.Initial)}
	cmd := exec.Command(helper, args...)
	stdin, e := cmd.StdinPipe()
	must(e)
	stdout, e := cmd.StdoutPipe()
	must(e)
	defer stdin.Close()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	scan := bufio.NewScanner(stdout)
	var raw bytes.Buffer
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("attributes before: " + stderr.String())
	}
	raw.Write(scan.Bytes())
	raw.WriteByte('\n')
	var before struct {
		Before     metadata
		Attributes string
	}
	must(json.Unmarshal(scan.Bytes(), &before))
	response, e := hex.DecodeString(before.Attributes)
	must(e)
	m, e := hostmeta.ParseDarwinACLAttributes(response)
	must(e)
	verifyAttributeMetadata(m, before.Before)
	var request []byte
	line := ""
	if kind == "go" {
		file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
		u, e := file.ACLUpdate(nil)
		must(e)
		m.Security, e = u.FileSecurity(m.Security)
		must(e)
		line = "-"
		if m.Security != nil {
			request, line, e = encode(m)
			must(e)
		}
		_, e = io.WriteString(stdin, line+"\n")
		must(e)
	}
	must(stdin.Close())
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("attributes after: " + stderr.String())
	}
	raw.Write(scan.Bytes())
	raw.WriteByte('\n')
	var after struct {
		result
		Attributes string
	}
	must(json.Unmarshal(scan.Bytes(), &after))
	if scan.Scan() {
		panic("extra attribute output")
	}
	must(scan.Err())
	must(cmd.Wait())
	afterResponse, e := hex.DecodeString(after.Attributes)
	must(e)
	decoded, e := hostmeta.ParseDarwinACLAttributes(afterResponse)
	must(e)
	verifyAttributeMetadata(decoded, after.After)
	commands = append(commands, command{Args: append([]string{helper}, args...), Input: line, Output: raw.String(), Error: stderr.String()})
	write(filepath.Join(dir, kind+"-attributes.jsonl"), raw.Bytes())
	write(filepath.Join(dir, kind+"-attributes.stdin"), []byte(line))
	return before.Before, response, after.result, afterResponse, request
}

func attributeWriteRequest(m hostmeta.ACLMetadata) ([]byte, string, error) {
	b, e := m.MarshalDarwinACLAttributes()
	return b, hex.EncodeToString(b), e
}
func chmodWriteRequest(m hostmeta.ACLMetadata) ([]byte, string, error) {
	r, e := m.DarwinChmodRequest()
	if e != nil {
		return nil, "", e
	}
	return r.Security, fmt.Sprintf("%d %d %d %x", r.UID, r.GID, r.Mode, r.Security), nil
}

type chmodConversion struct {
	Name    string
	Input   metadata
	Request hostmeta.DarwinChmodRequest
}
type chmodApplication struct {
	Name, Kind              string
	Initial                 int
	Mode, Flags             uint32
	Text                    []byte
	Before                  metadata
	Response, AfterResponse []byte
	Request                 *hostmeta.DarwinChmodRequest
	Native                  result
}
type chmodFixture struct {
	Revision, Host, HelperSHA256, ParentHelperSHA256, LibcSHA256, XNUSHA256 string
	Conversions                                                             []chmodConversion
	Applications                                                            []chmodApplication
}

func verifyChmod(root string, f *chmodFixture, attributes *attributeFixture, capture bool) {
	const helperSource = "testdata/appledouble/native/acl-chmod.c"
	f.LibcSHA256 = "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff"
	f.XNUSHA256 = "b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f"
	source := download("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c", f.LibcSHA256, filepath.Join(root, "chmodx_np.c"))
	download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/vfs_syscalls.c", f.XNUSHA256, filepath.Join(root, "vfs_syscalls.c"))
	header := bytes.Clone(source[:bytes.Index(source, []byte("#include"))])
	start := bytes.Index(source, []byte("static int\nchmodx1("))
	if start < 0 {
		panic("missing chmodx1")
	}
	header = append(header, source[start:]...)
	write(filepath.Join(root, "acl-chmod-source.h"), header)
	helper := filepath.Join(root, "acl-chmod")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "acl-chmod-"+arch+".ast.json"), ast)
	}
	for _, tc := range attributes.Conversions {
		dir := filepath.Join(root, "chmod-"+tc.Name)
		must(os.MkdirAll(dir, 0700))
		input, output := filepath.Join(dir, "input.bin"), filepath.Join(dir, "request.bin")
		write(input, tc.Input)
		expected := tc.Expected
		expected.Security = hex.EncodeToString(tc.Input)
		out := run(helper, "pack", input, output, fmt.Sprint(expected.UID), fmt.Sprint(expected.GID), fmt.Sprint(expected.Mode))
		var native hostmeta.DarwinChmodRequest
		must(json.Unmarshal(out, &native))
		native.Security = read(output)
		sec, e := appledouble.ParseDarwinFileSecurity(tc.Input)
		must(e)
		m := hostmeta.ACLMetadata{Security: sec, UID: expected.UID, GID: expected.GID, Mode: expected.Mode}
		request, e := m.DarwinChmodRequest()
		must(e)
		if !reflect.DeepEqual(request, native) {
			panic("Libc request differs: " + tc.Name)
		}
		f.Conversions = append(f.Conversions, chmodConversion{Name: tc.Name, Input: expected, Request: native})
	}
	for _, tc := range attributes.Applications {
		dir, e := os.MkdirTemp(root, "chmod-"+tc.Name+"-")
		must(e)
		input := filepath.Join(dir, "acl.txt")
		write(input, tc.Text)
		before, response, native, after, _ := attributeRun(helper, dir, input, tc, "native", chmodWriteRequest)
		goBefore, goResponse, goNative, goAfter, request := attributeRun(helper, dir, input, tc, "go", chmodWriteRequest)
		if before != goBefore || before != tc.Before || !bytes.Equal(response, goResponse) || !bytes.Equal(response, tc.Response) || native != goNative || native != tc.Reference || !bytes.Equal(after, goAfter) || !bytes.Equal(after, tc.ReferenceAfterResponse) || !native.IdentityUnchanged {
			panic("copyfile chmod mismatch: " + tc.Name)
		}
		var prepared *hostmeta.DarwinChmodRequest
		if len(request) > 0 {
			prepared = &hostmeta.DarwinChmodRequest{UID: goBefore.UID, GID: goBefore.GID, Mode: uint16(goBefore.Mode), Security: request}
		}
		f.Applications = append(f.Applications, chmodApplication{Name: tc.Name, Kind: tc.Kind, Initial: tc.Initial, Mode: tc.Mode, Flags: tc.Flags, Text: tc.Text, Before: before, Response: response, AfterResponse: after, Request: prepared, Native: native})
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed-chmod.json"), b)
	if capture {
		fmt.Printf("Captured %d Libc requests and %d extended chmod pairs; fixture NOT approved\n", len(f.Conversions), len(f.Applications))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/acl-chmod.json.gz")))
	must(e)
	var archived chmodFixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.ParentHelperSHA256 != f.ParentHelperSHA256 || archived.LibcSHA256 != f.LibcSHA256 || archived.XNUSHA256 != f.XNUSHA256 || !reflect.DeepEqual(archived.Conversions, f.Conversions) || len(archived.Applications) != len(f.Applications) {
		panic("chmod provenance/conversions differ")
	}
	for i, a := range archived.Applications {
		b := f.Applications[i]
		a.Before.UID = b.Before.UID
		a.Before.GID = b.Before.GID
		a.Native.After.UID = b.Native.After.UID
		a.Native.After.GID = b.Native.After.GID
		for _, pair := range [][2][]byte{{a.Response, b.Response}, {a.AfterResponse, b.AfterResponse}} {
			if len(pair[0]) < 12 || len(pair[1]) < 12 {
				panic("short chmod attribute frame")
			}
			copy(pair[0][4:12], pair[1][4:12])
		}
		if a.Request != nil && b.Request != nil {
			a.Request.UID = b.Request.UID
			a.Request.GID = b.Request.GID
		}
		if !reflect.DeepEqual(a, b) {
			panic("chmod observations differ: " + b.Name)
		}
	}
	fmt.Printf("Qualified %d Libc requests and %d actual extended chmod pairs\n", len(f.Conversions), len(f.Applications))
}

type principalIdentity struct {
	UID, GID uint32
	Groups   []uint32
}
type principalSeed struct {
	Name       string
	Text, Disk []byte
}
type principalRead struct {
	Metadata                      metadata
	SecurityErrno, AttributeErrno int
	Attributes                    *string
}
type principalObservation struct {
	Code, Errno, Captures, Writes, Resets int
	Applied, IdentityUnchanged            bool
	After                                 principalRead
}
type principalCase struct {
	Name, Filesystem, Kind, Seed string
	Owner, Group                 bool
	Mode, UID, GID               uint32
	Text, AfterDisk              []byte
	Before                       principalRead
	Native                       principalObservation
	Request                      *hostmeta.DarwinChmodRequest
	GoResult                     hostmeta.ACLRestoreResult
}
type principalImage struct{ Filesystem, BeforeSHA256, AfterSHA256 string }
type nonOwnerFixture struct {
	HFSSourceSHA256                                                  map[string]string
	Revision, Host, HelperSHA256, ParentHelperSHA256, CopyfileSHA256 string
	Actor                                                            principalIdentity
	Seeds                                                            []principalSeed
	Images                                                           []principalImage
	Cases                                                            []principalCase
}
type principalPipe struct {
	restorePipe
	request **hostmeta.DarwinChmodRequest
}

func (p principalPipe) CaptureACL() (hostmeta.ACLMetadata, error) {
	b := p.exchange("C")
	if e := nativeRestoreError(b); e != nil {
		return hostmeta.ACLMetadata{}, e
	}
	var r struct{ Captured metadata }
	must(json.Unmarshal(b, &r))
	raw, e := hex.DecodeString(r.Captured.Security)
	must(e)
	sec, e := appledouble.ParseDarwinFileSecurity(raw)
	return hostmeta.ACLMetadata{Security: sec, UID: r.Captured.UID, GID: r.Captured.GID, Mode: r.Captured.Mode}, e
}
func (p principalPipe) WriteACL(m hostmeta.ACLMetadata) error {
	r, e := m.DarwinChmodRequest()
	if e != nil {
		return e
	}
	*p.request = &r
	return nativeRestoreError(p.exchange(fmt.Sprintf("W %d %d %d %x", r.UID, r.GID, r.Mode, r.Security)))
}
func principalRun(helper, dir, destination, input string, tc principalCase, kind string) (principalRead, principalObservation, *hostmeta.DarwinChmodRequest, hostmeta.ACLRestoreResult) {
	args := []string{destination, input, kind, fmt.Sprint(tc.UID), fmt.Sprint(tc.GID), tc.Filesystem}
	cmd := exec.Command(helper, args...)
	stdin, e := cmd.StdinPipe()
	must(e)
	defer stdin.Close()
	stdout, e := cmd.StdoutPipe()
	must(e)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	scan := bufio.NewScanner(stdout)
	var output, requests bytes.Buffer
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("principal before: " + stderr.String())
	}
	output.Write(scan.Bytes())
	output.WriteByte('\n')
	var before struct{ Before principalRead }
	must(json.Unmarshal(scan.Bytes(), &before))
	var result hostmeta.ACLRestoreResult
	var request *hostmeta.DarwinChmodRequest
	var restoreErr error
	if kind == "go" {
		file := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: tc.Text}}}
		update, e := file.ACLUpdate(nil)
		must(e)
		result, restoreErr = hostmeta.RestoreACL(update, principalPipe{restorePipe{stdin, scan, &requests, &output}, &request})
		requests.WriteString("D\n")
		_, e = io.WriteString(stdin, "D\n")
		must(e)
	}
	must(stdin.Close())
	if !scan.Scan() {
		_ = cmd.Wait()
		panic("principal after: " + stderr.String())
	}
	output.Write(scan.Bytes())
	output.WriteByte('\n')
	var observed principalObservation
	must(json.Unmarshal(scan.Bytes(), &observed))
	if scan.Scan() {
		panic("extra principal output")
	}
	must(scan.Err())
	must(cmd.Wait())
	commands = append(commands, command{Args: append([]string{helper}, args...), Input: requests.String(), Output: output.String(), Error: stderr.String()})
	write(filepath.Join(dir, kind+"-principal.jsonl"), output.Bytes())
	write(filepath.Join(dir, kind+"-principal.stdin"), requests.Bytes())
	if kind == "go" && ((observed.Errno == 0 && restoreErr != nil) || (observed.Errno != 0 && !errors.Is(restoreErr, syscall.Errno(observed.Errno)))) {
		panic("principal native cause lost")
	}
	return before.Before, observed, request, result
}
func verifyNonOwner(root string, f *nonOwnerFixture, capture bool) {
	const helperSource = "testdata/appledouble/native/acl-nonowner.c"
	helper := filepath.Join(root, "acl-nonowner")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
		write(filepath.Join(root, "acl-nonowner-"+arch+".ast.json"), ast)
	}
	f.HFSSourceSHA256 = map[string]string{"hfs_vnops.c": "a07a8cd9bad0e485a6c7248facac3edcf66736727777715f8cf6a86fb77f3f44", "hfs_xattr.c": "22413ad83654198946ad26797c074fc9c64500a9fe75abbfcff426731ddce117"}
	for _, name := range []string{"hfs_vnops.c", "hfs_xattr.c"} {
		download("https://raw.githubusercontent.com/apple-oss-distributions/hfs/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/"+name, f.HFSSourceSHA256[name], filepath.Join(root, name))
	}
	must(json.Unmarshal(run(helper, "identity"), &f.Actor))
	const everyone = "group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:::"
	f.Seeds = []principalSeed{{Name: "none"}, {Name: "empty", Text: []byte("!#acl 1 no_inherit\n")}, {Name: "allow-write", Text: []byte("!#acl 1\n" + everyone + "allow:writesecurity\n")}, {Name: "deny-write", Text: []byte("!#acl 1\n" + everyone + "deny:writesecurity\n")}, {Name: "deny-read", Text: []byte("!#acl 1\n" + everyone + "deny:readsecurity\n")}, {Name: "allow-deny", Text: []byte("!#acl 1\n" + everyone + "allow:writesecurity\n" + everyone + "deny:writesecurity\n")}, {Name: "deny-allow", Text: []byte("!#acl 1\n" + everyone + "deny:writesecurity\n" + everyone + "allow:writesecurity\n")}, {Name: "inherit-only", Text: []byte("!#acl 1\n" + everyone + "allow,only_inherit:writesecurity\n")}, {Name: "unrelated", Text: []byte("!#acl 1\nuser:11234567-89AB-CDEF-0123-456789ABCDEF:::allow:writesecurity\n")}}
	for i := range f.Seeds {
		s := &f.Seeds[i]
		if s.Text == nil {
			continue
		}
		input, output := filepath.Join(root, "principal-seed-"+s.Name+".txt"), filepath.Join(root, "principal-seed-"+s.Name+".bin")
		write(input, s.Text)
		var encoded string
		must(json.Unmarshal(run(helper, "seed", input, output), &encoded))
		s.Disk = read(output)
		if hex.EncodeToString(s.Disk) != encoded {
			panic("seed export differs")
		}
	}
	texts := [][]byte{nil, []byte("invalid ACL"), []byte("!#acl 1\n"), []byte("!#acl 1\nuser:21234567-89AB-CDEF-0123-456789ABCDEF:::allow:read,write\n")}
	for _, filesystem := range []string{"apfs", "hfs"} {
		var cases []principalCase
		tree := &apfswrite.Entry{Name: "root", Mode: os.ModeDir | 0755, UID: f.Actor.UID, GID: f.Actor.GID}
		for _, kind := range []string{"file", "directory"} {
			for _, owner := range []bool{false, true} {
				for _, group := range []bool{false, true} {
					for _, writable := range []bool{false, true} {
						for _, seed := range f.Seeds {
							for index, text := range texts {
								mode := uint32(0444)
								if writable {
									mode = 0666
								}
								if kind == "directory" {
									mode |= 0111
								}
								uid, gid := uint32(60000), uint32(60000)
								if owner {
									uid = f.Actor.UID
								}
								if group {
									gid = f.Actor.GID
								}
								name := fmt.Sprintf("%s-%s-o%t-g%t-%04o-%s-%d", filesystem, kind, owner, group, mode, seed.Name, index)
								tc := principalCase{Name: name, Filesystem: filesystem, Kind: kind, Seed: seed.Name, Owner: owner, Group: group, Mode: mode, UID: uid, GID: gid, Text: text}
								cases = append(cases, tc)
								for _, variant := range []string{"native", "go"} {
									entry := &apfswrite.Entry{Name: name + "-" + variant, Mode: os.FileMode(mode), UID: uid, GID: gid}
									if kind == "directory" {
										entry.Mode |= os.ModeDir
									} else {
										entry.Data = []byte("ACL authorization fixture\n")
									}
									if seed.Disk != nil {
										entry.Xattrs = map[string][]byte{"com.apple.system.Security": seed.Disk}
									}
									tree.Children = append(tree.Children, entry)
								}
							}
						}
					}
				}
			}
		}
		imagePath := filepath.Join(root, "acl-principal-"+filesystem+".img")
		file, e := os.Create(imagePath)
		must(e)
		const size = 128 << 20
		must(file.Truncate(size))
		if filesystem == "apfs" {
			e = apfswrite.CreateContainer(file, size, &apfswrite.CreateOptions{VolumeName: "ACLPRINCIPAL", Root: tree})
		} else {
			e = hfsplus.CreateImage(file, size, "ACLPRINCIPAL", principalHFSTree(tree), nil)
		}
		closeErr := file.Close()
		must(e)
		must(closeErr)
		imageInfo := principalImage{Filesystem: filesystem, BeforeSHA256: sum(read(imagePath))}
		volume, e := os.MkdirTemp("", "acl-principal-")
		must(e)
		run("hdiutil", "attach", imagePath, "-owners", "on", "-nobrowse", "-mountpoint", volume)
		attached := true
		func() {
			defer func() {
				if attached {
					run("hdiutil", "detach", volume)
				}
			}()
			for _, tc := range cases {
				dir := filepath.Join(root, tc.Name)
				must(os.MkdirAll(dir, 0700))
				input := filepath.Join(dir, "acl.txt")
				write(input, tc.Text)
				before, native, _, _ := principalRun(helper, dir, filepath.Join(volume, tc.Name+"-native"), input, tc, "native")
				goBefore, goNative, request, result := principalRun(helper, dir, filepath.Join(volume, tc.Name+"-go"), input, tc, "go")
				if !reflect.DeepEqual(before, goBefore) || !reflect.DeepEqual(native, goNative) || !native.IdentityUnchanged {
					panic("principal parity differs: " + tc.Name)
				}
				m := before.Metadata
				if m.UID != tc.UID || m.GID != tc.GID || m.Mode&07777 != tc.Mode || m.Flags != 0 {
					panic("principal metadata setup: " + tc.Name)
				}
				after := native.After.Metadata
				if after.UID != m.UID || after.GID != m.GID || after.Mode != m.Mode || after.Flags != m.Flags {
					panic("principal write lost metadata: " + tc.Name)
				}
				if (!native.Applied || native.Code != 0) && !reflect.DeepEqual(before, native.After) {
					panic("principal failed/no-op write changed state: " + tc.Name)
				}
				if native.Applied != result.Applied || native.Writes != result.Attempts || native.Resets != 0 || result.Retried {
					panic("principal operation sequence differs: " + tc.Name)
				}
				tc.Before = before
				tc.Native = native
				tc.Request = request
				tc.GoResult = result
				f.Cases = append(f.Cases, tc)
			}
			run("hdiutil", "detach", volume)
			attached = false
		}()
		must(os.Remove(volume))
		imageInfo.AfterSHA256 = sum(read(imagePath))
		f.Images = append(f.Images, imageInfo)
		principalReadback(imagePath, filesystem, f)
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed-nonowner.json"), b)
	if capture {
		fmt.Printf("Captured %d owner/non-owner filesystem pairs; fixture NOT approved\n", len(f.Cases))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read("testdata/appledouble/native/acl-nonowner.json.gz")))
	must(e)
	var archived nonOwnerFixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if archived.HelperSHA256 != f.HelperSHA256 || archived.ParentHelperSHA256 != f.ParentHelperSHA256 || archived.CopyfileSHA256 != f.CopyfileSHA256 || !reflect.DeepEqual(archived.HFSSourceSHA256, f.HFSSourceSHA256) || !reflect.DeepEqual(archived.Seeds, f.Seeds) || len(archived.Cases) != len(f.Cases) {
		panic("principal fixture provenance differs")
	}
	for i, a := range archived.Cases {
		b := f.Cases[i]
		a.UID = b.UID
		a.GID = b.GID
		a.Before.Metadata.UID = b.Before.Metadata.UID
		a.Before.Metadata.GID = b.Before.Metadata.GID
		a.Native.After.Metadata.UID = b.Native.After.Metadata.UID
		a.Native.After.Metadata.GID = b.Native.After.Metadata.GID
		for _, pair := range [][2]*string{{a.Before.Attributes, b.Before.Attributes}, {a.Native.After.Attributes, b.Native.After.Attributes}} {
			if pair[0] != nil && pair[1] != nil {
				left, e := hex.DecodeString(*pair[0])
				must(e)
				right, e := hex.DecodeString(*pair[1])
				must(e)
				if len(left) < 12 || len(right) < 12 {
					panic("short principal frame")
				}
				copy(left[4:12], right[4:12])
				*pair[0] = hex.EncodeToString(left)
			}
		}
		if a.Request != nil && b.Request != nil {
			a.Request.UID = b.Request.UID
			a.Request.GID = b.Request.GID
		}
		if !reflect.DeepEqual(a, b) {
			panic("principal observations differ: " + b.Name)
		}
	}
	fmt.Printf("Qualified %d owner/non-owner APFS/HFS+ pairs\n", len(f.Cases))
}
func principalHFSTree(e *apfswrite.Entry) *hfsplus.Entry {
	out := &hfsplus.Entry{Name: e.Name, Mode: e.Mode, UID: e.UID, GID: e.GID, Data: e.Data, Xattrs: e.Xattrs}
	for _, c := range e.Children {
		out.Children = append(out.Children, principalHFSTree(c))
	}
	return out
}

type principalVolume interface {
	fs.FS
	Xattrs(string) (map[string][]byte, error)
}

func principalReadback(path, filesystem string, f *nonOwnerFixture) {
	var volume principalVolume
	file, e := os.Open(path)
	must(e)
	defer file.Close()
	if filesystem == "apfs" {
		container, e := apfs.Open(file, nil)
		must(e)
		volumes, e := container.Volumes()
		must(e)
		if len(volumes) != 1 {
			panic("principal volume count")
		}
		volume = volumes[0]
	} else {
		v, e := hfsplus.New(file)
		must(e)
		volume = v
	}
	seeds := map[string][]byte{}
	for _, s := range f.Seeds {
		seeds[s.Name] = s.Disk
	}
	for i := range f.Cases {
		tc := &f.Cases[i]
		if tc.Filesystem != filesystem {
			continue
		}
		var nativeAttrs map[string][]byte
		for _, variant := range []string{"native", "go"} {
			name := tc.Name + "-" + variant
			attrs, e := volume.Xattrs(name)
			must(e)
			if variant == "native" {
				nativeAttrs = attrs
			} else if !reflect.DeepEqual(attrs, nativeAttrs) {
				panic("offline ACL bytes differ: " + name)
			}
			if tc.Kind == "file" {
				content, e := fs.ReadFile(volume, name)
				must(e)
				if string(content) != "ACL authorization fixture\n" {
					panic("file contents changed")
				}
			}
			if !tc.Native.Applied && !bytes.Equal(attrs["com.apple.system.Security"], seeds[tc.Seed]) {
				panic("refused/no-op operation changed inaccessible ACL bytes: " + name)
			}
		}
		tc.AfterDisk = nativeAttrs["com.apple.system.Security"]
	}
}
