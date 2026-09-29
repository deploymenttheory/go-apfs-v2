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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
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
