//go:build ignore

// Qualify offline image ACL restoration against real copyfile writes.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagerestore"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

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
func fileSum(p string) string {
	f, e := os.Open(p)
	must(e)
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	must(e)
	return fmt.Sprintf("%x", h.Sum(nil))
}
func run(args ...string) []byte {
	b, e := cirunner.Command(args[0], args[1:]...).CombinedOutput()
	c := command{Args: args, Output: string(b)}
	if e != nil {
		c.Error = e.Error()
	}
	commands = append(commands, c)
	if e != nil {
		panic(fmt.Sprintf("%v: %v %s", args, e, b))
	}
	return b
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
	const root = "artifacts/image-acl-restore"
	const corpus = "testdata/appledouble/native/image-acl-restore.json.gz"
	must(os.MkdirAll(root, 0700))
	f := imagerestore.Fixture{Sources: map[string]string{}, Helpers: map[string]string{}, InitialImages: map[string]string{}, NativeImages: map[string]string{}, FinalImages: map[string]string{}, Aliases: map[string]imagerestore.Observation{}}
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
		panic("requires ordinary Mac user")
	}
	f.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	f.Host = string(run("sw_vers"))
	f.ActorUID, f.ActorGID = uint32(os.Getuid()), uint32(os.Getegid())
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	f.Sources["copyfile.c"] = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.Sources["kern_authorization.c"] = "6909f51300732fe195252b9de1ce0a2fb5d086af9072dc5746269a8ffeb2e249"
	copyfile := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.Sources["copyfile.c"], filepath.Join(root, "copyfile.c"))
	xnu := download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_authorization.c", f.Sources["kern_authorization.c"], filepath.Join(root, "kern_authorization.c"))
	// Retain the full kernel write implementation as provenance for the UUID
	// behavior, in addition to the unchanged functions compiled into the oracle.
	for name, hash := range map[string]string{"vfs_syscalls.c": "b30d68fb85f34b864b5e71e3127541c2674e0fb52e59d6ee072c8b0ecbb46a4f", "kpi_vfs.c": "26cd0285298c7eafe9ff86387d9fe273f5cbdf965f850458357eba4328303e53"} {
		f.Sources[name] = hash
		download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/"+name, hash, filepath.Join(root, name))
	}
	header := append(bytes.Clone(copyfile[:bytes.Index(copyfile, []byte("#include"))]), extract(copyfile, "static int copyfile_unset_acl(copyfile_state_t s)\n{", "\n/*")...)
	header = append(header, extract(copyfile, "static int copyfile_unpack_acl(copyfile_state_t s, uint32_t entry_length, void *dataptr)\n{", "\nstatic int copyfile_unpack_xattr")...)
	header = append(header, xnu[:bytes.Index(xnu, []byte("#include"))]...)
	header = append(header, extract(xnu, "void\nkauth_filesec_acl_setendian(", "\n/*\n * Allocate an ACL buffer.")...)
	write(filepath.Join(root, "filesec-source.h"), header)
	const source = "testdata/appledouble/native/image-acl-restore.c"
	for _, name := range []string{source, "testdata/appledouble/native/filesec.c"} {
		f.Helpers[name] = sum(read(name))
	}
	helper := filepath.Join(root, "image-acl-restore")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, source, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		for _, tree := range imagerestore.Trees(f.ActorUID, f.ActorGID) {
			name := kind + "-" + tree.Name
			hfsTree := imagesecurity.HFSTree(tree.Root)
			create := func(path string) {
				file, e := os.Create(path)
				must(e)
				defer file.Close()
				if strings.HasPrefix(kind, "apfs") {
					must(apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: tree.Root, VolumeName: "RESTORE", CaseSensitive: kind == "apfs-sensitive"}))
				} else {
					must(hfsplus.CreateImage(file, 64<<20, "RESTORE", hfsTree, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}))
				}
			}
			input := filepath.Join(root, name+"-input.img")
			create(input)
			f.InitialImages[name] = fileSum(input)
			initial := filepath.Join(root, name+"-native.img")
			copyImage(input, initial)
			mount, e := os.MkdirTemp("", "image-acl-native-")
			must(e)
			filesystem := "apfs"
			if strings.HasPrefix(kind, "hfs") {
				filesystem = "hfs"
			}
			start := len(f.Cases)
			run("hdiutil", "attach", initial, "-owners", "on", "-nobrowse", "-mountpoint", mount)
			func() {
				defer func() { run("hdiutil", "detach", mount); must(os.Remove(mount)) }()
				if tree.Name == "entries" {
					if b, e := os.ReadFile(filepath.Join(mount, "implicit-dir/child")); e != nil || string(b) != "nested" {
						panic(fmt.Sprintf("inferred directory payload: %v", e))
					}
				}
				for i, c := range tree.Cases {
					text := filepath.Join(root, fmt.Sprintf("%s-%04d.txt", name, i))
					write(text, c.Text)
					n := imagerestore.NativeCase{Filesystem: name, Case: c}
					must(json.Unmarshal(run(helper, "apply", filepath.Join(mount, c.Target), text, filesystem, mount), &n.Native))
					if n.Native.Code != 0 || n.Native.Errno != 0 || !n.Native.SameIdentity {
						panic(fmt.Sprintf("native application %s/%s: %+v", name, c.Name, n.Native))
					}
					var err error
					if strings.HasPrefix(kind, "apfs") {
						n.GoResult, err = imagerestore.ApplyAPFS(tree.Root, c)
					} else {
						n.GoResult, err = imagerestore.ApplyHFS(hfsTree, c)
					}
					must(err)
					if n.Native.Applied != n.GoResult.Applied || n.GoResult.Retried {
						panic("application result mismatch")
					}
					f.Cases = append(f.Cases, n)
					for _, alias := range c.Aliases {
						var o imagerestore.Observation
						must(json.Unmarshal(run(helper, "observe", filepath.Join(mount, alias), "-", filesystem, mount), &o))
						if o.After != n.Native.After || o.AfterAttributes != n.Native.AfterAttributes || o.Inode != n.Native.Inode {
							panic("native hard-link disagreement")
						}
						f.Aliases[name+"/native/"+alias] = o
					}
				}
			}()
			f.NativeImages[name] = fileSum(initial)
			if f.NativeImages[name] == f.InitialImages[name] {
				panic("native writes did not change image")
			}
			check(initial, kind)
			written := filepath.Join(root, name+"-go.img")
			create(written)
			beforeHash := fileSum(written)
			check(written, kind)
			mount, e = os.MkdirTemp("", "image-acl-written-")
			must(e)
			run("hdiutil", "attach", written, "-readonly", "-owners", "on", "-nobrowse", "-mountpoint", mount)
			func() {
				defer func() { run("hdiutil", "detach", mount); must(os.Remove(mount)) }()
				if tree.Name == "entries" {
					if b, e := os.ReadFile(filepath.Join(mount, "implicit-dir/child")); e != nil || string(b) != "nested" {
						panic(fmt.Sprintf("written inferred directory payload: %v", e))
					}
				}
				for i, c := range tree.Cases {
					n := &f.Cases[start+i]
					must(json.Unmarshal(run(helper, "observe", filepath.Join(mount, c.Target), "-", filesystem, mount), &n.Written))
					o := n.Written
					if o.Code != 0 || o.Errno != 0 || !o.SameIdentity || o.After != n.Native.After || o.AfterAttributes != n.Native.AfterAttributes {
						panic(fmt.Sprintf("written mismatch %s/%s: native=%+v written=%+v", name, c.Name, n.Native, o))
					}
					for _, alias := range c.Aliases {
						var a imagerestore.Observation
						must(json.Unmarshal(run(helper, "observe", filepath.Join(mount, alias), "-", filesystem, mount), &a))
						if a.After != o.After || a.AfterAttributes != o.AfterAttributes || a.Inode != o.Inode {
							panic("written hard-link disagreement")
						}
						f.Aliases[name+"/written/"+alias] = a
					}
				}
			}()
			if fileSum(written) != beforeHash {
				panic("read-only image changed")
			}
			f.FinalImages[name] = beforeHash
		}
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d ACL applications; NOT approved\n", len(f.Cases))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read(corpus)))
	must(e)
	var archived imagerestore.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	normalize(&archived, f.ActorUID, f.ActorGID)
	archived.Revision, archived.Host = f.Revision, f.Host
	archived.InitialImages, archived.NativeImages, archived.FinalImages = f.InitialImages, f.NativeImages, f.FinalImages
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d ACL applications and %d alias observations across %d images\n", len(f.Cases), len(f.Aliases), len(f.FinalImages))
}
func check(image, kind string) {
	if strings.HasPrefix(kind, "apfs") {
		run("/sbin/fsck_apfs", "-n", image)
		return
	}
	attached := run("hdiutil", "attach", "-imagekey", "diskimage-class=CRawDiskImage", "-nomount", "-readonly", image)
	device := regexp.MustCompile(`/dev/disk[0-9]+`).FindString(string(attached))
	if device == "" {
		panic("missing HFS device")
	}
	defer run("hdiutil", "detach", device)
	args := []string{"/sbin/fsck_hfs", "-n", device}
	output, e := cirunner.Command(args[0], args[1:]...).CombinedOutput()
	c := command{Args: args, Output: string(output)}
	if e != nil {
		c.Error = e.Error()
	}
	commands = append(commands, c)
	if !bytes.Contains(output, []byte("appears to be OK")) {
		panic(fmt.Sprintf("HFS check: %v %s", e, output))
	}
}
func normalize(f *imagerestore.Fixture, uid, gid uint32) {
	oldUID, oldGID := f.ActorUID, f.ActorGID
	observation := func(o *imagerestore.Observation) {
		for _, m := range []*imagerestore.Metadata{&o.Before, &o.After} {
			if m.UID != oldUID || m.GID != oldGID {
				panic("unexpected corpus owner")
			}
			m.UID, m.GID = uid, gid
		}
		for _, encoded := range []*string{&o.BeforeAttributes, &o.AfterAttributes} {
			b, e := hex.DecodeString(*encoded)
			must(e)
			if len(b) < 56 || binary.LittleEndian.Uint32(b[4:]) != oldUID || binary.LittleEndian.Uint32(b[8:]) != oldGID {
				panic("corpus numeric attributes")
			}
			binary.LittleEndian.PutUint32(b[4:], uid)
			binary.LittleEndian.PutUint32(b[8:], gid)
			*encoded = hex.EncodeToString(b)
		}
	}
	for i := range f.Cases {
		observation(&f.Cases[i].Native)
		observation(&f.Cases[i].Written)
	}
	for key, o := range f.Aliases {
		observation(&o)
		f.Aliases[key] = o
	}
	f.ActorUID, f.ActorGID = uid, gid
}

func copyImage(source, destination string) {
	input, e := os.Open(source)
	must(e)
	defer input.Close()
	output, e := os.Create(destination)
	must(e)
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	must(copyErr)
	must(closeErr)
	if fileSum(source) != fileSum(destination) {
		panic("image clone mismatch")
	}
}
