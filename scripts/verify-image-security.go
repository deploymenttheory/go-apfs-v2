//go:build ignore

// Native qualification of pure-Go APFS/HFS image security capture.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagestat"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/statcopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type command struct {
	Args           []string
	Output, Error  string
	Stdout, Stderr string `json:",omitempty"`
	ExitCode       *int   `json:",omitempty"`
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

// Retry only hdiutil's transient busy status through the shared strict policy.
// Every attempt is recorded; exhaustion, launch failures and other statuses fail.
// Ordinary detach is required: force ejection would hide leaked mount users.
func detach(target string) error {
	return diskimage.RetryDetach(context.Background(), func() (int, error) {
		args := []string{"hdiutil", "detach", target}
		cmd := cirunner.Command(args[0], args[1:]...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		record := command{Args: args, Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: &code}
		if err != nil {
			record.Error = err.Error()
		}
		commands = append(commands, record)
		if err != nil {
			err = fmt.Errorf("%v: %w: %s", args, err, stderr.String())
		}
		return code, err
	})
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
	modes := flag.Bool("modes", false, "qualify explicit permissions and special bits on both image writers")
	times := flag.Bool("times", false, "qualify independent inode timestamps and epoch preservation")
	roots := flag.Bool("roots", false, "qualify root writer metadata and storage")
	bsdFlags := flag.Bool("flags", false, "qualify independent image BSD flags")
	statStage := flag.Bool("stat", false, "qualify ordered stat staging in both image writers")
	flag.Parse()
	if (*statStage && (*roots || *modes || *times || *bsdFlags)) || (*roots && *modes) || (*times && (*roots || *modes)) || (*bsdFlags && (*roots || *modes || *times)) {
		panic("choose one of roots, modes, times, flags or stat")
	}
	root := "artifacts/image-security"
	helperSource := "testdata/appledouble/native/image-security.c"
	corpus := "testdata/appledouble/native/image-security.json.gz"
	if *roots {
		root = "artifacts/image-root-security"
		corpus = "testdata/appledouble/native/image-root-security.json.gz"
	}
	if *modes {
		root = "artifacts/image-mode-security"
		corpus = "testdata/appledouble/native/image-mode-security.json.gz"
	}
	if *times {
		root = "artifacts/image-times"
		corpus = "testdata/appledouble/native/image-times.json.gz"
	}
	if *bsdFlags {
		root = "artifacts/image-flags"
		corpus = "testdata/appledouble/native/image-flags.json.gz"
	}
	if *statStage {
		root = "artifacts/image-stat"
		corpus = "testdata/appledouble/native/image-stat.json.gz"
	}
	must(os.MkdirAll(root, 0700))
	var f imagesecurity.Fixture
	if *bsdFlags {
		f.Helpers = map[string]string{helperSource: sum(read(helperSource))}
		write(filepath.Join(root, "image-security-base.h"), bytes.Replace(read(helperSource), []byte("int main("), []byte("int image_security_main("), 1))
		helperSource = "testdata/appledouble/native/image-flags.c"
		f.DocumentIDs = map[string]uint32{}
	}
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
		panic("native qualification requires an ordinary Mac user")
	}
	f.Revision = strings.TrimSpace(string(run("git", "rev-parse", "HEAD")))
	f.Host = string(run("sw_vers"))
	run("uname", "-a")
	run("xcrun", "clang", "--version")
	run("xcrun", "--show-sdk-version")
	f.ActorUID, f.ActorGID = uint32(os.Getuid()), uint32(os.Getegid())
	f.Images = map[string]string{}
	if *modes {
		f.NativeAccess = map[string]string{}
	}
	f.HelperSHA256 = sum(read(helperSource))
	f.ParentSHA256 = sum(read("testdata/appledouble/native/security-copy.c"))
	f.CopyfileSHA256 = "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c"
	f.ChmodSHA256 = "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff"
	f.StatxSHA256 = "5a05eabc7d870f2c1a98c4e3b828d020e4a51e4b60c6887d955422add747730d"
	f.XNUSHA256 = "26cd0285298c7eafe9ff86387d9fe273f5cbdf965f850458357eba4328303e53"
	src := download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", f.CopyfileSHA256, filepath.Join(root, "copyfile.c"))
	h := append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	for _, p := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static int\ncopyfile_unset_posix_fsec", "/*\n * Used to remove acl information"}, {"static int copyfile_security(copyfile_state_t s)", "/*\n * Attempt to set the destination"}} {
		h = append(h, extract(src, p[0], p[1])...)
	}
	write(filepath.Join(root, "acl-copy-source.h"), h)
	src = download("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/sys/chmodx_np.c", f.ChmodSHA256, filepath.Join(root, "chmodx_np.c"))
	h = append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, src[bytes.Index(src, []byte("static int\nchmodx1(")):]...)
	write(filepath.Join(root, "acl-chmod-source.h"), h)
	src = download("https://raw.githubusercontent.com/apple-oss-distributions/Libc/71bbe350ab79eef58113991d817ccc6165061a64/sys/statx_np.c", f.StatxSHA256, filepath.Join(root, "statx_np.c"))
	h = append([]byte{}, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "static int\nlstatx_syscall(", "/*\n * Stat internals")...)
	h = append(h, src[bytes.Index(src, []byte("static int\nstatx1(")):]...)
	write(filepath.Join(root, "image-statx-source.h"), h)
	download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/vfs/kpi_vfs.c", f.XNUSHA256, filepath.Join(root, "kpi_vfs.c"))
	f.HFSSources = map[string]string{
		"UnicodeWrappers.c":     "7300de813b94d41d14faf9aa2a0ddf436010bb43d258f81fc92ab841bc7157f2",
		"UCStringCompareData.h": "88773669ce79ebe2d6bcc84d3341c3c2586e649984ac97453adb1b8706440464",
		"hfs_link.c":            "1238abcd80ada12e254a8d0e45dd82d990693f3dea047ecd7c7345c7a1410078",
	}
	if *bsdFlags {
		f.HFSSources["hfs_catalog.c"] = "a459793a5f38d05ad3b5a8e6f9761aefb3d9dfeb077962a7a190b6812bd37dd6"
		f.HFSSources["hfs_vnops.c"] = "a07a8cd9bad0e485a6c7248facac3edcf66736727777715f8cf6a86fb77f3f44"
		f.HFSSources["hfs_format.h"] = "114e5349032cd7169331760a5c601b5dea5d0cb9f955cc00e8f53577e74b36db"
		for _, name := range []string{"hfs_catalog.c", "hfs_vnops.c", "hfs_format.h"} {
			download("https://raw.githubusercontent.com/apple-oss-distributions/hfs/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/"+name, f.HFSSources[name], filepath.Join(root, name))
		}
	}
	if *bsdFlags {
		format := read(filepath.Join(root, "hfs_format.h"))
		vnops := read(filepath.Join(root, "hfs_vnops.c"))
		header := append([]byte{}, format[:bytes.Index(format, []byte("#ifndef"))]...)
		header = append(header, extract(format, "struct FndrExtendedFileInfo {", "/* HFS Plus Fork")...)
		header = append(header, vnops[:bytes.Index(vnops, []byte("#include"))]...)
		header = append(header, extract(vnops, "static u_int32_t \nhfs_get_document_id_internal", "/* getter(s) for document id */")...)
		write(filepath.Join(root, "image-document-source.h"), header)
	}
	hfsSource := map[string][]byte{}
	for _, name := range []string{"UnicodeWrappers.c", "UCStringCompareData.h", "hfs_link.c"} {
		hfsSource[name] = download("https://raw.githubusercontent.com/apple-oss-distributions/hfs/d1bac2f062e6e9c0dfcce302d9aacb10173d0eea/core/"+name, f.HFSSources[name], filepath.Join(root, name))
	}
	src = hfsSource["UCStringCompareData.h"]
	h = append([]byte{}, src[:bytes.Index(src, []byte("#ifndef"))]...)
	h = append(h, extract(src, "u_int16_t gLatinCaseFold[]", "#endif /* __APPLE_API_PRIVATE */")...)
	src = hfsSource["UnicodeWrappers.c"]
	h = append(h, src[:bytes.Index(src, []byte("#include"))]...)
	h = append(h, extract(src, "int32_t FastUnicodeCompare (", "/*\n * UnicodeBinaryCompare")...)
	write(filepath.Join(root, "image-fold-source.h"), h)
	if *statStage {
		f.Helpers = map[string]string{}
		for _, name := range []string{"testdata/appledouble/native/image-stat.c", "testdata/appledouble/native/stat-copy.c"} {
			f.Helpers[name] = sum(read(name))
		}
		f.StatSources = map[string]string{"copyfile_private.h": "8ac427e2c1dbe0ca92cfe2fbf114df90fd747f3fbe25c2a4919ff941a1be81c5", "fsctl.h": "dae81f19610f25fb7905b5c725f728fec4b8b4978f6214374415d420ffac258d"}
		download("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile_private.h", f.StatSources["copyfile_private.h"], filepath.Join(root, "copyfile_private.h"))
		source := read(filepath.Join(root, "copyfile.c"))
		header := append([]byte{}, source[:bytes.Index(source, []byte("#include"))]...)
		for _, part := range [][2]string{{"#define S_ISSUD", "#define COPYFILE_MNT_CPROTECT_MASK"}, {"static int\nfd_volume_has_feature", "static bool\npath_does_copy_protection"}, {"static errno_t copyfile_set_bsdflags", "/*\n * Attempt to copy the data section"}, {"static int copyfile_stat(copyfile_state_t s)", "/*\n * Copy the resource fork in pieces"}} {
			header = append(header, extract(source, part[0], part[1])...)
		}
		write(filepath.Join(root, "stat-source.h"), header)
		xnu := download("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/fsctl.h", f.StatSources["fsctl.h"], filepath.Join(root, "fsctl.h"))
		header = append([]byte{}, xnu[:bytes.Index(xnu, []byte("#ifndef"))]...)
		header = append(header, extract(xnu, "struct fsioc_cas_bsdflags {", "#define FSIOC_GRAFT_VERSION")...)
		header = append(header, extract(xnu, "#define FSIOC_CAS_BSDFLAGS", "/* Check if a file is only open once")...)
		write(filepath.Join(root, "stat-fsctl.h"), header)
		const sourcePath = "testdata/appledouble/native/image-stat.c"
		oracle := filepath.Join(root, "image-stat")
		run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-I", root, sourcePath, "-o", oracle)
		for _, arch := range []string{"arm64", "x86_64"} {
			ast := run("xcrun", "clang", "-arch", arch, "-I", root, "-fsyntax-only", "-Xclang", "-ast-dump=json", sourcePath)
			commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(ast))
			write(filepath.Join(root, arch+"-stat.ast.json"), ast)
		}
		for _, tc := range imagestat.Models() {
			must(json.Unmarshal(run(oracle, fmt.Sprint(tc.SourceFlags), fmt.Sprint(tc.TargetFlags), fmt.Sprint(tc.Options)), &tc.Native))
			_, _, err := statcopy.Replay(tc)
			must(err)
			f.StatModels = append(f.StatModels, tc)
		}
	}
	helper := filepath.Join(root, "image-security")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-Wno-unused-but-set-variable", "-I", root, "-I", "testdata/appledouble/native", helperSource, "-o", helper)
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-I", root, "-I", "testdata/appledouble/native", "-fsyntax-only", "-Xclang", "-ast-dump=json", helperSource)
		commands[len(commands)-1].Output = fmt.Sprintf("AST retained: %d bytes", len(b))
		write(filepath.Join(root, arch+".ast.json"), b)
	}
	tree, cases := imagesecurity.Tree(f.ActorUID, f.ActorGID)
	type scenario struct {
		kind, name string
		tree       *apfswrite.Entry
		cases      []imagesecurity.Case
		snapshots  []apfswrite.SnapshotSpec
	}
	var scenarios []scenario
	if *statStage {
		for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
			scenarios = append(scenarios, scenario{kind: kind, name: kind + "-stat", snapshots: []apfswrite.SnapshotSpec{{Name: "stat"}}})
		}
	} else if *bsdFlags {
		for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
			tree, cases := imagesecurity.FlagTree()
			var snaps []apfswrite.SnapshotSpec
			if strings.HasPrefix(kind, "apfs") {
				snaps = []apfswrite.SnapshotSpec{{Name: "flags"}}
			}
			scenarios = append(scenarios, scenario{kind, kind + "-flags", tree, cases, snaps})
		}
	} else if *times {
		for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
			for _, clamp := range []bool{false, true} {
				tree, cases := imagesecurity.TimeTree(clamp)
				name := kind + "-times"
				if clamp {
					name += "-clamp"
				}
				var snaps []apfswrite.SnapshotSpec
				if strings.HasPrefix(kind, "apfs") {
					snaps = []apfswrite.SnapshotSpec{{Name: "times"}}
				}
				scenarios = append(scenarios, scenario{kind, name, tree, cases, snaps})
			}
		}
	} else if *roots {
		for _, kind := range []string{"apfs", "apfs-sensitive"} {
			for _, r := range imagesecurity.Roots(f.ActorUID, f.ActorGID) {
				scenarios = append(scenarios, scenario{kind, kind + "-" + r.Name, r.Root, []imagesecurity.Case{r.Case}, r.Snapshots})
			}
		}
	} else if *modes {
		for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
			for _, r := range imagesecurity.Modes(f.ActorUID, f.ActorGID) {
				scenarios = append(scenarios, scenario{kind, kind + "-" + r.Name, r.Root, r.Cases, nil})
			}
		}
	} else {
		for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
			scenarios = append(scenarios, scenario{kind, kind, tree, cases, nil})
		}
	}
	for _, scene := range scenarios {
		kind, tree, cases := scene.kind, scene.tree, scene.cases
		var stagedHFS *hfsplus.Entry
		if *statStage {
			var err error
			tree, stagedHFS, cases, err = imagestat.Build(f.StatModels, strings.HasPrefix(kind, "hfs"))
			must(err)
		}
		image := filepath.Join(root, scene.name+".img")
		file, e := os.Create(image)
		must(e)
		if strings.HasPrefix(kind, "apfs") {
			must(apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: tree, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive", Snapshots: scene.snapshots, ClampModTimes: strings.HasSuffix(scene.name, "-clamp")}))
		} else {
			if stagedHFS == nil {
				stagedHFS = imagesecurity.HFSTree(tree)
			}
			must(hfsplus.CreateImage(file, 64<<20, "SECURITY", stagedHFS, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus", ClampModTimes: strings.HasSuffix(scene.name, "-clamp")}))
		}
		must(file.Close())
		if *roots || *modes || *times || *bsdFlags || *statStage {
			if strings.HasPrefix(kind, "apfs") {
				run("/sbin/fsck_apfs", "-n", image)
			} else {
				func() {
					attached := run("hdiutil", "attach", "-plist", "-imagekey", "diskimage-class=CRawDiskImage", "-nomount", "-readonly", image)
					device, err := diskimage.AttachmentDevice(attached)
					must(err)
					defer func() { must(detach(device)) }()
					args := []string{"/sbin/fsck_hfs", "-n", device}
					output, err := cirunner.Command(args[0], args[1:]...).CombinedOutput()
					c := command{Args: args, Output: string(output)}
					if err != nil {
						c.Error = err.Error()
					}
					commands = append(commands, c)
					// Like the existing HFS acceptance gate, require the completed
					// clean-volume verdict. Ordinary users can get a nonzero exit
					// for the raw character-device pass despite a clean block pass.
					if !bytes.Contains(output, []byte("appears to be OK")) {
						panic(fmt.Sprintf("HFS check: %v %s", err, output))
					}
				}()
			}
		}
		beforeHash := fileSum(image)
		file, e = os.Open(image)
		must(e)
		var volume imagesecurity.Volume
		if strings.HasPrefix(kind, "apfs") {
			c, e := apfs.Open(file, nil)
			must(e)
			v, e := c.Volumes()
			must(e)
			if len(v) != 1 {
				panic("volume count")
			}
			volume = v[0]
		} else {
			v, e := hfsplus.New(file)
			must(e)
			volume = v
		}
		mount, e := os.MkdirTemp("", "image-security-")
		must(e)
		device, e := diskimage.AttachmentDevice(run("hdiutil", "attach", "-plist", image, "-readonly", "-owners", "on", "-nobrowse", "-mountpoint", mount))
		must(e)
		func() {
			defer func() {
				// Release our reader before detaching, even if qualification panics.
				must(errors.Join(file.Close(), detach(device)))
				must(os.Remove(mount))
			}()
			if *roots {
				attrs, e := volume.Xattrs(".")
				must(e)
				if len(attrs) != len(tree.Xattrs) {
					panic("root attribute count")
				}
				if f.NativeXattrs == nil {
					f.NativeXattrs = map[string]map[string]imagesecurity.XattrObservation{}
				}
				f.NativeXattrs[scene.name] = map[string]imagesecurity.XattrObservation{}
				for name, want := range tree.Xattrs {
					if !bytes.Equal(attrs[name], want) {
						panic("root attribute bytes: " + name)
					}
					var native imagesecurity.XattrObservation
					must(json.Unmarshal(run(helper, "--xattr", mount, name), &native))
					f.NativeXattrs[scene.name][name] = native
					if scene.name == kind+"-owner-mode" {
						if native.Errno != 13 || native.Length != -1 || native.Value != nil {
							panic("expected native permission denial")
						}
						continue
					}
					if name == "com.apple.system.Security" {
						if native.Errno != 1 || native.Length != -1 || native.Value != nil {
							panic("expected protected security xattr denial")
						}
						continue
					}
					if name == "com.apple.ResourceFork" {
						if native.Errno != 93 || native.Length != -1 || native.Value != nil {
							panic(fmt.Sprintf("directory root fork result: %+v", native))
						}
						continue
					}
					if native.Errno != 0 {
						panic(fmt.Sprintf("native xattr %s/%s: %+v", scene.name, name, native))
					}
					if native.Length != len(want) || native.Value == nil || !strings.EqualFold(*native.Value, fmt.Sprintf("%x", want)) {
						panic("native root attribute bytes: " + name)
					}
				}

			}
			for _, tc := range cases {

				n := imagesecurity.NativeCase{Filesystem: scene.name, Case: tc}
				path := mount
				if tc.Name != "." {
					path = filepath.Join(mount, tc.Name)
				}
				must(json.Unmarshal(run(helper, path), &n.Native))
				f.Cases = append(f.Cases, n)
				native := n.Native
				if *bsdFlags || *statStage {
					got, e := volume.BSDFlags(tc.Name)
					must(e)
					if *bsdFlags && got&0x40 != 0 {
						var id uint32
						_, err := fmt.Sscan(string(run(helper, "--document-id", path)), &id)
						must(err)
						if (id == 0) != (!strings.HasPrefix(kind, "apfs") && tc.Kind == "symlink") {
							panic("tracked inode has no document ID")
						}
						f.DocumentIDs[scene.name+"/"+tc.Name] = id
					}
					if native.Flags != *tc.Flags || got != *tc.Flags {
						panic(fmt.Sprintf("BSD flags %s/%s: native=%#x reader=%#x want=%#x", scene.name, tc.Name, native.Flags, got, *tc.Flags))
					}
				}
				if *statStage {
					attrs, err := volume.Xattrs(tc.Name)
					must(err)
					if string(attrs["org.example.keep"]) != "kept" {
						panic("stat stage changed unrelated xattr")
					}
					var value imagesecurity.XattrObservation
					must(json.Unmarshal(run(helper, "--xattr", path, "org.example.keep"), &value))
					if value.Errno != 0 || value.Length != 4 || value.Value == nil || *value.Value != "6b657074" {
						panic("native unrelated xattr mismatch")
					}
					if f.NativeXattrs == nil {
						f.NativeXattrs = map[string]map[string]imagesecurity.XattrObservation{}
					}
					f.NativeXattrs[scene.name+"/"+tc.Name] = map[string]imagesecurity.XattrObservation{"org.example.keep": value}
				}
				if *times || *statStage {
					want := *tc.Times
					if !strings.HasPrefix(kind, "apfs") {
						for i, v := range want {
							want[i] = time.Unix(0, v).Unix() * 1e9
						}
					}
					if native.Times != want {
						panic(fmt.Sprintf("native timestamp %s/%s: %v != %v", scene.name, tc.Name, native.Times, want))
					}
					got, e := volume.FileTimes(tc.Name)
					must(e)
					actual := [4]int64{got.Birth.UnixNano(), got.Modify.UnixNano(), got.Change.UnixNano(), got.Access.UnixNano()}
					if actual != want {
						panic("reader timestamp mismatch")
					}
				}
				if (*modes || *statStage) && (native.Mode != uint32(tc.Mode) || native.UID != tc.UID || native.GID != tc.GID) {
					panic(fmt.Sprintf("native mode/ownership %s/%s: got %#o want %#o", scene.name, tc.Name, native.Mode, tc.Mode))
				}
				if *roots {
					stamp := tree.ModTime
					if stamp.IsZero() {
						stamp = apfswrite.DefaultTime
					}
					for _, got := range native.Times {
						if got != stamp.UnixNano() {
							panic(fmt.Sprintf("native root timestamp %s: %d/%d", scene.name, got, stamp.UnixNano()))
						}
					}
				}
				if native.Code != 0 || native.ReferenceCode != 0 || native.Errno != 0 || native.ReferenceErrno != 0 || !native.SameIdentity || !reflect.DeepEqual(native.Properties, native.ReferenceProperties) {
					panic("native capture mismatch: " + kind + "/" + tc.Name)
				}
				got, e := volume.Security(tc.Name)
				must(e)
				p := securitycopy.PropertiesFromGo(got.Source.Properties)
				if !reflect.DeepEqual(p, native.Properties) || got.Disposition != tc.Disposition || got.Source.UID != native.UID || got.Source.GID != native.GID || got.Source.Mode != native.Mode {
					a, _ := json.Marshal(p)
					b, _ := json.Marshal(native.Properties)
					panic(fmt.Sprintf("reader mismatch %s/%s: disposition %d/%d properties %s/%s", kind, tc.Name, got.Disposition, tc.Disposition, a, b))
				}
				info, e := fs.Stat(volume, tc.Name)
				must(e)
				if *modes {
					nativeInfo, e := os.Lstat(path)
					must(e)
					if info.Mode() != nativeInfo.Mode() {
						panic(fmt.Sprintf("FileInfo.Mode mismatch %s/%s: %s/%s", scene.name, tc.Name, info.Mode(), nativeInfo.Mode()))
					}
				}
				var inode uint64
				switch s := info.Sys().(type) {
				case *apfs.Inode:
					inode = s.Identifier
				case *hfsplus.HFSPlusCatalogFile:
					inode = uint64(s.FileID)
				case *hfsplus.HFSPlusCatalogFolder:
					inode = uint64(s.FolderID)
				default:
					panic("inode metadata")
				}
				if inode != native.Inode {
					panic("inode mismatch: " + tc.Name)
				}
				if tc.Kind == "file" || strings.HasPrefix(tc.Kind, "hard-") {
					b, e := fs.ReadFile(volume, tc.Name)
					must(e)
					if string(b) != "payload" {
						panic("payload mismatch")
					}
					nativePayload, e := os.ReadFile(path)
					if *modes {
						value := fmt.Sprintf("read:%x", nativePayload)
						if e != nil {
							value = "read:errno13"
						}
						f.NativeAccess[scene.name+"/"+tc.Name] = value
					}
					if *modes && tc.Mode&0400 == 0 {
						if !errors.Is(e, syscall.EACCES) {
							panic(fmt.Sprintf("expected native read refusal %s: %v", path, e))
						}
					} else if e != nil || !bytes.Equal(b, nativePayload) {
						panic("native payload mismatch")
					}
				}
				if tc.Kind == "symlink" {
					target, e := volume.Readlink(tc.Name)
					must(e)
					b, e := os.Readlink(path)
					if *modes {
						value := "readlink:" + b
						if e != nil {
							value = "readlink:errno13"
						}
						f.NativeAccess[scene.name+"/"+tc.Name] = value
					}
					if *modes && tc.Mode&0400 == 0 {
						if !errors.Is(e, syscall.EACCES) {
							panic(fmt.Sprintf("expected native readlink refusal %s: %v", path, e))
						}
					} else if e != nil || target != b {
						panic("link target mismatch")
					}
				}
			}
		}()
		if fileSum(image) != beforeHash {
			panic("read-only image changed")
		}
		f.Images[scene.name] = beforeHash
	}
	b, e := json.MarshalIndent(f, "", "  ")
	must(e)
	write(filepath.Join(root, "observed.json"), b)
	if *capture {
		fmt.Printf("Captured %d image entries; NOT approved\n", len(f.Cases))
		return
	}
	z, e := gzip.NewReader(bytes.NewReader(read(corpus)))
	must(e)
	var archived imagesecurity.Fixture
	must(json.NewDecoder(z).Decode(&archived))
	must(z.Close())
	if len(archived.Cases) != len(f.Cases) {
		panic("case count")
	}
	oldUID, oldGID := archived.ActorUID, archived.ActorGID
	for i := range archived.Cases {
		if *times || *bsdFlags || *statStage {
			continue
		} // Timestamp/flag fixtures deliberately use fixed foreign IDs.
		c := &archived.Cases[i]
		if c.Case.UID == oldUID {
			c.Case.UID = f.ActorUID
		}
		if c.Case.GID == oldGID {
			c.Case.GID = f.ActorGID
		}
		n := &c.Native
		if n.UID == oldUID {
			n.UID = f.ActorUID
		}
		if n.GID == oldGID {
			n.GID = f.ActorGID
		}
		for _, p := range []*securitycopy.Properties{&n.Properties, &n.ReferenceProperties} {
			if p.UID != nil && *p.UID == oldUID {
				v := f.ActorUID
				p.UID = &v
			}
			if p.GID != nil && *p.GID == oldGID {
				v := f.ActorGID
				p.GID = &v
			}
		}
	}
	archived.Revision, archived.Host, archived.ActorUID, archived.ActorGID = f.Revision, f.Host, f.ActorUID, f.ActorGID
	// Image bytes include actor IDs; each fresh image is independently hashed and
	// checked unchanged over read-only mounting, not normalized byte-by-byte.
	if !*bsdFlags && !*statStage {
		archived.Images = f.Images
	} // Flag fixtures use fixed IDs and must reproduce the approved image hashes.
	if !reflect.DeepEqual(archived, f) {
		panic("archived observations differ")
	}
	passed = true
	fmt.Printf("Qualified %d image entries, public and unchanged Libc capture, source identity and read-only hashes\n", len(f.Cases))
}
