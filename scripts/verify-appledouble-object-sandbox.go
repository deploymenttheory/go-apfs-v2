//go:build ignore

// Run complete Go and installed C object operations inside real signed App
// Sandbox bundles. System-managed containers are restricted to disposable CI.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

const artifactDir = "artifacts/appledouble-object-sandbox"
const nativeSource = "testdata/appledouble/native/appledouble-object-sandbox.c"

type outcome struct {
	Code, Errno int
	Stage       string
	Sandboxed   bool
}
type attribute struct{ Name, Value string }
type metadata struct {
	Mode, Flags uint32
	Mtime       int64
	Nano        int64 `json:"mtime_nano"`
	Attrs       []attribute
	ACL         *string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(name string) []byte { data, err := os.ReadFile(name); must(err); return data }
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func run(args ...string) []byte {
	data, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%s: %v: %s", args[0], err, data))
	}
	return data
}
func inspect(oracle, path string) metadata {
	var value metadata
	must(json.Unmarshal(run(oracle, "inspect", path), &value))
	sort.Slice(value.Attrs, func(i, j int) bool { return value.Attrs[i].Name < value.Attrs[j].Name })
	return value
}
func main() {
	child := flag.Bool("sandbox-child", false, "internal signed operation")
	ephemeral := flag.Bool("ephemeral-runner", false, "require disposable GitHub-hosted macOS VM")
	flag.Parse()
	if *child {
		operate(flag.Args())
		return
	}
	if runtime.GOOS != "darwin" || !*ephemeral || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		panic("signed object qualification requires -ephemeral-runner on disposable GitHub-hosted macOS; never creates local App Sandbox containers")
	}
	must(os.MkdirAll(artifactDir, 0755))
	ast := map[string]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		data := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", nativeSource)
		must(os.WriteFile(filepath.Join(artifactDir, arch+".ast.json"), data, 0600))
		ast[arch] = hash(data)
	}
	oracle, err := filepath.Abs(filepath.Join(artifactDir, "oracle"))
	must(err)
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", nativeSource, "-o", oracle)
	work, err := os.MkdirTemp("", "appledouble-object-sandbox-")
	must(err)
	defer os.RemoveAll(work)
	// Canonical /private paths avoid entitlement aliases through /var symlinks.
	work, err = filepath.EvalSymlinks(work)
	must(err)
	allowed := filepath.Join(work, "allowed")
	must(os.Mkdir(allowed, 0700))
	home, err := os.UserHomeDir()
	must(err)
	denied, err := os.MkdirTemp(home, "appledouble-denied-sandbox-")
	must(err)
	defer os.RemoveAll(denied)
	self, err := os.Executable()
	must(err)
	generated := map[string]string{}
	nativeApp := sign(work, "native", oracle, allowed, generated)
	goApp := sign(work, "go", self, allowed, generated)
	var cases []map[string]any
	observe := func(binary, operation, source, target string, acl, stat bool) outcome {
		a, b := "0", "0"
		if acl {
			a = "1"
		}
		if stat {
			b = "1"
		}
		args := []string{binary}
		if binary == goApp {
			args = append(args, "-sandbox-child")
		}
		args = append(args, operation, source, target, a, b)
		var result outcome
		must(json.Unmarshal(run(args...), &result))
		if !result.Sandboxed {
			panic("operation did not enter actual sandbox")
		}
		return result
	}
	for _, acl := range []bool{false, true} {
		for _, stat := range []bool{false, true} {
			for _, fork := range []bool{false, true} {
				name := fmt.Sprintf("acl-%t-stat-%t-fork-%t", acl, stat, fork)
				dir := filepath.Join(allowed, name)
				must(os.Mkdir(dir, 0700))
				files := map[string]*os.File{}
				for _, key := range []string{"source", "go-packed", "native-packed", "go-target", "native-target"} {
					file, err := os.OpenFile(filepath.Join(dir, key), os.O_CREATE|os.O_RDWR, 0600)
					must(err)
					files[key] = file
				}
				src := files["source"]
				must(hostmeta.SetXattr(src, "user.object", []byte("sandbox fixture")))
				must(hostmeta.SetXattr(src, "user.empty", nil))
				finder := make([]byte, 32)
				copy(finder, "TEXTttxt")
				must(hostmeta.SetXattr(src, appledouble.FinderInfoName, finder))
				must(hostmeta.SetXattr(src, appledouble.QuarantineName, []byte("0080;6553f100;Fixture;")))
				if fork {
					must(hostmeta.SetXattr(src, appledouble.ResourceForkName, []byte("sandbox fork")))
				}
				held, err := hostmeta.NewHeldMetadata(src)
				must(err)
				if acl {
					must(held.SetACL(&appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}))
				}
				must(held.Chmod(0640))
				must(held.SetTimes(time.Unix(1700000000, 0), time.Unix(1700000001, 0)))
				for _, operation := range []string{"pack", "unpack"} {
					sourceGo, sourceC := src.Name(), src.Name()
					targetGo, targetC := files["go-packed"].Name(), files["native-packed"].Name()
					if operation == "unpack" {
						sourceGo, sourceC = targetGo, targetC
						targetGo, targetC = files["go-target"].Name(), files["native-target"].Name()
						for _, key := range []string{"go-target", "native-target"} {
							must(hostmeta.SetXattr(files[key], "user.stale", []byte("remove")))
							must(files[key].Chmod(0400))
							must(os.Chtimes(files[key].Name(), time.Unix(1600000000, 0), time.Unix(1600000001, 0)))
						}
					}
					expected := observe(nativeApp, operation, sourceC, targetC, acl, stat)
					actual := observe(goApp, operation, sourceGo, targetGo, acl, stat)
					if expected.Code != actual.Code || expected.Stage != actual.Stage || (expected.Code < 0 && expected.Errno != actual.Errno) {
						panic(fmt.Sprintf("%s/%s outcome mismatch native%+v Go%+v", name, operation, expected, actual))
					}
					if expected.Code != 0 {
						panic(fmt.Sprintf("scoped sandbox operation failed %s/%s: %+v", name, operation, expected))
					}
					goBytes, nativeBytes := read(targetGo), read(targetC)
					if operation == "pack" && !bytes.Equal(nativeBytes, goBytes) {
						panic(fmt.Sprintf("%s: sandbox packed bytes differ Go length=%d sha256=%s native length=%d sha256=%s", name, len(goBytes), hash(goBytes), len(nativeBytes), hash(nativeBytes)))
					}
					goMetadata, nativeMetadata := inspect(oracle, targetGo), inspect(oracle, targetC)
					if !reflect.DeepEqual(nativeMetadata, goMetadata) {
						goJSON, _ := json.Marshal(goMetadata)
						nativeJSON, _ := json.Marshal(nativeMetadata)
						panic(fmt.Sprintf("%s/%s: sandbox metadata differs Go=%s native=%s", name, operation, goJSON, nativeJSON))
					}
					cases = append(cases, map[string]any{"name": name + "/" + operation, "native": expected, "go": actual, "bytes_sha256": hash(read(targetGo)), "metadata_equal": true})
				}
				for _, file := range files {
					must(file.Close())
				}
			}
		}
	}
	// Denied acquisition is real App Sandbox enforcement, not an injected errno.
	// Both sides must report the same refusal before metadata mutation.
	for _, operation := range []string{"pack", "unpack"} {
		source, target := filepath.Join(denied, "source"), filepath.Join(allowed, "denied-target")
		must(os.WriteFile(source, []byte("denied"), 0600))
		must(os.WriteFile(target, []byte("unchanged"), 0600))
		expected := observe(nativeApp, operation, source, target, false, false)
		actual := observe(goApp, operation, source, target, false, false)
		if !reflect.DeepEqual(expected, actual) || expected.Code != -1 || expected.Stage != "open-source" || (expected.Errno != int(syscall.EACCES) && expected.Errno != int(syscall.EPERM)) {
			panic(fmt.Sprintf("sandbox denied acquisition mismatch %+v %+v", expected, actual))
		}
		if string(read(target)) != "unchanged" {
			panic("denied acquisition mutated destination")
		}
		cases = append(cases, map[string]any{"name": "denied/" + operation, "native": expected, "go": actual, "destination_unchanged": true})
	}
	if len(cases) != 18 {
		panic("incomplete signed object matrix")
	}
	hashes, err := evidenceaudit.SourceHashes(os.DirFS("."), []string{nativeSource, "testdata/appledouble/native/appledouble-object.c", "scripts/verify-appledouble-object-sandbox.go", "pkg/hostmeta/appledouble_object*.go", "pkg/hostmeta/held*.go", "pkg/hostmeta/quarantine*.go", "pkg/hostmeta/sandbox*.go", "pkg/hostmeta/xattr_intent*.go", "pkg/hostmeta/libsystem*.go", "go.mod", "go.sum"})
	must(err)
	must(os.RemoveAll(work))
	must(os.RemoveAll(denied))
	for _, path := range []string{work, denied} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			panic("sandbox fixture cleanup failed")
		}
	}
	report := map[string]any{"passed": true, "revision": strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "host": string(run("sw_vers")), "cases": cases, "source_sha256": hashes, "ast_sha256": ast, "generated_sha256": generated, "container_lifecycle": "Two unique synthetic App Sandbox containers expire with the disposable GitHub-hosted VM. Application bundles and all allowed/denied fixture data are removed before success."}
	data, err := json.MarshalIndent(report, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(artifactDir, "report.json"), data, 0600))
	fmt.Printf("Qualified %d signed sandbox object/acquisition cases\n", len(cases))
}
func operate(args []string) {
	if len(args) != 5 {
		panic("invalid child arguments")
	}
	sandboxed, err := hostmeta.CaptureAppSandbox()
	must(err)
	if !sandboxed {
		panic("child is not actually sandboxed")
	}
	result := outcome{Code: -1, Sandboxed: true}
	fail := func(stage string, err error) {
		result.Stage = stage
		var number syscall.Errno
		if !errors.As(err, &number) {
			panic(fmt.Sprintf("%s has no native errno: %v", stage, err))
		}
		result.Errno = int(number)
		must(json.NewEncoder(os.Stdout).Encode(result))
	}
	source, err := os.Open(args[1])
	if err != nil {
		fail("open-source", err)
		return
	}
	defer source.Close()
	flags := os.O_RDONLY
	if args[0] == "pack" {
		flags = os.O_RDWR
	}
	target, err := os.OpenFile(args[2], flags, 0)
	if err != nil {
		fail("open-destination", err)
		return
	}
	defer target.Close()
	a, err := hostmeta.NewHostAppleDoubleObject(context.Background(), source)
	must(err)
	b, err := hostmeta.NewHostAppleDoubleObject(context.Background(), target)
	must(err)
	var lifecycle hostmeta.HeldLifecycleResult
	if args[0] == "pack" {
		options := hostmeta.DefaultObjectPackOptions()
		options.CopyACL = args[3] == "1"
		options.Stat = args[4] == "1"
		r, e := hostmeta.PackAppleDoubleObject(context.Background(), a, b, target, options)
		lifecycle, err = r.Lifecycle, e
	} else {
		info, e := source.Stat()
		must(e)
		options := hostmeta.DefaultObjectUnpackOptions()
		options.Stat = args[4] == "1"
		r, e := hostmeta.UnpackAppleDoubleObject(context.Background(), io.NewSectionReader(source, 0, info.Size()), a, b, options)
		lifecycle, err = r.Lifecycle, e
	}
	result.Code, result.Stage = lifecycle.Code, "operation"
	if lifecycle.Code < 0 {
		fail("operation", err)
		return
	}
	must(json.NewEncoder(os.Stdout).Encode(result))
}
func sign(work, label, executable, allowed string, hashes map[string]string) string {
	id := "org.deploymenttheory.appledouble.object." + filepath.Base(work) + "." + label
	home, err := os.UserHomeDir()
	must(err)
	if _, err = os.Lstat(filepath.Join(home, "Library", "Containers", id)); !os.IsNotExist(err) {
		panic("sandbox container already exists")
	}
	contents := filepath.Join(work, label+".app", "Contents")
	must(os.MkdirAll(filepath.Join(contents, "MacOS"), 0700))
	binary := filepath.Join(contents, "MacOS", "object-probe")
	must(os.WriteFile(binary, read(executable), 0700))
	plist := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + id + `</string><key>CFBundleExecutable</key><string>object-probe</string><key>CFBundlePackageType</key><string>APPL</string><key>LSBackgroundOnly</key><true/></dict></plist>`)
	must(os.WriteFile(filepath.Join(contents, "Info.plist"), plist, 0600))
	hashes[label+"-info.plist"] = hash(plist)
	entitlement := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.temporary-exception.files.absolute-path.read-write</key><array><string>` + allowed + `/</string></array></dict></plist>`)
	path := filepath.Join(work, label+"-entitlements.plist")
	must(os.WriteFile(path, entitlement, 0600))
	hashes[label+"-entitlements.plist"] = hash(entitlement)
	run("codesign", "--force", "--sign", "-", "--entitlements", path, filepath.Dir(contents))
	return binary
}
