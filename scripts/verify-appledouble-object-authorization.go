//go:build ignore

// Verify held-descriptor authorization using real root and nonowner processes.
// Run on disposable macOS CI with passwordless sudo; no account is created.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

const artifactDir = "artifacts/appledouble-object-authorization"
const cSource = "testdata/appledouble/native/appledouble-object.c"

type result struct {
	Code, Errno int
	UID         uint32 `json:"uid"`
	EUID        uint32 `json:"euid"`
}
type attr struct{ Name, Value string }
type metadata struct {
	Mode, Flags uint32
	Mtime       int64
	Nano        int64 `json:"mtime_nano"`
	Attrs       []attr
	ACL         *string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func run(args ...string) []byte {
	b, e := exec.Command(args[0], args[1:]...).CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s: %v: %s", args[0], e, b))
	}
	return b
}
func hash(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(path string) []byte { b, e := os.ReadFile(path); must(e); return b }
func emit(value any)          { must(json.NewEncoder(os.Stdout).Encode(value)) }
func main() {
	supervisor := flag.Bool("supervisor", false, "internal root fixture supervisor")
	operation := flag.String("child-operation", "", "internal credential-constrained held operation")
	stat := flag.Bool("stat", false, "inner route stat option")
	oracle := flag.String("oracle", "", "compiled independent native observer")
	flag.Parse()
	if runtime.GOOS != "darwin" {
		panic("live authorization qualification requires macOS")
	}
	if *operation != "" {
		child(*operation, *stat)
		return
	}
	if *supervisor {
		if os.Getuid() != 0 || os.Geteuid() != 0 {
			panic("supervisor requires actual root")
		}
		supervise(*oracle)
		return
	}
	// Fail before fixture creation; never prompt or turn authorization into a skip.
	run("sudo", "-n", "true")
	must(os.MkdirAll(artifactDir, 0755))
	ast := map[string]string{}
	for _, arch := range []string{"arm64", "x86_64"} {
		b := run("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", cSource)
		must(os.WriteFile(filepath.Join(artifactDir, arch+".ast.json"), b, 0600))
		ast[arch] = hash(b)
	}
	native, e := filepath.Abs(filepath.Join(artifactDir, "oracle"))
	must(e)
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", cSource, "-o", native)
	self, e := os.Executable()
	must(e)
	output := run("sudo", "-n", self, "-supervisor", "-oracle", native)
	var cases []map[string]any
	must(json.Unmarshal(output, &cases))
	if len(cases) != 16 {
		panic("incomplete authorization matrix")
	}
	hashes, e := evidenceaudit.SourceHashes(os.DirFS("."), []string{cSource, "scripts/verify-appledouble-object-authorization.go", "pkg/hostmeta/*.go", "pkg/hostmeta/held_lifecycle*.go", "pkg/hostmeta/held_metadata*.go", "pkg/hostmeta/appledouble_pack*.go", "pkg/hostmeta/appledouble_sequential*.go", "pkg/hostmeta/quarantine_file*.go", "go.mod", "go.sum"})
	must(e)
	report := map[string]any{"revision": strings.TrimSpace(string(run("git", "rev-parse", "HEAD"))), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "ast_sha256": ast, "cases": cases, "passed": true, "sdk": strings.TrimSpace(string(run("xcrun", "--show-sdk-version"))), "host": string(run("sw_vers")), "compiler": string(run("xcrun", "clang", "--version")), "authorization": "actual root and existing nobody UID; held descriptors acquired before credential drop; supplementary groups cleared; no account mutation"}
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(artifactDir, "report.json"), b, 0600))
	fmt.Printf("Qualified %d root/nonowner held-descriptor cases\n", len(cases))
}
func child(operation string, stat bool) {
	source, target := os.NewFile(3, "source"), os.NewFile(4, "target")
	if source == nil || target == nil {
		panic("missing inherited descriptors")
	}
	defer source.Close()
	defer target.Close()
	a, e := hostmeta.NewHostAppleDoubleObject(context.Background(), source)
	must(e)
	b, e := hostmeta.NewHostAppleDoubleObject(context.Background(), target)
	must(e)
	var lifecycle hostmeta.HeldLifecycleResult
	var operationErr error
	if operation == "pack" {
		opts := hostmeta.DefaultObjectPackOptions()
		opts.Stat = stat
		r, err := hostmeta.PackAppleDoubleObject(context.Background(), a, b, target, opts)
		operationErr = err
		lifecycle = r.Lifecycle
	} else if operation == "unpack" {
		s, err := source.Stat()
		must(err)
		opts := hostmeta.DefaultObjectUnpackOptions()
		opts.Stat = stat
		r, err := hostmeta.UnpackAppleDoubleObject(context.Background(), io.NewSectionReader(source, 0, s.Size()), a, b, opts)
		operationErr = err
		lifecycle = r.Lifecycle
	} else {
		panic("unknown child operation")
	}
	out := result{Code: lifecycle.Code, UID: uint32(os.Getuid()), EUID: uint32(os.Geteuid())}
	if out.Code < 0 {
		var nativeErrno syscall.Errno
		if errors.As(operationErr, &nativeErrno) {
			out.Errno = int(nativeErrno)
		}
		for _, step := range lifecycle.Steps {
			if step.Operation == "route" {
				var errno syscall.Errno
				if errors.As(step.Err, &errno) {
					out.Errno = int(errno)
				}
			}
		}
		if out.Errno == 0 {
			panic(fmt.Sprintf("failed operation without native errno: %v", operationErr))
		}
	} else {
		must(operationErr)
	}
	emit(out)
}
func invoke(binary string, args []string, uid, gid uint32, source, target *os.File) result {
	command := exec.Command(binary, args...)
	command.ExtraFiles = []*os.File{source, target}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	b, e := command.CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("credential child uid=%d: %v: %s", uid, e, b))
	}
	var out result
	must(json.Unmarshal(b, &out))
	if out.UID != uid || out.EUID != uid {
		panic("child credential mismatch")
	}
	return out
}
func inspect(oracle, path string) metadata {
	var s metadata
	must(json.Unmarshal(run(oracle, "inspect", path), &s))
	sort.Slice(s.Attrs, func(i, j int) bool { return s.Attrs[i].Name < s.Attrs[j].Name })
	return s
}
func supervise(oracle string) {
	uid, e := strconv.ParseUint(strings.TrimSpace(string(run("id", "-u", "nobody"))), 10, 32)
	must(e)
	gid, e := strconv.ParseUint(strings.TrimSpace(string(run("id", "-g", "nobody"))), 10, 32)
	must(e)
	if uid == 0 || gid == 0 {
		panic("nonowner fixture identity unexpectedly privileged")
	}
	work, e := os.MkdirTemp("/private/tmp", "appledouble-authorization-")
	must(e)
	must(os.Chmod(work, 0755))
	defer func() { must(os.RemoveAll(work)) }()
	self, e := os.Executable()
	must(e)
	childPath := filepath.Join(work, "go-observer")
	must(os.WriteFile(childPath, read(self), 0755))
	native := filepath.Join(work, "native-observer")
	must(os.WriteFile(native, read(oracle), 0755))
	cases := []map[string]any{}
	for _, identity := range []struct {
		name     string
		uid, gid uint32
	}{{"root", 0, 0}, {"nonowner", uint32(uid), uint32(gid)}} {
		for _, operation := range []string{"pack", "unpack"} {
			for _, mode := range []os.FileMode{0400, 0666} {
				for _, stat := range []bool{false, true} {
					name := fmt.Sprintf("%s-%s-mode%o-stat%t", identity.name, operation, mode, stat)
					dir := filepath.Join(work, name)
					must(os.Mkdir(dir, 0755))
					files := map[string]*os.File{}
					for _, key := range []string{"source", "wire", "go-target", "native-target"} {
						f, e := os.OpenFile(filepath.Join(dir, key), os.O_CREATE|os.O_RDWR, 0600)
						must(e)
						files[key] = f
					}
					source := files["source"]
					must(hostmeta.SetXattr(source, "user.authorization", []byte("fixed owner fixture")))
					must(hostmeta.SetXattr(source, appledouble.ResourceForkName, []byte("fixed fork")))
					must(source.Chmod(0644))
					must(os.Chtimes(source.Name(), time.Unix(1700000000, 0), time.Unix(1700000001, 0)))
					statArg := "0"
					if stat {
						statArg = "1"
					}
					if operation == "unpack" {
						baseline := invoke(native, []string{"fd-pack", "0", "1"}, 0, 0, source, files["wire"])
						if baseline.Code != 0 {
							panic("root baseline pack failed")
						}
						source = files["wire"]
					}
					for _, key := range []string{"go-target", "native-target"} {
						f := files[key]
						must(hostmeta.SetXattr(f, "user.stale", []byte("stale fixture")))
						must(hostmeta.SetXattr(f, appledouble.ResourceForkName, []byte("old fork with suffix")))
						must(f.Chmod(mode))
						must(os.Chtimes(f.Name(), time.Unix(1600000000, 0), time.Unix(1600000001, 0)))
					}
					goStart := time.Now().UTC()
					actual := invoke(childPath, []string{"-child-operation", operation, "-stat=" + strconv.FormatBool(stat)}, identity.uid, identity.gid, source, files["go-target"])
					goEnd := time.Now().UTC()
					nativeStart := time.Now().UTC()
					expected := invoke(native, []string{"fd-" + operation, "0", statArg}, identity.uid, identity.gid, source, files["native-target"])
					nativeEnd := time.Now().UTC()
					if actual.Code != expected.Code || (actual.Code < 0 && actual.Errno != expected.Errno) {
						panic(fmt.Sprintf("%s: result differs Go=%+v native=%+v", name, actual, expected))
					}
					goMetadata, nativeMetadata := inspect(native, files["go-target"].Name()), inspect(native, files["native-target"].Name())
					goComparable, nativeComparable := goMetadata, nativeMetadata
					timestampPolicy := "exact source or unchanged destination timestamp"
					if identity.uid != 0 && operation == "pack" {
						// Inherited writable descriptors permit PACK data writes, but a
						// nonowner cannot install the root-owned source's fixed mtime.
						// Native observation retains each operation's actual write time.
						// Check both independently against their own invocation bounds;
						// neither the old destination nor source timestamp may pass.
						for _, observation := range []struct {
							label      string
							metadata   metadata
							start, end time.Time
						}{{"Go", goMetadata, goStart, goEnd}, {"native", nativeMetadata, nativeStart, nativeEnd}} {
							stamp := time.Unix(observation.metadata.Mtime, observation.metadata.Nano)
							if observation.metadata.Nano < 0 || observation.metadata.Nano >= int64(time.Second) || observation.end.Before(observation.start) || stamp.Before(observation.start) || stamp.After(observation.end) {
								panic(fmt.Sprintf("%s: %s write timestamp %s outside actual invocation [%s, %s]", name, observation.label, stamp.Format(time.RFC3339Nano), observation.start.Format(time.RFC3339Nano), observation.end.Format(time.RFC3339Nano)))
							}
						}
						timestampPolicy = "each nonowner PACK mtime strictly within its own recorded invocation"
						goComparable.Mtime, goComparable.Nano = 0, 0
						nativeComparable.Mtime, nativeComparable.Nano = 0, 0
					}
					if !reflect.DeepEqual(goComparable, nativeComparable) {
						goJSON, _ := json.Marshal(goMetadata)
						nativeJSON, _ := json.Marshal(nativeMetadata)
						panic(fmt.Sprintf("%s: independently observed destination metadata differs Go=%s native=%s", name, goJSON, nativeJSON))
					}
					goBytes, nativeBytes := read(files["go-target"].Name()), read(files["native-target"].Name())
					if !bytes.Equal(goBytes, nativeBytes) {
						panic(fmt.Sprintf("%s: output bytes differ Go length=%d sha256=%s native length=%d sha256=%s", name, len(goBytes), hash(goBytes), len(nativeBytes), hash(nativeBytes)))
					}
					for _, f := range files {
						must(f.Close())
					}
					cases = append(cases, map[string]any{"name": name, "code": actual.Code, "failure_errno": actual.Errno, "output_sha256": hash(goBytes), "metadata_equivalent": true, "non_timestamp_metadata_equal": true, "verified_real_uid": identity.uid,
						"timestamp_policy": timestampPolicy, "go_metadata": goMetadata, "native_metadata": nativeMetadata,
						"go_invocation_start": goStart, "go_invocation_end": goEnd, "native_invocation_start": nativeStart, "native_invocation_end": nativeEnd})
				}
			}
		}
	}
	must(os.RemoveAll(work))
	emit(cases)
}
