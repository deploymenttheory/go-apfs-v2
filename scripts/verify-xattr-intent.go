//go:build ignore

// Qualify the complete unchanged Apple xattr property policy and live selector.
package main

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	sandbox "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/sandbox"
	xattrintent "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/xattrintent"
)

const dir = "artifacts/xattr-intent"
const pin = "9f91eb6ced021952278816cdc76ad68da8631ccb"

type sample struct {
	Name                []byte
	Intent              uint32
	Sandboxed, Preserve bool
}
type evidence struct {
	Revision, Host, SDK, Compiler string
	SourceSHA256, ASTSHA256       map[string]string
	Cases                         []sample
	LiveCases                     int
	LiveSandboxed                 bool
	SandboxLiveCases              int
	ContainerLifecycle            string
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(p string) []byte { b, e := os.ReadFile(p); must(e); return b }
func run(input []byte, args ...string) []byte {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	b, e := cmd.CombinedOutput()
	if e != nil {
		panic(fmt.Sprintf("%s: %v %s", args[0], e, b))
	}
	return b
}
func main() {
	capture := flag.Bool("capture", false, "replace portable controlled source fixture")
	child := flag.Bool("sandbox-child", false, "run signed Go sandbox policy observer")
	ephemeral := flag.Bool("ephemeral-runner", false, "require GitHub-hosted disposable macOS VM; sandbox containers expire with VM teardown")
	flag.Parse()
	if *child {
		sandboxChild()
		return
	}
	if runtime.GOOS != "darwin" {
		panic("native intent qualification requires Darwin")
	}
	// macOS protects container-manager metadata from ordinary unlink, including
	// the owner. Do not create persistent containers on developer machines.
	if !*ephemeral || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		panic("signed App Sandbox qualification requires -ephemeral-runner on a disposable GitHub-hosted macOS VM; local container cleanup is not supported")
	}
	must(os.MkdirAll(filepath.Join(dir, "xpc"), 0755))
	sourceHashes := map[string]string{}
	for name, want := range map[string]string{"xattr_flags.c": "991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc", "xattr_flags.h": "0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49", "xattr_properties.h": "5be7721f4dc452af3864d15240c4afccde87cc160842c92c092d745b2ba6fe7e"} {
		url := "https://raw.githubusercontent.com/apple-oss-distributions/copyfile/" + pin + "/" + name
		client := http.Client{Timeout: 30 * time.Second}
		response, e := client.Get(url)
		must(e)
		b, e := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		must(e)
		must(response.Body.Close())
		if response.StatusCode != 200 || hash(b) != want {
			panic("Apple source pin mismatch: " + name)
		}
		must(os.WriteFile(filepath.Join(dir, name), b, 0600))
		sourceHashes[url] = want
	}
	shim := []byte("#include <stdbool.h>\nbool _xpc_runtime_is_app_sandboxed(void);\n")
	must(os.WriteFile(filepath.Join(dir, "xpc/private.h"), shim, 0600))
	sourceHashes["generated:xpc/private.h"] = hash(shim)
	source := "testdata/appledouble/native/xattr-intent.c"
	oracle := filepath.Join(dir, "oracle")
	flags := []string{"xcrun", "clang", "-std=c11", "-fblocks", "-I", dir}
	compile := append(append([]string{}, flags...), "-Wall", "-Wextra", "-Werror", source, "-o", oracle)
	run(nil, compile...)
	report := evidence{SourceSHA256: sourceHashes, ASTSHA256: map[string]string{}}
	for _, arch := range []string{"arm64", "x86_64"} {
		args := append(append([]string{}, flags...), "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		b := run(nil, args...)
		must(os.WriteFile(filepath.Join(dir, arch+".ast.json"), b, 0600))
		report.ASTSHA256[arch] = hash(b)
	}
	names := []string{"", "unknown", "com.apple.quarantine", "com.apple.ResourceFork", "com.apple.FinderInfo", "com.apple.TextEncoding", "com.apple.root.installed", "com.apple.metadata:kMDItemCollaborationIdentifier", "com.apple.metadata:kMDItemIsShared", "com.apple.metadata:kMDItemSharedItemCurrentUserRole", "com.apple.metadata:kMDItemOwnerName", "com.apple.metadata:kMDItemFavoriteRank", "com.apple.metadata:custom", "com.apple.security.custom", "com.apple.metadata:custom#", "unknown#N#S", "unknown#S\x00N", "unknown#?\xff"}
	for mask := 0; mask < 64; mask++ {
		var upper, lower strings.Builder
		for i, c := range []byte("PCNSBX") {
			if mask&(1<<i) != 0 {
				upper.WriteByte(c)
				lower.WriteByte(c + 'a' - 'A')
			}
		}
		names = append(names, "unknown#"+upper.String(), "unknown#PCNSBX"+lower.String(), "unknown#"+lower.String()+upper.String(), "com.apple.security.custom#N#"+upper.String())
	}
	var input bytes.Buffer
	var queries []sample
	for _, name := range names {
		for _, intent := range []uint32{0, 1, 2, 3, 4, 5, 99, 0xffffffff} {
			encoded := hex.EncodeToString([]byte(name))
			if encoded == "" {
				encoded = "-"
			}
			fmt.Fprintf(&input, "%d %s\n", intent, encoded)
			queries = append(queries, sample{Name: []byte(name), Intent: intent})
		}
	}
	for _, mode := range []string{"0", "1", "live"} {
		lines := strings.Fields(string(run(input.Bytes(), oracle, mode)))
		if len(lines) != len(queries)+2 || lines[0] != "sandbox" {
			panic("incomplete native intent transcript")
		}
		sandboxed := lines[1] == "1"
		if mode != "live" && sandboxed != (mode == "1") {
			panic("controlled sandbox mismatch")
		}
		if mode == "live" {
			actual, e := sandbox.CaptureAppSandbox()
			must(e)
			if actual != sandboxed {
				panic("C and Go live sandbox capture differ")
			}
			report.LiveSandboxed = sandboxed
		}
		for i, q := range queries {
			n, e := strconv.Atoi(lines[i+2])
			must(e)
			if n != 0 && n != 1 {
				panic("invalid native intent result")
			}
			q.Sandboxed = sandboxed
			q.Preserve = n == 1
			if got := xattrintent.PreserveXattrForIntent(string(q.Name), q.Intent, q.Sandboxed); got != q.Preserve {
				panic(fmt.Sprintf("intent mismatch mode%s query%d", mode, i))
			}
			if mode == "live" {
				report.LiveCases++
			} else {
				report.Cases = append(report.Cases, q)
			}
		}
	}
	// App Sandbox requires an application bundle: merely signing a bare
	// executable can fail during libsecinit before main. Observe both helpers.
	work, e := os.MkdirTemp("", "appledouble-intent-apps-")
	must(e)
	defer func() { must(os.RemoveAll(work)) }()
	var containers []string
	nativeApp := signedSandboxApp(work, "native", oracle, &containers, sourceHashes)
	self, e := os.Executable()
	must(e)
	goApp := signedSandboxApp(work, "go", self, &containers, sourceHashes)
	nativeOutput := strings.Fields(string(run(input.Bytes(), nativeApp, "live")))
	goOutput := strings.Fields(string(run(input.Bytes(), goApp, "-sandbox-child")))
	if len(nativeOutput) != len(queries)+2 || len(goOutput) != len(nativeOutput) || nativeOutput[0] != "sandbox" || nativeOutput[1] != "1" || strings.Join(nativeOutput, " ") != strings.Join(goOutput, " ") {
		panic("signed native/Go live sandbox policy mismatch")
	}
	for i, query := range queries {
		want := xattrintent.PreserveXattrForIntent(string(query.Name), query.Intent, true)
		if (nativeOutput[i+2] == "1") != want {
			panic("signed sandbox disagrees with portable policy")
		}
	}
	report.SandboxLiveCases = len(queries)
	if len(containers) != 2 {
		panic("incomplete signed application fixture set")
	}
	// Qualify temporary-bundle cleanup before publishing a successful report.
	// Protected system-managed containers have the explicit VM lifetime above.
	must(os.RemoveAll(work))
	report.ContainerLifecycle = "Two uniquely named synthetic App Sandbox containers remain under macOS container-manager ownership until this disposable GitHub-hosted VM is destroyed. Temporary application bundles are removed before successful exit."
	for _, pattern := range []string{"pkg/hostdata/*.go", "pkg/hostdata/*/*.go", "internal/hosttime/*.go", "internal/testutil/heldfixture/*.go", "pkg/hostdata/sandbox/sandbox_capture*.go", source, "scripts/verify-xattr-intent.go", "go.mod", "go.sum"} {
		paths, e := filepath.Glob(pattern)
		must(e)
		for _, p := range paths {
			report.SourceSHA256[p] = hash(read(p))
		}
	}
	report.Revision = strings.TrimSpace(string(run(nil, "git", "rev-parse", "HEAD")))
	report.Host = string(run(nil, "sw_vers"))
	report.SDK = strings.TrimSpace(string(run(nil, "xcrun", "--show-sdk-version")))
	report.Compiler = string(run(nil, "xcrun", "clang", "--version"))
	b, e := json.MarshalIndent(report, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(dir, "report.json"), b, 0600))
	if *capture {
		f, e := os.Create("testdata/appledouble/native/xattr-intent.json.gz")
		must(e)
		z := gzip.NewWriter(f)
		must(json.NewEncoder(z).Encode(report))
		must(z.Close())
		must(f.Close())
	}
	fmt.Printf("Qualified %d controlled cases, %d live cases (sandbox=%t), and %d signed native/Go sandbox cases\n", len(report.Cases), report.LiveCases, report.LiveSandboxed, report.SandboxLiveCases)
}

func sandboxChild() {
	sandboxed, err := sandbox.CaptureAppSandbox()
	must(err)
	if !sandboxed {
		panic("Go helper did not enter App Sandbox")
	}
	fmt.Println("sandbox 1")
	input := bufio.NewReader(os.Stdin)
	for {
		var intent uint32
		var name string
		_, err := fmt.Fscan(input, &intent, &name)
		if err == io.EOF {
			return
		}
		must(err)
		if name == "-" {
			name = ""
		}
		decoded, err := hex.DecodeString(name)
		must(err)
		result := 0
		if xattrintent.PreserveXattrForIntent(string(decoded), intent, sandboxed) {
			result = 1
		}
		fmt.Println(result)
	}
}

func signedSandboxApp(work, label, executable string, containers *[]string, hashes map[string]string) string {
	id := "org.deploymenttheory.appledouble.intent." + filepath.Base(work) + "." + label
	home, err := os.UserHomeDir()
	must(err)
	container := filepath.Join(home, "Library", "Containers", id)
	if _, err := os.Lstat(container); !os.IsNotExist(err) {
		panic("sandbox fixture container already exists")
	}
	*containers = append(*containers, container)
	contents := filepath.Join(work, label+".app", "Contents")
	must(os.MkdirAll(filepath.Join(contents, "MacOS"), 0700))
	binary := filepath.Join(contents, "MacOS", "intent-probe")
	must(os.WriteFile(binary, read(executable), 0700))
	plist := []byte(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>` + id + `</string><key>CFBundleExecutable</key><string>intent-probe</string><key>CFBundlePackageType</key><string>APPL</string><key>LSBackgroundOnly</key><true/></dict></plist>`)
	must(os.WriteFile(filepath.Join(contents, "Info.plist"), plist, 0600))
	must(os.WriteFile(filepath.Join(dir, label+"-info.plist"), plist, 0600))
	hashes["generated:"+label+"-info.plist"] = hash(plist)
	entitlements := []byte(`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>`)
	path := filepath.Join(work, "entitlements.plist")
	must(os.WriteFile(path, entitlements, 0600))
	must(os.WriteFile(filepath.Join(dir, "entitlements.plist"), entitlements, 0600))
	hashes["generated:entitlements.plist"] = hash(entitlements)
	run(nil, "codesign", "--force", "--sign", "-", "--entitlements", path, filepath.Dir(contents))
	return binary
}
