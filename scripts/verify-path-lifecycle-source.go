//go:build ignore

// Retain full pinned path lifecycle bodies and both SDK ASTs. This is a source
// qualification gate; execution evidence lives in separate native harnesses.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	source := flag.String("source", "", "optional pinned copyfile source cache")
	flag.Parse()
	if err := verify(*source); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(cache string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("SDK AST qualification requires macOS")
	}
	const dir = "artifacts/path-lifecycle-source"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	read := func(url, cache string) ([]byte, error) {
		if cache != "" {
			return os.ReadFile(cache)
		}
		client := http.Client{Timeout: 60 * time.Second}
		r, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("source HTTP %d", r.StatusCode)
		}
		return io.ReadAll(io.LimitReader(r.Body, 2<<20))
	}
	source, err := read("https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/copyfile.c", cache)
	if err != nil {
		return err
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(source))
	if sum != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		return fmt.Errorf("copyfile hash %s", sum)
	}
	if err = os.WriteFile(filepath.Join(dir, "copyfile.c"), source, 0600); err != nil {
		return err
	}
	license := bytes.Index(source, []byte("#include"))
	if license < 0 {
		return fmt.Errorf("license boundary")
	}
	extracted := bytes.Clone(source[:license])
	for _, bounds := range [][2]string{
		{"enum cfInternalFlags {", "\n#define GET_PROT_CLASS"},
		{"static int\nacl_compare_permset_np(acl_permset_t p1, acl_permset_t p2)", "\n\nstatic int\ndoesdecmpfs"},
		{"static int\nfd_volume_has_feature(int fd, long mnt_flag)", "\nstatic void\nsort_xattrname_list"},
		{"static int\nadd_uberace(acl_t *acl)", "\n/*\n * copytree --"},
		{"static bool copyfile_paths_identical(const char *src, const char *dst)", "\n/*\n * Used to clear out the BSD/POSIX"},
		{"static int copyfile_open(copyfile_state_t s)", "\n\n/*\n * copyfile_check(),"},
	} {
		start := bytes.Index(source, []byte(bounds[0]))
		if start < 0 {
			return fmt.Errorf("missing start %s", bounds[0])
		}
		end := bytes.Index(source[start:], []byte(bounds[1]))
		if end < 0 {
			return fmt.Errorf("missing end %s", bounds[1])
		}
		extracted = append(extracted, source[start:start+end]...)
		extracted = append(extracted, '\n')
	}
	if err = os.WriteFile(filepath.Join(dir, "path-lifecycle-source.h"), extracted, 0600); err != nil {
		return err
	}
	for _, item := range []struct{ path, hash string }{
		{"libsyscall/wrappers/open_dprotected_np.c", "97edddddaeead17d09bc6d609b4a48f4fd860a893c44d9a8189b2755391fd0a2"},
		{"bsd/sys/content_protection.h", "bb5bfccb8e088060d439708f82aa579f62fc50f26a1b1cbbe015f231dffeb393"},
	} {
		data, err := read("https://raw.githubusercontent.com/apple-oss-distributions/xnu/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/"+item.path, "")
		if err != nil {
			return err
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != item.hash {
			return fmt.Errorf("%s hash %s", item.path, got)
		}
		if err = os.WriteFile(filepath.Join(dir, filepath.Base(item.path)), data, 0600); err != nil {
			return err
		}
	}
	const helper = "testdata/appledouble/native/path-lifecycle-ast.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		cmd := exec.Command("xcrun", "clang", "-arch", arch, "-I", dir, "-fsyntax-only", "-Xclang", "-ast-dump=json", helper)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		ast, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("%s AST: %w %s", arch, err, stderr.String())
		}
		if err = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); err != nil {
			return err
		}
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	hashes := map[string]string{}
	for _, path := range []string{helper, "scripts/verify-path-lifecycle-source.go"} {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		hashes[path] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": true, "evidence": "source-and-sdk-ast-only", "revision": strings.TrimSpace(string(revision)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "copyfile_sha256": sum, "source_sha256": hashes}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	fmt.Println("complete path lifecycle source and arm64/x86_64 SDK ASTs verified")
	return nil
}
