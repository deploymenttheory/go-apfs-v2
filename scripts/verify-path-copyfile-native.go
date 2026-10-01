//go:build ignore

// Run installed macOS copyfile on real disposable path objects, preserving
// creation/cleanup, ACL, contents, callback and explicit state-free evidence.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func main() {
	capture := flag.Bool("capture", false, "retain unapproved native observations")
	flag.Parse()
	if err := verify(*capture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(capture bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native qualification requires macOS")
	}
	const dir = "artifacts/path-copyfile-native"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	const source = "testdata/appledouble/native/path-copyfile.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		cmd := exec.Command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		ast, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("AST %s: %w %s", arch, err, stderr.String())
		}
		if err = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); err != nil {
			return err
		}
	}
	helper, err := filepath.Abs(filepath.Join(dir, "path-copyfile"))
	if err != nil {
		return err
	}
	if out, err := exec.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w %s", err, out)
	}
	if err := verifyLinkWrite(dir); err != nil {
		return err
	}
	cases := pathnative.Cases()
	for i := range cases {
		if err := observe(helper, dir, &cases[i]); err != nil {
			return fmt.Errorf("case %d (%+v): %w", i, cases[i], err)
		}
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	host, err := exec.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	helperBytes, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	fixture := pathnative.Fixture{Revision: strings.TrimSpace(string(revision)), Host: string(host), HelperSHA256: fmt.Sprintf("%x", sha256.Sum256(helperBytes)), Cases: cases}
	provider, err := os.ReadFile("testdata/appledouble/native/xattr-provider-context.h")
	if err != nil {
		return err
	}
	fixture.ProviderSHA256 = fmt.Sprintf("%x", sha256.Sum256(provider))
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "observations.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	matchedContexts, changedContexts := 0, 0
	if !capture {
		f, err := os.Open("testdata/appledouble/native/path-copyfile.json.gz")
		if err != nil {
			return err
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer z.Close()
		var approved pathnative.Fixture
		if err = json.NewDecoder(z).Decode(&approved); err != nil {
			return err
		}
		if approved.HelperSHA256 != fixture.HelperSHA256 || approved.ProviderSHA256 != fixture.ProviderSHA256 || len(approved.Cases) != len(cases) {
			return fmt.Errorf("native path helper/case inventory changed")
		}
		for i, current := range cases {
			prior := approved.Cases[i]
			currentSpec, priorSpec := current, prior
			currentSpec.Native, priorSpec.Native = pathnative.Observation{}, pathnative.Observation{}
			if !reflect.DeepEqual(currentSpec, priorSpec) {
				return fmt.Errorf("native path case %d specification changed", i)
			}
			// Caller-owned state is a separate native contract: the Go path
			// facade owns its descriptors and cannot exercise explicit free.
			// Preserve those exact assertions even if ambient xattrs differ.
			if current.Native.SourceOpenBeforeFree != prior.Native.SourceOpenBeforeFree ||
				current.Native.DestinationOpenBeforeFree != prior.Native.DestinationOpenBeforeFree ||
				current.Native.SourceClosedAfterFree != prior.Native.SourceClosedAfterFree ||
				current.Native.DestinationClosedAfterFree != prior.Native.DestinationClosedAfterFree ||
				current.Native.FreeCode != prior.Native.FreeCode || current.Native.FreeErrno != prior.Native.FreeErrno {
				return fmt.Errorf("native path case %d caller-owned state behavior changed", i)
			}
			if reflect.DeepEqual(current.Native.Input.WithoutObjectIdentity(), prior.Native.Input.WithoutObjectIdentity()) {
				matchedContexts++
				current.Native.Input, prior.Native.Input = current.Native.Input.WithoutObjectIdentity(), prior.Native.Input.WithoutObjectIdentity()
				current.Native.Output, prior.Native.Output = current.Native.Output.WithoutObjectIdentity(), prior.Native.Output.WithoutObjectIdentity()
				if !reflect.DeepEqual(current.Native, prior.Native) {
					return fmt.Errorf("native path case %d behavior changed with identical input context", i)
				}
			} else {
				changedContexts++
			}
		}
		// Every current context must pass an independent installed-C versus Go
		// comparison, including contexts different from the retained baseline.
		// The test first verifies full ordered metadata input equivalence and
		// then checks exact output bytes, callbacks and filesystem effects.
		log, err := os.Create(filepath.Join(dir, "replay.tests.jsonl"))
		if err != nil {
			return err
		}
		cmd := exec.Command("go", "test", "-json", "-count=1", "./pkg/hostdata", "-run", "^TestAppleDoublePathNativeReplay$")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, log), io.MultiWriter(os.Stderr, log)
		err = cmd.Run()
		closeErr := log.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("current-context native replay: command=%v close=%v", err, closeErr)
		}
	}
	hashes := map[string]string{}
	for _, p := range []string{source, "testdata/appledouble/native/xattr-provider-context.h", "testdata/appledouble/native/path-link-write.c", "scripts/verify-path-copyfile-native.go", "internal/testutil/pathnative/oracle.go", "internal/testutil/pathnative/removal.go", "pkg/hostdata/appledouble_path_native_test.go"} {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		hashes[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": !capture, "capture": capture, "cases": len(cases), "baseline_context_matches": matchedContexts, "baseline_context_differences": changedContexts, "current_context_differential_replay": !capture, "revision": fixture.Revision, "host": fixture.Host, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes}
	encoded, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("public path copyfile: %d cases; capture=%t\n", len(cases), capture)
	return nil
}

// The full path corpus proves failed-PACK unlink effects. This independent
// primitive probe establishes that acquiring a writable no-follow link succeeds
// and EPERM occurs at transfer, with the held link and referent unchanged.
func verifyLinkWrite(dir string) error {
	const source = "testdata/appledouble/native/path-link-write.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		out, err := exec.Command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source).Output()
		if err != nil {
			return fmt.Errorf("link write AST %s: %w", arch, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "link-write-"+arch+".ast.json"), out, 0600); err != nil {
			return err
		}
	}
	helper, err := filepath.Abs(filepath.Join(dir, "link-write"))
	if err != nil {
		return err
	}
	if out, err := exec.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper).CombinedOutput(); err != nil {
		return fmt.Errorf("link write compile: %w: %s", err, out)
	}
	out, err := exec.Command(helper).CombinedOutput()
	if err != nil {
		return fmt.Errorf("native link write: %w: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "link-write.json"), out, 0600); err != nil {
		return err
	}
	var observation struct {
		Cases []struct {
			Dangling, IdentityPreserved, ReferentUnchanged                      bool
			OpenErrno, HeldMode, AccessMode, WriteCount, WriteErrno, CloseErrno int
		}
		CleanupVerified bool
	}
	if err := json.Unmarshal(out, &observation); err != nil {
		return err
	}
	if len(observation.Cases) != 2 || !observation.CleanupVerified {
		return fmt.Errorf("incomplete native link-write evidence: %s", out)
	}
	for i, c := range observation.Cases {
		if c.Dangling != (i == 1) || !c.IdentityPreserved || !c.ReferentUnchanged || c.OpenErrno != 0 || c.HeldMode&0170000 != 0120000 || c.AccessMode != 1 || c.WriteCount != -1 || c.WriteErrno != 1 || c.CloseErrno != 0 {
			return fmt.Errorf("native nofollow link-write behavior changed: %+v", c)
		}
	}
	return nil
}

func observe(helper, dir string, c *pathnative.Case) error {
	root, err := os.MkdirTemp(dir, "case-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	src, dst, target := filepath.Join(root, "source"), filepath.Join(root, "destination"), filepath.Join(root, "target")
	if err = os.WriteFile(target, []byte("TARGET"), 0440); err != nil {
		return err
	}
	data := []byte("SOURCE")
	if c.Route == 1 {
		data, err = (&appledouble.File{Attrs: []appledouble.Attr{{Name: "com.example.path", Value: []byte("source")}}}).Encode()
		if err != nil {
			return err
		}
	}
	kind := c.SourceKind
	if c.Route == 1 && kind == 1 {
		data = data[:len(data)-1]
		kind = 0
	} else if c.Route == 1 && kind > 1 {
		kind--
	}
	switch kind {
	case 0:
		err = os.WriteFile(src, data, 0440)
	case 1:
		err = os.Mkdir(src, 0550)
	case 2:
		err = os.WriteFile(filepath.Join(root, "source-target"), data, 0440)
		if err == nil {
			err = os.Symlink("source-target", src)
		}
	case 3:
		err = os.Symlink("missing-source", src)
	}
	if err != nil {
		return err
	}
	switch c.DestinationKind {
	case 1:
		err = os.WriteFile(dst, []byte("DESTINATION"), 0400)
	case 2:
		err = os.Mkdir(dst, 0500)
	case 3:
		err = os.Symlink("target", dst)
	case 4:
		err = os.Symlink("missing-destination", dst)
	}
	if err != nil {
		return err
	}
	if c.NullSource {
		src = os.DevNull
	}
	mask := -1
	if c.SetUmask {
		mask = c.Umask
	}
	cmd := exec.Command(helper, src, dst, target, strconv.Itoa(c.Route), strconv.Itoa(c.Selected), strconv.Itoa(c.Quit), strconv.Itoa(c.SourceMode), strconv.Itoa(mask))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("helper: %w %s %s", err, stderr.String(), out)
	}
	if err = json.Unmarshal(out, &c.Native); err != nil {
		return fmt.Errorf("decode: %w %s", err, out)
	}
	if st, err := os.Lstat(dst); err == nil && st.Mode().IsRegular() {
		b, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		c.Native.DestinationSHA256 = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	return nil
}
