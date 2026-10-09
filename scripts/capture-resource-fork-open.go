//go:build ignore

// Capture real resource-fork opening routes; retain every success and failure.
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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type forkCase struct {
	Filesystem, Method, State, Access string
	Observation                       json.RawMessage
}
type forkCapture struct {
	Schema              int
	Host, Compiler, SDK string
	Sources             map[string]string
	Cases               []forkCase
}

const forkArtifact = "artifacts/resource-fork-open"

func forkCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", filepath.Join(forkArtifact, "native.json.gz"), "fresh complete observations")
	check := flag.Bool("check", false, "compare a retained profile after saving fresh evidence")
	flag.Parse()
	if e := captureFork(*out, *check); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func captureFork(out string, check bool) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native resource fork capture requires macOS")
	}
	host, e := forkCommand("sw_vers")
	if e != nil {
		return e
	}
	version, e := osversion.ParseProductVersion(string(host))
	if e != nil {
		return e
	}
	profile, e := osversion.ProfileForMacOS(version)
	if e != nil {
		return e
	}
	baseline := fmt.Sprintf("testdata/appledouble/native/resource-fork-open-macos%d.json.gz", profile)
	if check {
		destination, e := filepath.Abs(out)
		if e != nil {
			return e
		}
		for _, p := range []osversion.MacOSProfile{osversion.MacOS15, osversion.MacOS26, osversion.MacOS27} {
			retained, e := filepath.Abs(fmt.Sprintf("testdata/appledouble/native/resource-fork-open-macos%d.json.gz", p))
			if e != nil {
				return e
			}
			if destination == retained {
				return errors.New("check cannot overwrite a native baseline")
			}
		}
	}
	if e = os.MkdirAll(forkArtifact, 0755); e != nil {
		return e
	}
	root, e := os.MkdirTemp("", "resource-fork-open-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(root)) }()
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return e
	}
	corpus := forkCapture{Schema: 1, Host: string(host), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), filepath.Dir(out), corpus.Sources); err != nil {
		return err
	}
	for _, item := range []struct {
		args []string
		dst  *string
	}{{[]string{"clang", "--version"}, &corpus.Compiler}, {[]string{"--show-sdk-version"}, &corpus.SDK}} {
		b, e := forkCommand("xcrun", item.args...)
		if e != nil {
			return e
		}
		*item.dst = string(b)
	}
	hash := func(name string, b []byte) { corpus.Sources[name] = fmt.Sprintf("%x", sha256.Sum256(b)) }
	const source = "testdata/appledouble/native/resource-fork-open.c"
	for _, name := range []string{source, "scripts/capture-resource-fork-open.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		hash(name, b)
	}
	sdk, e := forkCommand("xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	for _, header := range []string{"sys/fcntl.h", "sys/stat.h", "sys/mount.h", "sys/xattr.h"} {
		name := filepath.Join(strings.TrimSpace(string(sdk)), "usr/include", header)
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		hash(name, b)
	}
	helper := filepath.Join(root, "oracle")
	if _, e = forkCommand("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper); e != nil {
		return e
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := forkCommand("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("CompoundStmt")) {
			return errors.New("incomplete resource fork AST")
		}
		name := arch + "-resource-fork-open.c.ast.json"
		hash(name, b)
		if e = os.WriteFile(filepath.Join(forkArtifact, name), b, 0600); e != nil {
			return e
		}
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		if e = captureForkVolume(root, helper, filesystem, &corpus); e != nil {
			return e
		}
	}
	if len(corpus.Cases) != 180 {
		return fmt.Errorf("incomplete fork inventory: %d", len(corpus.Cases))
	}
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	if e = errors.Join(json.NewEncoder(z).Encode(corpus), z.Close(), f.Close()); e != nil {
		return e
	}
	if check {
		f, e := os.Open(baseline)
		if e != nil {
			return e
		}
		defer f.Close()
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		var prior forkCapture
		if e = json.NewDecoder(z).Decode(&prior); e != nil {
			return e
		}
		if err := captureprovenance.VerifyReference(os.DirFS("."), prior.Sources); err != nil {
			return err
		}
		version, e := osversion.ParseProductVersion(prior.Host)
		if e != nil {
			return e
		}
		oldProfile, e := osversion.ProfileForMacOS(version)
		if e != nil || oldProfile != profile || prior.Schema != corpus.Schema || len(prior.Cases) != len(corpus.Cases) {
			return errors.New("native fork profile/inventory mismatch")
		}
		for i, c := range corpus.Cases {
			a, e := json.Marshal(prior.Cases[i])
			if e != nil {
				return e
			}
			b, e := json.Marshal(c)
			if e != nil {
				return e
			}
			if !bytes.Equal(a, b) {
				return fmt.Errorf("native fork case differs %d (%s/%s/%s/%s); fresh evidence: %s", i, c.Filesystem, c.Method, c.State, c.Access, out)
			}
		}
	}
	fmt.Printf("Native resource-fork opening: %d cases on macOS %s across host/APFS/HFS+\n", len(corpus.Cases), version)
	return nil
}
func captureForkVolume(root, helper, filesystem string, corpus *forkCapture) (result error) {
	mount := filepath.Join(root, filesystem)
	if e := os.Mkdir(mount, 0700); e != nil {
		return e
	}
	if filesystem != "host" {
		image := filepath.Join(root, filesystem+".dmg")
		if _, e := forkCommand("hdiutil", "create", "-size", "256m", "-fs", filesystem, "-volname", "ResourceForkOpen", image); e != nil {
			return e
		}
		attached, e := forkCommand("hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
		if e != nil {
			return e
		}
		device, e := diskimage.AttachmentDevice(attached)
		if e != nil {
			_, cleanup := forkCommand("hdiutil", "detach", mount)
			return errors.Join(e, cleanup)
		}
		defer func() {
			var attempts []map[string]any
			err := diskimage.RetryDetach(context.Background(), func() (int, error) {
				output, err := forkCommand("hdiutil", "detach", device)
				code := 0
				if err != nil {
					code = -1
					var exit *exec.ExitError
					if errors.As(err, &exit) {
						code = exit.ExitCode()
					}
				}
				attempts = append(attempts, map[string]any{"device": device, "exit": code, "output": string(output)})
				return code, err
			})
			b, encode := json.MarshalIndent(attempts, "", "  ")
			result = errors.Join(result, err, encode, os.WriteFile(filepath.Join(forkArtifact, filesystem+"-detach.json"), b, 0600))
		}()
		if e = os.WriteFile(filepath.Join(forkArtifact, filesystem+"-attach.plist"), attached, 0600); e != nil {
			return e
		}
	}
	for _, method := range []string{"path", "openat", "openfrom", "devfd", "volfs", "getpath"} {
		for _, state := range []string{"live", "renamed", "replaced", "unlinked", "empty"} {
			for _, access := range []string{"read", "write"} {
				dir, e := os.MkdirTemp(mount, "case-")
				if e != nil {
					return e
				}
				b, e := forkCommand(helper, method, state, access, dir)
				if e != nil {
					return e
				}
				if !json.Valid(b) {
					return errors.New("invalid native fork observation")
				}
				corpus.Cases = append(corpus.Cases, forkCase{filesystem, method, state, access, json.RawMessage(bytes.TrimSpace(b))})
				if e = os.RemoveAll(dir); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
