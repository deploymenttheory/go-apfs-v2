//go:build ignore

// Record actual filesystem removal effects under explicit source-system
// contexts; replay never infers a policy from an attribute's name.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/pathnative"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func main() {
	capture := flag.Bool("capture", false, "retain unapproved native provider observations")
	flag.Parse()
	if err := verify(*capture); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verify(capture bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native removal evidence requires macOS")
	}
	const dir = "artifacts/xattr-remove-effects-native"
	const source = "testdata/appledouble/native/xattr-remove-effects.c"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		out, err := cirunner.Command("xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source).Output()
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, arch+".ast.json"), out, 0600); err != nil {
			return err
		}
	}
	helper, err := filepath.Abs(filepath.Join(dir, "probe"))
	if err != nil {
		return err
	}
	if out, err := cirunner.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-o", helper).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w: %s", err, out)
	}
	fixture := pathnative.RemovalFixture{}
	owned, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, operation := range []string{"remove", "write"} {
		for _, mode := range []int{0400, 0500, 0600, 0700, 0640, 0644, 0755, 0440, 0660} {
			for _, directory := range []int{0, 1, 2, 3} {
				for _, acl := range []int{0, 1, 2} {
					for _, access := range []int{0, 2} {
						// The retained path corpus uses held read-only links at
						// mode0755, including both valid and dangling referents.
						if directory >= 2 && (mode != 0755 || access != 0) {
							continue
						}
						out, err := cirunner.Command(helper, strconv.Itoa(directory), strconv.FormatInt(int64(mode), 8), strconv.Itoa(acl), strconv.Itoa(access), owned, operation).CombinedOutput()
						if err != nil {
							return fmt.Errorf("mode%o dir%d ACL%d access%d: %w: %s", mode, directory, acl, access, err, out)
						}
						var c pathnative.RemovalCase
						if err = json.Unmarshal(out, &c); err != nil {
							return err
						}
						if c.Operation != operation || c.Directory != (directory == 1) || c.Symlink != (directory >= 2) || c.Dangling != (directory == 3) || c.RequestedMode != mode || c.ACLKind != acl || c.RequestedAccess != access || !c.CleanupVerified || c.BeforeContext != c.AfterContext {
							return fmt.Errorf("native removal context or cleanup changed: %+v", c)
						}
						if c.BeforeContext.Mode&0777 != uint32(mode) || c.BeforeContext.Device == 0 || c.BeforeContext.Inode == 0 || c.BeforeContext.FileSystem == "" {
							return fmt.Errorf("incomplete context: %+v", c)
						}
						if c.OpenErrno == 0 {
							if c.BeforeContext.OpenFlags&3 != access {
								return fmt.Errorf("descriptor access changed")
							}
							names, err := hex.DecodeString(c.NamesHex)
							if err != nil {
								return err
							}
							var listed []string
							for len(names) > 0 {
								at := bytes.IndexByte(names, 0)
								if at < 0 {
									return fmt.Errorf("unterminated attribute list")
								}
								listed = append(listed, hex.EncodeToString(names[:at]))
								names = names[at+1:]
							}
							if len(listed) != len(c.Operations) || len(listed) == 0 {
								return fmt.Errorf("incomplete removal operations")
							}
							for i, op := range c.Operations {
								wantInput := ""
								if operation == "write" {
									wantInput = hex.EncodeToString([]byte("replacement"))
								}
								if op.InputHex != wantInput {
									return fmt.Errorf("native write input changed: %+v", op)
								}
								if op.NameHex != listed[i] || (op.Code != 0 && op.Code != -1) || (op.Code == 0 && op.Errno != 0) || (op.Code == -1 && op.Errno == 0) {
									return fmt.Errorf("invalid removal result: %+v", op)
								}
								for _, v := range []pathnative.RemovalValue{op.Before, op.After} {
									data, err := hex.DecodeString(v.Hex)
									if err != nil {
										return err
									}
									if v.Read >= 0 && (len(data) != v.Read || v.ReadErrno != 0) || v.Size >= 0 && v.SizeErrno != 0 {
										return fmt.Errorf("invalid native readback: %+v", v)
									}
								}
							}
						} else if c.OpenErrno != 13 && c.OpenErrno != 1 && !(directory == 1 && access == 2 && c.OpenErrno == 21) || len(c.Operations) != 0 {
							return fmt.Errorf("unexpected acquisition result: %+v", c)
						}
						fixture.Cases = append(fixture.Cases, c)
					}
				}
			}
		}
	}
	if len(fixture.Cases) != 228 {
		return fmt.Errorf("incomplete context matrix: %d", len(fixture.Cases))
	}
	revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	host, err := cirunner.Command("sw_vers").Output()
	if err != nil {
		return err
	}
	helperBytes, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	fixture.Revision, fixture.Host, fixture.HelperSHA256 = strings.TrimSpace(string(revision)), string(host), fmt.Sprintf("%x", sha256.Sum256(helperBytes))
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
	matches, differences := 0, 0
	if !capture {
		f, err := os.Open("testdata/appledouble/native/xattr-remove-effects.json.gz")
		if err != nil {
			return err
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer z.Close()
		var prior pathnative.RemovalFixture
		if err = json.NewDecoder(z).Decode(&prior); err != nil {
			return err
		}
		if prior.HelperSHA256 != fixture.HelperSHA256 || prior.ProviderSHA256 != fixture.ProviderSHA256 || len(prior.Cases) != len(fixture.Cases) {
			return fmt.Errorf("retained removal source/inventory changed")
		}
		for i, c := range fixture.Cases {
			p := prior.Cases[i]
			if c.Operation != p.Operation || c.Directory != p.Directory || c.Symlink != p.Symlink || c.Dangling != p.Dangling || c.RequestedMode != p.RequestedMode || c.ACLKind != p.ACLKind || c.RequestedAccess != p.RequestedAccess {
				return fmt.Errorf("retained removal input changed")
			}
			a, b := c.BeforeContext, p.BeforeContext
			a.Device, a.Inode, b.Device, b.Inode = 0, 0, 0, 0
			same := a == b && c.OpenErrno == p.OpenErrno && c.NamesHex == p.NamesHex && len(c.Operations) == len(p.Operations)
			if same {
				for j := range c.Operations {
					if c.Operations[j].Before != p.Operations[j].Before {
						same = false
					}
				}
			}
			if same {
				matches++
				if !reflect.DeepEqual(c.Operations, p.Operations) {
					return fmt.Errorf("native removal effect changed for matched context %d", i)
				}
			} else {
				differences++
			}
		}
		current, err := filepath.Abs(filepath.Join(dir, "observations.json"))
		if err != nil {
			return err
		}
		log, err := os.Create(filepath.Join(dir, "replay.tests.jsonl"))
		if err != nil {
			return err
		}
		cmd := cirunner.Command("go", "test", "-json", "-count=1", "./pkg/hostdata", "-run", "^TestPathCapturedMutationNativeObservations$")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "APPLEDOUBLE_MUTATION_FIXTURE="+current)
		var transcript bytes.Buffer
		cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, log, &transcript), io.MultiWriter(os.Stderr, log)
		runErr, closeErr := cmd.Run(), log.Close()
		if runErr != nil || closeErr != nil {
			return fmt.Errorf("current provider replay: command=%v close=%v", runErr, closeErr)
		}
		passed := false
		for _, line := range bytes.Split(transcript.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var event struct{ Action, Test string }
			if err := json.Unmarshal(line, &event); err != nil {
				return err
			}
			if event.Action == "skip" {
				return fmt.Errorf("provider replay skipped: %s", event.Test)
			}
			if event.Action == "pass" && event.Test == "TestPathCapturedMutationNativeObservations" {
				passed = true
			}
		}
		if !passed {
			return fmt.Errorf("current provider replay test did not execute")
		}
	}
	hashes := map[string]string{}
	for _, p := range []string{source, "testdata/appledouble/native/xattr-provider-context.h", "scripts/verify-xattr-remove-effects-native.go", "internal/testutil/pathnative/removal.go"} {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		hashes[p] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	report := map[string]any{"passed": !capture, "capture": capture, "cases": len(fixture.Cases), "baseline_context_matches": matches, "baseline_context_differences": differences, "revision": fixture.Revision, "host": fixture.Host, "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes}
	encoded, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(encoded, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("Native xattr removal: %d explicit contexts; capture=%t, baseline matches=%d differences=%d\n", len(fixture.Cases), capture, matches, differences)
	return nil
}
