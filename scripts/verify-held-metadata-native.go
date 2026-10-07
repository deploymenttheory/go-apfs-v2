//go:build ignore

// Retain SDK ABI evidence and independent native held-descriptor readbacks.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type observation struct {
	UID        uint32             `json:"uid"`
	GID        uint32             `json:"gid"`
	Mode       uint32             `json:"mode"`
	Flags      uint32             `json:"flags"`
	Times      []int64            `json:"times"`
	Properties map[string]*string `json:"properties"`
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func verify() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native qualification requires Darwin")
	}
	dir := "artifacts/held-metadata-native"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	sdk, err := cirunner.Command("xcrun", "--show-sdk-path").Output()
	if err != nil {
		return err
	}
	source := "testdata/appledouble/native/held-metadata.c"
	for _, arch := range []string{"arm64", "x86_64"} {
		args := []string{"clang", "-arch", arch, "-isysroot", strings.TrimSpace(string(sdk)), "-std=c11", "-Xclang", "-ast-dump=json", "-fsyntax-only", source}
		ast, err := cirunner.Command("xcrun", args...).Output()
		if err != nil {
			return fmt.Errorf("%s AST: %w", arch, err)
		}
		if err = os.WriteFile(filepath.Join(dir, arch+".ast.json"), ast, 0600); err != nil {
			return err
		}
	}
	helper := filepath.Join(dir, "held-metadata")
	if out, err := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", helper).CombinedOutput(); err != nil {
		return fmt.Errorf("compile: %w: %s", err, out)
	}
	work, err := os.MkdirTemp(dir, "objects-")
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(work)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = os.WriteFile(filepath.Join(work, "file"), []byte("content"), 0600); err != nil {
		return err
	}
	if err = os.Mkdir(filepath.Join(work, "directory"), 0700); err != nil {
		return err
	}
	if err = os.Symlink("file", filepath.Join(work, "link")); err != nil {
		return err
	}
	if err = os.Symlink("missing", filepath.Join(work, "dangling")); err != nil {
		return err
	}
	observations := map[string]observation{}
	for _, name := range []string{"file", "directory", "link", "dangling"} {
		f, err := hostdata.OpenMetadataFile(root, name)
		if err != nil {
			return err
		}
		h, err := hostdata.NewHeldMetadata(f)
		if err != nil {
			_ = f.Close()
			return err
		}
		for _, phase := range []string{"initial", "times", "permissions", "acl"} {
			if phase == "times" {
				if err = h.SetTimes(time.Unix(1700000000, 1234), time.Unix(1700000001, 5678)); err != nil {
					_ = f.Close()
					return fmt.Errorf("%s times: %w", name, err)
				}
			}
			if phase == "permissions" && name != "link" && name != "dangling" {
				if err = h.Chmod(0640); err != nil {
					_ = f.Close()
					return err
				}
			}
			if phase == "acl" {
				if err = h.SetACL(&appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}); err != nil {
					_ = f.Close()
					return fmt.Errorf("%s acl: %w", name, err)
				}
			}
			want, err := capture(h)
			if err != nil {
				_ = f.Close()
				return err
			}
			out, err := cirunner.Command(helper, filepath.Join(work, name)).Output()
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("%s oracle: %w", name, err)
			}
			var actual observation
			if err = json.Unmarshal(out, &actual); err != nil {
				_ = f.Close()
				return err
			}
			if !reflect.DeepEqual(want, actual) {
				_ = f.Close()
				return fmt.Errorf("%s/%s mismatch: Go %+v C %+v", name, phase, want, actual)
			}
			observations[name+"/"+phase] = actual
		}
		if err = f.Close(); err != nil {
			return err
		}
	}
	hashes := map[string]string{}
	for _, path := range []string{source, "scripts/verify-held-metadata-native.go", "pkg/hostdata/libsystem_security_darwin.go", "pkg/hostdata/held_metadata_darwin.go", "pkg/hostdata/held_metadata.go", "pkg/hostdata/metadata_open.go", "pkg/hostdata/metadata_open_darwin.go"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		hashes[path] = hex.EncodeToString(sum[:])
	}
	rev, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	report := map[string]any{"revision": strings.TrimSpace(string(rev)), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "source_sha256": hashes, "cases": len(observations), "observations": observations, "sdk": strings.TrimSpace(string(sdk))}
	for key, args := range map[string][]string{"sw_vers": {"sw_vers"}, "kernel": {"uname", "-r"}, "clang": {"xcrun", "clang", "--version"}} {
		out, e := cirunner.Command(args[0], args[1:]...).Output()
		if e != nil {
			return e
		}
		report[key] = strings.TrimSpace(string(out))
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "report.json"), append(b, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("Qualified %d native descriptor metadata readbacks; both architecture SDK ASTs retained\n", len(observations))
	return nil
}
func capture(h *hostdata.HeldMetadata) (observation, error) {
	s, err := h.CaptureSecurity()
	if err != nil {
		return observation{}, err
	}
	st, err := h.CaptureStat()
	if err != nil {
		return observation{}, err
	}
	o := observation{UID: st.UID, GID: st.GID, Mode: st.Mode, Flags: st.Flags, Properties: map[string]*string{"1": nil, "2": nil, "4": nil, "3": nil, "6": nil, "100": nil}}
	for _, t := range []time.Time{st.Times.Birth, st.Times.Modify, st.Times.Change, st.Times.Access} {
		o.Times = append(o.Times, t.Unix(), int64(t.Nanosecond()))
	}
	for key, p := range map[string]*uint32{"1": s.Properties.UID, "2": s.Properties.GID, "4": s.Properties.Mode} {
		if p != nil {
			var b bytes.Buffer
			if key == "4" {
				_ = binary.Write(&b, binary.LittleEndian, uint16(*p))
			} else {
				_ = binary.Write(&b, binary.LittleEndian, *p)
			}
			v := hex.EncodeToString(b.Bytes())
			o.Properties[key] = &v
		}
	}
	for key, p := range map[string]*[16]byte{"3": s.Properties.OwnerUUID, "6": s.Properties.GroupUUID} {
		if p != nil {
			v := hex.EncodeToString(p[:])
			o.Properties[key] = &v
		}
	}
	if s.Properties.RawSecurity != nil {
		b, e := s.Properties.RawSecurity.MarshalDarwinBinary()
		if e != nil {
			return o, e
		}
		v := hex.EncodeToString(b)
		o.Properties["100"] = &v
	}
	return o, nil
}
