//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
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
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type state struct {
	Dev, Inode            uint64
	UID, GID, Mode, Flags uint32
	Mount                 uint32 `json:"mount_flags"`
	Filesystem, Security  string
	Captured              bool `json:"security_captured"`
}
type entry struct {
	Name  string
	State state
}
type result struct {
	UID        uint32
	Groups     []uint32
	Errno      int
	SetupErr   int `json:"setup_errno"`
	CloseErr   int `json:"close_errno"`
	Process    int `json:"process_policy"`
	ProcessErr int `json:"process_policy_errno"`
}
type record struct {
	ID, Qualification, Operation, Route string
	Profile, Family                     string
	Cleanup                             bool   `json:"cleanup_complete"`
	Control                             result `json:"positive_open_control"`
	User                                string `json:"user_uuid"`
	Group                               string `json:"group_uuid"`
	Member                              int    `json:"group_member"`
	MemberErr                           int    `json:"group_membership_errno"`
	Before                              []entry
	Result                              result
}

func main() {
	capturePath := flag.String("capture", "", "genuine native capture path")
	artifactDir := flag.String("artifacts", "", "complete capture artifact directory; defaults to capture parent")
	report := flag.String("report", "", "write revision- and capture-bound replay report")
	flag.Parse()
	if *artifactDir == "" {
		*artifactDir = filepath.Dir(*capturePath)
	}
	spec, specBytes, err := readSpec("testdata/appledouble/native/pathname-authorization-cases.json")
	must(err)
	b, e := os.ReadFile(*capturePath)
	must(e)
	captureHash := digest(b)
	if strings.HasSuffix(*capturePath, ".gz") {
		z, e := gzip.NewReader(bytes.NewReader(b))
		must(e)
		b, e = io.ReadAll(z)
		must(e)
		must(z.Close())
	}
	var capture captureRecord
	must(json.Unmarshal(b, &capture))
	must(inventory(capture, spec))
	must(provenance(capture, *artifactDir, specBytes))
	var version osversion.Version
	for _, line := range strings.Split(capture.Host, "\n") {
		if strings.HasPrefix(line, "ProductVersion:") {
			version, e = osversion.Parse(strings.TrimSpace(strings.TrimPrefix(line, "ProductVersion:")))
			must(e)
		}
	}
	total := 0
	failed := 0
	for _, c := range capture.Cases {
		if c.Qualification != "captured" {
			panic("uncaptured case: " + c.ID)
		}
		if c.Result.ProcessErr != 0 || c.Result.Process < 0 || c.Result.Process > 1 {
			panic("uncaptured native process policy: " + c.ID)
		}
		a := authorization.Authority{UID: c.Result.UID, Groups: c.Result.Groups, Membership: map[[16]byte]authorization.Membership{}, Process: &authorization.ProcessPolicy{IgnoreNodePermissions: c.Result.Process == 1}}
		raw, e := hex.DecodeString(c.User)
		must(e)
		uuid := [16]byte(raw)
		a.UserUUID = &uuid
		raw, e = hex.DecodeString(c.Group)
		must(e)
		group := [16]byte(raw)
		if c.MemberErr != 0 {
			a.Membership[group] = authorization.MembershipFailed
		} else if c.Member != 0 {
			a.Membership[group] = authorization.Member
		} else {
			a.Membership[group] = authorization.NotMember
		}
		ev, e := authorization.New(version, &a)
		must(e)
		nodes := map[string]authorization.Node{}
		for _, entry := range c.Before {
			s := entry.State
			n := authorization.Node{Observed: true, Stat: hostdata.StatCopySource{UID: s.UID, GID: s.GID, Mode: s.Mode, Flags: s.Flags}, Identity: s.Inode, Mount: &authorization.Mount{Identity: strconv.FormatUint(s.Dev, 10), Filesystem: s.Filesystem, Flags: s.Mount}, SecurityState: authorization.SecurityAbsent}
			if s.Security != "" {
				raw, e := hex.DecodeString(s.Security)
				must(e)
				n.Security, e = appledouble.ParseFileSecurity(raw)
				must(e)
				n.SecurityState = authorization.SecurityPresent
			}
			if !s.Captured {
				panic("uncaptured native security")
			}
			nodes[entry.Name] = n
		}
		var actual error
		ctx := context.Background()
		dirs := []string{"root", "a", "a/b"}
		if c.Route == "parent" {
			dirs = []string{"a/b"}
		}
		if c.Operation != "held-write" {
			for _, d := range dirs {
				if actual = ev.Search(ctx, nodes[d]); actual != nil {
					break
				}
			}
		}
		if actual == nil {
			switch c.Operation {
			case "open", "held-write", "chmod-open":
				// Endpoint permission state remains admitted in these pathname-only profiles.
			case "create":
				actual = ev.Create(ctx, nodes["a/b"], false)
			case "unlink":
				actual = ev.Delete(ctx, nodes["a/b"], nodes["a/b/file"])
			case "rename":
				dst := nodes["a/b/file"]
				actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/b"], &dst)
			case "rename-absent":
				actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/b"], nil)
			case "rename-cross":
				if actual = ev.Search(ctx, nodes["a/c"]); actual == nil {
					dst := nodes["a/c/file"]
					actual = ev.Rename(ctx, nodes["a/b"], nodes["a/b/stage"], nodes["a/c"], &dst)
				}
			default:
				panic("unqualified operation: " + c.Operation)
			}
		}
		var expected error
		switch c.Result.Errno {
		case 0:
		case 1:
			expected = syscall.EPERM
		case 13:
			expected = syscall.EACCES
		case 30:
			expected = syscall.EROFS
		default:
			panic(c.Result.Errno)
		}
		if !errors.Is(actual, expected) {
			fmt.Println("DIFFER", c.ID, actual, "native", expected)
			failed++
		}
		total++
	}
	if *report != "" {
		revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
		must(err)
		output, err := json.MarshalIndent(map[string]any{"schema": 1, "revision": strings.TrimSpace(string(revision)), "capture_sha256": captureHash, "spec_sha256": digest(specBytes), "host": runtime.GOOS, "arch": runtime.GOARCH, "compared": total, "failed": failed}, "", "  ")
		must(err)
		must(os.WriteFile(*report, append(output, '\n'), 0644))
	}
	fmt.Println("compared", total, "failed", failed)
	if failed > 0 {
		os.Exit(1)
	}
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}

type caseSpec struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Profile    string `json:"profile"`
	Operation  string `json:"operation"`
	Route      string `json:"route"`
	Privileged bool   `json:"privileged_fixture"`
}

type captureRecord struct {
	Schema      int
	Host        string
	Compiler    string
	SDK         string
	Cases       []record
	Sources     map[string]string `json:"source_sha256"`
	Release     string            `json:"apple_source_release"`
	Expected    int               `json:"expected_cases"`
	Unavailable int               `json:"unavailable_cases"`
	Failed      int               `json:"failed_cases"`
}

func readSpec(name string) ([]caseSpec, []byte, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}
	var spec struct {
		Schema        int
		Qualification string
		Cases         []caseSpec
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&spec); err != nil {
		return nil, nil, err
	}
	if spec.Schema != 1 || spec.Qualification != "specified-before-capture" || len(spec.Cases) != 318 {
		return nil, nil, errors.New("unqualified expected case specification")
	}
	seen := map[string]bool{}
	for _, c := range spec.Cases {
		if c.ID != strings.Join([]string{c.Family, c.Profile, c.Operation, c.Route}, "/") || seen[c.ID] {
			return nil, nil, fmt.Errorf("invalid/duplicate expected case %q", c.ID)
		}
		switch c.Route {
		case "path", "root", "parent":
		default:
			return nil, nil, fmt.Errorf("unknown route %q", c.Route)
		}
		switch c.Operation {
		case "open", "create", "unlink", "rename", "rename-absent", "rename-cross", "held-write", "chmod-open":
		default:
			return nil, nil, fmt.Errorf("unknown operation %q", c.Operation)
		}
		seen[c.ID] = true
	}
	return spec.Cases, b, nil
}

func inventory(c captureRecord, expected []caseSpec) error {
	if c.Schema != 1 || c.Expected != len(expected) || len(c.Cases) != len(expected) || c.Unavailable != 0 || c.Failed != 0 {
		return errors.New("incomplete native pathname capture")
	}
	wanted := map[string]caseSpec{}
	for _, s := range expected {
		wanted[s.ID] = s
	}
	for _, row := range c.Cases {
		spec, ok := wanted[row.ID]
		if !ok {
			return fmt.Errorf("duplicate or unknown native case %q", row.ID)
		}
		if row.Family != spec.Family || row.Profile != spec.Profile || row.Operation != spec.Operation || row.Route != spec.Route {
			return fmt.Errorf("case metadata differs: %s", row.ID)
		}
		if row.Qualification != "captured" || !row.Cleanup || row.Result.SetupErr != 0 || row.Result.CloseErr != 0 || row.Control.Errno != 0 || row.Control.SetupErr != 0 || row.Control.CloseErr != 0 {
			return fmt.Errorf("incomplete operation lifecycle: %s", row.ID)
		}
		if row.Result.Groups == nil || row.Result.ProcessErr != 0 || row.Result.Process < 0 || row.Result.Process > 1 {
			return fmt.Errorf("uncaptured process authority: %s", row.ID)
		}
		expectedNodes := map[string]bool{"root": true, "a": true, "a/b": true, "a/b/file": true, "a/b/stage": true, "a/c": true, "a/c/file": true}
		for _, n := range row.Before {
			if !expectedNodes[n.Name] || !n.State.Captured {
				return fmt.Errorf("duplicate, unknown or uncaptured node %s/%s", row.ID, n.Name)
			}
			delete(expectedNodes, n.Name)
		}
		if len(expectedNodes) != 0 {
			return fmt.Errorf("missing node observations: %s", row.ID)
		}
		for _, uuid := range []string{row.User, row.Group} {
			raw, e := hex.DecodeString(uuid)
			if e != nil || len(raw) != 16 {
				return fmt.Errorf("invalid UUID observation: %s", row.ID)
			}
		}
		delete(wanted, row.ID)
	}
	if len(wanted) != 0 {
		return errors.New("missing expected native cases")
	}
	return nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func provenance(c captureRecord, directory string, spec []byte) error {
	if c.Release != "xnu-11417.140.69" || c.Compiler == "" || c.SDK == "" {
		return errors.New("missing native provenance")
	}
	expected := map[string]string{"probe.c": "testdata/appledouble/native/pathname-authorization.c", "capture.go": "scripts/capture-pathname-authorization.go", "case-manifest.json": "", "probe": "", "arm64-apple-macos15.ast.json": "", "x86_64-apple-macos15.ast.json": ""}
	for _, name := range []string{"sys/stat.h", "sys/mount.h", "sys/acl.h", "sys/kauth.h", "sys/fcntl.h", "sys/resource.h", "membership.h"} {
		expected["SDK/"+name] = ""
	}
	var apple struct {
		Release string
		Sources []struct{ File, SHA256 string }
	}
	b, e := os.ReadFile("testdata/appledouble/native/pathname-authorization-source/sources.json")
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &apple); e != nil {
		return e
	}
	if apple.Release != c.Release || len(apple.Sources) != 8 {
		return errors.New("unqualified pinned XNU source inventory")
	}
	pinned := map[string]string{}
	for _, s := range apple.Sources {
		key := "apple-source/" + strings.TrimSuffix(s.File, ".gz")
		if _, ok := expected[key]; ok {
			return errors.New("duplicate pinned source")
		}
		expected[key] = ""
		pinned[key] = s.SHA256
	}
	if len(c.Sources) != len(expected) {
		return errors.New("source provenance inventory differs")
	}
	for name, current := range expected {
		wanted, ok := c.Sources[name]
		decoded, err := hex.DecodeString(wanted)
		if !ok || err != nil || len(decoded) != 32 {
			return fmt.Errorf("missing/invalid source digest: %s", name)
		}
		raw, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		if digest(raw) != wanted {
			return fmt.Errorf("artifact digest mismatch: %s", name)
		}
		if current != "" {
			present, err := os.ReadFile(current)
			if err != nil {
				return err
			}
			if digest(present) != wanted {
				return fmt.Errorf("stale source capture: %s", name)
			}
		}
		if p, ok := pinned[name]; ok && p != wanted {
			return fmt.Errorf("pinned Apple source mismatch: %s", name)
		}
		if name == "case-manifest.json" && !bytes.Equal(raw, spec) {
			return errors.New("case specification differs from predeclared inventory")
		}
		if strings.HasSuffix(name, ".ast.json") {
			var ast struct{ Kind string }
			if err = json.Unmarshal(raw, &ast); err != nil || ast.Kind != "TranslationUnitDecl" {
				return fmt.Errorf("invalid complete Clang AST: %s", name)
			}
		}
	}
	return nil
}
