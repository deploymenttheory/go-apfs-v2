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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"github.com/deploymenttheory/go-apfs-v2/pkg/recompression"
)

type state struct {
	Dev, Inode            uint64
	UID, GID, Mode, Flags uint32
	Mount                 uint32 `json:"mount_flags"`
	Filesystem, Security  string
	Data                  string
	Times                 [4][2]int64
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
	Cleanup                             bool    `json:"cleanup_complete"`
	Control                             *result `json:"positive_open_control"`
	User                                string  `json:"user_uuid"`
	Group                               string  `json:"group_uuid"`
	Member                              int     `json:"group_member"`
	MemberErr                           int     `json:"group_membership_errno"`
	Before                              []entry
	Result                              result
}

func main() {
	capturePath := flag.String("capture", "", "genuine native capture path")
	artifactDir := flag.String("artifacts", "", "complete capture artifact directory; defaults to capture parent")
	report := flag.String("report", "", "write revision- and capture-bound replay report")
	mounted := flag.Bool("mounted", false, "verify complete mounted readonly/cross-volume native corpus")
	oracleArtifacts := flag.String("oracle-artifacts", "artifacts/pathname-authorization", "source-bound runtime oracle directory")
	flag.Parse()
	if *mounted {
		must(verifyMounted(*capturePath, *artifactDir, *oracleArtifacts, *report))
		return
	}
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
		actual := evaluate(c, version)
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
		revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
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
		if row.Qualification != "captured" || !row.Cleanup || row.Result.SetupErr != 0 || row.Result.CloseErr != 0 || row.Control == nil || row.Control.Errno != 0 || row.Control.SetupErr != 0 || row.Control.CloseErr != 0 {
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
	harness, err := captureprovenance.Inventory(os.DirFS("."))
	if err != nil {
		return err
	}
	if err = captureprovenance.Verify(os.DirFS("."), c.Sources); err != nil {
		return err
	}
	for name := range harness {
		expected[name] = name
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

// Write-open is exercised through the public recompression endpoint instead of
// fabricating a standalone readonly errno in the research replay. These tiny
// native fixtures decline compression after acquisition; access failures still
// occur at the actual production endpoint boundary.
func endpointOpen(ctx context.Context, c record, target osversion.Version, authority *authorization.Authority) (result error) {
	var leaf state
	found := false
	for _, entry := range c.Before {
		if entry.Name == "a/b/file" {
			leaf = entry.State
			found = true
			break
		}
	}
	if !found {
		return errors.New("missing native leaf")
	}
	data, err := hex.DecodeString(leaf.Data)
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "pathname-open-replay-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(root)) }()
	payload, metadata := filepath.Join(root, "payload"), filepath.Join(root, "metadata")
	for _, dir := range []string{payload, metadata} {
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
	}
	if err = os.WriteFile(filepath.Join(payload, "file"), data, 0600); err != nil {
		return err
	}
	store, err := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	access := time.Unix(leaf.Times[0][0], leaf.Times[0][1]).UTC()
	modify := time.Unix(leaf.Times[1][0], leaf.Times[1][1]).UTC()
	baseline := metatransport.BlobRef{SHA256: digest(data), Size: int64(len(data))}
	record := metatransport.Record{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file", Payload: &baseline, SourceAttributesCaptured: true, Darwin: metatransport.DarwinState{UID: &leaf.UID, GID: &leaf.GID, Mode: &leaf.Mode, Flags: &leaf.Flags, Access: &access, Modify: &modify}}
	if leaf.Security != "" {
		raw, err := hex.DecodeString(leaf.Security)
		if err != nil {
			return err
		}
		ref, err := store.PutBlob(ctx, bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return err
		}
		record.Darwin.Security = &ref
	}
	if err = store.Commit(ctx, metatransport.Manifest{Version: 1, Records: []metatransport.Record{record}}, 0); err != nil {
		return err
	}
	_, err = recompression.RecompressRecord(ctx, store, "file", 1, recompression.Options{Target: target, Authority: authority, Volume: &recompression.Volume{Filesystem: leaf.Filesystem, Flags: leaf.Mount}})
	return err
}

func evaluate(c record, version osversion.Version) error {
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
		case "held-write", "chmod-open", "open-read":
			// Endpoint permission state remains admitted in these pathname-only profiles.
		case "open":
			actual = endpointOpen(ctx, c, version, &a)
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

	return actual
}

type mountedSpec struct{ ID, Family, Source, Target, Profile, Operation, Route string }

func verifyMounted(capturePath, artifactDirectory, oracleDirectory, reportPath string) error {
	if artifactDirectory == "" {
		artifactDirectory = filepath.Dir(capturePath)
	}
	raw, err := os.ReadFile(capturePath)
	if err != nil {
		return err
	}
	var captured struct {
		Schema      int
		Host        string
		Expected    int               `json:"expected_cases"`
		Unavailable int               `json:"unavailable_cases"`
		Detached    bool              `json:"mounts_detached"`
		Sources     map[string]string `json:"source_sha256"`
		Cases       []struct {
			Case          mountedSpec
			Qualification string
			Preparation   []record
			Native        struct {
				record
				Closed bool `json:"handles_closed"`
			}
		}
	}
	if err = json.Unmarshal(raw, &captured); err != nil {
		return err
	}
	if captured.Schema != 1 || captured.Expected != 128 || len(captured.Cases) != 128 || captured.Unavailable != 0 || !captured.Detached {
		return errors.New("incomplete mounted native capture")
	}
	specBytes, err := os.ReadFile("testdata/appledouble/native/pathname-mount-cases.json")
	if err != nil {
		return err
	}
	var specs []mountedSpec
	if err = json.Unmarshal(specBytes, &specs); err != nil {
		return err
	}
	if len(specs) != 128 {
		return errors.New("unqualified mounted case inventory")
	}
	expected := map[string]mountedSpec{}
	for _, spec := range specs {
		if spec.ID != strings.Join([]string{spec.Family, spec.Source, spec.Target, spec.Profile, spec.Operation, spec.Route}, "/") {
			return errors.New("invalid mounted specification")
		}
		if _, found := expected[spec.ID]; found {
			return errors.New("duplicate mounted specification")
		}
		expected[spec.ID] = spec
	}
	runtimeCapture, err := os.ReadFile(filepath.Join(oracleDirectory, "capture.json"))
	if err != nil {
		return err
	}
	var oracle captureRecord
	if err = json.Unmarshal(runtimeCapture, &oracle); err != nil {
		return err
	}
	baseSpec, baseBytes, err := readSpec("testdata/appledouble/native/pathname-authorization-cases.json")
	if err != nil {
		return err
	}
	if err = inventory(oracle, baseSpec); err != nil {
		return err
	}
	if err = provenance(oracle, oracleDirectory, baseBytes); err != nil {
		return err
	}
	inputs := map[string]string{"oracle_capture.json": filepath.Join(oracleDirectory, "capture.json"), "probe.c": filepath.Join(oracleDirectory, "probe.c"), "probe": filepath.Join(oracleDirectory, "probe"), "capture.go": "scripts/capture-pathname-mounts.go", "case-manifest.json": "testdata/appledouble/native/pathname-mount-cases.json"}
	harness, err := captureprovenance.Inventory(os.DirFS("."))
	if err != nil {
		return err
	}
	if err = captureprovenance.Verify(os.DirFS("."), captured.Sources); err != nil {
		return err
	}
	for name := range harness {
		inputs[name] = name
	}
	if len(captured.Sources) != len(inputs) {
		return errors.New("mounted source provenance inventory differs")
	}
	for name, source := range inputs {
		b, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if captured.Sources[name] != digest(b) {
			return fmt.Errorf("mounted capture source mismatch: %s", name)
		}
		if name == "capture.go" || name == "case-manifest.json" || name == "oracle_capture.json" || harness[name] != "" {
			artifact, err := os.ReadFile(filepath.Join(artifactDirectory, name))
			if err != nil {
				return err
			}
			if !bytes.Equal(artifact, b) {
				return fmt.Errorf("mounted artifact changed: %s", name)
			}
		}
	}
	version, err := osversion.ParseProductVersion(captured.Host)
	if err != nil {
		return err
	}
	if captured.Host != oracle.Host {
		return errors.New("mounted/runtime oracle hosts differ")
	}
	canonical := captureRecord{Schema: 1, Expected: 128}
	canonicalSpec := make([]caseSpec, 0, 128)
	for _, row := range captured.Cases {
		want, ok := expected[row.Case.ID]
		if !ok || want != row.Case {
			return fmt.Errorf("duplicate or unexpected mounted case: %s", row.Case.ID)
		}
		delete(expected, row.Case.ID)
		if row.Qualification != "captured" || !row.Native.Closed || len(row.Preparation) == 0 {
			return fmt.Errorf("uncaptured mounted operation: %s", row.Case.ID)
		}
		r := row.Native.record
		r.ID = want.ID
		r.Family = want.Family
		r.Profile = want.Profile
		r.Cleanup = row.Native.Closed && captured.Detached
		r.Control = row.Preparation[0].Control
		canonical.Cases = append(canonical.Cases, r)
		canonicalSpec = append(canonicalSpec, caseSpec{ID: want.ID, Family: want.Family, Profile: want.Profile, Operation: want.Operation, Route: want.Route})
	}
	if len(expected) != 0 {
		return errors.New("missing mounted cases")
	}
	if err = inventory(canonical, canonicalSpec); err != nil {
		return err
	}
	compared := 0
	for _, r := range canonical.Cases {
		var expected error
		switch r.Result.Errno {
		case 0:
		case 1:
			expected = syscall.EPERM
		case 13:
			expected = syscall.EACCES
		case 18:
			expected = syscall.EXDEV
		case 30:
			expected = syscall.EROFS
		default:
			return fmt.Errorf("unqualified mounted Darwin errno: %d", r.Result.Errno)
		}
		actual := evaluate(r, version)
		if !errors.Is(actual, expected) {
			return fmt.Errorf("mounted %s: portable=%v native=%v", r.ID, actual, expected)
		}
		compared++
	}
	if reportPath != "" {
		revision, err := cirunner.Command("git", "rev-parse", "HEAD").Output()
		if err != nil {
			return err
		}
		report, err := json.MarshalIndent(map[string]any{"schema": 1, "revision": strings.TrimSpace(string(revision)), "capture_sha256": digest(raw), "spec_sha256": digest(specBytes), "host": runtime.GOOS, "compared": compared, "failed": 0}, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(reportPath, append(report, '\n'), 0644); err != nil {
			return err
		}
	}
	fmt.Printf("compared %d mounted native operations\n", compared)
	return nil
}
