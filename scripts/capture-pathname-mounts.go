//go:build ignore

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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

type mountedCase struct{ ID, Family, Source, Target, Profile, Operation, Route string }
type mountedImage struct {
	image, root, device, name, artifact string
	attaches, detaches                  int
}

func mountCases() []mountedCase {
	var cases []mountedCase
	add := func(family, source, target string, profiles, operations, routes []string) {
		for _, p := range profiles {
			for _, op := range operations {
				for _, route := range routes {
					id := strings.Join([]string{family, source, target, p, op, route}, "/")
					cases = append(cases, mountedCase{id, family, source, target, p, op, route})
				}
			}
		}
	}
	for _, source := range []string{"APFS", "HFS+"} {
		add("readonly", source, source, []string{"ordinary", "parent-no-search", "leaf-immutable", "leaf-deny-delete"}, []string{"open-read", "open", "create", "unlink", "rename"}, []string{"root", "parent"})
		target := "APFS"
		if source == target {
			target = "HFS+"
		}
		add("cross-device", source, target, []string{"ordinary", "parent-no-search", "parent-deny-delete", "stage-immutable", "destination-deny-search", "destination-deny-add", "destination-deny-delete", "destination-immutable"}, []string{"rename-cross"}, []string{"path", "root", "parent"})
	}
	return cases
}
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func writeJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (i *mountedImage) attach(ctx context.Context, readonly bool) error {
	args := []string{"attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", i.root}
	if readonly {
		args = append(args, "-readonly")
	}
	args = append(args, i.image)
	b, e := runCommand(ctx, "hdiutil", args...)
	i.attaches++
	recordErr := os.WriteFile(filepath.Join(i.artifact, fmt.Sprintf("%s-attach-%d.plist", i.name, i.attaches)), b, 0644)
	if e != nil {
		return errors.Join(e, recordErr)
	}
	device, parseErr := diskimage.AttachmentDevice(b)
	if device == "" {
		device = i.root
	}
	i.device = device
	return errors.Join(parseErr, recordErr)
}
func (i *mountedImage) detach() error {
	if i.device == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var attempts []map[string]any
	e := diskimage.RetryDetach(ctx, func() (int, error) {
		b, e := exec.CommandContext(ctx, "hdiutil", "detach", i.device).CombinedOutput()
		code := 0
		if e != nil {
			code = -1
			var exit *exec.ExitError
			if errors.As(e, &exit) {
				code = exit.ExitCode()
			}
		}
		attempts = append(attempts, map[string]any{"device": i.device, "exit_code": code, "output": string(b)})
		return code, e
	})
	i.detaches++
	recordErr := writeJSON(filepath.Join(i.artifact, fmt.Sprintf("%s-detach-%d.json", i.name, i.detaches)), attempts)
	if e == nil {
		i.device = ""
	}
	return errors.Join(e, recordErr)
}
func makeImage(ctx context.Context, dir, kind string) (*mountedImage, error) {
	name := strings.ReplaceAll(kind, "+", "plus")
	i := &mountedImage{image: filepath.Join(dir, name+".dmg"), root: filepath.Join(dir, name+"-mount"), name: name, artifact: dir}
	if e := os.Mkdir(i.root, 0700); e != nil {
		return nil, e
	}
	if _, e := runCommand(ctx, "hdiutil", "create", "-size", "64m", "-fs", kind, "-volname", "PathnameAuthority", i.image); e != nil {
		return nil, e
	}
	return i, i.attach(ctx, false)
}
func callOracle(ctx context.Context, binary string, sudo bool, args ...string) (map[string]any, error) {
	name := binary
	if sudo {
		args = append([]string{"-n", binary}, args...)
		name = "sudo"
	}
	b, e := runCommand(ctx, name, args...)
	if e != nil {
		return nil, e
	}
	var row map[string]any
	e = json.Unmarshal(b, &row)
	return row, e
}
func main() {
	out := flag.String("out", "artifacts/pathname-mounts", "new artifact directory")
	oracle := flag.String("oracle-artifacts", "artifacts/pathname-authorization", "source-bound runtime oracle capture directory")
	sudo := flag.Bool("sudo", false, "use sudo -n only for descriptor acquisition through denied paths")
	complete := flag.Bool("require-complete", false, "require every privilege-dependent mounted control")
	flag.Parse()
	if e := run(*out, *oracle, *sudo, *complete); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out, oracle string, useSudo, require bool) (result error) {
	if runtime.GOOS != "darwin" || os.Getuid() == 0 {
		return errors.New("requires Darwin unprivileged research actor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if e := os.MkdirAll(out, 0755); e != nil {
		return e
	}
	out, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	oracle, e = filepath.Abs(oracle)
	if e != nil {
		return e
	}
	binary := filepath.Join(oracle, "probe")
	source, e := os.ReadFile("testdata/appledouble/native/pathname-authorization.c")
	if e != nil {
		return e
	}
	retained, e := os.ReadFile(filepath.Join(oracle, "probe.c"))
	if e != nil {
		return e
	}
	if !bytes.Equal(source, retained) {
		return errors.New("runtime oracle capture is stale")
	}
	binaryBytes, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	capture, e := os.ReadFile(filepath.Join(oracle, "capture.json"))
	if e != nil {
		return e
	}
	var provenance struct {
		Sources map[string]string `json:"source_sha256"`
	}
	if e = json.Unmarshal(capture, &provenance); e != nil {
		return e
	}
	if provenance.Sources["probe"] != hash(binaryBytes) {
		return errors.New("oracle binary digest mismatch")
	}
	script, e := os.ReadFile("scripts/capture-pathname-mounts.go")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "capture.go"), script, 0644); e != nil {
		return e
	}
	cases := mountCases()
	if len(cases) != 128 {
		return errors.New("mounted case inventory differs")
	}
	specBytes, e := os.ReadFile("testdata/appledouble/native/pathname-mount-cases.json")
	if e != nil {
		return e
	}
	var specified []mountedCase
	if e = json.Unmarshal(specBytes, &specified); e != nil {
		return e
	}
	if !reflect.DeepEqual(cases, specified) {
		return errors.New("mounted predeclared specification differs")
	}
	if e = os.WriteFile(filepath.Join(out, "case-manifest.json"), specBytes, 0644); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "oracle_capture.json"), capture, 0644); e != nil {
		return e
	}
	sudoAvailable := false
	var sudoOutput []byte
	if useSudo {
		sudoOutput, e = runCommand(ctx, "sudo", "-n", "true")
		sudoAvailable = e == nil
	}
	images := map[string]*mountedImage{}
	defer func() {
		for _, kind := range []string{"HFS+", "APFS"} {
			if image := images[kind]; image != nil {
				result = errors.Join(result, image.detach())
			}
		}
	}()
	for _, kind := range []string{"APFS", "HFS+"} {
		image, e := makeImage(ctx, out, kind)
		if image != nil {
			images[kind] = image
		}
		if e != nil {
			return e
		}
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	prepared := map[string][2]string{}
	preparation := map[string][]map[string]any{}
	for _, c := range cases {
		src, e := callOracle(ctx, binary, false, "--prepare", images[c.Source].root, c.Profile, "open", "parent", uid, gid)
		if e != nil {
			return e
		}
		sourcePath, ok := src["fixture"].(string)
		if !ok || src["prepared"] != true || src["handles_closed"] != true {
			return errors.New("incomplete source fixture preparation")
		}
		targetPath := sourcePath
		preparation[c.ID] = []map[string]any{src}
		if c.Family == "cross-device" {
			dst, e := callOracle(ctx, binary, false, "--prepare", images[c.Target].root, c.Profile, "open", "parent", uid, gid)
			if e != nil {
				return e
			}
			targetPath, ok = dst["fixture"].(string)
			if !ok || dst["prepared"] != true || dst["handles_closed"] != true {
				return errors.New("incomplete destination fixture preparation")
			}
			preparation[c.ID] = append(preparation[c.ID], dst)
		}
		prepared[c.ID] = [2]string{sourcePath, targetPath}
	}
	if e = writeJSON(filepath.Join(out, "preparation.json"), preparation); e != nil {
		return e
	}
	observations := []map[string]any{}
	unavailable := 0
	observe := func(c mountedCase) error {
		paths := prepared[c.ID]
		row := map[string]any{"case": c, "preparation": preparation[c.ID]}
		// Snapshot acquisition through denied ancestry requires root; the child still
		// executes the actual operation with the explicitly recorded ordinary actor.
		needsRoot := c.Profile == "parent-no-search" || c.Profile == "destination-deny-search"
		if needsRoot && !sudoAvailable {
			row["qualification"] = "unavailable"
			row["reason"] = "requires noninteractive privileged held-descriptor acquisition"
			unavailable++
			observations = append(observations, row)
			return writeJSON(filepath.Join(out, "observations.json"), observations)
		}
		native, e := callOracle(ctx, binary, needsRoot, "--mounted", c.Operation, c.Route, paths[0], paths[1], uid, gid)
		if e != nil {
			return e
		}
		if native["handles_closed"] != true {
			return errors.New("mounted oracle leaked handles")
		}
		row["qualification"] = "captured"
		row["native"] = native
		observations = append(observations, row)
		fmt.Println(c.ID)
		return writeJSON(filepath.Join(out, "observations.json"), observations)
	}
	// Independent mutable fixtures run first, before both images are remounted read-only.
	for _, c := range cases {
		if c.Family == "cross-device" {
			if e = observe(c); e != nil {
				return e
			}
		}
	}
	for _, kind := range []string{"APFS", "HFS+"} {
		image := images[kind]
		if e = image.detach(); e != nil {
			return e
		}
		if e = image.attach(ctx, true); e != nil {
			return e
		}
	}
	for _, c := range cases {
		if c.Family == "readonly" {
			if e = observe(c); e != nil {
				return e
			}
		}
	}
	for _, kind := range []string{"HFS+", "APFS"} {
		if e = images[kind].detach(); e != nil {
			return e
		}
	}
	host, e := runCommand(ctx, "sw_vers")
	if e != nil {
		return e
	}
	report := map[string]any{"schema": 1, "host": string(host), "source_sha256": map[string]string{"oracle_capture.json": hash(capture), "probe.c": hash(source), "probe": hash(binaryBytes), "capture.go": hash(script), "case-manifest.json": hash(specBytes)}, "expected_cases": len(cases), "unavailable_cases": unavailable, "sudo_available": sudoAvailable, "sudo_diagnostic": string(sudoOutput), "cases": observations, "mounts_detached": true}
	if e = writeJSON(filepath.Join(out, "capture.json"), report); e != nil {
		return e
	}
	if require && unavailable != 0 {
		return fmt.Errorf("%d mounted native cases unavailable", unavailable)
	}
	return nil
}
