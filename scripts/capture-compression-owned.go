//go:build ignore

// Capture independent native rooted acquisition and held volume observations.
package main

import (
	"bufio"
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
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type capture struct {
	Schema              int
	Host, Compiler, SDK string
	Sources             map[string]string
	Cases               []trial
}
type trial struct {
	Filesystem  string
	Observation json.RawMessage
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", "artifacts/compression-owned/native.json.gz", "fresh observations")
	check := flag.Bool("check", false, "compare the complete retained profile")
	replay := flag.String("replay", "", "replay independently captured native evidence on live volumes")
	comparison := flag.String("compare", "", "compare independently captured evidence with its retained native profile")
	qualify := flag.String("qualify", "", "verify this run's independent native bundle and record Go qualification")
	profile := flag.String("profile", "", "required native producer OS profile")
	consumer := flag.String("consumer", "", "required receiving host profile")
	receipts := flag.String("receipts", "artifacts/owned-qualification", "separate Go verification receipt directory")
	aggregate := flag.String("aggregate", "", "require all producer profiles and portable consumer receipts")
	flag.Parse()
	var err error
	operations := 0
	for _, path := range []string{*replay, *comparison, *qualify, *aggregate} {
		if path != "" {
			operations++
		}
	}
	if operations > 1 {
		fmt.Fprintln(os.Stderr, "capture, baseline, replay, qualification and aggregation are separate operations")
		os.Exit(1)
	}
	switch {
	case *replay != "" && *comparison != "":
		err = errors.New("replay and compare are separate operations")
	case *replay != "":
		err = replayCapture(*replay)
		if err == nil {
			err = recordOwnedLiveReceipt(*replay)
		}
	case *comparison != "":
		err = compareCapture(*comparison)
	case *qualify != "":
		err = qualifyOwnedCapture(*qualify, *profile, *consumer, *receipts)
	case *aggregate != "":
		err = aggregateOwnedCapture(*aggregate)
	default:
		err = run(*out, *check)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			err = publishOwnedBundle(ctx, *out)
			if err == nil {
				err = captureprovenance.SealExecution(ctx, filepath.Dir(*out))
			}
			cancel()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(out string, check bool) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("native capture requires macOS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	host, e := command(ctx, "sw_vers")
	if e != nil {
		return e
	}
	version, e := osversion.ParseProductVersion(string(host))
	if e != nil {
		return e
	}
	if _, e = osversion.ProfileForMacOS(version); e != nil {
		return e
	}
	baseline := fmt.Sprintf("testdata/appledouble/native/compression-owned-macos%d.json.gz", version.Major)
	absolute, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	retained, e := filepath.Abs(baseline)
	if e != nil {
		return e
	}
	if check && absolute == retained {
		return errors.New("fresh capture must not overwrite retained evidence")
	}
	artifact := filepath.Dir(out)
	if e = os.MkdirAll(artifact, 0755); e != nil {
		return e
	}
	directory, e := os.MkdirTemp("", "compression-owned-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(directory)) }()
	directory, e = filepath.EvalSymlinks(directory)
	if e != nil {
		return e
	}
	report := capture{Schema: 1, Host: string(host), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), artifact, report.Sources); err != nil {
		return err
	}
	hashFile := func(name, key string) error {
		b, e := os.ReadFile(name)
		if e != nil {
			return e
		}
		report.Sources[key] = fmt.Sprintf("%x", sha256.Sum256(b))
		return nil
	}
	const source = "testdata/appledouble/native/compression-owned.c"
	for _, name := range []string{source, "scripts/capture-compression-owned.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
		if e = hashFile(name, name); e != nil {
			return e
		}
	}
	helper := filepath.Join(artifact, "native")
	if _, e = command(ctx, "xcrun", "clang", "-Wall", "-Wextra", "-Werror", source, "-lz", "-o", helper); e != nil {
		return e
	}
	if e = hashFile(helper, "native-binary"); e != nil {
		return e
	}
	b, e := command(ctx, "xcrun", "clang", "--version")
	if e != nil {
		return e
	}
	report.Compiler = string(b)
	b, e = command(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	report.SDK = strings.TrimSpace(string(b))
	for _, header := range []string{"sys/stat.h", "sys/mount.h", "sys/xattr.h", "fcntl.h", "unistd.h", "zlib.h"} {
		name := filepath.Join(report.SDK, "usr/include", header)
		if e = hashFile(name, name); e != nil {
			return e
		}
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e = command(ctx, "xcrun", "clang", "-arch", arch, "-fsyntax-only", "-Xclang", "-ast-dump=json", source)
		if e != nil {
			return e
		}
		if !json.Valid(b) || !bytes.Contains(b, []byte("CompoundStmt")) {
			return errors.New("incomplete AST")
		}
		name := arch + "-compression-owned.ast.json"
		if e = os.WriteFile(filepath.Join(artifact, name), b, 0644); e != nil {
			return e
		}
		report.Sources[name] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		e = func() (err error) {
			base := directory
			if filesystem != "host" {
				var cleanup func() error
				base, cleanup, err = mount(ctx, directory, filesystem, artifact)
				if err != nil {
					return err
				}
				defer func() { err = errors.Join(err, cleanup()) }()
			}
			for _, compressed := range []string{"0", "1", "2"} {
				for _, route := range []string{"direct", "root"} {
					for _, mutation := range []string{"none", "root-before", "root-after", "leaf-after"} {
						path := filepath.Join(base, "case-"+compressed+"-"+route+"-"+mutation)
						b, e := command(ctx, helper, path, route, mutation, compressed)
						if e != nil {
							return e
						}
						if !json.Valid(b) {
							return errors.New("invalid native observation")
						}
						report.Cases = append(report.Cases, trial{filesystem, json.RawMessage(b)})
					}
				}
			}

			return nil
		}()
		if e != nil {
			return e
		}
	}
	b, e = json.Marshal(report)
	if e != nil {
		return e
	}
	f, e := os.Create(out)
	if e != nil {
		return e
	}
	z := gzip.NewWriter(f)
	_, e = z.Write(b)
	if e = errors.Join(e, z.Close(), f.Close()); e != nil {
		return e
	}
	if len(report.Cases) != 72 {
		return fmt.Errorf("incomplete inventory %d", len(report.Cases))
	}
	if check {
		previous, e := readCapture(baseline)
		if e != nil {
			return e
		}
		if e = compare(previous, report); e != nil {
			return e
		}
	}
	fmt.Printf("72 native held-input cases across host/APFS/HFS+; macOS %s\n", version)
	return nil
}
func mount(ctx context.Context, directory, kind, artifact string) (string, func() error, error) {
	name := strings.ReplaceAll(kind, "+", "plus")
	image := filepath.Join(directory, name+".dmg")
	root := filepath.Join(directory, name+"-mount")
	if e := os.Mkdir(root, 0700); e != nil {
		return "", nil, e
	}
	if _, e := command(ctx, "hdiutil", "create", "-size", "64m", "-fs", kind, "-volname", "OwnedCompression", image); e != nil {
		return "", nil, e
	}
	attached, e := command(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", root, image)
	if e != nil {
		return "", nil, e
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = root
	}
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var attempts []map[string]any
		e := diskimage.RetryDetach(cleanupCtx, func() (int, error) {
			b, e := cirunner.CommandContext(cleanupCtx, "hdiutil", "detach", device).CombinedOutput()
			code := 0
			if e != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(e, &exit) {
					code = exit.ExitCode()
				}
			}
			attempts = append(attempts, map[string]any{"device": device, "output": string(b), "exit_code": code})
			return code, e
		})
		b, marshalErr := json.Marshal(attempts)
		return errors.Join(e, marshalErr, os.WriteFile(filepath.Join(artifact, name+"-detach.json"), b, 0644))
	}
	if e = os.WriteFile(filepath.Join(artifact, name+"-attach.plist"), attached, 0644); e != nil || parseErr != nil {
		return "", nil, errors.Join(e, parseErr, cleanup())
	}
	return root, cleanup, nil
}
func readCapture(name string) (capture, error) {
	var c capture
	f, e := os.Open(name)
	if e != nil {
		return c, e
	}
	z, e := gzip.NewReader(f)
	if e != nil {
		return c, errors.Join(e, f.Close())
	}
	e = json.NewDecoder(z).Decode(&c)
	return c, errors.Join(e, z.Close(), f.Close())
}

// Compare stable native results, retaining the full timestamp/identity snapshots
// in both archives. Absolute inode numbers and operation-clock times are not
// reproducible across independent files; relationships are checked by replay.
func compare(before, after capture) error {
	oldProfile, err := osversion.ParseProductVersion(before.Host)
	if err != nil {
		return err
	}
	newProfile, err := osversion.ParseProductVersion(after.Host)
	if err != nil || newProfile.Major != oldProfile.Major {
		return errors.New("mixed owned native OS profiles")
	}
	for _, sources := range []map[string]string{before.Sources, after.Sources} {
		reference, err := captureprovenance.Reference(os.DirFS("."), sources)
		if err != nil {
			return err
		}
		if err = captureprovenance.Verify(reference, sources); err != nil {
			return err
		}
		for _, name := range []string{"testdata/appledouble/native/compression-owned.c", "scripts/capture-compression-owned.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
			if _, err = captureprovenance.ReadSource(reference, sources, name); err != nil {
				return err
			}
		}
	}
	if before.Schema != 1 || after.Schema != 1 || len(before.Cases) != 72 || len(after.Cases) != 72 {
		return errors.New("incomplete retained capture")
	}
	normalize := ownedStableResult
	for i, old := range before.Cases {
		fresh := after.Cases[i]
		if old.Filesystem != fresh.Filesystem {
			return fmt.Errorf("filesystem inventory %d", i)
		}
		a, e := normalize(old.Observation)
		if e != nil {
			return e
		}
		b, e := normalize(fresh.Observation)
		if e != nil {
			return e
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("native case differs %d/%s", i, old.Filesystem)
		}
	}
	return nil
}

// Preserve the existing comparison contract. Raw clock/identity snapshots stay
// in the sealed native report, and live replay verifies their relationships.
func ownedStableResult(raw json.RawMessage) ([]byte, error) {
	var v map[string]any
	if e := json.Unmarshal(raw, &v); e != nil {
		return nil, e
	}
	for _, key := range []string{"before", "after_open", "after_duplicate", "after_zero_write", "after_close"} {
		if state, ok := v[key].(map[string]any); ok {
			for _, name := range []string{"dev", "inode", "mtime", "atime", "ctime", "birth", "mount_flags"} {
				delete(state, name)
			}
		}
	}
	return json.Marshal(v)
}

// Native collection finishes before any Go implementation is evaluated.
func compareCapture(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := captureprovenance.VerifyExecution(ctx, filepath.Dir(path)); err != nil {
		return err
	}
	fresh, err := readCapture(path)
	if err != nil {
		return err
	}
	version, err := osversion.ParseProductVersion(fresh.Host)
	if err != nil {
		return err
	}
	if _, err = osversion.ProfileForMacOS(version); err != nil {
		return err
	}
	previous, err := readCapture(fmt.Sprintf("testdata/appledouble/native/compression-owned-macos%d.json.gz", version.Major))
	if err != nil {
		return err
	}
	return compare(previous, fresh)
}

func replayCapture(path string) (result error) {
	if runtime.GOOS != "darwin" {
		return errors.New("live mounted replay requires macOS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := captureprovenance.VerifyExecution(ctx, filepath.Dir(path)); err != nil {
		return err
	}
	report, err := readCapture(path)
	if err != nil {
		return err
	}
	if report.Schema != 1 || len(report.Cases) != 72 {
		return errors.New("incomplete native owned capture")
	}
	host, err := command(ctx, "sw_vers")
	if err != nil {
		return err
	}
	producer, err := osversion.ParseProductVersion(report.Host)
	if err != nil {
		return err
	}
	receiver, err := osversion.ParseProductVersion(string(host))
	if err != nil {
		return err
	}
	if producer.Major != receiver.Major {
		return errors.New("live replay requires the qualified native OS profile")
	}
	if _, err = verifyOwnedBundle(ctx, filepath.Dir(path), fmt.Sprintf("macos%d", producer.Major)); err != nil {
		return err
	}
	reference, err := captureprovenance.Reference(os.DirFS("."), report.Sources)
	if err != nil {
		return err
	}
	if err = captureprovenance.Verify(reference, report.Sources); err != nil {
		return err
	}
	artifact := "artifacts/compression-owned-replay"
	if err = os.MkdirAll(artifact, 0755); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "compression-owned-replay-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(directory)) }()
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		err = func() (result error) {
			base := directory
			if filesystem != "host" {
				var cleanup func() error
				base, cleanup, result = mount(ctx, directory, filesystem, artifact)
				if result != nil {
					return result
				}
				defer func() { result = errors.Join(result, cleanup()) }()
			}
			mounted := report
			mounted.Cases = nil
			for _, trial := range report.Cases {
				if trial.Filesystem == filesystem {
					mounted.Cases = append(mounted.Cases, trial)
				}
			}
			if len(mounted.Cases) != 24 {
				return fmt.Errorf("incomplete native filesystem inventory %s", filesystem)
			}
			observed, err := json.Marshal(mounted)
			if err != nil {
				return err
			}
			capturedPath, err := filepath.Abs(filepath.Join(artifact, strings.ReplaceAll(filesystem, "+", "plus")+"-cases.json"))
			if err != nil {
				return err
			}
			if err = os.WriteFile(capturedPath, observed, 0644); err != nil {
				return err
			}
			replay := cirunner.CommandContext(ctx, "go", "test", "-count=1", "-json", "./pkg/hostdata", "-run", "^TestNativeCompressionOwnedMounted$")
			replay.Env = append(os.Environ(), "APFS_COMPRESSION_OWNED_MOUNT="+base, "APFS_COMPRESSION_OWNED_CAPTURE="+capturedPath)
			transcript, replayErr := replay.CombinedOutput()
			writeErr := os.WriteFile(filepath.Join(artifact, strings.ReplaceAll(filesystem, "+", "plus")+"-replay.jsonl"), transcript, 0644)
			return errors.Join(replayErr, writeErr)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// The contract records the complete family before publication. Portable readers
// of every native profile are separate from the matching-profile live replay.
func ownedContract() nativeevidence.Contract {
	c := nativeevidence.Contract{Schema: 1, ID: "owned-compression", Profiles: []string{"macos15", "macos26", "macos27"}, Consumers: []string{"linux", "windows2022", "windows2025", "macos15", "macos26", "macos27", "native-live"}, Comparator: "owned-state-v1"}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		for compressed := 0; compressed <= 2; compressed++ {
			for _, route := range []string{"direct", "root"} {
				for _, mutation := range []string{"none", "root-before", "root-after", "leaf-after"} {
					c.Cases = append(c.Cases, fmt.Sprintf("%s/%s/%s/%d", filesystem, route, mutation, compressed))
				}
			}
		}
	}
	return c
}

func ownedObservation(report capture, put func([]byte) (string, error)) (nativeevidence.Observation, error) {
	var observation nativeevidence.Observation
	profile, err := osversion.ParseProductVersion(report.Host)
	if err != nil {
		return observation, err
	}
	if _, err = osversion.ProfileForMacOS(profile); err != nil {
		return observation, err
	}
	if report.Schema != 1 || len(report.Cases) != 72 {
		return observation, errors.New("incomplete owned native observation")
	}
	contract := ownedContract()
	hash, err := nativeevidence.ContractDigest(contract)
	if err != nil {
		return observation, err
	}
	observation = nativeevidence.Observation{Schema: 1, Contract: hash, Profile: fmt.Sprintf("macos%d", profile.Major)}
	seen := map[string]bool{}
	for _, trial := range report.Cases {
		var args struct {
			Route      string `json:"route"`
			Mutation   string `json:"mutation"`
			Compressed int    `json:"compressed"`
		}
		if err := json.Unmarshal(trial.Observation, &args); err != nil {
			return observation, err
		}
		id := fmt.Sprintf("%s/%s/%s/%d", trial.Filesystem, args.Route, args.Mutation, args.Compressed)
		found := false
		for _, expected := range contract.Cases {
			if expected == id {
				found = true
				break
			}
		}
		if !found || seen[id] {
			return observation, fmt.Errorf("unknown or duplicate owned native case %s", id)
		}
		seen[id] = true
		// Exact argv shape and native setup are bound to archived C source. Paths
		// use the fixed logical operand, rather than producer-specific temp roots.
		input, _ := json.Marshal(struct {
			Filesystem string
			Argv       []string
		}{trial.Filesystem, []string{"<file>", args.Route, args.Mutation, fmt.Sprint(args.Compressed)}})
		inputHash, err := put(input)
		if err != nil {
			return observation, err
		}
		stable, err := ownedStableResult(trial.Observation)
		if err != nil {
			return observation, err
		}
		outputHash, err := put(stable)
		if err != nil {
			return observation, err
		}
		observation.Cases = append(observation.Cases, nativeevidence.Case{ID: id, Input: inputHash, Result: outputHash})
	}
	return observation, nil
}

func publishOwnedBundle(ctx context.Context, path string) error {
	report, err := readCapture(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.Mkdir(filepath.Join(dir, "blobs"), 0755); err != nil {
		return err
	}
	put := func(data []byte) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		hash := nativeevidence.Digest(data)
		return hash, os.WriteFile(filepath.Join(dir, "blobs", hash), data, 0644)
	}
	observation, err := ownedObservation(report, put)
	if err != nil {
		return err
	}
	execution, err := captureprovenance.CurrentExecution(ctx)
	if err != nil {
		return err
	}
	profile, err := osversion.ParseProductVersion(report.Host)
	if err != nil {
		return err
	}
	build := ""
	for _, line := range strings.Split(report.Host, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "BuildVersion" {
			build = strings.TrimSpace(value)
		}
	}
	bundle := nativeevidence.Bundle{Schema: 1, Complete: true, Observation: observation, Execution: execution, Capture: nativeevidence.Capture{Profile: observation.Profile, Environment: map[string]string{"os_version": profile.String(), "os_build": build, "architecture": runtime.GOARCH, "compiler": report.Compiler, "sdk": report.SDK}, Sources: report.Sources, Artifacts: map[string]string{}}}
	for name, expected := range report.Sources {
		source := name
		if name == "native-binary" {
			source = filepath.Join(dir, "native")
		}
		if strings.HasSuffix(name, ".ast.json") {
			source = filepath.Join(dir, name)
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		hash, err := put(data)
		if err != nil {
			return err
		}
		if hash != expected {
			return fmt.Errorf("source changed before native publication: %s", name)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash, err := put(raw)
	if err != nil {
		return err
	}
	bundle.Capture.Artifacts["raw-native-report"] = hash
	if err = nativeevidence.VerifyBundle(ctx, os.DirFS(dir), ownedContract(), bundle, &execution); err != nil {
		return err
	}
	for name, value := range map[string]any{"contract.json": ownedContract(), "bundle.json": bundle} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0644); err != nil {
			return err
		}
	}
	return nil
}

func verifyOwnedBundle(ctx context.Context, dir, profile string) (nativeevidence.Bundle, error) {
	var bundle nativeevidence.Bundle
	if err := captureprovenance.VerifyExecution(ctx, dir); err != nil {
		return bundle, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return bundle, err
	}
	if err = json.Unmarshal(data, &bundle); err != nil {
		return bundle, err
	}
	if bundle.Observation.Profile != profile {
		return bundle, errors.New("wrong owned native producer profile")
	}
	execution, err := captureprovenance.CurrentExecution(ctx)
	if err != nil {
		return bundle, err
	}
	return bundle, nativeevidence.VerifyBundle(ctx, os.DirFS(dir), ownedContract(), bundle, &execution)
}

func ownedTranscriptPassed(raw []byte) error {
	return ownedTestCompleted(raw, "TestCompressionOwnedNativeEvidence")
}

func ownedTestCompleted(raw []byte, suite string) error {
	var started, passed, packagePassed bool
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		var event struct{ Action, Package, Test string }
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		if event.Package != "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata" {
			return errors.New("unexpected owned verification package")
		}
		if event.Action == "fail" || event.Action == "skip" {
			return errors.New("failed or skipped owned verification")
		}
		if event.Test != "" && event.Test != suite && !strings.HasPrefix(event.Test, suite+"/") {
			return errors.New("unexpected owned verification test")
		}
		if event.Test == suite {
			switch event.Action {
			case "run":
				if started {
					return errors.New("duplicate owned verification")
				}
				started = true
			case "pass":
				if !started || passed {
					return errors.New("invalid owned verification completion")
				}
				passed = true
			}
		}
		if event.Test == "" && event.Action == "pass" {
			if packagePassed {
				return errors.New("duplicate owned package completion")
			}
			packagePassed = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !started || !passed || !packagePassed {
		return errors.New("incomplete owned Go verification")
	}
	return nil
}

func qualifyOwnedCapture(dir, profile, consumer, output string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	declared := false
	for _, allowed := range ownedContract().Consumers {
		if consumer == allowed && consumer != "native-live" {
			declared = true
		}
	}
	if !declared {
		return errors.New("undeclared owned consumer")
	}
	if consumer == "linux" && runtime.GOOS != "linux" || strings.HasPrefix(consumer, "windows") && runtime.GOOS != "windows" || strings.HasPrefix(consumer, "macos") && runtime.GOOS != "darwin" {
		return errors.New("wrong owned verification host")
	}
	if strings.HasPrefix(consumer, "macos") {
		host, err := command(ctx, "sw_vers")
		if err != nil {
			return err
		}
		version, err := osversion.ParseProductVersion(string(host))
		if err != nil || consumer != fmt.Sprintf("macos%d", version.Major) {
			return errors.New("wrong owned receiver native profile")
		}
	}
	bundle, err := verifyOwnedBundle(ctx, dir, profile)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(output, 0755); err != nil {
		return err
	}
	path, err := filepath.Abs(filepath.Join(dir, "native.json.gz"))
	if err != nil {
		return err
	}
	cmd := cirunner.CommandContext(ctx, "go", "test", "-count=1", "-json", "./pkg/hostdata", "-run", "^TestCompressionOwnedNativeEvidence$")
	cmd.Env = append(os.Environ(), "APFS_COMPRESSION_OWNED_EVIDENCE="+path)
	transcript, runErr := cmd.CombinedOutput()
	writeErr := os.WriteFile(filepath.Join(output, profile+"-tests.jsonl"), transcript, 0644)
	if err = errors.Join(runErr, writeErr); err != nil {
		return err
	}
	if err = ownedTranscriptPassed(transcript); err != nil {
		return err
	}
	execution, err := captureprovenance.CurrentExecution(ctx)
	if err != nil {
		return err
	}
	receipt := nativeevidence.Receipt{Schema: 1, Contract: bundle.Observation.Contract, Observation: nativeevidence.ObservationDigest(bundle.Observation), Consumer: consumer, Execution: execution, Complete: true, Cases: map[string]string{}, Artifacts: map[string]string{profile + "-tests.jsonl": nativeevidence.Digest(transcript)}}
	for _, id := range ownedContract().Cases {
		receipt.Cases[id] = "pass"
	}
	if err = nativeevidence.VerifyReceipt(ownedContract(), bundle, receipt, execution); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, profile+"-receipt.json"), append(data, '\n'), 0644)
}

func aggregateOwnedCapture(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	execution, err := captureprovenance.CurrentExecution(ctx)
	if err != nil {
		return err
	}
	var bundles []nativeevidence.Bundle
	var receipts []nativeevidence.Receipt
	for _, producer := range []struct{ Runner, Profile string }{{"macos-15", "macos15"}, {"macos-latest", "macos26"}, {"xcode-27", "macos27"}} {
		bundle, err := verifyOwnedBundle(ctx, filepath.Join(dir, "compression-owned-capture-"+producer.Runner+"-"+os.Getenv("GITHUB_RUN_ATTEMPT")), producer.Profile)
		if err != nil {
			return err
		}
		bundles = append(bundles, bundle)
		for _, consumer := range ownedContract().Consumers {
			name := consumer
			if consumer == "native-live" {
				name += "-" + producer.Runner
			}
			path := filepath.Join(dir, "compression-owned-receipt-"+name+"-"+os.Getenv("GITHUB_RUN_ATTEMPT"), producer.Profile+"-receipt.json")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var receipt nativeevidence.Receipt
			if err = json.Unmarshal(data, &receipt); err != nil {
				return err
			}
			if receipt.Consumer != consumer {
				return errors.New("mixed owned consumer receipt path")
			}
			if consumer == "native-live" {
				if err := verifyOwnedLiveArtifacts(filepath.Dir(path), receipt.Artifacts); err != nil {
					return err
				}
				receipts = append(receipts, receipt)
				continue
			}
			if len(receipt.Artifacts) != 1 || receipt.Artifacts[producer.Profile+"-tests.jsonl"] == "" {
				return errors.New("incomplete owned consumer artifact inventory")
			}
			transcript, err := os.ReadFile(filepath.Join(filepath.Dir(path), producer.Profile+"-tests.jsonl"))
			if err != nil {
				return err
			}
			if nativeevidence.Digest(transcript) != receipt.Artifacts[producer.Profile+"-tests.jsonl"] {
				return errors.New("changed owned Go verification transcript")
			}
			if err = ownedTranscriptPassed(transcript); err != nil {
				return err
			}
			receipts = append(receipts, receipt)
		}
	}
	return nativeevidence.Aggregate([]nativeevidence.Contract{ownedContract()}, bundles, receipts, execution)
}

func ownedLiveTranscriptPassed(raw []byte, filesystem string) error {
	const suite = "TestNativeCompressionOwnedMounted"
	if err := ownedTestCompleted(raw, suite); err != nil {
		return err
	}
	wanted := map[string]bool{}
	for compressed := 0; compressed <= 2; compressed++ {
		for _, route := range []string{"direct", "root"} {
			for _, mutation := range []string{"none", "root-before", "root-after", "leaf-after"} {
				wanted[fmt.Sprintf("%s/%s/%d/%s/%s", suite, filesystem, compressed, route, mutation)] = true
			}
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 16<<20)
	for scanner.Scan() {
		var event struct{ Action, Test string }
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		if event.Action != "pass" || event.Test == "" || event.Test == suite {
			continue
		}
		if !wanted[event.Test] {
			return fmt.Errorf("unexpected or duplicate live owned case %s", event.Test)
		}
		delete(wanted, event.Test)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(wanted) != 0 {
		return fmt.Errorf("missing live owned cases: %d", len(wanted))
	}
	return nil
}

func verifyOwnedLiveArtifacts(dir string, artifacts map[string]string) error {
	if len(artifacts) != 3 {
		return errors.New("incomplete live owned verification artifacts")
	}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		name := strings.ReplaceAll(filesystem, "+", "plus") + "-replay.jsonl"
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if nativeevidence.Digest(data) != artifacts[name] {
			return errors.New("changed live owned verification transcript")
		}
		if err = ownedLiveTranscriptPassed(data, filesystem); err != nil {
			return err
		}
	}
	return nil
}

// Publish only after live replay and every mount/temp cleanup have succeeded.
func recordOwnedLiveReceipt(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	report, err := readCapture(path)
	if err != nil {
		return err
	}
	version, err := osversion.ParseProductVersion(report.Host)
	if err != nil {
		return err
	}
	profile := fmt.Sprintf("macos%d", version.Major)
	bundle, err := verifyOwnedBundle(ctx, filepath.Dir(path), profile)
	if err != nil {
		return err
	}
	const output = "artifacts/compression-owned-replay"
	artifacts := map[string]string{}
	for _, filesystem := range []string{"host", "APFS", "HFS+"} {
		name := strings.ReplaceAll(filesystem, "+", "plus") + "-replay.jsonl"
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			return err
		}
		artifacts[name] = nativeevidence.Digest(data)
	}
	if err = verifyOwnedLiveArtifacts(output, artifacts); err != nil {
		return err
	}
	execution, err := captureprovenance.CurrentExecution(ctx)
	if err != nil {
		return err
	}
	receipt := nativeevidence.Receipt{Schema: 1, Contract: bundle.Observation.Contract, Observation: nativeevidence.ObservationDigest(bundle.Observation), Consumer: "native-live", Execution: execution, Complete: true, Cases: map[string]string{}, Artifacts: artifacts}
	for _, id := range ownedContract().Cases {
		receipt.Cases[id] = "pass"
	}
	if err = nativeevidence.VerifyReceipt(ownedContract(), bundle, receipt, execution); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, profile+"-receipt.json"), append(data, '\n'), 0644)
}
