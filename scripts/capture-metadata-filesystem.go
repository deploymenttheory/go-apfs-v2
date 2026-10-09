//go:build ignore

// Capture filesystem-selected AppleDouble visibility independently of the Go codec.
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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

var metadataStates = []string{"absent", "sidecar", "truncated", "bad-magic", "empty", "directory", "seeded", "seeded-equal", "seeded-conflict", "readonly"}
var metadataActions = []string{"read", "set", "create", "replace", "remove", "remove-fork", "remove-finder", "zero-finder", "set-fork", "create-fork", "replace-fork", "empty-plain"}
var metadataFilesystems = []string{"ExFAT", "MS-DOS FAT32", "APFS", "HFS+"}

type metadataCase struct {
	ID          string                   `json:"id"`
	Before      map[string]metadataEntry `json:"before"`
	Observation json.RawMessage          `json:"observation"`
	After       map[string]metadataEntry `json:"after"`
}
type metadataEntry struct {
	Mode   uint32 `json:"mode"`
	Bytes  []byte `json:"bytes,omitempty"`
	Target string `json:"target,omitempty"`
}
type metadataCapture struct {
	Profile      string            `json:"profile,omitempty"`
	Schema       int               `json:"schema"`
	Complete     bool              `json:"complete"`
	GoReadCases  int               `json:"go_read_cases"`
	Host         string            `json:"host"`
	Compiler     string            `json:"compiler"`
	SDK          string            `json:"sdk"`
	Architecture string            `json:"architecture"`
	GoVersion    string            `json:"go_version"`
	Sources      map[string]string `json:"sources"`
	Seed         []byte            `json:"seed"`
	Cases        []metadataCase    `json:"cases"`
}

func metadataCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var stderr bytes.Buffer
	cmd := cirunner.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w\n%s", name, args, err, stderr.Bytes())
	}
	return b, nil
}

func metadataTree(root string) (map[string]metadataEntry, error) {
	result := map[string]metadataEntry{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		value := metadataEntry{Mode: uint32(info.Mode())}
		path := filepath.Join(root, entry.Name())
		if info.Mode().IsRegular() {
			value.Bytes, err = os.ReadFile(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			value.Target, err = os.Readlink(path)
		}
		if err != nil {
			return nil, err
		}
		result[entry.Name()] = value
	}
	return result, nil
}

func prepareMetadataCase(root, state, kind string, seed []byte, oracle string) error {
	path := filepath.Join(root, "input")
	var err error
	if kind == "directory" {
		err = os.Mkdir(path, 0755)
	} else {
		err = os.WriteFile(path, []byte("payload"), 0644)
	}
	if err != nil {
		return err
	}
	// Remove the sidecar the host may have created for provenance during fixture creation.
	// The absent/seeded states then describe the explicitly prepared storage.
	if err := os.Remove(filepath.Join(root, "._input")); err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.HasPrefix(state, "seeded") {
		action := "seed"
		if state == "seeded-conflict" {
			action = "seed-different"
		}
		if _, err := metadataCommand(oracle, path, action); err != nil {
			return err
		}
	}
	if state == "absent" || state == "seeded" {
		return nil
	}
	data := bytes.Clone(seed)
	sidecar := filepath.Join(root, "._input")
	switch state {
	case "truncated":
		data = data[:20]
	case "bad-magic":
		data[0] ^= 0xff
	case "empty":
		data = nil
	case "directory":
		return os.Mkdir(sidecar, 0755)

	}
	if err := os.WriteFile(sidecar, data, 0644); err != nil {
		return err
	}
	if state == "readonly" {
		return os.Chmod(sidecar, 0444)
	}
	return nil
}

// FAT has no stored Unix ownership. Use its normal shared-volume mount mode;
// forcing owners on makes fixture access depend on the mount service's identity
// (which can differ from the unprivileged CI runner). APFS/HFS+ retain ownership.
// File modes, including readonly sidecars, remain enforced in either mode.
func metadataMountOwnership(filesystem string) string {
	if filesystem == "ExFAT" || filesystem == "MS-DOS FAT32" {
		return "off"
	}
	return "on"
}

func captureMetadataFilesystem(out, profile string) (result error) {
	states, err := metadataProfileStates(profile)
	if err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native metadata capture requires macOS")
	}
	artifact, err := filepath.Abs(filepath.Dir(out))
	if err != nil {
		return err
	}
	if err = os.MkdirAll(artifact, 0755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "metadata-filesystem-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(work)) }()
	capture := metadataCapture{Schema: 1, Profile: profile, Sources: map[string]string{}}
	defer func() {
		encoded, err := json.MarshalIndent(capture, "", "  ")
		if err == nil {
			err = os.WriteFile(out, append(encoded, '\n'), 0644)
		}
		result = errors.Join(result, err)
	}()
	if err = captureprovenance.Bind(os.DirFS("."), artifact, capture.Sources); err != nil {
		return err
	}
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	const source = "testdata/appledouble/native/metadata-filesystem.c"
	for _, path := range []string{source, "scripts/capture-metadata-filesystem.go", "internal/testutil/diskimage/attachment.go", "internal/testutil/diskimage/detach.go", "internal/testutil/diskimage/create.go", "go.mod", "go.sum", "testdata/appledouble/native/metadata-vfs-ast.c", "testdata/appledouble/native/metadata-vfs-bodies.inc", "testdata/appledouble/native/metadata-vfs-xnu.c.gz", "testdata/appledouble/native/metadata-vfs-source.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		capture.Sources[path] = hash(data)
	}
	implementations, err := filepath.Glob("pkg/hostdata/filesystem_metadata*.go")
	if err != nil {
		return err
	}
	for _, path := range implementations {
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		capture.Sources[path] = hash(data)
	}
	host, err := metadataCommand("sw_vers")
	if err != nil {
		return err
	}
	capture.Host = string(host)
	capture.Architecture = runtime.GOARCH
	capture.GoVersion = runtime.Version()
	compiler, err := metadataCommand("xcrun", "clang", "--version")
	if err != nil {
		return err
	}
	capture.Compiler = string(compiler)
	sdk, err := metadataCommand("xcrun", "--show-sdk-path")
	if err != nil {
		return err
	}
	capture.SDK = strings.TrimSpace(string(sdk))
	for _, name := range []string{"sys/xattr.h", "sys/stat.h", "sys/mount.h", "copyfile.h", "sys/kauth.h"} {
		b, e := os.ReadFile(filepath.Join(capture.SDK, "usr/include", name))
		if e != nil {
			return e
		}
		capture.Sources["sdk/"+name] = hash(b)
	}
	oracle := filepath.Join(work, "oracle")
	if _, err = metadataCommand("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", oracle); err != nil {
		return err
	}
	oracleBytes, err := os.ReadFile(oracle)
	if err != nil {
		return err
	}
	capture.Sources["oracle.bin"] = hash(oracleBytes)
	if err = os.WriteFile(filepath.Join(artifact, "oracle.bin"), oracleBytes, 0600); err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, err := metadataCommand("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", source)
		if err != nil {
			return err
		}
		if !json.Valid(ast) || !bytes.Contains(ast, []byte("fgetxattr")) || !bytes.Contains(ast, []byte("observe")) {
			return fmt.Errorf("invalid %s AST", arch)
		}
		name := arch + ".ast.json"
		capture.Sources[name] = hash(ast)
		if err = os.WriteFile(filepath.Join(artifact, name), ast, 0644); err != nil {
			return err
		}
	}
	if err = metadataVFSAST(artifact, capture.Sources); err != nil {
		return err
	}
	seedPath := filepath.Join(work, "seed")
	if err = os.WriteFile(seedPath, []byte("payload"), 0644); err != nil {
		return err
	}
	seedAction := "seed"
	if profile == "packed-empty" {
		seedAction = "seed-empty"
	}
	installed, err := metadataCommand(oracle, seedPath, seedAction)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(artifact, "seed-install.json"), installed, 0644); err != nil {
		return err
	}
	if _, err = metadataCommand(oracle, seedPath, "pack"); err != nil {
		return err
	}
	seed, err := os.ReadFile(seedPath + ".packed")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(artifact, "seed.appledouble"), seed, 0644); err != nil {
		return err
	}
	capture.Sources["seed.appledouble"] = hash(seed)
	capture.Seed = bytes.Clone(seed)
	if err = validateMetadataProfileSeed(seed, profile); err != nil {
		return err
	}
	for fi, filesystem := range metadataFilesystems {
		err = func() (result error) {
			image := filepath.Join(work, fmt.Sprintf("image-%d.dmg", fi))
			mount := filepath.Join(work, fmt.Sprintf("mount-%d", fi))
			if err := os.Mkdir(mount, 0700); err != nil {
				return err
			}
			createContext, cancelCreate := context.WithTimeout(context.Background(), 2*time.Minute)
			createError := diskimage.Create(createContext, image, filesystem, "METADATA")
			cancelCreate()
			if createError != nil {
				return createError
			}
			attached, err := metadataCommand("hdiutil", "attach", "-plist", "-nobrowse", "-owners", metadataMountOwnership(filesystem), "-mountpoint", mount, image)
			if err != nil {
				return err
			}
			device := mount
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				result = errors.Join(result, diskimage.RetryDetach(ctx, func() (int, error) {
					cmd := cirunner.CommandContext(ctx, "hdiutil", "detach", device)
					cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
					err := cmd.Run()
					code := -1
					if cmd.ProcessState != nil {
						code = cmd.ProcessState.ExitCode()
					}
					return code, err
				}))
			}()
			backing, parseErr := diskimage.AttachmentDevice(attached)
			if parseErr != nil {
				return parseErr
			}
			device = backing
			if err = os.WriteFile(filepath.Join(artifact, fmt.Sprintf("attach-%d.plist", fi)), attached, 0600); err != nil {
				return err
			}
			// Record actual credentials and mount permissions before fixture creation,
			// so a setup failure still leaves useful native evidence in CI artifacts.
			diagnostic, err := metadataCommand(oracle, mount, "mount")
			if err != nil {
				return err
			}
			if !json.Valid(diagnostic) {
				return fmt.Errorf("invalid mount diagnostic for %s", filesystem)
			}
			name := fmt.Sprintf("mount-%d.json", fi)
			if err = os.WriteFile(filepath.Join(artifact, name), diagnostic, 0600); err != nil {
				return err
			}
			capture.Sources[name] = hash(diagnostic)
			fmt.Printf("MOUNT %s owners=%s %s", filesystem, metadataMountOwnership(filesystem), diagnostic)
			for _, kind := range []string{"file", "directory"} {
				for _, state := range states {
					for _, action := range metadataActions {
						id := fmt.Sprintf("%s/%s/%s/%s", filesystem, kind, state, action)
						// Keep cases independent until the volume is detached. Removing
						// an attribute-file target on mounted ExFAT can stall on macOS 15.
						root := filepath.Join(mount, fmt.Sprintf("case-%04d", len(capture.Cases)))
						if err = os.Mkdir(root, 0755); err != nil {
							return fmt.Errorf("create case directory %s: %w", id, err)
						}
						if err = prepareMetadataCase(root, state, kind, seed, oracle); err != nil {
							return fmt.Errorf("prepare %s: %w", id, err)
						}
						target := "input"
						if profile == "attribute-target" {
							target = "._input"
							if state == "sidecar" {
								if err = os.Rename(filepath.Join(root, "._input"), filepath.Join(root, "._._input")); err != nil {
									return err
								}
							}
							if err = os.Rename(filepath.Join(root, "input"), filepath.Join(root, target)); err != nil {
								return err
							}
						}
						before, err := metadataTree(root)
						if err != nil {
							return err
						}
						b, err := metadataCommand(oracle, filepath.Join(root, target), action)
						if err != nil {
							return fmt.Errorf("observe %s: %w", id, err)
						}
						if !json.Valid(b) {
							return fmt.Errorf("invalid oracle JSON: %s", id)
						}
						after, err := metadataTree(root)
						if err != nil {
							return err
						}
						capture.Cases = append(capture.Cases, metadataCase{id, before, b, after})
						if err = qualifyMetadataFilesystemRead(root, target, b); err != nil {
							return fmt.Errorf("Go/native readback %s: %w", id, err)
						}
						capture.GoReadCases++
						fmt.Printf("CASE %s (%d)\n", id, len(capture.Cases))
					}
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	capture.Complete = true
	if err = validateMetadataCapture(capture); err != nil {
		capture.Complete = false
		return err
	}
	return nil
}

// This validates evidence membership and native input controls, not Go parity.
func metadataProfileStates(profile string) ([]string, error) {
	switch profile {
	case "":
		return metadataStates, nil
	case "packed-empty":
		return []string{"sidecar"}, nil
	case "attribute-target":
		return []string{"absent", "sidecar"}, nil
	default:
		return nil, fmt.Errorf("unknown filesystem metadata profile %q", profile)
	}
}

func validateMetadataProfileSeed(seed []byte, profile string) error {
	f, err := appledouble.Decode(seed)
	if err != nil {
		return err
	}
	attrs := f.Xattrs()
	for _, name := range []string{"com.example.phase2", appledouble.ResourceForkName} {
		expected := []byte("native-value")
		if profile == "packed-empty" && name == "com.example.phase2" {
			expected = nil
		}
		actual, present := attrs[name]
		if !present || !bytes.Equal(actual, expected) {
			return fmt.Errorf("native seed missing %s", name)
		}
	}
	if len(attrs[appledouble.FinderInfoName]) != 32 || string(attrs[appledouble.FinderInfoName][:4]) != "TEST" {
		return errors.New("native seed FinderInfo mismatch")
	}
	return nil
}

func metadataVFSAST(out string, sources map[string]string) error {
	const root = "testdata/appledouble/native/"
	compressed, err := os.ReadFile(root + "metadata-vfs-xnu.c.gz")
	if err != nil {
		return err
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	body, err := io.ReadAll(z)
	if err = errors.Join(err, z.Close()); err != nil {
		return err
	}
	manifestBytes, err := os.ReadFile(root + "metadata-vfs-source.json")
	if err != nil {
		return err
	}
	var manifest struct {
		SHA256 string `json:"sha256"`
	}
	if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != manifest.SHA256 {
		return errors.New("pinned XNU source changed")
	}
	fragment, err := os.ReadFile(root + "metadata-vfs-bodies.inc")
	if err != nil {
		return err
	}
	if !bytes.Contains(body, bytes.TrimSuffix(fragment, []byte("\n"))) {
		return errors.New("XNU bodies are not a complete verbatim source range")
	}
	for _, name := range []string{"vn_getxattr", "vn_setxattr", "vn_removexattr", "vn_listxattr"} {
		if bytes.Count(fragment, []byte("\n"+name+"(")) != 1 {
			return fmt.Errorf("missing/duplicate complete body %s", name)
		}
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, err := metadataCommand("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-Xclang", "-ast-dump=json", "-fsyntax-only", root+"metadata-vfs-ast.c")
		if err != nil {
			return err
		}
		if !json.Valid(b) {
			return fmt.Errorf("invalid VFS AST %s", arch)
		}
		name := arch + ".vfs.ast.json"
		sum := sha256.Sum256(b)
		sources[name] = hex.EncodeToString(sum[:])
		if err = os.WriteFile(filepath.Join(out, name), b, 0644); err != nil {
			return err
		}
	}
	return nil
}

func validateMetadataCapture(c metadataCapture) error {
	states, err := metadataProfileStates(c.Profile)
	if err != nil {
		return err
	}
	if c.Schema != 1 || !c.Complete || c.Compiler == "" || c.SDK == "" || c.Architecture == "" || c.GoVersion == "" {
		return errors.New("incomplete native metadata capture")
	}
	v, err := osversion.ParseProductVersion(c.Host)
	if err != nil {
		return err
	}
	if _, err = osversion.ProfileForMacOS(v); err != nil {
		return err
	}
	if len(c.Sources) == 0 {
		return errors.New("missing source provenance")
	}
	for path, value := range c.Sources {
		b, e := hex.DecodeString(value)
		if e != nil || len(b) != sha256.Size || path == "" {
			return errors.New("invalid source provenance")
		}
	}
	seedHash := sha256.Sum256(c.Seed)
	if c.Sources["seed.appledouble"] != hex.EncodeToString(seedHash[:]) {
		return errors.New("seed provenance mismatch")
	}
	if err = validateMetadataProfileSeed(c.Seed, c.Profile); err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, fs := range metadataFilesystems {
		for _, kind := range []string{"file", "directory"} {
			for _, state := range states {
				for _, action := range metadataActions {
					expected[fs+"/"+kind+"/"+state+"/"+action] = true
				}
			}
		}
	}
	if c.GoReadCases != 0 && c.GoReadCases != len(expected) {
		return errors.New("incomplete Go/native readback")
	}
	if len(c.Cases) != len(expected) {
		return fmt.Errorf("metadata case count %d, require %d", len(c.Cases), len(expected))
	}
	for _, record := range c.Cases {
		if !expected[record.ID] {
			return fmt.Errorf("unexpected/duplicate case %s", record.ID)
		}
		delete(expected, record.ID)
		if record.Before == nil || record.After == nil {
			return fmt.Errorf("missing tree observation %s", record.ID)
		}
		var observation struct {
			Filesystem string `json:"filesystem"`

			OpenErrno  int `json:"open_errno"`
			CloseErrno int `json:"close_errno"`
		}
		// A map retains the exact lower-case oracle field names.
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(record.Observation, &fields); err != nil {
			return err
		}
		required := []string{"filesystem", "volume_flags", "open_errno", "before_path", "before_held", "result", "errno", "after_path", "after_held", "close_errno"}
		if len(fields) != len(required) {
			return errors.New("incomplete native observation fields")
		}
		for _, name := range required {
			if _, ok := fields[name]; !ok {
				return fmt.Errorf("missing oracle field %s", name)
			}
		}
		if err = json.Unmarshal(record.Observation, &observation); err != nil {
			return err
		}
		if !slices.Contains([]string{"apfs", "hfs", "exfat", "msdos"}, observation.Filesystem) {
			return fmt.Errorf("unknown actual filesystem %s", observation.Filesystem)
		}
		if observation.OpenErrno != 0 || observation.CloseErrno != 0 {
			return fmt.Errorf("oracle handle failure %s", record.ID)
		}
		for _, field := range []string{"before_path", "before_held", "after_path", "after_held"} {
			var value struct {
				Attributes []struct {
					Name      string `json:"name"`
					Size      int    `json:"size"`
					SizeErrno int    `json:"size_errno"`
					Read      int    `json:"read"`
					ReadErrno int    `json:"read_errno"`
					Bytes     string `json:"bytes"`
				}
				ListResult int    `json:"list_result"`
				ListErrno  int    `json:"list_errno"`
				ListBytes  string `json:"list_bytes"`
			}
			if err = json.Unmarshal(fields[field], &value); err != nil {
				return err
			}
			if len(value.Attributes) != 3 {
				return fmt.Errorf("missing attribute observations %s %s", record.ID, field)
			}
			for i, a := range value.Attributes {
				if a.Name != []string{"com.example.phase2", appledouble.FinderInfoName, appledouble.ResourceForkName}[i] {
					return errors.New("wrong attribute inventory")
				}
				b, e := hex.DecodeString(a.Bytes)
				if e != nil {
					return e
				}
				if (a.Read < 0) != (a.ReadErrno != 0) || (a.Size < 0) != (a.SizeErrno != 0) || (a.Read >= 0 && a.Read != len(b)) || (a.Read < 0 && len(b) != 0) {
					return errors.New("inconsistent native attribute result")
				}
			}
			b, e := hex.DecodeString(value.ListBytes)
			if e != nil {
				return e
			}
			if (value.ListResult < 0) != (value.ListErrno != 0) || (value.ListResult >= 0 && value.ListResult != len(b)) {
				return errors.New("inconsistent native list result")
			}
		}
	}
	return nil
}

func readMetadataCapture(path string) (metadataCapture, error) {
	var result metadataCapture
	b, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	if strings.HasSuffix(path, ".gz") {
		z, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			return result, e
		}
		b, err = io.ReadAll(z)
		err = errors.Join(err, z.Close())
		if err != nil {
			return result, err
		}
	}
	err = json.Unmarshal(b, &result)
	return result, err
}

// The C observation is already captured independently; this verifies the live
// public Go view against its complete visible attribute names and values.
func qualifyMetadataFilesystemRead(path, target string, raw json.RawMessage) (err error) {
	var o struct {
		After struct {
			Attributes []struct {
				Name      string
				ReadErrno int `json:"read_errno"`
				Bytes     string
			}
			ListBytes string `json:"list_bytes"`
			ListErrno int    `json:"list_errno"`
		} `json:"after_held"`
	}
	if err = json.Unmarshal(raw, &o); err != nil {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	view, err := hostdata.OpenFilesystemMetadata(context.Background(), root, target)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, view.Close()) }()
	names, listErr := view.List(context.Background(), hostdata.MaxXattrListSize)
	if o.After.ListErrno == 1 {
		if !errors.Is(listErr, syscall.EPERM) {
			return fmt.Errorf("Go/native list EPERM mismatch: %v", listErr)
		}
	} else if o.After.ListErrno == 93 {
		if !errors.Is(listErr, hostdata.ErrXattrNotFound) {
			return fmt.Errorf("Go/native list ENOATTR mismatch: %v", listErr)
		}
	} else if listErr != nil || o.After.ListErrno != 0 {
		return fmt.Errorf("Go/native list error mismatch: native=%d Go=%v", o.After.ListErrno, listErr)
	}
	var listed strings.Builder
	for _, name := range names {
		listed.WriteString(name)
		listed.WriteByte(0)
	}
	if hex.EncodeToString([]byte(listed.String())) != o.After.ListBytes {
		return errors.New("Go/native name list mismatch")
	}
	for _, attr := range o.After.Attributes {
		value, present, e := view.Read(context.Background(), attr.Name, 65536)
		if attr.ReadErrno != 0 && attr.ReadErrno != 93 {
			var errno syscall.Errno
			if present || !errors.As(e, &errno) || int(errno) != attr.ReadErrno {
				return fmt.Errorf("Go/native read errno mismatch %s: native=%d Go=%v", attr.Name, attr.ReadErrno, e)
			}
			continue
		}
		if e != nil {
			return fmt.Errorf("%s: %w", attr.Name, e)
		}
		if present != (attr.ReadErrno == 0) || hex.EncodeToString(value) != attr.Bytes {
			return fmt.Errorf("Go/native value mismatch: %s", attr.Name)
		}
	}
	return nil
}

func main() {
	profile := flag.String("profile", "", "native input profile: default, packed-empty or attribute-target")
	out := flag.String("out", "artifacts/metadata-filesystem/native.json", "native capture path")
	verify := flag.String("verify", "", "validate a complete native capture without executing native commands")
	major := flag.Uint("major", 0, "require the native producer's macOS major version")
	flag.Parse()
	var err error
	if *verify != "" {
		var capture metadataCapture
		capture, err = readMetadataCapture(*verify)
		if err == nil {
			err = validateMetadataCapture(capture)
		}
		if err == nil && *profile != "" && capture.Profile != *profile {
			err = errors.New("wrong native input profile")
		}
		if err == nil && *major != 0 {
			var v osversion.Version
			v, err = osversion.ParseProductVersion(capture.Host)
			if err == nil && uint(v.Major) != *major {
				err = errors.New("wrong native producer version")
			}
		}
	} else {
		if *major != 0 {
			var v osversion.Version
			v, err = osversion.Detect(context.Background())
			if err == nil && uint(v.Major) != *major {
				err = errors.New("wrong native capture runner version")
			}
		}
		if err == nil {
			err = captureMetadataFilesystem(*out, *profile)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
