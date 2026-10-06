//go:build ignore

// Capture native HFS special components and independent raw catalog keys.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"strings"
	"time"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

const specialSource = "testdata/appledouble/native/hfs-special-names.c"

type specialNative struct {
	Filesystem string
	Flags      uint32
	Sensitive  bool `json:"case_sensitive"`
	Count      int
	Cases      []specialCase
}
type specialCase struct {
	ID          string
	Name        string `json:"name_hex"`
	Parent      uint64
	CreateErrno int `json:"create_errno"`
	Inode       uint64
	LookupErrno int    `json:"lookup_errno"`
	LookupInode uint64 `json:"lookup_inode"`
	Stored      []struct {
		Hex   string
		Inode uint64
	}
}
type specialRecord struct {
	Parent, Inode uint32
	UTF16         []uint16
	Key, Value    string
}
type specialVolume struct {
	Kind        string
	Native      specialNative
	Raw         []specialRecord
	ImageSHA256 string
	Detach      []string
}
type specialCapture struct {
	Schema                        int
	Host, Compiler, SDK, Revision string
	Sources                       map[string]string
	Volumes                       []specialVolume
}

func specialHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func specialCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w: %s", name, args, e, b)
	}
	return b, nil
}
func main() {
	out := flag.String("out", "artifacts/hfs-special-names", "native evidence directory")
	flag.Parse()
	if err := captureSpecial(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func captureSpecial(out string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native HFS capture requires Darwin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	out, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		return err
	}
	host, err := specialCommand(ctx, "sw_vers")
	if err != nil {
		return err
	}
	version, err := osversion.ParseProductVersion(string(host))
	if err != nil {
		return err
	}
	if _, err = osversion.ProfileForMacOS(version); err != nil {
		return err
	}
	compiler, err := specialCommand(ctx, "xcrun", "clang", "--version")
	if err != nil {
		return err
	}
	sdk, err := specialCommand(ctx, "xcrun", "--show-sdk-path")
	if err != nil {
		return err
	}
	revision, err := specialCommand(ctx, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	report := specialCapture{Schema: 1, Host: string(host), Compiler: string(compiler), SDK: strings.TrimSpace(string(sdk)), Revision: strings.TrimSpace(string(revision)), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), out, report.Sources); err != nil {
		return err
	}
	for _, p := range []string{specialSource, "scripts/capture-hfs-special-names.go", "testdata/appledouble/native/name-comparison-source/vfs_utfconv.c.gz", "testdata/appledouble/native/name-comparison-source/sources.json", "go.mod", "go.sum"} {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		report.Sources[p] = specialHash(b)
	}
	binaryPath := filepath.Join(out, "probe")
	if _, err = specialCommand(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", specialSource, "-o", binaryPath); err != nil {
		return err
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		b, e := specialCommand(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-target", arch+"-apple-macos15.0", "-isysroot", report.SDK, "-Xclang", "-ast-dump=json", "-fsyntax-only", specialSource)
		if e != nil {
			return e
		}
		p := arch + ".ast.json"
		report.Sources[p] = specialHash(b)
		if e = os.WriteFile(filepath.Join(out, p), b, 0644); e != nil {
			return e
		}
	}
	for _, header := range []string{"sys/stat.h", "sys/mount.h", "sys/attr.h", "sys/fcntl.h", "dirent.h", "unistd.h", "sys/errno.h"} {
		b, e := os.ReadFile(filepath.Join(report.SDK, "usr/include", header))
		if e != nil {
			return e
		}
		p := "SDK/" + header
		report.Sources[p] = specialHash(b)
		dest := filepath.Join(out, p)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			return e
		}
	}
	probe, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	report.Sources["native-binary"] = specialHash(probe)
	for _, kind := range []string{"HFS+", "HFSX"} {
		v, e := captureSpecialVolume(ctx, out, kind, binaryPath)
		if e != nil {
			return e
		}
		report.Volumes = append(report.Volumes, v)
	}
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	err = json.NewEncoder(z).Encode(report)
	if err = errors.Join(err, z.Close()); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "native.json.gz"), compressed.Bytes(), 0644); err != nil {
		return err
	}
	fmt.Printf("26 independent HFS component creations, lookup/readdir identities, full payloads and raw catalog keys on macOS%d\n", version.Major)
	return nil
}
func captureSpecialVolume(ctx context.Context, out, kind, probe string) (result specialVolume, err error) {
	result.Kind = kind
	stem := strings.ReplaceAll(kind, "+", "plus")
	image := filepath.Join(out, stem+".dmg")
	mount := filepath.Join(out, stem+"-mount")
	if err = os.Mkdir(mount, 0700); err != nil {
		return result, err
	}
	if _, err = specialCommand(ctx, "hdiutil", "create", "-size", "64m", "-fs", kind, "-volname", "Names", image); err != nil {
		return result, err
	}
	attached, err := specialCommand(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	if err != nil {
		return result, err
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = mount
	}
	detach := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		e := diskimage.RetryDetach(cleanup, func() (int, error) {
			b, e := cirunner.CommandContext(cleanup, "hdiutil", "detach", device).CombinedOutput()
			result.Detach = append(result.Detach, string(b))
			code := 0
			if e != nil {
				code = -1
				var exit *exec.ExitError
				if errors.As(e, &exit) {
					code = exit.ExitCode()
				}
			}
			return code, e
		})
		if e == nil {
			device = ""
			e = os.Remove(mount)
		}
		return e
	}
	defer func() {
		if device != "" {
			err = errors.Join(err, detach())
		}
	}()
	if err = os.WriteFile(filepath.Join(out, stem+"-attach.plist"), attached, 0644); err != nil {
		return result, err
	}
	if parseErr != nil {
		return result, parseErr
	}
	raw, err := specialCommand(ctx, probe, mount)
	if err != nil {
		return result, err
	}
	if err = os.WriteFile(filepath.Join(out, stem+"-native.json"), raw, 0644); err != nil {
		return result, err
	}
	if err = json.Unmarshal(raw, &result.Native); err != nil {
		return result, err
	}
	if err = detach(); err != nil {
		return result, err
	}
	result.Raw, err = readSpecialCatalog(image)
	if err != nil {
		return result, err
	}
	raw, err = json.MarshalIndent(result.Raw, "", "  ")
	if err != nil {
		return result, err
	}
	if err = os.WriteFile(filepath.Join(out, stem+"-raw.json"), raw, 0644); err != nil {
		return result, err
	}
	raw, err = os.ReadFile(image)
	if err != nil {
		return result, err
	}
	result.ImageSHA256 = specialHash(raw)
	if err = validateSpecial(result); err != nil {
		return result, err
	}
	return result, nil
}
func readSpecialCatalog(image string) ([]specialRecord, error) {
	reader, offset, closer, err := disk.OpenWithOffset(image)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	reader = io.NewSectionReader(reader, offset, 1<<40)
	h := make([]byte, 512)
	if _, err = reader.ReadAt(h, 1024); err != nil {
		return nil, err
	}
	u16 := binary.BigEndian.Uint16
	u32 := binary.BigEndian.Uint32
	block := u32(h[40:])
	start := int64(u32(h[288:])) * int64(block)
	size := int64(u32(h[292:])) * int64(block)
	if size < int64(binary.BigEndian.Uint64(h[272:])) {
		return nil, errors.New("native fixture catalog unexpectedly fragmented")
	}
	header := make([]byte, 128)
	if _, err = reader.ReadAt(header, start); err != nil {
		return nil, err
	}
	nodeSize := int(u16(header[32:]))
	if nodeSize < 512 {
		return nil, errors.New("catalog node size")
	}
	leaf := u32(header[24:])
	var rows []specialRecord
	seen := map[uint32]bool{}
	for leaf != 0 {
		if seen[leaf] {
			return nil, errors.New("catalog leaf cycle")
		}
		seen[leaf] = true
		b := make([]byte, nodeSize)
		if _, err = reader.ReadAt(b, start+int64(leaf)*int64(nodeSize)); err != nil {
			return nil, err
		}
		if int8(b[8]) != -1 {
			return nil, errors.New("non-leaf")
		}
		count := int(u16(b[10:]))
		if count*2 > nodeSize-14 {
			return nil, errors.New("catalog record count")
		}
		for i := 0; i < count; i++ {
			a := int(u16(b[len(b)-2*(i+1):]))
			z := int(u16(b[len(b)-2*(i+2):]))
			if a < 14 || a+2 > z || z > nodeSize-2*(count+1) {
				return nil, errors.New("catalog record bounds")
			}
			n := int(u16(b[a:]))
			if a+2+n > z {
				return nil, errors.New("catalog key bounds")
			}
			key := b[a+2 : a+2+n]
			value := b[a+2+n : z]
			if len(key) < 6 || len(value) < 12 {
				return nil, errors.New("short catalog record")
			}
			if u16(value) != 2 {
				continue
			}
			units := make([]uint16, u16(key[4:]))
			if len(key) != 6+len(units)*2 {
				return nil, errors.New("catalog name length")
			}
			for j := range units {
				units[j] = u16(key[6+2*j:])
			}
			rows = append(rows, specialRecord{Parent: u32(key), Inode: u32(value[8:]), UTF16: units, Key: hex.EncodeToString(key), Value: hex.EncodeToString(value)})
		}
		leaf = u32(b)
	}
	return rows, nil
}
func validateSpecial(v specialVolume) error {
	names := []string{"plain", ".", "..", ".\u200d", "\u200d.", "..\u200d", "\u200d..", "\u200d", "x\u2400y", "\u2400", "x\uffffy", "x%EF%BF%BFy", "x:y"}
	for _, r := range v.Raw {
		key, e := hex.DecodeString(r.Key)
		if e != nil {
			return e
		}
		value, e := hex.DecodeString(r.Value)
		if e != nil {
			return e
		}
		if len(key) != 6+2*len(r.UTF16) || len(value) < 12 || binary.BigEndian.Uint16(value) != 2 || binary.BigEndian.Uint32(key) != r.Parent || binary.BigEndian.Uint32(value[8:]) != r.Inode || int(binary.BigEndian.Uint16(key[4:])) != len(r.UTF16) {
			return errors.New("raw catalog record mismatch")
		}
		for j, u := range r.UTF16 {
			if binary.BigEndian.Uint16(key[6+2*j:]) != u {
				return errors.New("raw catalog name mismatch")
			}
		}
	}
	if v.Native.Filesystem != "hfs" || v.Native.Sensitive != (v.Kind == "HFSX") || v.Native.Count != 13 || len(v.Native.Cases) != 13 || len(v.Detach) == 0 {
		return errors.New("incomplete special-name native inventory")
	}
	for i, c := range v.Native.Cases {
		if c.Name != hex.EncodeToString([]byte(names[i])) || c.ID != fmt.Sprintf("case-%03d", i) || c.Parent == 0 || c.LookupErrno != 0 {
			return errors.New("special-name lookup inventory")
		}
		if i == 1 || i == 2 {
			if c.CreateErrno != 17 || len(c.Stored) != 0 || c.Inode != 0 || (i == 1 && c.LookupInode != c.Parent) || (i == 2 && c.LookupInode != 2) {
				return errors.New("special dot creation")
			}
			continue
		}
		if c.CreateErrno != 0 || c.Inode == 0 || c.LookupInode != c.Inode || len(c.Stored) != 1 || c.Stored[0].Inode != c.Inode {
			return errors.New("special-name creation identity")
		}
		stored := names[i]
		if i == 10 {
			stored = "x%EF%BF%BFy"
		}
		if c.Stored[0].Hex != hex.EncodeToString([]byte(stored)) {
			return errors.New("native readdir spelling")
		}
		catalog := strings.NewReplacer(":", "/", "\u2400", "\x00").Replace(stored)
		expected := utf16.Encode([]rune(catalog))
		matched := 0
		for _, r := range v.Raw {
			if uint64(r.Parent) == c.Parent && uint64(r.Inode) == c.Inode {
				if fmt.Sprint(r.UTF16) != fmt.Sprint(expected) {
					return errors.New("unexpected native catalog spelling")
				}
				matched++
			}
		}
		if matched != 1 {
			return errors.New("raw/native catalog identity")
		}
	}
	return nil
}
