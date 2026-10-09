//go:build ignore

// Independent native name lookup and on-disk directory-key capture. Production
// comparison and hashing are deliberately not used to derive expected results.
package main

import (
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

const corpusDir = "testdata/appledouble/native/name-collation-source"
const casesPerVolume = 3753

type nameCase struct{ ID, Created, Queried string }
type nativeCase struct {
	Stored               string
	StoredInode          uint64 `json:"stored_inode"`
	ID, Created, Queried string
	CreateErrno          int    `json:"create_errno"`
	LookupErrno          int    `json:"lookup_errno"`
	Same                 bool   `json:"same_inode"`
	Parent               uint64 `json:"parent_inode"`
	Inode                uint64 `json:"created_inode"`
	QueriedInode         uint64 `json:"queried_inode"`
}
type nativeCapture struct {
	Filesystem          string
	Flags               uint32 `json:"mount_flags"`
	Capabilities, Valid [4]uint32
	Sensitive           bool `json:"case_sensitive"`
	Cases               []nativeCase
	Count               int
	Retained            bool `json:"owned_files_retained"`
}
type diskRecord struct {
	ID, Name, Key, Value string
	Hash                 uint32
	Inode                uint64
}
type volumeCapture struct {
	Kind, ImageSHA256 string
	Native            nativeCapture
	Records           []diskRecord
}
type capture struct {
	Schema                        int
	Host, Compiler, SDK, Revision string
	Sources                       map[string]string
	Cases                         []nameCase
	Volumes                       []volumeCapture
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := cirunner.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return b, fmt.Errorf("%s %v: %w\n%s", name, args, e, b)
	}
	return b, nil
}
func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func main() {
	out := flag.String("out", "artifacts/name-collation", "new native corpus directory")
	check := flag.Bool("check", false, "require complete retained native version baseline")
	flag.Parse()
	if e := run(*out, *check); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(out string, check bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native collation capture requires Darwin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	absolute, e := filepath.Abs(out)
	if e != nil {
		return e
	}
	out = absolute
	if e = os.MkdirAll(out, 0755); e != nil {
		return e
	}
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
	compiler, e := command(ctx, "xcrun", "clang", "--version")
	if e != nil {
		return e
	}
	sdkRaw, e := command(ctx, "xcrun", "--show-sdk-path")
	if e != nil {
		return e
	}
	sdk := strings.TrimSpace(string(sdkRaw))
	revision, e := command(ctx, "git", "rev-parse", "HEAD")
	if e != nil {
		return e
	}
	report := capture{Schema: 1, Host: string(host), Compiler: string(compiler), SDK: sdk, Revision: strings.TrimSpace(string(revision)), Sources: map[string]string{}}
	if err := captureprovenance.Bind(os.DirFS("."), out, report.Sources); err != nil {
		return err
	}
	raw, e := os.ReadFile(filepath.Join(corpusDir, "sources.json"))
	if e != nil {
		return e
	}
	var manifest struct {
		Unicode string
		Sources []struct{ File, URL, SHA256 string }
	}
	if e = json.Unmarshal(raw, &manifest); e != nil {
		return e
	}
	if manifest.Unicode != "17.0.0" || len(manifest.Sources) != 2 {
		return errors.New("unexpected Unicode corpus")
	}
	tables := map[string][]byte{}
	for _, source := range manifest.Sources {
		if filepath.Base(source.File) != source.File || source.URL != "https://www.unicode.org/Public/17.0.0/ucd/"+strings.TrimSuffix(source.File, ".gz") {
			return errors.New("invalid source identity")
		}
		p := filepath.Join(corpusDir, source.File)
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		report.Sources[filepath.ToSlash(p)] = sum(b)
		z, e := gzip.NewReader(bytes.NewReader(b))
		if e != nil {
			return e
		}
		body, readErr := io.ReadAll(z)
		if e = errors.Join(readErr, z.Close()); e != nil {
			return e
		}
		if sum(body) != source.SHA256 {
			return errors.New("Unicode source hash mismatch")
		}
		tables[strings.TrimSuffix(source.File, ".gz")] = body
	}
	cases, e := makeCases(tables)
	if e != nil {
		return e
	}
	report.Cases = cases
	var tsv bytes.Buffer
	for _, c := range cases {
		fmt.Fprintf(&tsv, "%s\t%s\t%s\n", c.ID, c.Created, c.Queried)
	}
	casePath := filepath.Join(out, "cases.tsv")
	if e = os.WriteFile(casePath, tsv.Bytes(), 0644); e != nil {
		return e
	}
	report.Sources["cases.tsv"] = sum(tsv.Bytes())
	for _, p := range []string{filepath.Join(corpusDir, "sources.json"), filepath.Join(corpusDir, "LICENSE.txt"), "testdata/appledouble/native/name-collation.c", "scripts/capture-name-collation.go", "scripts/capture-name-collation_test.go", ".github/workflows/name-collation.yml", "go.mod", "go.sum"} {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		report.Sources[filepath.ToSlash(p)] = sum(b)
	}
	binary := filepath.Join(out, "probe")
	if _, e = command(ctx, "xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "testdata/appledouble/native/name-collation.c", "-o", binary); e != nil {
		return e
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	report.Sources["native-binary"] = sum(b)
	for _, arch := range []string{"arm64", "x86_64"} {
		ast, e := command(ctx, "xcrun", "clang", "-target", arch+"-apple-macos15", "-isysroot", sdk, "-std=c11", "-Werror", "-Xclang", "-ast-dump=json", "-fsyntax-only", "testdata/appledouble/native/name-collation.c")
		if e != nil {
			return e
		}
		name := arch + ".ast.json"
		if e = os.WriteFile(filepath.Join(out, name), ast, 0644); e != nil {
			return e
		}
		report.Sources[name] = sum(ast)
	}
	for _, h := range []string{"sys/stat.h", "sys/mount.h", "sys/attr.h", "sys/fcntl.h", "unistd.h", "sys/errno.h"} {
		b, e := os.ReadFile(filepath.Join(sdk, "usr/include", h))
		if e != nil {
			return e
		}
		report.Sources["SDK/"+h] = sum(b)
		dest := filepath.Join(out, "SDK", h)
		if e = os.MkdirAll(filepath.Dir(dest), 0755); e != nil {
			return e
		}
		if e = os.WriteFile(dest, b, 0644); e != nil {
			return e
		}
	}
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		v, e := captureVolume(ctx, out, kind, binary, casePath, cases)
		if e != nil {
			return e
		}
		report.Volumes = append(report.Volumes, v)
	}
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	encoderErr := json.NewEncoder(z).Encode(report)
	if e = errors.Join(encoderErr, z.Close()); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(out, "native.json.gz"), encoded.Bytes(), 0644); e != nil {
		return e
	}
	if check {
		path := fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", version.Major)
		f, e := os.Open(path)
		if e != nil {
			return fmt.Errorf("required native baseline: %w", e)
		}
		z, e := gzip.NewReader(f)
		if e != nil {
			return errors.Join(e, f.Close())
		}
		var prior capture
		e = json.NewDecoder(z).Decode(&prior)
		if e = errors.Join(e, z.Close(), f.Close()); e != nil {
			return e
		}
		if e = compareStable(prior, report); e != nil {
			return e
		}
	}
	fmt.Printf("%d native cases on four observed filesystem profiles; raw APFS keys and HFS catalog names retained; macOS%s\n", casesPerVolume*4, version)
	return nil
}
func captureVolume(ctx context.Context, out, kind, binary, casePath string, cases []nameCase) (result volumeCapture, err error) {
	result.Kind = kind
	stem := strings.ReplaceAll(kind, "+", "plus")
	image := filepath.Join(out, stem+".dmg")
	mount := filepath.Join(out, stem+"-mount")
	if err = os.Mkdir(mount, 0700); err != nil {
		return result, err
	}
	formatter := kind
	if kind == "APFSX" {
		formatter = "Case-sensitive APFS"
	}
	if _, err = command(ctx, "hdiutil", "create", "-size", "128m", "-fs", formatter, "-volname", "Collation", image); err != nil {
		return result, err
	}
	attached, err := command(ctx, "hdiutil", "attach", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	if err != nil {
		return result, err
	}
	device, parseErr := diskimage.AttachmentDevice(attached)
	if device == "" {
		device = mount
	}
	detached := false
	cleanup := func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
		raw, marshalErr := json.Marshal(attempts)
		return errors.Join(e, marshalErr, os.WriteFile(filepath.Join(out, stem+"-detach.json"), raw, 0644))
	}
	defer func() {
		if !detached {
			err = errors.Join(err, cleanup())
		}
	}()
	if e := os.WriteFile(filepath.Join(out, stem+"-attach.plist"), attached, 0644); e != nil || parseErr != nil {
		return result, errors.Join(e, parseErr)
	}
	native, e := command(ctx, binary, mount, casePath)
	if e != nil {
		return result, e
	}
	if e = os.WriteFile(filepath.Join(out, stem+"-native.json"), native, 0644); e != nil {
		return result, e
	}
	if e = json.Unmarshal(native, &result.Native); e != nil {
		return result, e
	}
	if e = validateNative(result.Native, kind, cases); e != nil {
		return result, e
	}
	if e = cleanup(); e != nil {
		return result, e
	}
	detached = true
	if result.Native.Filesystem == "apfs" {
		container, closer, e := apfs.OpenImage(image, nil)
		if e != nil {
			return result, e
		}
		defer func() { err = errors.Join(err, closer.Close()) }()
		volumes, e := container.Volumes()
		if e != nil {
			return result, e
		}
		if len(volumes) != 1 {
			return result, errors.New("unexpected APFS volume inventory")
		}
		v := volumes[0]
		if v.FileSystemBTree.UseCaseFolding == result.Native.Sensitive {
			return result, errors.New("APFS observed capabilities disagree with image flags")
		}
		for _, c := range result.Native.Cases {
			entries, e := v.FileSystemBTree.AllRecordsForOID(v.Reader, c.Parent)
			if e != nil {
				return result, e
			}
			found := 0
			for _, entry := range entries {
				typ, e := apfs.ExtractDataTypeFromKey(entry.KeyData)
				if e != nil {
					return result, e
				}
				if typ != apfs.FileSystemRecordTypeDirectoryEntry {
					continue
				}
				d := apfs.NewDirectoryEntryRecord()
				if e = d.ReadKeyData(entry.KeyData); e != nil {
					return result, e
				}
				if e = d.ReadValueData(entry.ValueData); e != nil {
					return result, e
				}
				if d.Identifier != c.Inode || c.CreateErrno != 0 {
					return result, fmt.Errorf("native/image identity differs: %s", c.ID)
				}
				name := strings.TrimSuffix(string(d.Name), "\x00")
				if hex.EncodeToString([]byte(name)) != c.Created {
					return result, fmt.Errorf("APFS changed stored name: %s", c.ID)
				}
				result.Records = append(result.Records, diskRecord{ID: c.ID, Name: hex.EncodeToString([]byte(name)), Key: hex.EncodeToString(entry.KeyData), Value: hex.EncodeToString(entry.ValueData), Hash: d.NameHash, Inode: d.Identifier})
				found++
			}
			if (c.CreateErrno == 0 && found != 1) || (c.CreateErrno != 0 && found != 0) {
				return result, fmt.Errorf("native/image file inventory differs: %s", c.ID)
			}
		}
	} else {
		reader, offset, closer, e := disk.OpenWithOffset(image)
		if e != nil {
			return result, e
		}
		defer func() { err = errors.Join(err, closer.Close()) }()
		v, e := hfsplus.New(io.NewSectionReader(reader, offset, 1<<40))
		if e != nil {
			return result, e
		}
		if v.CaseSensitive() != result.Native.Sensitive {
			return result, errors.New("HFS catalog comparison type disagrees with native capabilities")
		}
		for _, c := range result.Native.Cases {
			entries, e := v.ReadDir("collation/" + c.ID)
			if e != nil {
				return result, e
			}
			if c.CreateErrno != 0 {
				if len(entries) != 0 {
					return result, errors.New("rejected HFS name created an entry")
				}
				continue
			}
			if len(entries) != 1 {
				return result, errors.New("incomplete native HFS directory")
			}
			result.Records = append(result.Records, diskRecord{ID: c.ID, Name: hex.EncodeToString([]byte(entries[0].Name())), Inode: c.Inode})
		}
	}
	if e := validateRecords(result); e != nil {
		return result, e
	}
	f, e := os.Open(image)
	if e != nil {
		return result, e
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, f)
	if e = errors.Join(copyErr, f.Close()); e != nil {
		return result, e
	}
	result.ImageSHA256 = hex.EncodeToString(hash.Sum(nil))
	b, e := json.Marshal(result.Records)
	if e != nil {
		return result, e
	}
	err = os.WriteFile(filepath.Join(out, stem+"-records.json"), b, 0644)
	return result, err
}
func validateNative(n nativeCapture, kind string, cases []nameCase) error {
	wantFS := "apfs"
	if strings.HasPrefix(kind, "HFS") {
		wantFS = "hfs"
	}
	sensitive := strings.HasSuffix(kind, "X")
	if n.Filesystem != wantFS || n.Sensitive != sensitive || n.Valid[0]&0x100 == 0 || ((n.Capabilities[0]&0x100) != 0) != sensitive || n.Count != casesPerVolume || len(n.Cases) != casesPerVolume || !n.Retained {
		return errors.New("incomplete observed filesystem/case inventory")
	}
	positive := 0
	for i, c := range n.Cases {
		if c.ID != cases[i].ID || c.Created != cases[i].Created || c.Queried != cases[i].Queried || c.Parent == 0 {
			return errors.New("native case identity mismatch")
		}
		if c.CreateErrno < 0 || c.LookupErrno < 0 {
			return errors.New("invalid native errno")
		}
		if c.CreateErrno == 0 {
			if c.Stored == "" || c.StoredInode != c.Inode {
				return errors.New("native readdir identity missing or changed")
			}
			if c.Inode == 0 {
				return errors.New("successful create lacks native identity")
			}
			positive++
		} else if c.Inode != 0 || c.Stored != "" || c.StoredInode != 0 {
			return errors.New("failed create has an identity")
		}
		if c.LookupErrno == 0 && c.QueriedInode == 0 {
			return errors.New("successful lookup lacks identity")
		}
		if c.ID == "ascii" {
			want := 0
			if sensitive {
				want = 2
			}
			if c.CreateErrno != 0 || c.LookupErrno != want || c.Same == sensitive {
				return errors.New("ASCII case positive control failed")
			}
		}
		if strings.HasPrefix(c.ID, "length-ascii-") && c.ID != "length-ascii-256" || c.ID == "replacement" {
			if c.CreateErrno != 0 || c.LookupErrno != 0 || !c.Same {
				return errors.New("required native ASCII/replacement positive control failed")
			}
		}
		if c.Same != (c.CreateErrno == 0 && c.LookupErrno == 0 && c.Inode == c.QueriedInode) {
			return errors.New("native identity relationship mismatch")
		}
	}
	if positive < 3000 {
		return errors.New("native positive controls incomplete")
	}
	return nil
}
func makeCases(tables map[string][]byte) ([]nameCase, error) {
	var cases []nameCase
	add := func(id, a, b string) {
		cases = append(cases, nameCase{id, hex.EncodeToString([]byte(a)), hex.EncodeToString([]byte(b))})
	}
	pair := func(id, a, b string) { add(id, "x"+a+"y", "x"+b+"y") }
	for _, p := range [][3]string{{"ascii", "A", "a"}, {"sigma", "Σ", "ς"}, {"sharp-s", "ß", "ss"}, {"joiner", "ab", "a\u200Db"}, {"nonjoiner", "ab", "a\u200Cb"}, {"variation-selector", "a", "a\uFE0F"}, {"soft-hyphen", "ab", "a\u00adb"}, {"post9-georgian", "\u1c90", "\u10d0"}, {"post9-vithkuqi", "\U00010570", "\U00010597"}, {"post9-latin", "\ua7d0", "\ua7d1"}, {"hangul-LV", "가", "가"}, {"hangul-LVT", "각", "각"}, {"replacement", "�", "�"}} {
		pair(p[0], p[1], p[2])
	}
	sequence := func(s string) (string, error) {
		var b strings.Builder
		for _, word := range strings.Fields(s) {
			n, e := strconv.ParseUint(word, 16, 32)
			if e != nil || n > 0x10ffff {
				return "", errors.New("invalid Unicode scalar")
			}
			b.WriteRune(rune(n))
		}
		return b.String(), nil
	}
	classes := map[int]rune{}
	for _, file := range []string{"UnicodeData.txt", "CaseFolding.txt"} {
		raw, ok := tables[file]
		if !ok {
			return nil, errors.New("missing Unicode source")
		}
		scan := bufio.NewScanner(bytes.NewReader(raw))
		for scan.Scan() {
			line, _, _ := strings.Cut(scan.Text(), "#")
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Split(line, ";")
			if len(fields) < 3 {
				return nil, errors.New("malformed Unicode source")
			}
			cp, e := sequence(strings.TrimSpace(fields[0]))
			if e != nil {
				return nil, e
			}
			if len([]rune(cp)) != 1 {
				return nil, errors.New("invalid codepoint inventory")
			}
			if file == "UnicodeData.txt" {
				if len(fields) != 15 {
					return nil, errors.New("malformed UnicodeData row")
				}
				class, e := strconv.Atoi(fields[3])
				if e != nil {
					return nil, e
				}
				if class > 0 {
					if _, ok := classes[class]; !ok {
						classes[class] = []rune(cp)[0]
					}
				}
				if fields[5] != "" && !strings.HasPrefix(fields[5], "<") {
					s, e := sequence(fields[5])
					if e != nil {
						return nil, e
					}
					pair("canonical-"+fields[0], cp, s)
				}
			} else if status := strings.TrimSpace(fields[1]); status == "C" || status == "F" {
				s, e := sequence(fields[2])
				if e != nil {
					return nil, e
				}
				pair("fold-"+fields[0], cp, s)
			}
		}
		if e := scan.Err(); e != nil {
			return nil, e
		}
	}
	var keys []int
	for c := range classes {
		keys = append(keys, c)
	}
	sort.Ints(keys)
	for i := 1; i < len(keys); i++ {
		lo, hi := classes[keys[i-1]], classes[keys[i]]
		pair(fmt.Sprintf("reorder-%d-%d", keys[i-1], keys[i]), string([]rune{'a', hi, lo}), string([]rune{'a', lo, hi}))
	}
	for _, unit := range []struct{ name, value string }{{"ascii", "a"}, {"e-acute", "é"}, {"decomposed-e", "e\u0301"}, {"emoji", "😀"}} {
		for _, n := range []int{127, 128, 254, 255, 256} {
			s := strings.Repeat(unit.value, n)
			add(fmt.Sprintf("length-%s-%d", unit.name, n), s, s)
		}
	}
	if len(cases) != casesPerVolume {
		return nil, fmt.Errorf("case inventory %d, want%d", len(cases), casesPerVolume)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			return nil, errors.New("duplicate native case")
		}
		seen[c.ID] = true
	}
	return cases, nil
}
func validateRecords(v volumeCapture) error {
	byID := map[string]diskRecord{}
	for _, r := range v.Records {
		if _, ok := byID[r.ID]; ok {
			return errors.New("duplicate retained directory record")
		}
		byID[r.ID] = r
	}
	created := 0
	for _, c := range v.Native.Cases {
		r, exists := byID[c.ID]
		if c.CreateErrno != 0 {
			if exists {
				return errors.New("rejected name has retained record")
			}
			continue
		}
		created++
		if !exists || r.ID != c.ID || r.Name != c.Stored || r.Inode != c.Inode {
			return fmt.Errorf("native/retained identity or stored name differs: %s", c.ID)
		}
		if v.Native.Filesystem == "apfs" {
			key, e := hex.DecodeString(r.Key)
			if e != nil {
				return e
			}
			value, e := hex.DecodeString(r.Value)
			if e != nil {
				return e
			}
			typ, e := apfs.ExtractDataTypeFromKey(key)
			if e != nil || typ != apfs.FileSystemRecordTypeDirectoryEntry {
				return errors.New("retained key is not a directory record")
			}
			d := apfs.NewDirectoryEntryRecord()
			if e = d.ReadKeyData(key); e != nil {
				return e
			}
			if e = d.ReadValueData(value); e != nil {
				return e
			}
			name := hex.EncodeToString([]byte(strings.TrimSuffix(string(d.Name), "\x00")))
			if d.ParentIdentifier != c.Parent || d.Identifier != c.Inode || d.NameHash != r.Hash || name != r.Name || r.Name != c.Created {
				return errors.New("raw APFS key/value differs from native observation")
			}
		} else if r.Key != "" || r.Value != "" || r.Hash != 0 {
			return errors.New("unexpected HFS record representation")
		}
	}
	if created != len(v.Records) {
		return errors.New("extra retained records")
	}
	return nil
}
func compareStable(a, b capture) error {
	for _, sources := range []map[string]string{a.Sources, b.Sources} {
		if err := captureprovenance.VerifyReference(os.DirFS("."), sources); err != nil {
			return err
		}
	}
	if a.Schema != 1 || b.Schema != 1 || len(a.Cases) != casesPerVolume || len(b.Cases) != casesPerVolume || len(a.Volumes) != 4 || len(b.Volumes) != 4 {
		return errors.New("incomplete retained native corpus")
	}
	for i, c := range a.Cases {
		if c != b.Cases[i] {
			return errors.New("retained input case inventory changed")
		}
	}
	kinds := []string{"APFS", "APFSX", "HFS+", "HFSX"}
	for _, capture := range []capture{a, b} {
		for i, v := range capture.Volumes {
			if v.Kind != kinds[i] {
				return errors.New("incorrect retained filesystem inventory")
			}
			if e := validateNative(v.Native, v.Kind, capture.Cases); e != nil {
				return e
			}
			if e := validateRecords(v); e != nil {
				return e
			}
		}
	}

	for i, prior := range a.Volumes {
		fresh := b.Volumes[i]
		if prior.Kind != fresh.Kind || prior.Native.Filesystem != fresh.Native.Filesystem || prior.Native.Sensitive != fresh.Native.Sensitive || len(prior.Native.Cases) != casesPerVolume || len(prior.Records) != len(fresh.Records) {
			return errors.New("native volume inventory changed")
		}
		for j, old := range prior.Native.Cases {
			next := fresh.Native.Cases[j]
			old.Parent = 0
			old.Inode = 0
			old.QueriedInode = 0
			old.StoredInode = 0
			next.Parent = 0
			next.Inode = 0
			next.QueriedInode = 0
			next.StoredInode = 0
			if old != next {
				return fmt.Errorf("native name behavior changed: %s/%s", prior.Kind, old.ID)
			}
		}
		for j, old := range prior.Records {
			next := fresh.Records[j]
			if old.ID != next.ID || old.Name != next.Name || old.Hash != next.Hash {
				return fmt.Errorf("native directory encoding changed: %s/%s", prior.Kind, old.ID)
			}
		}
	}
	return nil
}
