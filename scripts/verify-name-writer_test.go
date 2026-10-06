//go:build ignore

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

type nameWriterCheck struct {
	ID, Kind, First, Second string
	Errno, Writes           int
}
type nameWriterRecord struct {
	ID, Created, Queried, Stored string
	CreateErrno, LookupErrno     int
	Parent, Inode, QueriedInode  uint64
	Hash                         uint32
	Key, Value                   string
}
type nameWriterImage struct {
	Target                            uint32
	Kind, File, SHA256, FixtureSHA256 string
	Size                              int64
	Cases                             []nameWriterRecord
	Checks                            []nameWriterCheck
}
type nameWriterReport struct {
	Schema               int
	Host, Arch, Revision string
	Sources              map[string]string
	Images               []nameWriterImage
}
type preflightDestination struct{ calls int }

func (w *preflightDestination) WriteAt([]byte, int64) (int, error) {
	w.calls++
	return 0, io.ErrClosedPipe
}
func nativeNameErrno(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	for _, v := range []struct {
		value  error
		number int
	}{{syscall.EILSEQ, 92}, {syscall.ENAMETOOLONG, 63}, {syscall.EEXIST, 17}, {syscall.EINVAL, 22}, {syscall.ENOENT, 2}} {
		if errors.Is(err, v.value) {
			return v.number, nil
		}
	}
	return 0, fmt.Errorf("unqualified portable name error: %w", err)
}
func nameWriterSources() (map[string]string, error) {
	paths := []string{"go.mod", "go.sum", "scripts/verify-name-writer_test.go", "scripts/capture-name-collation.go", "scripts/verify-name-comparison_test.go"}
	for _, dir := range []string{"pkg/apfswrite", "pkg/apfs", "pkg/hfsplus", "pkg/osversion", "internal/nameunicode"} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				paths = append(paths, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sources := map[string]string{}
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.FromSlash(path))
		if err != nil {
			return nil, err
		}
		sources[path] = sum(raw)
	}
	return sources, nil
}
func TestProduceNameImages(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	out := os.Getenv("FILESYSTEM_NAME_WRITER_OUTPUT")
	if out == "" {
		t.Fatal("FILESYSTEM_NAME_WRITER_OUTPUT is required")
	}
	if err = os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	sources, err := nameWriterSources()
	if err != nil {
		t.Fatal(err)
	}
	revision, err := command(t.Context(), "git", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	report := nameWriterReport{Schema: 1, Host: runtime.GOOS, Arch: runtime.GOARCH, Revision: strings.TrimSpace(string(revision)), Sources: sources}
	for _, major := range []uint32{15, 26, 27} {
		fixture := fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", major)
		native := readComparisonCapture(t, fixture)
		if err = compareStable(native, native); err != nil {
			t.Fatal(err)
		}
		target, err := osversion.ParseProductVersion(native.Host)
		if err != nil || target.Major != major {
			t.Fatal("native profile mislabeled", err)
		}
		source, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, volume := range native.Volumes {
			t.Run(fmt.Sprintf("%d/%s", major, volume.Kind), func(t *testing.T) {
				var image nameWriterImage
				if strings.HasPrefix(volume.Kind, "APFS") {
					image = produceAPFSNameImage(t, out, major, volume)
				} else {
					image = produceHFSNameImage(t, out, major, volume)
				}
				image.FixtureSHA256 = sum(source)
				report.Images = append(report.Images, image)
			})
		}
	}
	if len(report.Images) != 12 {
		t.Fatal("incomplete writer target/volume inventory")
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "manifest.json"), append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
func produceAPFSNameImage(t *testing.T, out string, target uint32, source volumeCapture) nameWriterImage {
	t.Helper()
	result := nameWriterImage{Target: target, Kind: source.Kind, File: fmt.Sprintf("macos%d-%s.img", target, source.Kind)}
	corpus := &apfswrite.Entry{Name: "collation", Mode: os.ModeDir}
	expectedHashes := map[string]diskRecord{}
	for _, r := range source.Records {
		expectedHashes[r.ID] = r
	}
	for _, c := range source.Native.Cases {
		created, err := hex.DecodeString(c.Created)
		if err != nil {
			t.Fatal(err)
		}
		queried, err := hex.DecodeString(c.Queried)
		if err != nil {
			t.Fatal(err)
		}
		directory := &apfswrite.Entry{Name: c.ID, Mode: os.ModeDir}
		if c.CreateErrno == 0 {
			directory.Children = []*apfswrite.Entry{{Name: string(created)}}
		} else {
			check := writerPreflight(t, target, source.Native.Filesystem, source.Native.Sensitive, c.ID, "rejected", string(created), "")
			if check.Errno != c.CreateErrno {
				t.Fatalf("native rejected %s errno%d portable%d", c.ID, c.CreateErrno, check.Errno)
			}
			result.Checks = append(result.Checks, check)
		}
		if c.CreateErrno == 0 && c.LookupErrno == 0 && c.Same {
			check := writerPreflight(t, target, source.Native.Filesystem, source.Native.Sensitive, c.ID, "collision", string(created), string(queried))
			if check.Errno != 17 {
				t.Fatalf("equivalent sibling was not rejected as EEXIST: %s %+v", c.ID, check)
			}
			result.Checks = append(result.Checks, check)
		}
		corpus.Children = append(corpus.Children, directory)
	}
	result.Checks = append(result.Checks, writerExtraPreflights(t, target, source.Native.Filesystem, source.Native.Sensitive)...)
	imagePath := filepath.Join(out, result.File)
	file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	const imageSize = 64 << 20
	if err = file.Truncate(imageSize); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	options := &apfswrite.CreateOptions{TargetVersion: osversion.Version{Major: target}, VolumeName: fmt.Sprintf("names%d", target), CaseSensitive: source.Native.Sensitive, Root: &apfswrite.Entry{Children: []*apfswrite.Entry{corpus}}}
	writeErr := apfswrite.CreateContainer(file, imageSize, options)
	if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	result.Size = imageSize
	container, closer, err := apfs.OpenImage(imagePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			t.Error(err)
		}
	}()
	volumes, err := container.Volumes()
	if err != nil || len(volumes) != 1 {
		t.Fatal("produced volume inventory", err)
	}
	volume := volumes[0]
	if volume.FileSystemBTree.UseCaseFolding == source.Native.Sensitive {
		t.Fatal("produced case policy differs")
	}
	for _, c := range source.Native.Cases {
		record := nameWriterRecord{ID: c.ID, Created: c.Created, Queried: c.Queried, Stored: c.Stored, CreateErrno: c.CreateErrno, LookupErrno: c.LookupErrno}
		directory, err := volume.FileEntryByPath("collation/" + c.ID)
		if err != nil {
			t.Fatal(err)
		}
		record.Parent, err = directory.Identifier()
		if err != nil {
			t.Fatal(err)
		}
		entries, err := volume.FileSystemBTree.AllRecordsForOID(volume.Reader, record.Parent)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range entries {
			kind, err := apfs.ExtractDataTypeFromKey(entry.KeyData)
			if err != nil {
				t.Fatal(err)
			}
			if kind != apfs.FileSystemRecordTypeDirectoryEntry {
				continue
			}
			parsed := apfs.NewDirectoryEntryRecord()
			if err = parsed.ReadKeyData(entry.KeyData); err != nil {
				t.Fatal(err)
			}
			if err = parsed.ReadValueData(entry.ValueData); err != nil {
				t.Fatal(err)
			}
			spelling := hex.EncodeToString([]byte(strings.TrimSuffix(string(parsed.Name), "\x00")))
			expected, ok := expectedHashes[c.ID]
			if !ok || c.CreateErrno != 0 || spelling != c.Stored || parsed.NameHash != expected.Hash {
				t.Fatalf("produced raw key differs from native %s spelling=%s hash=%d native=%d", c.ID, spelling, parsed.NameHash, expected.Hash)
			}
			record.Inode = parsed.Identifier
			record.Hash = parsed.NameHash
			record.Key = hex.EncodeToString(entry.KeyData)
			record.Value = hex.EncodeToString(entry.ValueData)
			count++
		}
		expectedCount := 0
		if c.CreateErrno == 0 {
			expectedCount = 1
		}
		if count != expectedCount {
			t.Fatal("produced directory inventory differs", c.ID, count, expectedCount)
		}
		for _, lookup := range []struct {
			raw     string
			present bool
			query   bool
		}{{c.Created, c.CreateErrno == 0, false}, {c.Queried, c.LookupErrno == 0, true}} {
			name, err := hex.DecodeString(lookup.raw)
			if err != nil {
				t.Fatal(err)
			}
			data, err := volume.ReadFile("collation/" + c.ID + "/" + string(name))
			if !lookup.present {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("native absent lookup differs", c.ID, err)
				}
				continue
			}
			if err != nil {
				t.Fatal("native present lookup differs", c.ID, err)
			}
			entry, err := volume.FileEntryByPath("collation/" + c.ID + "/" + string(name))
			if err != nil {
				t.Fatal(err)
			}
			inode, err := entry.Identifier()
			if err != nil || inode != record.Inode {
				t.Fatal("produced lookup identity differs", c.ID, inode, record.Inode, err)
			}
			if err != nil || len(data) != 0 {
				t.Fatal("native empty payload differs", c.ID, err)
			}
			if lookup.query {
				record.QueriedInode = inode
			}
		}
		result.Cases = append(result.Cases, record)
	}
	if len(result.Cases) != casesPerVolume {
		t.Fatal("produced case count differs")
	}
	raw, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	result.SHA256 = sum(raw)
	return result
}
func writerPreflight(t *testing.T, target uint32, filesystem string, sensitive bool, id, kind, first, second string) nameWriterCheck {
	t.Helper()
	options := &apfswrite.CreateOptions{TargetVersion: osversion.Version{Major: target}, CaseSensitive: sensitive, RootFiles: []apfswrite.RootFile{{Name: first}}}
	if kind == "collision" {
		options.RootFiles = append(options.RootFiles, apfswrite.RootFile{Name: second})
	}
	destination := &preflightDestination{}
	var err error
	if filesystem == "apfs" {
		err = apfswrite.CreateContainer(destination, 64<<20, options)
	} else {
		entries := []*hfsplus.Entry{{Name: first}}
		if kind == "collision" {
			entries = append(entries, &hfsplus.Entry{Name: second})
		}
		err = hfsplus.CreateImage(destination, 64<<20, "names", &hfsplus.Entry{Children: entries}, &hfsplus.CreateOptions{CaseInsensitive: !sensitive})
	}

	code, classificationErr := nativeNameErrno(err)
	if err == nil || classificationErr != nil || destination.calls != 0 {
		t.Fatal("invalid name reached output or had an unqualified error", id, err, classificationErr, destination.calls)
	}
	return nameWriterCheck{ID: id, Kind: kind, First: hex.EncodeToString([]byte(first)), Second: hex.EncodeToString([]byte(second)), Errno: code, Writes: destination.calls}
}

func produceHFSNameImage(t *testing.T, out string, target uint32, source volumeCapture) nameWriterImage {
	t.Helper()
	result := nameWriterImage{Target: target, Kind: source.Kind, File: fmt.Sprintf("macos%d-%s.img", target, source.Kind)}
	corpus := &hfsplus.Entry{Name: "collation", Mode: os.ModeDir}
	for _, c := range source.Native.Cases {
		created, err := hex.DecodeString(c.Created)
		if err != nil {
			t.Fatal(err)
		}
		queried, err := hex.DecodeString(c.Queried)
		if err != nil {
			t.Fatal(err)
		}
		directory := &hfsplus.Entry{Name: c.ID, Mode: os.ModeDir}
		if c.CreateErrno == 0 {
			directory.Children = []*hfsplus.Entry{{Name: string(created)}}
		} else {
			check := writerPreflight(t, target, source.Native.Filesystem, source.Native.Sensitive, c.ID, "rejected", string(created), "")
			if check.Errno != c.CreateErrno {
				t.Fatal("native HFS rejection differs", c.ID, check.Errno, c.CreateErrno)
			}
			result.Checks = append(result.Checks, check)
		}
		if c.CreateErrno == 0 && c.LookupErrno == 0 && c.Same {
			check := writerPreflight(t, target, source.Native.Filesystem, source.Native.Sensitive, c.ID, "collision", string(created), string(queried))
			if check.Errno != 17 {
				t.Fatal("native equivalent HFS name not rejected", c.ID, check.Errno)
			}
			result.Checks = append(result.Checks, check)
		}
		corpus.Children = append(corpus.Children, directory)
	}
	result.Checks = append(result.Checks, writerExtraPreflights(t, target, source.Native.Filesystem, source.Native.Sensitive)...)
	imagePath := filepath.Join(out, result.File)
	file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	const imageSize = 64 << 20
	if err = file.Truncate(imageSize); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	writeErr := hfsplus.CreateImage(file, imageSize, fmt.Sprintf("names%d", target), &hfsplus.Entry{Children: []*hfsplus.Entry{corpus}}, &hfsplus.CreateOptions{CaseInsensitive: !source.Native.Sensitive})
	if err = errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		t.Fatal(err)
	}
	result.Size = imageSize
	reader, err := os.Open(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	volume, err := hfsplus.New(reader)
	if err != nil {
		t.Fatal(err)
	}
	if volume.CaseSensitive() != source.Native.Sensitive {
		t.Fatal("produced HFS comparison policy differs")
	}
	for _, c := range source.Native.Cases {
		record := nameWriterRecord{ID: c.ID, Created: c.Created, Queried: c.Queried, Stored: c.Stored, CreateErrno: c.CreateErrno, LookupErrno: c.LookupErrno}
		directory := "collation/" + c.ID
		info, err := volume.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		parent, ok := info.Sys().(*hfsplus.HFSPlusCatalogFolder)
		if !ok {
			t.Fatal("missing HFS catalog directory identity")
		}
		record.Parent = uint64(parent.FolderID)
		entries, err := volume.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		expectedCount := 0
		if c.CreateErrno == 0 {
			expectedCount = 1
		}
		if len(entries) != expectedCount {
			t.Fatal("produced HFS case inventory differs", c.ID)
		}
		if len(entries) == 1 {
			if hex.EncodeToString([]byte(entries[0].Name())) != c.Stored {
				t.Fatal("HFS stored spelling differs", c.ID, entries[0].Name(), c.Stored)
			}
			info, err := entries[0].Info()
			if err != nil {
				t.Fatal(err)
			}
			file, ok := info.Sys().(*hfsplus.HFSPlusCatalogFile)
			if !ok {
				t.Fatal("missing HFS file identity")
			}
			record.Inode = uint64(file.FileID)
		}
		for _, lookup := range []struct {
			raw     string
			present bool
			query   bool
		}{{c.Created, c.CreateErrno == 0, false}, {c.Queried, c.LookupErrno == 0, true}} {
			name, err := hex.DecodeString(lookup.raw)
			if err != nil {
				t.Fatal(err)
			}
			full := directory + "/" + string(name)
			data, err := volume.ReadFile(full)
			if !lookup.present {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("native absent HFS lookup differs", c.ID, err)
				}
				continue
			}
			if err != nil || len(data) != 0 {
				t.Fatal("native present HFS lookup differs", c.ID, err)
			}
			info, err := volume.Stat(full)
			if err != nil {
				t.Fatal(err)
			}
			file, ok := info.Sys().(*hfsplus.HFSPlusCatalogFile)
			if !ok || uint64(file.FileID) != record.Inode {
				t.Fatal("HFS alias identity differs", c.ID)
			}
			if lookup.query {
				record.QueriedInode = uint64(file.FileID)
			}
		}
		result.Cases = append(result.Cases, record)
	}
	if len(result.Cases) != casesPerVolume {
		t.Fatal("HFS case count differs")
	}
	raw, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	result.SHA256 = sum(raw)
	return result
}

func writerExtraPreflights(t *testing.T, target uint32, filesystem string, sensitive bool) []nameWriterCheck {
	t.Helper()
	inputs := []struct {
		id, name string
		errno    int
	}{{"extra-dot", ".", 17}, {"extra-dotdot", "..", 17}, {"extra-ascii-256", strings.Repeat("a", 256), 63}, {"extra-unassigned-prefix-255", "\u0378" + strings.Repeat("a", 255), 63}, {"extra-unassigned-suffix-255", strings.Repeat("a", 255) + "\u0378", 63}}
	malformed := 92
	if filesystem == "hfs" {
		malformed = 63
	}
	inputs = append(inputs, struct {
		id, name string
		errno    int
	}{"extra-malformed-prefix-255", "\x80" + strings.Repeat("a", 255), malformed}, struct {
		id, name string
		errno    int
	}{"extra-malformed-suffix-255", strings.Repeat("a", 255) + "\x80", malformed})
	if filesystem == "apfs" {
		inputs = append(inputs, struct {
			id, name string
			errno    int
		}{"extra-unassigned-prefix-254", "\u0378" + strings.Repeat("a", 254), 92}, struct {
			id, name string
			errno    int
		}{"extra-unassigned-suffix-254", strings.Repeat("a", 254) + "\u0378", 92})
	}
	var checks []nameWriterCheck
	for _, input := range inputs {
		check := writerPreflight(t, target, filesystem, sensitive, input.id, "rejected", input.name, "")
		if check.Errno != input.errno {
			t.Fatal("native creation ordering differs", input.id, filesystem, check.Errno, input.errno)
		}
		checks = append(checks, check)
	}
	return checks
}
