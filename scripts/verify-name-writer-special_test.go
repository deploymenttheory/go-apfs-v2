//go:build ignore

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

type writerSpecialRecord struct {
	Parent, Inode uint32
	UTF16         []uint16
	Key, Value    string
}
type writerSpecialVolume struct {
	Kind   string
	Native struct {
		Cases []struct {
			ID            string
			Name          string `json:"name_hex"`
			Parent, Inode uint64
			CreateErrno   int    `json:"create_errno"`
			LookupErrno   int    `json:"lookup_errno"`
			LookupInode   uint64 `json:"lookup_inode"`
			Stored        []struct {
				Hex   string
				Inode uint64
			}
		}
	}
	Raw []writerSpecialRecord
}

func writerSpecialInspect(t *testing.T, mode, input string, target uint32, destination any) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "inspection.json")
	absolute, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	cmd := cirunner.CommandContext(t.Context(), "go", "test", "scripts/capture-hfs-special-names.go", "scripts/inspect-hfs-special-writer_test.go", "-run", "^TestInspectWriterHFSSpecial$", "-count=1")
	cmd.Env = append(os.Environ(), "APFS_WRITER_SPECIAL_MODE="+mode, "APFS_WRITER_SPECIAL_INPUT="+absolute, "APFS_WRITER_SPECIAL_OUTPUT="+output, "APFS_WRITER_SPECIAL_TARGET="+strconv.FormatUint(uint64(target), 10))
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("independent HFS %s inspection failed: %v\n%s", mode, err, raw)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, destination); err != nil {
		t.Fatal(err)
	}
}
func readWriterSpecialVolume(t *testing.T, target uint32, kind string) (writerSpecialVolume, string) {
	t.Helper()
	path := fmt.Sprintf("testdata/appledouble/native/hfs-special-names-macos%d.json.gz", target)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("required native HFS special-name profile", err)
	}
	var volumes []writerSpecialVolume
	writerSpecialInspect(t, "fixture", path, target, &volumes)
	for _, volume := range volumes {
		if volume.Kind == kind {
			return volume, sum(raw)
		}
	}
	t.Fatal("missing native special-name volume", kind)
	return writerSpecialVolume{}, ""
}
func appendWriterSpecialCases(t *testing.T, result *nameWriterImage, corpus *hfsplus.Entry, source writerSpecialVolume, sensitive bool) {
	t.Helper()
	for _, c := range source.Native.Cases {
		name, err := hex.DecodeString(c.Name)
		if err != nil {
			t.Fatal(err)
		}
		id := "special-" + c.ID
		kind := "collision"
		second := string(name)
		if c.CreateErrno != 0 {
			kind = "rejected"
			second = ""
		}
		check := writerPreflight(t, result.Target, "hfs", sensitive, id, kind, string(name), second)
		if check.Errno != 17 {
			t.Fatal("native special-name exclusive-create differs", id, check)
		}
		result.Checks = append(result.Checks, check)
		if c.CreateErrno != 0 {
			continue
		}
		corpus.Children = append(corpus.Children, &hfsplus.Entry{Name: id, Mode: os.ModeDir, Children: []*hfsplus.Entry{{Name: string(name), Data: []byte("payload")}}})
	}
}
func collectWriterSpecialCases(t *testing.T, result *nameWriterImage, volume *hfsplus.Volume, imagePath string, source writerSpecialVolume) {
	t.Helper()
	var records []writerSpecialRecord
	writerSpecialInspect(t, "image", imagePath, result.Target, &records)
	for _, c := range source.Native.Cases {
		if c.CreateErrno != 0 {
			continue
		}
		id := "special-" + c.ID
		directory := "collation/" + id
		info, err := volume.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		parent, ok := info.Sys().(*hfsplus.HFSPlusCatalogFolder)
		if !ok {
			t.Fatal("missing produced special directory identity")
		}
		entries, err := volume.ReadDir(directory)
		if err != nil || len(entries) != 1 {
			t.Fatal("special produced inventory", err)
		}
		fileInfo, err := entries[0].Info()
		if err != nil {
			t.Fatal(err)
		}
		file, ok := fileInfo.Sys().(*hfsplus.HFSPlusCatalogFile)
		if !ok {
			t.Fatal("missing produced special file identity")
		}
		record := nameWriterRecord{Payload: hex.EncodeToString([]byte("payload")), ID: id, Created: c.Name, Queried: c.Name, Stored: hex.EncodeToString([]byte(entries[0].Name())), Parent: uint64(parent.FolderID), Inode: uint64(file.FileID), QueriedInode: uint64(file.FileID)}
		if record.Stored != c.Stored[0].Hex {
			t.Fatal("special native stored spelling differs", id)
		}
		rawMatches := 0
		for _, r := range records {
			if uint64(r.Parent) == record.Parent && uint64(r.Inode) == record.Inode {
				record.Key = r.Key
				record.Value = r.Value
				record.UTF16 = r.UTF16
				rawMatches++
			}
		}
		if rawMatches != 1 {
			t.Fatal("special raw produced catalog identity", id)
		}
		name, err := hex.DecodeString(c.Name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := volume.ReadFile(directory + "/" + string(name))
		if err != nil || string(data) != "payload" {
			t.Fatal("native special complete-payload readback", id, err)
		}
		absent, err := volume.ReadFile(directory + "/absent-control")
		if !errors.Is(err, fs.ErrNotExist) || len(absent) != 0 {
			t.Fatal("special missing lookup", err)
		}
		validateWriterSpecialRaw(t, record, source)
		result.ExtraCases = append(result.ExtraCases, record)
	}
	if len(result.ExtraCases) != 11 {
		t.Fatal("incomplete produced HFS special inventory")
	}
}
func validateWriterSpecialRaw(t *testing.T, c nameWriterRecord, source writerSpecialVolume) {
	t.Helper()
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	value, err := hex.DecodeString(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 6+len(c.UTF16)*2 || len(value) < 12 || binary.BigEndian.Uint16(value) != 2 || uint64(binary.BigEndian.Uint32(key)) != c.Parent || uint64(binary.BigEndian.Uint32(value[8:])) != c.Inode || int(binary.BigEndian.Uint16(key[4:])) != len(c.UTF16) || c.Hash != 0 {
		t.Fatal("produced raw HFS catalog identity", c.ID)
	}
	for i, u := range c.UTF16 {
		if binary.BigEndian.Uint16(key[6+i*2:]) != u {
			t.Fatal("produced raw HFS UTF16 differs", c.ID)
		}
	}
	for _, native := range source.Native.Cases {
		if "special-"+native.ID != c.ID {
			continue
		}
		for _, r := range source.Raw {
			if uint64(r.Parent) == native.Parent && uint64(r.Inode) == native.Inode {
				if !reflect.DeepEqual(c.UTF16, r.UTF16) {
					t.Fatal("native and produced UTF16 differ", c.ID)
				}
				return
			}
		}
	}
	t.Fatal("missing native raw HFS special record", c.ID)
}
func validateWriterSpecialManifest(t *testing.T, image nameWriterImage, checks map[string]nameWriterCheck) {
	t.Helper()
	if image.Kind != "HFS+" && image.Kind != "HFSX" {
		if len(image.ExtraCases) != 0 || image.ExtraFixtureSHA256 != "" {
			t.Fatal("unexpected special filesystem inventory")
		}
		return
	}
	source, digest := readWriterSpecialVolume(t, image.Target, image.Kind)
	if image.ExtraFixtureSHA256 != digest || len(image.ExtraCases) != 11 {
		t.Fatal("special native source/inventory mismatch")
	}
	index := 0
	for _, c := range source.Native.Cases {
		id := "special-" + c.ID
		kind := "collision"
		second := c.Name
		if c.CreateErrno != 0 {
			kind = "rejected"
			second = ""
		}
		checks[kind+"/"+id] = nameWriterCheck{ID: id, Kind: kind, First: c.Name, Second: second, Errno: 17}
		if c.CreateErrno != 0 {
			continue
		}
		actual := image.ExtraCases[index]
		index++
		if actual.Payload != hex.EncodeToString([]byte("payload")) || actual.ID != id || actual.Created != c.Name || actual.Queried != c.Name || actual.Stored != c.Stored[0].Hex || actual.CreateErrno != 0 || actual.LookupErrno != 0 || actual.Parent == 0 || actual.Inode == 0 || actual.QueriedInode != actual.Inode {
			t.Fatal("produced special case differs from native", id)
		}
		validateWriterSpecialRaw(t, actual, source)
	}
}
