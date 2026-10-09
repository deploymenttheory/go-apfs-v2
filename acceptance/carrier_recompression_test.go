package acceptance

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"github.com/deploymenttheory/go-apfs-v2/pkg/recompression"
)

type carrierRecompressionTrial struct {
	Filesystem, Scenario, Requested, Inline, Fault, Trace string
	Attribute, Fork, Data                                 []byte
	Observation                                           struct {
		Filesystem      string `json:"filesystem_type"`
		Volume          uint32 `json:"volume_flags"`
		Accepted        bool   `json:"accepted"`
		Errno           int    `json:"errno"`
		BeforeMode      uint32 `json:"before_mode"`
		BeforeFlags     uint32 `json:"before_flags"`
		AfterMode       uint32 `json:"after_mode"`
		AfterFlags      uint32 `json:"after_flags"`
		ModifyUnchanged bool   `json:"modify_unchanged"`
		AccessUnchanged bool   `json:"access_unchanged"`
	}
}
type carrierRecompressionCorpus struct {
	Schema                       int
	Host, Compiler, SDK, Library string
	Sources                      map[string]string
	Cases                        []carrierRecompressionTrial
}
type carrierRecompressionExpected struct {
	Name, Scenario, Requested, Inline string
	IdentityGroup                     string
	Links                             uint32
	Attribute, Fork, Data             []byte
	Mode, Flags                       uint32
	Birth, Modify, Change, Access     time.Time
}
type carrierRecompressionImage struct {
	Schema                           int
	Profile, Filesystem, ImageSHA256 string
	FixtureSHA256                    string
	Cases                            []carrierRecompressionExpected
}

func carrierRecompressionLoad(t *testing.T, profile string) (carrierRecompressionCorpus, string) {
	t.Helper()
	path := "../testdata/appledouble/native/" + profile + ".json.gz"
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	var c carrierRecompressionCorpus
	e = json.NewDecoder(z).Decode(&c)
	if e = errors.Join(e, z.Close()); e != nil {
		t.Fatal(e)
	}
	if c.Schema != 1 || len(c.Cases) != 330 || c.Host == "" || !strings.Contains(c.Compiler, "clang") || c.SDK == "" || !strings.Contains(c.Library, "-uuid:") {
		t.Fatal("incomplete native operation corpus")
	}
	// Retained observations bind their original archived sources. The current
	// implementation is exercised below without relabeling historical captures.
	reference, e := captureprovenance.Reference(os.DirFS(".."), c.Sources)
	if e != nil {
		t.Fatal(e)
	}
	if e = captureprovenance.Verify(reference, c.Sources); e != nil {
		t.Fatal(e)
	}
	for source := range c.Sources {
		if !strings.HasPrefix(source, "scripts/") && !strings.HasPrefix(source, "testdata/") && !strings.HasPrefix(source, "pkg/") && source != "go.mod" && source != "go.sum" {
			continue
		}
		if _, e := captureprovenance.ReadSource(reference, c.Sources, source); e != nil {
			t.Fatal(e)
		}
	}
	for _, arch := range []string{"arm64", "x86_64"} {
		if len(c.Sources[arch+"-compression-operation.c.ast.json"]) != 64 {
			t.Fatal("missing native AST", arch)
		}
	}
	return c, fmt.Sprintf("%x", sha256.Sum256(raw))
}
func carrierRecompressionInput(c carrierRecompressionTrial) []byte {
	n := 65536
	if c.Scenario == "multi-block" {
		n = 131076
	}
	if strings.HasPrefix(c.Scenario, "size-") {
		n, _ = strconv.Atoi(strings.TrimPrefix(c.Scenario, "size-"))
	}
	b := make([]byte, n)
	state := uint32(0x12345678)
	for i := range b {
		b[i] = "abcd"[i%4]
		if c.Scenario == "incompressible" {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			b[i] = byte(state)
		}
	}
	return b
}

// TestCarrierRecompressionNativeProfiles executes every non-fault regular-file
// input in all three retained native operation profiles. Host descriptors,
// FIFOs, directory and symlink operation contracts remain covered by their
// existing native suites; this API explicitly operates on regular records.
func TestCarrierRecompressionNativeProfiles(t *testing.T) {
	out := os.Getenv("APFS_CARRIER_RECOMPRESSION_OUTPUT")
	if out == "" {
		out = t.TempDir()
	}
	if e := os.MkdirAll(out, 0700); e != nil {
		t.Fatal(e)
	}
	total := 0
	for _, profile := range []string{"compression-operation-macos15", "compression-operation-macos26", "compression-operation"} {
		corpus, digest := carrierRecompressionLoad(t, profile)
		version, e := osversion.ParseProductVersion(corpus.Host)
		if e != nil {
			t.Fatal(e)
		}
		for _, filesystem := range []string{"host", "APFS", "HFS+"} {
			t.Run(fmt.Sprintf("macos%d/%s", version.Major, filesystem), func(t *testing.T) {
				payload, metadata := filepath.Join(t.TempDir(), "payload"), filepath.Join(t.TempDir(), "metadata")
				for _, p := range []string{payload, metadata} {
					if e := os.Mkdir(p, 0700); e != nil {
						t.Fatal(e)
					}
				}
				store, e := metatransport.Open(payload, metadata, metatransport.DefaultLimits())
				if e != nil {
					t.Fatal(e)
				}
				defer func() {
					if e := store.Close(); e != nil {
						t.Error(e)
					}
				}()
				manifest := metatransport.Manifest{Version: 1}
				uid, gid := uint32(501), uint32(20)
				var trials []carrierRecompressionTrial
				for _, c := range corpus.Cases {
					if c.Filesystem == filesystem && c.Fault == "" && c.Observation.BeforeMode&0170000 == 0100000 {
						trials = append(trials, c)
					}
				}
				if len(trials) != 72 {
					t.Fatal("regular nonfault inventory", len(trials))
				}
				for i, c := range trials {
					name := fmt.Sprintf("case-%03d", i)
					if c.Scenario == "appledouble-name" {
						name = "._" + name
					}
					b := carrierRecompressionInput(c)
					if e := os.WriteFile(filepath.Join(payload, name), b, 0600); e != nil {
						t.Fatal(e)
					}
					digest := fmt.Sprintf("%x", sha256.Sum256(b))
					modify, access, birth := time.Unix(1600000000, 0).UTC(), time.Unix(1550000000, 0).UTC(), time.Unix(1500000000, 0).UTC()
					if c.Scenario == "subsecond" {
						modify = modify.Add(987654321)
						access = access.Add(345678901)
					}
					if c.Observation.Filesystem == "hfs" {
						modify = modify.Truncate(time.Second)
						access = access.Truncate(time.Second)
					}
					change := time.Unix(1650000000, 0).UTC()
					mode, flags := c.Observation.BeforeMode, c.Observation.BeforeFlags
					attrs := map[string][]byte{}
					if c.Observation.BeforeFlags&hostdata.UFCompressed != 0 {
						for _, initial := range corpus.Cases {
							if initial.Filesystem == filesystem && initial.Scenario == "ordinary" && initial.Requested == "default" && initial.Inline == "default" && initial.Fault == "" {
								attrs[hostdata.DecmpfsName] = initial.Attribute
								if len(initial.Fork) > 0 {
									attrs[hostdata.ResourceForkName] = initial.Fork
								}
								break
							}
						}
					}
					if c.Scenario == "fork" || c.Scenario == "already-compressed-fork" {
						attrs[hostdata.ResourceForkName] = []byte("independent")
					}
					if c.Scenario == "empty-fork" {
						attrs[hostdata.ResourceForkName] = []byte{}
					}
					if c.Scenario == "stale-attribute" {
						attrs[hostdata.DecmpfsName] = []byte("stale")
					}
					stored, e := store.StoreAttributes(t.Context(), attrs)
					if e != nil {
						t.Fatal(e)
					}
					r := metatransport.Record{Original: name, Materialized: name, Kind: "file", MaterializedKind: "file", Payload: &metatransport.BlobRef{SHA256: digest, Size: int64(len(b))}, Attributes: stored, Darwin: metatransport.DarwinState{UID: &uid, GID: &gid, Mode: &mode, Flags: &flags, Birth: &birth, Modify: &modify, Change: &change, Access: &access}}
					carrierRecompressionSecurity(t, store, &r, c.Scenario)
					if c.Scenario == "hardlink" {
						r.LinkGroup = name
						alias := r
						alias.Original, alias.Materialized = name+"-alias", name+"-alias"
						if e := os.WriteFile(filepath.Join(payload, alias.Materialized), b, 0600); e != nil {
							t.Fatal(e)
						}
						manifest.Records = append(manifest.Records, alias)
					}
					manifest.Records = append(manifest.Records, r)
				}
				if e := store.Commit(t.Context(), manifest, 0); e != nil {
					t.Fatal(e)
				}
				image := carrierRecompressionImage{Schema: 1, Profile: profile, Filesystem: filesystem, FixtureSHA256: digest}
				generation := uint64(1)
				for i, c := range trials {
					name := fmt.Sprintf("case-%03d", i)
					if c.Scenario == "appledouble-name" {
						name = "._" + name
					}
					t.Run(fmt.Sprintf("case-%03d-%s-%s-%s", i, c.Scenario, c.Requested, c.Inline), func(t *testing.T) {
						options := recompression.Options{Target: version, Volume: &recompression.Volume{Filesystem: c.Observation.Filesystem, Flags: c.Observation.Volume}, Encoding: decmpfs.EncodeOptions{ResourceForkOnly: c.Inline == "no"}, Clock: func() time.Time { return time.Unix(1700000000, 123456789) }}
						if c.Requested != "default" {
							kind, e := strconv.ParseUint(c.Requested, 10, 32)
							if e != nil {
								t.Fatal(e)
							}
							options.Encoding.Type = uint32(kind)
						}
						carrierRecompressionAuthority(&options)
						result, e := recompression.RecompressRecord(t.Context(), store, name, generation, options)
						loaded, loadErr := store.Load(t.Context())
						if loadErr != nil {
							t.Fatal(loadErr)
						}
						if result.Published {
							if loaded.Generation != generation+1 {
								t.Fatal("generation did not advance exactly once")
							}
							generation++
						} else if loaded.Generation != generation {
							t.Fatal("failed operation advanced generation")
						}
						if result.Operation.Accepted != c.Observation.Accepted {
							t.Fatalf("native accepted=%v errno=%d; result=%+v error=%v", c.Observation.Accepted, c.Observation.Errno, result, e)
						}
						if (e != nil) != carrierRecompressionCallerFailed(t, c.Trace) {
							t.Fatalf("native errno=%d result=%+v error=%v", c.Observation.Errno, result, e)
						}
						var record metatransport.Record
						for _, r := range loaded.Records {
							if r.Original == name {
								record = r
								break
							}
						}
						if record.Darwin.Flags == nil || *record.Darwin.Flags != c.Observation.AfterFlags || record.Darwin.Mode == nil || *record.Darwin.Mode != c.Observation.AfterMode {
							t.Fatal("native metadata differs", record.Darwin, c.Observation)
						}
						values, e := store.ReadRecordAttributes(t.Context(), record, 1<<20)
						if e != nil {
							t.Fatal(e)
						}
						if !bytes.Equal(values[hostdata.DecmpfsName], c.Attribute) || !bytes.Equal(values[hostdata.ResourceForkName], c.Fork) {
							t.Fatalf("native storage differs attr=%d/%d fork=%d/%d", len(values[hostdata.DecmpfsName]), len(c.Attribute), len(values[hostdata.ResourceForkName]), len(c.Fork))
						}
						data, e := os.ReadFile(filepath.Join(payload, name))
						if e != nil || !bytes.Equal(data, c.Data) {
							t.Fatalf("full payload differs length %d/%d: %v", len(data), len(c.Data), e)
						}
						if e := store.VerifyPayload(t.Context(), record); e != nil {
							t.Fatal(e)
						}
						// Native timestamps establish preservation/rounding independently of
						// the output manifest. The fixed operation clock substitutes only for
						// wall-clock values which native observations explicitly show changing.
						wantModify, wantAccess := time.Unix(1600000000, 0).UTC(), time.Unix(1550000000, 0).UTC()
						if c.Scenario == "subsecond" {
							wantModify = wantModify.Add(987654321).Truncate(time.Microsecond)
							wantAccess = wantAccess.Add(345678901).Truncate(time.Microsecond)
						}
						if c.Observation.BeforeFlags&hostdata.UFCompressed != 0 {
							wantModify = options.Clock().UTC().Truncate(time.Microsecond)
						}
						if c.Scenario == "deny-writeattr" {
							wantModify = options.Clock().UTC()
							wantAccess = options.Clock().UTC()
						}
						if c.Observation.Filesystem == "hfs" {
							wantModify = wantModify.Truncate(time.Second)
							wantAccess = wantAccess.Truncate(time.Second)
						}
						if record.Darwin.Birth == nil || !record.Darwin.Birth.Equal(time.Unix(1500000000, 0)) || record.Darwin.Change == nil || record.Darwin.Modify == nil || record.Darwin.Access == nil || !record.Darwin.Modify.Equal(wantModify) || !record.Darwin.Access.Equal(wantAccess) {
							t.Fatalf("native timestamp result differs: modify=%v want=%s access=%v want=%s", record.Darwin.Modify, wantModify, record.Darwin.Access, wantAccess)
						}
						expected := carrierRecompressionExpected{Name: name, Scenario: c.Scenario, Requested: c.Requested, Inline: c.Inline, Attribute: c.Attribute, Fork: c.Fork, Data: c.Data, Flags: c.Observation.AfterFlags, Mode: c.Observation.AfterMode, Birth: *record.Darwin.Birth, Modify: *record.Darwin.Modify, Change: *record.Darwin.Change, Access: *record.Darwin.Access}
						image.Cases = append(image.Cases, expected)
						if c.Scenario == "hardlink" {
							expected.Name += "-alias"
							image.Cases = append(image.Cases, expected)
						}
						total++
					})
				}
				carrierReplacementCases(t, store, payload, version, trials[0].Observation.Filesystem, &image)
				if len(image.Cases) != 94 {
					t.Fatal("complete image inventory", len(image.Cases))
				}
				if t.Failed() {
					return
				}
				path := filepath.Join(out, fmt.Sprintf("macos%d-%s.dmg", version.Major, filesystem))
				f, e := os.Create(path)
				if e != nil {
					t.Fatal(e)
				}
				if filesystem == "HFS+" {
					tree, err := hfsplus.OpenEntryTreeFromDir(payload, &hfsplus.WalkOptions{Context: t.Context(), MetadataRoot: metadata, Xattrs: true})
					if err != nil {
						f.Close()
						t.Fatal(err)
					}
					e = errors.Join(hfsplus.CreateImage(f, 64<<20, "CarrierRecompression", tree.Root, nil), tree.Close(), f.Close())
				} else {
					tree, err := apfswrite.OpenEntryTreeFromDir(payload, &apfswrite.WalkOptions{Context: t.Context(), MetadataRoot: metadata, Xattrs: true})
					if err != nil {
						f.Close()
						t.Fatal(err)
					}
					e = errors.Join(apfswrite.CreateContainer(f, 64<<20, &apfswrite.CreateOptions{Root: tree.Root}), tree.Close(), f.Close())
				}
				if e != nil {
					t.Fatal(e)
				}
				f, e = os.Open(path)
				if e != nil {
					t.Fatal(e)
				}
				hash := sha256.New()
				_, e = io.Copy(hash, f)
				if e = errors.Join(e, f.Close()); e != nil {
					t.Fatal(e)
				}
				image.ImageSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
				b, e := json.MarshalIndent(image, "", "  ")
				if e != nil {
					t.Fatal(e)
				}
				zfile, e := os.Create(path + ".json.gz")
				if e != nil {
					t.Fatal(e)
				}
				z := gzip.NewWriter(zfile)
				_, e = z.Write(b)
				if e = errors.Join(e, z.Close(), zfile.Close()); e != nil {
					t.Fatal(e)
				}
				volume := compressionStateOpen(t, path, map[bool]string{true: "HFS+", false: "APFS"}[filesystem == "HFS+"])
				for _, expected := range image.Cases {
					data, e := volume.ReadFile(expected.Name)
					if e != nil || !bytes.Equal(data, expected.Data) {
						t.Fatal("image logical readback", expected.Name, e)
					}
					m, e := volume.Metadata(expected.Name)
					if e != nil || m.BSDFlags != expected.Flags || m.Mode != expected.Mode || m.UID != 501 || m.GID != 20 || m.Times == nil || !m.Times.Birth.Equal(expected.Birth) || !m.Times.Change.Equal(expected.Change) || !m.Times.Modify.Equal(expected.Modify) || !m.Times.Access.Equal(expected.Access) {
						t.Fatal("image flags, ownership, mode or timestamps", expected.Name, m, e)
					}
					attrs, e := volume.Xattrs(expected.Name)
					if e != nil || !bytes.Equal(attrs[hostdata.DecmpfsName], expected.Attribute) || !bytes.Equal(attrs[hostdata.ResourceForkName], expected.Fork) {
						t.Fatal("image exact storage", expected.Name, e)
					}
				}
			})
		}
	}
	if total != 648 {
		t.Fatal("complete native regular-file inventory", total)
	}
}

// The native probe attaches one owner UUID deny ACE. Substitute an explicit
// foreign owner UUID consistently in actor and ACL; no receiving-host identity
// resolver or effective UID is used by this replay.
func carrierRecompressionSecurity(t *testing.T, s *metatransport.Store, r *metatransport.Record, scenario string) {
	t.Helper()
	rights := map[string]uint32{"deny-read": 1 << 1, "deny-write": 1 << 2, "deny-writeattr": 1 << 8, "deny-readxattr": 1 << 9, "deny-writexattr": 1 << 10}
	right, ok := rights[scenario]
	if !ok {
		return
	}
	security := &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 2, Rights: right}}}}
	b, e := security.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	ref, e := s.PutBlob(t.Context(), bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	r.Darwin.Security = &ref
}
func carrierRecompressionAuthority(options *recompression.Options) {
	identity := [16]byte{1}
	options.Authority = &recompression.Authority{UID: 501, Groups: []uint32{20}, UserUUID: &identity}
}

// AppleFSCompression does not clear errno after success (the macOS15 named
// fork route retains ENOENT). Compare actual failed caller operations, not a
// stale thread-local errno observed after joining the queue.
func carrierRecompressionCallerFailed(t *testing.T, trace string) bool {
	t.Helper()
	failed := false
	for _, line := range strings.Split(trace, "\n") {
		if line == "" {
			continue
		}
		var event struct {
			Thread, Operation string
			Result            int64
			Errno             int
		}
		if e := json.Unmarshal([]byte(line), &event); e != nil {
			t.Fatal(e)
		}
		if event.Thread == "caller" && event.Result < 0 && event.Errno != 0 {
			failed = true
		}
	}
	return failed
}
