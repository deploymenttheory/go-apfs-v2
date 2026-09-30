package hostmeta_test

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

// Real writer APIs compose through the coordinator and produce exactly the
// same image bytes as explicitly ordered stage execution. Distinct security
// and stat modes make reversed ordering observable. This is offline staging;
// the unchanged native stage/image corpora qualify the constituent operations.
func TestCopyPipelineImageComposition(t *testing.T) {
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			var hashes [2]string
			for variant := range 2 {
				times := hostmeta.FileTimes{Birth: time.Unix(1700000000, 0), Modify: time.Unix(1700000001, 0), Change: time.Unix(1700000002, 0), Access: time.Unix(1700000003, 0)}
				source := hostmeta.SecurityCopySource{UID: 501, GID: 20, Mode: 0106711, Properties: hostmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 1}}}}}}
				stat := hostmeta.StatCopySource{UID: 501, GID: 20, Mode: 0100640, Flags: 1, Times: hostmeta.FileTimes{Modify: time.Unix(1700000010, 0), Access: time.Unix(1700000020, 0)}}
				securityOptions := hostmeta.SecurityCopyOptions{ACL: true, Stat: true}
				root := &apfswrite.Entry{Name: "", Mode: os.ModeDir | 0755, Times: &times}
				child := &apfswrite.Entry{Name: "file", Mode: 0600, Times: &times, UID: 501, GID: 20}
				root.Children = []*apfswrite.Entry{child}
				hroot := &hfsplus.Entry{Name: "", Mode: os.ModeDir | 0755, Times: &times}
				hchild := &hfsplus.Entry{Name: "file", Mode: 0600, Times: &times, UID: 501, GID: 20}
				hroot.Children = []*hfsplus.Entry{hchild}
				hfs := kind == "hfsx" || kind == "hfsplus"
				var order []hostmeta.CopyStage
				b := pipelineBackend{run: func(stage hostmeta.CopyStage) hostmeta.CopyStageResult {
					order = append(order, stage)
					var err error
					switch stage {
					case hostmeta.CopyStageXattrs:
						if hfs {
							hchild.Xattrs = map[string][]byte{"org.example.pipeline": []byte("metadata")}
						} else {
							child.Xattrs = map[string][]byte{"org.example.pipeline": []byte("metadata")}
						}
					case hostmeta.CopyStageData:
						if hfs {
							hchild.Data = []byte("pipeline payload")
						} else {
							child.Data = []byte("pipeline payload")
						}
					case hostmeta.CopyStageSecurity:
						var r hostmeta.SecurityCopyResult
						if hfs {
							r, err = hroot.CopySecurity(hchild, source, securityOptions)
						} else {
							r, err = root.CopySecurity(child, source, securityOptions)
						}
						if err == nil && (!r.Completed || len(r.Failures) > 0) {
							err = fmt.Errorf("security: %+v", r)
						}
					case hostmeta.CopyStageStat:
						var r hostmeta.ImageStatCopyResult
						if hfs {
							r, err = hroot.CopyStat(hchild, stat, hostmeta.StatCopyOptions{})
						} else {
							r, err = root.CopyStat(child, stat, hostmeta.StatCopyOptions{})
						}
						if err == nil && !r.Applied {
							err = fmt.Errorf("stat: %+v", r)
						}
					default:
						t.Fatalf("unexpected stage %s", stage)
					}
					if err != nil {
						return hostmeta.CopyStageResult{Code: -1, Err: err}
					}
					return hostmeta.CopyStageResult{}
				}}
				expected := []hostmeta.CopyStage{hostmeta.CopyStageXattrs, hostmeta.CopyStageData, hostmeta.CopyStageSecurity, hostmeta.CopyStageStat}
				if variant == 0 {
					for _, s := range expected {
						if r := b.Run(s); r.Err != nil {
							t.Fatal(r.Err)
						}
					}
				} else {
					r, e := hostmeta.RunCopyPipeline(hostmeta.CopyPipelineOptions{SourceReady: true, DestinationReady: true, Xattrs: true, Data: true, ACL: true, Stat: true}, b)
					if e != nil || !r.Completed || len(r.Steps) != 4 {
						t.Fatal(r, e)
					}
				}
				if !reflect.DeepEqual(order, expected) {
					t.Fatal(order)
				}
				if hfs {
					if hchild.Mode != 0640 || hchild.BSDFlags == nil || *hchild.BSDFlags != 1 || !hchild.Times.Modify.Equal(stat.Times.Modify) || string(hchild.Xattrs["org.example.pipeline"]) != "metadata" {
						t.Fatal("HFS final state", hchild)
					}
				} else if child.Mode != 0640 || child.BSDFlags == nil || *child.BSDFlags != 1 || !child.Times.Modify.Equal(stat.Times.Modify) || string(child.Xattrs["org.example.pipeline"]) != "metadata" {
					t.Fatal("APFS final state", child)
				}
				file, e := os.Create(filepath.Join(t.TempDir(), "pipeline.img"))
				if e != nil {
					t.Fatal(e)
				}
				if hfs {
					e = hfsplus.CreateImage(file, 64<<20, "PIPELINE", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"})
				} else {
					e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "PIPELINE", CaseSensitive: kind == "apfs-sensitive", Snapshots: []apfswrite.SnapshotSpec{{Name: "pipeline"}}})
				}
				if e != nil {
					file.Close()
					t.Fatal(e)
				}
				if _, e = file.Seek(0, io.SeekStart); e != nil {
					file.Close()
					t.Fatal(e)
				}
				hash := sha256.New()
				_, e = io.Copy(hash, file)
				closeErr := file.Close()
				if e != nil || closeErr != nil {
					t.Fatal(e, closeErr)
				}
				hashes[variant] = fmt.Sprintf("%x", hash.Sum(nil))
			}
			if hashes[0] != hashes[1] {
				t.Fatal("composition changed image bytes", hashes)
			}
			t.Logf("%s direct/coordinated SHA256 %s", kind, hashes[0])
		})
	}
}
