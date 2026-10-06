package acceptance

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"github.com/deploymenttheory/go-apfs-v2/pkg/recompression"
)

// Add replacement compositions to the existing three-host producer and native
// APFS/HFS+ readback matrix without replacing any retained native operation case.
func carrierReplacementCases(t *testing.T, store *metatransport.Store, payload string, version osversion.Version, filesystem string, image *carrierRecompressionImage) {
	t.Helper()
	for _, names := range []int{2, 3} {
		for _, linked := range []bool{false, true} {
			for _, denied := range []bool{false, true} {
				label := fmt.Sprintf("replace-%d-linked-%t-denied-%t", names, linked, denied)
				t.Run("composition-"+label, func(t *testing.T) {
					ctx := t.Context()
					opts := recompression.Options{Target: version, Authority: &recompression.Authority{UID: 501, Groups: []uint32{20}}, Volume: &recompression.Volume{Filesystem: filesystem}, Clock: func() time.Time { return time.Unix(1700000000, 0).UTC() }, TemporaryDirectory: t.TempDir()}
					original := bytes.Repeat([]byte("abcd"), 16384)
					replacement := bytes.Repeat([]byte("dcba"), 16384)
					uid, gid, mode, flags := uint32(501), uint32(20), uint32(0100644), uint32(0)
					birth, modify, access, change := time.Unix(1500000000, 0).UTC(), time.Unix(1600000000, 0).UTC(), time.Unix(1550000000, 0).UTC(), time.Unix(1650000000, 0).UTC()
					ref := metatransport.BlobRef{SHA256: fmt.Sprintf("%x", sha256.Sum256(original)), Size: int64(len(original))}
					r := metatransport.Record{Original: label, Materialized: label, Kind: "file", MaterializedKind: "file", Payload: &ref, Darwin: metatransport.DarwinState{UID: &uid, GID: &gid, Mode: &mode, Flags: &flags, Birth: &birth, Modify: &modify, Access: &access, Change: &change}}
					if err := os.WriteFile(filepath.Join(payload, label), original, 0600); err != nil {
						t.Fatal(err)
					}
					m, err := store.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					m.Records = append(m.Records, r)
					if err = store.Commit(ctx, m, m.Generation); err != nil {
						t.Fatal(err)
					}
					initial, err := recompression.RecompressRecord(ctx, store, label, m.Generation+1, opts)
					if err != nil || !initial.Published || *initial.Record.Darwin.Flags&hostdata.UFCompressed == 0 {
						t.Fatal(initial, err)
					}
					m, err = store.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					selected := len(m.Records) - 1
					r = m.Records[selected]
					r.LinkGroup = label
					m.Records[selected] = r
					for i := 1; i < names; i++ {
						alias := r
						alias.Original = fmt.Sprintf("%s-alias-%d", label, i)
						alias.Materialized = alias.Original
						if linked {
							err = os.Link(filepath.Join(payload, label), filepath.Join(payload, alias.Materialized))
						} else {
							err = os.WriteFile(filepath.Join(payload, alias.Materialized), original, 0600)
						}
						if err != nil {
							t.Fatal(err)
						}
						m.Records = append(m.Records, alias)
					}
					if err = store.Commit(ctx, m, m.Generation); err != nil {
						t.Fatal(err)
					}
					m, err = store.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					oldAliases := append([]metatransport.Record(nil), m.Records[selected+1:]...)
					root, err := os.OpenRoot(payload)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := root.Close(); e != nil {
							t.Error(e)
						}
					}()
					source, err := root.Open(label)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := source.Close(); e != nil {
							t.Error(e)
						}
					}()
					oldInfo, err := source.Stat()
					if err != nil {
						t.Fatal(err)
					}
					stage, err := hostdata.PrepareReplacementAtContext(ctx, source, root, ".")
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if e := stage.Close(); e != nil {
							t.Error(e)
						}
					}()
					if err = stage.File.Truncate(0); err != nil {
						t.Fatal(err)
					}
					if _, err = stage.File.WriteAt(replacement, 0); err != nil {
						t.Fatal(err)
					}
					if err = stage.RestoreMetadataContext(ctx); err != nil {
						t.Fatal(err)
					}
					if err = stage.File.Sync(); err != nil {
						t.Fatal(err)
					}
					if err = stage.File.Close(); err != nil {
						t.Fatal(err)
					}
					next := r
					next.LinkGroup = ""
					next.AppleDouble = nil
					newFlags := *r.Darwin.Flags &^ hostdata.UFCompressed
					next.Darwin.Flags = &newFlags
					next.Payload = &metatransport.BlobRef{SHA256: fmt.Sprintf("%x", sha256.Sum256(replacement)), Size: int64(len(replacement))}
					attrs, err := store.ReadRecordAttributes(ctx, r, 1<<20)
					if err != nil {
						t.Fatal(err)
					}
					delete(attrs, hostdata.DecmpfsName)
					delete(attrs, hostdata.ResourceForkName)
					next.Attributes, err = store.StoreAttributes(ctx, attrs)
					if err != nil {
						t.Fatal(err)
					}
					m.Records[selected] = next
					published, err := store.Publish(ctx, m, m.Generation, func() error {
						if e := store.CheckPayload(ctx, label, source); e != nil {
							return e
						}
						if e := metatransport.VerifyHeldPayload(ctx, source, *r.Payload); e != nil {
							return e
						}
						return root.Rename(stage.Path, label)
					})
					if err != nil || !published {
						t.Fatal(published, err)
					}
					if err = stage.Close(); err != nil {
						t.Fatal(err)
					}
					newInfo, err := root.Stat(label)
					if err != nil || os.SameFile(oldInfo, newInfo) {
						t.Fatal("replacement inode", err)
					}
					durable, err := store.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					next = durable.Records[selected]
					if denied {
						opts.Authority = &recompression.Authority{UID: 502, Groups: []uint32{20}}
					}
					result, err := recompression.RecompressRecord(ctx, store, label, m.Generation+1, opts)
					if denied {
						if err == nil || result.Published || result.Operation.Accepted {
							t.Fatal(result, err)
						}
					} else if err != nil || !result.Published || !result.Operation.Accepted {
						t.Fatal(result, err)
					}
					after, err := store.Load(ctx)
					if err != nil {
						t.Fatal(err)
					}
					for i := 0; i < names; i++ {
						got := after.Records[selected+i]
						wantData := original
						if i == 0 {
							wantData = replacement
							if got.LinkGroup != "" {
								t.Fatal("replacement link group retained")
							}
							if denied && !reflect.DeepEqual(got, next) {
								t.Fatal("admission failure changed signed baseline")
							}
							if !denied && *got.Darwin.Flags&hostdata.UFCompressed == 0 {
								t.Fatal("successful compression did not activate")
							}
						} else if !reflect.DeepEqual(got, oldAliases[i-1]) {
							t.Fatal("unaffected alias metadata changed")
						}
						if err = store.VerifyPayload(ctx, got); err != nil {
							t.Fatal(err)
						}
						data, e := root.ReadFile(got.Materialized)
						if e != nil || !bytes.Equal(data, wantData) {
							t.Fatal("complete payload", e)
						}
						info, e := root.Stat(got.Materialized)
						if e != nil {
							t.Fatal(e)
						}
						if i > 0 && (os.SameFile(info, newInfo) || linked && !os.SameFile(info, oldInfo)) {
							t.Fatal("alias identity")
						}
						values, e := store.ReadRecordAttributes(ctx, got, 1<<20)
						if e != nil {
							t.Fatal(e)
						}
						expected := carrierRecompressionExpected{Name: got.Original, Scenario: "replacement-composition", Data: wantData, Attribute: values[hostdata.DecmpfsName], Fork: values[hostdata.ResourceForkName], Mode: *got.Darwin.Mode, Flags: *got.Darwin.Flags, Birth: *got.Darwin.Birth, Modify: *got.Darwin.Modify, Change: *got.Darwin.Change, Access: *got.Darwin.Access, Links: 1, IdentityGroup: label + "-new"}
						if i > 0 {
							expected.Links = uint32(names - 1)
							expected.IdentityGroup = label + "-old"
						}
						image.Cases = append(image.Cases, expected)
					}
				})
			}
		}
	}
}
