package recompression

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func pathFixture(t *testing.T) (*metatransport.Store, string, metatransport.Manifest, PathCapture, PathOptions) {
	t.Helper()
	s, p, _, file, o := carrierRecompressionFixture(t)
	mode := uint32(0040700)
	root := metatransport.Record{Original: ".", Materialized: ".", Kind: "directory", MaterializedKind: "directory", Darwin: file.Darwin}
	root.Darwin.Mode = &mode
	m := metatransport.Manifest{Version: 1, Generation: 1, Records: []metatransport.Record{root, file}}
	if err := s.Commit(t.Context(), m, 1); err != nil {
		t.Fatal(err)
	}
	m.Generation = 2
	capture := PathCapture{Root: ".", Complete: true, Nodes: map[string]PathObservation{".": {Security: authorization.SecurityAbsent, Mount: authorization.Mount{Identity: "source-volume", Filesystem: "apfs"}}, "file": {Security: authorization.SecurityAbsent, Mount: authorization.Mount{Identity: "source-volume", Filesystem: "apfs"}}}}
	bound, err := NewPathContext(t.Context(), s, 2, capture)
	if err != nil {
		t.Fatal(err)
	}
	o.Authority.Process = &authorization.ProcessPolicy{}
	return s, p, m, capture, PathOptions{Options: o, Context: bound}
}
func TestRecompressPathPublication(t *testing.T) {
	s, p, _, capture, options := pathFixture(t)
	capture.Nodes["."] = PathObservation{} // binding owns its observations
	result, err := RecompressPath(t.Context(), s, "./file", 2, options)
	if err != nil || !result.Published || !result.Operation.Accepted || result.Generation != 3 {
		t.Fatal(result, err)
	}
	if err = s.VerifyPayload(t.Context(), result.Record); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(p, "file")); err != nil {
		t.Fatal(err)
	}
	if _, err = RecompressPath(t.Context(), s, "file", 2, options); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
}
func TestRecompressPathMissingContextDoesNotMutate(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*PathCapture, *PathOptions)
		want error
	}{
		{"ancestor-security", func(c *PathCapture, _ *PathOptions) {
			v := c.Nodes["."]
			v.Security = authorization.SecurityUncaptured
			c.Nodes["."] = v
		}, ErrAuthority},
		{"leaf-security", func(c *PathCapture, _ *PathOptions) { delete(c.Nodes, "file") }, ErrAuthority},
		{"present-without-attribute", func(c *PathCapture, _ *PathOptions) {
			v := c.Nodes["file"]
			v.Security = authorization.SecurityPresent
			c.Nodes["file"] = v
		}, ErrAuthority},
		{"missing-volume", func(c *PathCapture, _ *PathOptions) { v := c.Nodes["file"]; v.Mount.Identity = ""; c.Nodes["file"] = v }, ErrAuthority},
		{"missing-process", func(_ *PathCapture, o *PathOptions) { o.Authority.Process = nil }, ErrAuthority},
		{"missing-groups", func(_ *PathCapture, o *PathOptions) { o.Authority.Groups = nil }, ErrAuthority},
		{"leaf-mount-mismatch", func(c *PathCapture, _ *PathOptions) { v := c.Nodes["file"]; v.Mount.Flags = 1; c.Nodes["file"] = v }, ErrAuthority},
		{"missing-operation-volume", func(_ *PathCapture, o *PathOptions) { o.Volume = nil }, ErrAuthority},
		{"unqualified-target", func(_ *PathCapture, o *PathOptions) { o.Target = osversion.Version{} }, osversion.ErrMacOSProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, m, capture, options := pathFixture(t)
			before, err := os.ReadFile(filepath.Join(p, "file"))
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&capture, &options)
			options.Context, err = NewPathContext(t.Context(), s, 2, capture)
			if err != nil {
				t.Fatal(err)
			}
			result, err := RecompressPath(t.Context(), s, "file", 2, options)
			if !errors.Is(err, tc.want) || result.Published {
				t.Fatal(result, err)
			}
			after, e := s.Load(t.Context())
			if e != nil || after.Generation != m.Generation {
				t.Fatal(after, e)
			}
			data, e := os.ReadFile(filepath.Join(p, "file"))
			if e != nil || string(data) != string(before) {
				t.Fatal("payload changed", e)
			}
			checkRecompressionCleanup(t, options.TemporaryDirectory)
		})
	}
}
func TestPathBindingValidation(t *testing.T) {
	s, _, m, capture, options := pathFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewPathContext(ctx, s, 2, capture); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, root := range []string{"", "/", "../outside", "file", "missing"} {
		c := capture
		c.Root = root
		if _, err := NewPathContext(t.Context(), s, 2, c); err == nil {
			t.Fatal(root)
		}
	}
	if _, err := NewPathContext(t.Context(), nil, 2, capture); !errors.Is(err, metatransport.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := NewPathContext(t.Context(), s, 1, capture); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := RecompressPath(ctx, s, "file", 2, options); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	other, _, _, _, _ := pathFixture(t)
	if _, err := RecompressPath(t.Context(), other, "file", 2, options); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	if _, err := RecompressPath(t.Context(), s, "file", 3, options); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	bad := options
	bad.Context = nil
	if _, err := RecompressPath(t.Context(), s, "file", 2, bad); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	// A complete manifest mismatch cannot reuse a context even at the same generation.
	options.Context.digest = [32]byte{}
	if _, err := RecompressPath(t.Context(), s, "file", 2, options); !errors.Is(err, metatransport.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := (pathCarrier{manifest: m}).Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPathContext(t.Context(), s, 2, capture); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := RecompressPath(t.Context(), s, "file", 2, options); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestOriginalPathTraversal(t *testing.T) {
	s, _, m, capture, options := pathFixture(t)
	root, file := m.Records[0], m.Records[1]
	records := map[string]metatransport.Record{".": root, "file": file}
	directory := root
	directory.Original = "a"
	records["a"] = directory
	capture.Nodes["a"] = capture.Nodes["."]
	symlink := func(name, target string) {
		records[name] = metatransport.Record{Original: name, Materialized: name, Kind: "symlink", MaterializedKind: "symlink", Target: target}
	}
	symlink("alias", "a/../file")
	symlink("absolute", "/file")
	symlink("loop", "loop")
	symlink("dangling", "absent")
	symlink("empty", "")
	symlink("nul", "file\x00bad")
	symlink("slash", "file/")
	evaluator, err := authorization.New(options.Target, options.Authority)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want error
	}{
		{"file", nil}, {"alias", nil}, {"a/../file", nil}, {"a/./../file", nil},
		{"", metatransport.ErrInvalid}, {"file\x00tail", metatransport.ErrInvalid}, {"missing", fs.ErrNotExist}, {"loop", syscall.ELOOP}, {"dangling", fs.ErrNotExist}, {"empty", fs.ErrNotExist}, {"nul", metatransport.ErrInvalid}, {"slash", syscall.ENOTDIR}, {"file/", syscall.ENOTDIR}, {"file/child", syscall.ENOTDIR}, {"a", syscall.EISDIR}, {"../file", ErrAuthority}, {"/file", ErrAuthority}, {"absolute", ErrAuthority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, _, err := resolvePath(t.Context(), s, records, capture, evaluator, tc.name)
			if !errors.Is(err, tc.want) || err == nil && resolved != "file" {
				t.Fatalf("resolved=%s error=%v want=%v", resolved, err, tc.want)
			}
		})
	}
	capture.FilesystemRoot = true
	for _, name := range []string{"absolute", "/file", "../file"} {
		resolved, _, err := resolvePath(t.Context(), s, records, capture, evaluator, name)
		if err != nil || resolved != "file" {
			t.Fatal(name, resolved, err)
		}
	}
	capture.Complete = false
	if _, _, err := resolvePath(t.Context(), s, records, capture, evaluator, "missing"); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	// Searching a/.. still requires a's search authority; lexical cleaning would incorrectly grant this.
	denied := uint32(0040600)
	directory.Darwin.Mode = &denied
	records["a"] = directory
	if _, _, err := resolvePath(t.Context(), s, records, capture, evaluator, "a/../file"); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	delete(records, ".")
	if _, _, err := resolvePath(t.Context(), s, records, capture, evaluator, "file"); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
}

func TestPathObservedSecurityAndFailures(t *testing.T) {
	s, _, m, capture, options := pathFixture(t)
	file := m.Records[1]
	observation := capture.Nodes["file"]
	file.Darwin.Flags = nil
	if _, err := observedNode(t.Context(), s, file, observation); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	file = m.Records[1]
	sentinel := errors.New("borrow failed")
	fault := faultCarrier{Store: s, borrow: func(context.Context, metatransport.Record) (map[string]appledouble.Value, error) {
		return nil, sentinel
	}}
	if _, err := observedNode(t.Context(), fault, file, observation); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	security := &appledouble.FileSecurity{}
	raw, err := security.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	file.Attributes = []metatransport.Attribute{{Name: "com.apple.system.Security", Value: mustBlob(t, s, raw)}}
	if _, err := observedNode(t.Context(), s, file, observation); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	observation.Security = authorization.SecurityPresent
	if _, err := observedNode(t.Context(), s, file, observation); err != nil {
		t.Fatal(err)
	}
	file.Attributes[0].Value = mustBlob(t, s, []byte("broken"))
	if _, err := observedNode(t.Context(), s, file, observation); !errors.Is(err, appledouble.ErrFileSecurity) {
		t.Fatal(err)
	}
	evaluator, err := authorization.New(options.Target, options.Authority)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]metatransport.Record{".": m.Records[0], "file": m.Records[1]}
	fault.borrow = func(context.Context, metatransport.Record) (map[string]appledouble.Value, error) {
		return nil, sentinel
	}
	if _, _, err := resolvePath(t.Context(), fault, records, capture, evaluator, "file"); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := resolvePath(ctx, s, records, capture, evaluator, "file"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Leaf admission remains a separately observable native operation failure.
	_, err = recompressPath(t.Context(), s, "file", 2, options, func(context.Context, func(context.Context) (hostdata.CompressionInput, error), hostdata.RecompressionOptions) (hostdata.RecompressionResult, error) {
		return hostdata.RecompressionResult{}, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}

func TestCapturedPathObservation(t *testing.T) {
	s, _, m, capture, _ := pathFixture(t)
	r := m.Records[1]
	mount := capture.Nodes["file"].Mount
	if _, err := CapturedPathObservation(t.Context(), s, r, mount, 42); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	r.SourceAttributesCaptured = true
	got, err := CapturedPathObservation(t.Context(), s, r, mount, 42)
	if err != nil || got.Security != authorization.SecurityAbsent || got.Identity != 42 {
		t.Fatal(got, err)
	}
	ref := mustBlob(t, s, []byte("opaque"))
	r.Darwin.Security = &ref
	got, err = CapturedPathObservation(t.Context(), s, r, mount, 42)
	if err != nil || got.Security != authorization.SecurityPresent {
		t.Fatal(got, err)
	}
	if _, err = CapturedPathObservation(t.Context(), nil, r, mount, 42); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	if _, err = CapturedPathObservation(t.Context(), s, r, authorization.Mount{}, 42); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = CapturedPathObservation(ctx, s, r, mount, 42); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
