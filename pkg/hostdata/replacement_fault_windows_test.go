package hostdata

import (
	"bytes"
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestReplacementWindowsHeldStreams(t *testing.T) {
	for _, kind := range []string{"ordinary", "compressed", "sparse"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source")
			source, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if _, err = source.WriteString("old main data must be excluded"); err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("x"), (8<<20)+1)
			if err = os.WriteFile(path+":metadata", payload, 0600); err != nil {
				t.Fatal(err)
			}
			strictWindowsSet(t, path, "replacement.test", []byte("native EA"))
			if kind == "compressed" {
				replacementCompress(t, path)
			}
			if kind == "sparse" {
				if err = replacementSparse(source); err != nil {
					t.Fatal(err)
				}
				named, e := os.OpenFile(path+":sparse", os.O_CREATE|os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = replacementSparse(named); e != nil {
					t.Fatal(e)
				}
				const position = int64(4<<30) + 23
				_, e = named.WriteAt([]byte("tail"), position)
				if e = errors.Join(e, named.Close()); e != nil {
					t.Fatal(e)
				}
			}
			info, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			_, stage, parent := replacementTestStage(t)
			target, err := prepareReplacementStreamsAtContext(t.Context(), source, stage, info)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if info, e := target.Stat(); e != nil || info.Size() != 0 {
				t.Fatalf("main data retained: %v %v", info, e)
			}
			if err = restoreReplacementMetadataAtContext(t.Context(), source, target, info); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(parent, "private", "replacement") + ":metadata")
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("ADS drift: %v", err)
			}
			value, present, err := ReadXattr(target, "replacement.test", 128)
			if err != nil || !present || string(value) != "native EA" {
				t.Fatalf("EA drift: %q %v %v", value, present, err)
			}
			actual, e := replacementBasic(target)
			if e != nil {
				t.Fatal(e)
			}
			original, e := replacementBasic(source)
			if e != nil {
				t.Fatal(e)
			}
			if actual.Attributes != original.Attributes {
				t.Fatalf("attributes=%#x want %#x", actual.Attributes, original.Attributes)
			}
			if kind == "sparse" {
				named, e := os.Open(filepath.Join(parent, "private", "replacement") + ":sparse")
				if e != nil {
					t.Fatal(e)
				}
				var tail [4]byte
				_, e = named.ReadAt(tail[:], int64(4<<30)+23)
				if e = errors.Join(e, named.Close()); e != nil || string(tail[:]) != "tail" {
					t.Fatalf("large sparse ADS: %q %v", tail, e)
				}
			}
		})
	}
}

func TestReplacementWindowsBackupAdapterFailures(t *testing.T) {
	fault := errors.New("native backup failure")
	for _, tc := range []struct {
		name string
		n    uint32
		err  error
		want error
	}{
		{"read-failure", 0, fault, fault}, {"overlong", 3, nil, nil}, {"read-eof", 0, nil, io.EOF}, {"short-write", 1, nil, io.ErrShortWrite}, {"complete", 2, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter := &replacementBackup{call: func(_ *os.File, _ []byte, _ bool, state *uintptr) (uint32, error) { *state = 1; return tc.n, tc.err }}
			buffer := make([]byte, 2)
			var err error
			if tc.name == "short-write" || tc.name == "complete" {
				_, err = adapter.Write(buffer)
			} else {
				_, err = adapter.Read(buffer)
			}
			if tc.name == "overlong" {
				if err == nil {
					t.Fatal("accepted native overrun")
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			adapter.call = func(_ *os.File, _ []byte, abort bool, _ *uintptr) (uint32, error) {
				if !abort {
					t.Fatal("cleanup did not abort")
				}
				return 0, fault
			}
			if err = adapter.close(); !errors.Is(err, fault) {
				t.Fatal(err)
			}
			adapter.state = 0
			if err = adapter.close(); err != nil {
				t.Fatal(err)
			}
			if n, err := adapter.Read(nil); n != 0 || err != nil {
				t.Fatal(n, err)
			}
			if n, err := adapter.Write(nil); n != 0 || err != nil {
				t.Fatal(n, err)
			}
		})
	}
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	adapter := &replacementBackup{file: source, call: replacementBackupRead}
	if _, err = adapter.Read(make([]byte, 20)); err == nil {
		t.Fatal("accepted closed native source")
	}
}

func TestReplacementWindowsMissingAndCloseFailure(t *testing.T) {
	missing := windows.NTStatus(0xc0000034)
	closeErr := errors.New("private metadata directory close failed")
	for _, tc := range []struct {
		name   string
		input  error
		failed bool
	}{
		{"missing", missing, false},
		{"single joined missing", errors.Join(missing), false},
		{"missing plus close", errors.Join(missing, closeErr), true},
		{"nested missing plus close", errors.Join(errors.Join(missing), closeErr), true},
		{"close alone", closeErr, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized := replacementWindowsError(tc.input)
			got := cleanupReplacement(func() error { return normalized })
			if tc.failed {
				if !errors.Is(got, closeErr) {
					t.Fatalf("lost cleanup failure: %v", got)
				}
			} else if got != nil {
				t.Fatal(got)
			}
			if errors.Is(tc.input, missing) && !errors.Is(normalized, os.ErrNotExist) {
				t.Fatalf("missing native cause not normalized: %v", normalized)
			}
		})
	}
	if replacementWindowsError(nil) != nil {
		t.Fatal("nil changed")
	}
}

func TestReplacementWindowsSecurityDescriptorFidelity(t *testing.T) {
	for _, descriptor := range []string{
		"D:P(A;;FA;;;WD)", "D:(A;ID;FA;;;WD)", "D:AI(A;ID;FA;;;WD)", "D:P", "D:NO_ACCESS_CONTROL",
	} {
		t.Run(descriptor, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "security")
			name, err := windows.UTF16PtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(handle), path)
			original, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if e := replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, original); e != nil {
					t.Error(e)
				}
				if e := file.Close(); e != nil {
					t.Error(e)
				}
			}()
			wanted, err := windows.SecurityDescriptorFromString(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err = replacementSetFileSecurity(file, windows.DACL_SECURITY_INFORMATION, wanted); err != nil {
				t.Fatal(err)
			}
			actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if actual.String() != wanted.String() {
				t.Fatalf("full DACL fidelity: got %s want %s", actual.String(), wanted.String())
			}
		})
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if err = replacementSetFileSecurity(closed, windows.DACL_SECURITY_INFORMATION, sd); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestReplacementWindowsNativeFailures(t *testing.T) {
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err = closed.Close(); err != nil {
		t.Fatal(err)
	}
	live, err := os.CreateTemp(t.TempDir(), "live")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	info, err := live.Stat()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name   string
		invoke func() error
	}{
		{"identity closed", func() error { _, e := replacementHeldIdentity(closed); return e }},
		{"final path closed", func() error { _, e := replacementFinalPath(t.Context(), closed); return e }},
		{"final path canceled", func() error { _, e := replacementFinalPath(canceled, live); return e }},
		{"duplicate invalid", func() error { _, e := duplicateReplacementHandle(windows.InvalidHandle, "invalid"); return e }},
		{"reopen closed", func() error { _, e := reopenReplacementFile(closed, windows.GENERIC_READ); return e }},
		{"private acl closed", func() error { return replacementPrivateFileAccess(closed) }},
		{"readonly closed", func() error { return replacementClearReadonly(t.Context(), closed) }},
		{"cleanup capability closed", func() error { _, e := replacementCleanupCapability(closed); return e }},
		{"metadata closed root", func() error { _, e := openReplacementStageMetadata(root); return e }},
		{"anchor closed root", func() error { _, e := replacementStageAnchor(root); return e }},
		{"private parent closed", func() error { _, e := makeReplacementDirectoryAt(t.Context(), root, "private"); return e }},
		{"private canceled", func() error { _, e := makeReplacementDirectoryAt(canceled, root, "private"); return e }},
		{"restore source closed", func() error { return restoreReplacementMetadataContext(t.Context(), closed, live, info) }},
		{"restore target closed", func() error { return restoreReplacementMetadataContext(t.Context(), live, closed, info) }},
		{"restore canceled", func() error { return restoreReplacementMetadataContext(canceled, live, live, info) }},
		{"restore rooted canceled", func() error { return restoreReplacementMetadataAtContext(canceled, live, live, info) }},
		{"restore rooted closed", func() error { return restoreReplacementMetadataAtContext(t.Context(), closed, live, info) }},
		{"compression closed", func() error { return copyReplacementCompression(t.Context(), closed, live) }},
		{"streams closed", func() error { return copyReplacementStreamsContext(t.Context(), closed, live) }},
		{"prepare streams canceled", func() error { _, e := prepareReplacementStreamsAtContext(canceled, live, root, info); return e }},
		{"prepare streams source closed", func() error { _, e := prepareReplacementStreamsAtContext(t.Context(), closed, root, info); return e }},
		{"prepare streams root closed", func() error { _, e := prepareReplacementStreamsAtContext(t.Context(), live, root, info); return e }},
		{"prepare native source closed", func() error { _, e := prepareReplacementAtContext(t.Context(), closed, root, info); return e }},
		{"efs pin canceled", func() error { _, e := replacementPinEFS(canceled, live); return e }},
		{"efs pin closed", func() error { _, e := replacementPinEFS(t.Context(), closed); return e }},
		{"efs verify closed", func() error { return replacementVerifyEFS(t.Context(), closed, live) }},
		{"efs query canceled", func() error { _, e := replacementQueryEFS(canceled, live.Name(), replacementQueryUsers); return e }},
		{"efs query invalid name", func() error { _, e := replacementQueryEFS(t.Context(), "bad\x00name", replacementQueryUsers); return e }},
		{"efs query absent", func() error {
			_, e := replacementQueryEFS(t.Context(), filepath.Join(t.TempDir(), "absent"), replacementQueryUsers)
			return e
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.invoke(); e == nil {
				t.Fatal("native failure accepted")
			}
		})
	}
	if replacementCopyProgress(0, 0, 0, 0) != 1 {
		t.Fatal("unknown callback capability accepted")
	}
	for _, initial := range []error{errors.New("earlier callback failure"), nil} {
		state := &replacementCopyState{ctx: canceled, err: initial}
		if state.progress(0, windows.InvalidHandle, windows.InvalidHandle) != 1 || state.err == nil {
			t.Fatal("canceled or failed callback continued")
		}
	}
	id, err := replacementHeldIdentity(live)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		source, target windows.Handle
		state          replacementCopyState
	}{
		{"invalid source", windows.InvalidHandle, windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context()}},
		{"invalid destination", windows.Handle(live.Fd()), windows.InvalidHandle, replacementCopyState{ctx: t.Context(), source: id}},
		{"changed destination", windows.Handle(live.Fd()), windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context(), source: id, validated: true}},
		{"closed stage", windows.Handle(live.Fd()), windows.Handle(live.Fd()), replacementCopyState{ctx: t.Context(), source: id, stage: root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.state.progress(0, tc.source, tc.target) != 1 || tc.state.err == nil {
				t.Fatal("invalid callback continued")
			}
		})
	}
}

func TestReplacementWindowsEFSKeyValidation(t *testing.T) {
	world, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	value := byte(1)
	for _, tc := range []struct {
		name        string
		left, right replacementEFSHash
		equal       bool
	}{
		{"one missing SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{Hash: &replacementEFSBlob{}}, false},
		{"different SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{SID: system, Hash: &replacementEFSBlob{}}, false},
		{"same SID", replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, replacementEFSHash{SID: world, Hash: &replacementEFSBlob{}}, true},
		{"different sizes", replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &value}}, replacementEFSHash{Hash: &replacementEFSBlob{}}, false},
		{"missing bytes", replacementEFSHash{Hash: &replacementEFSBlob{Size: 1}}, replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &value}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := replacementEFSKeyEqual(&tc.left, &tc.right); got != tc.equal {
				t.Fatal(got)
			}
		})
	}
}

func setReplacementTestInfo(r *Replacement, info os.FileInfo) { r.rooted.info = info }
