package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func replacementEncrypt(t *testing.T, path string) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := windows.NewLazySystemDLL("advapi32.dll").NewProc("EncryptFileW").Call(uintptr(unsafe.Pointer(p)))
	if ok == 0 {
		t.Fatalf("required native EFS setup: %v", err)
	}
}
func replacementCompress(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var format uint16 = 2
	var n uint32
	err = windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_SET_COMPRESSION, (*byte)(unsafe.Pointer(&format)), 2, nil, 0, &n, nil)
	if err = errors.Join(err, f.Close()); err != nil {
		t.Fatalf("required NTFS compression setup: %v", err)
	}
}

func TestReplacementWindowsNativeCapabilities(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		for _, kind := range []string{"plain", "empty", "compressed", "compressed-empty", "efs", "efs-empty", "deny-write", "deny-write-readonly"} {
			t.Run(kind, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "source")
				payload := bytes.Repeat([]byte("native copy control"), 8192)
				if kind == "empty" || kind == "compressed-empty" || kind == "efs-empty" {
					payload = nil
				}
				if err := os.WriteFile(path, payload, 0600); err != nil {
					t.Fatal(err)
				}
				stream := bytes.Repeat([]byte{0x74}, (8<<20)+1)
				if err := os.WriteFile(path+":metadata", stream, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "compressed" || kind == "compressed-empty" {
					replacementCompress(t, path)
				}
				if kind == "efs" || kind == "efs-empty" {
					replacementEncrypt(t, path)
				}
				if kind == "deny-write-readonly" {
					name, e := windows.UTF16PtrFromString(path)
					if e != nil {
						t.Fatal(e)
					}
					if e = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_READONLY); e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { _ = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_NORMAL) })
				}
				if kind == "deny-write" || kind == "deny-write-readonly" {
					replacementDenyWrites(t, path)
				}
				source, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				// Independent native copy control has no production callback or validation.
				reference := filepath.Join(t.TempDir(), "reference")
				from, _ := windows.UTF16PtrFromString(path)
				to, _ := windows.UTF16PtrFromString(reference)
				ok, _, nativeErr := copyFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0, 0, 0, 0x801)
				if ok == 0 {
					t.Fatalf("native CopyFileEx control: %v", nativeErr)
				}
				want, err := os.Open(reference)
				if err != nil {
					t.Fatal(err)
				}
				defer want.Close()
				dir := t.TempDir()
				r, err := prepare(source, dir)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if _, err = r.File.WriteAt([]byte("replacement bytes"), 0); err != nil {
					t.Fatal(err)
				}
				if err = r.File.Truncate(17); err != nil {
					t.Fatal(err)
				}
				if err = r.RestoreMetadata(); err != nil {
					t.Fatal(err)
				}
				actual, err := replacementBasic(r.File)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := replacementBasic(want)
				if err != nil {
					t.Fatal(err)
				}
				if actual.Attributes != expected.Attributes || actual.CreationTime != expected.CreationTime {
					t.Fatalf("native metadata mismatch: %#v want %#v", actual, expected)
				}
				if err = replacementVerifyEFS(context.Background(), want, r.File); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(r.File.Name() + ":metadata")
				if err != nil || !bytes.Equal(got, stream) {
					t.Fatalf("alternate stream: size %d, %v", len(got), err)
				}
				unchanged, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(unchanged, payload) {
					t.Fatalf("source changed: %v", err)
				}
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("stage cleanup: %v %v", entries, err)
				}
			})
		}
	})
}

func replacementTestStage(t *testing.T) (*os.Root, *os.Root, string) {
	t.Helper()
	parent := t.TempDir()
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	release, err := makeReplacementDirectoryAt(context.Background(), root, "private")
	if err != nil {
		t.Fatal(err)
	}
	stage, err := root.OpenRoot("private")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(release(), stage.Close(), root.Close()); err != nil {
			t.Error(err)
		}
	})
	return root, stage, parent
}

func TestReplacementWindowsCopyCallbacks(t *testing.T) {
	for _, name := range []string{"success", "empty", "cancel-first", "cancel-after-copy", "omitted-callback", "wrong-source", "ancestor-rename", "dangling-leaf"} {
		t.Run(name, func(t *testing.T) {
			root, stage, parent := replacementTestStage(t)
			sourcePath := filepath.Join(t.TempDir(), "source")
			data := []byte("actual held input")
			if name == "empty" {
				data = nil
			}
			if err := os.WriteFile(sourcePath, data, 0600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			seen := 0
			outside := filepath.Join(t.TempDir(), "must-not-exist")
			copied, err := copyReplacementWindows(ctx, source, stage, func(from, to *uint16, state *replacementCopyState) error {
				if name == "omitted-callback" {
					return nil
				}
				if name == "wrong-source" {
					state.source.ID[0] ^= 1
				}
				if name == "ancestor-rename" {
					if e := os.Rename(parent, parent+"-escaped"); e == nil {
						t.Fatal("namespace anchor permitted ancestor rename")
					}
					if e := root.Rename("private", "rebound"); e == nil {
						t.Fatal("private creation handle permitted stage rename")
					}
				}
				if name == "dangling-leaf" {
					if e := os.Symlink(outside, filepath.Join(parent, "private", "replacement")); e != nil {
						t.Fatalf("required symlink control: %v", e)
					}
				}
				state.observe = func(uint32) error {
					seen++
					if name == "cancel-first" {
						cancel()
					}
					return nil
				}
				e := runReplacementCopy(from, to, state)
				if name == "cancel-after-copy" {
					cancel()
				}
				return e
			})
			wantError := name == "cancel-first" || name == "cancel-after-copy" || name == "omitted-callback" || name == "wrong-source" || name == "dangling-leaf"
			if wantError {
				if err == nil || copied != nil {
					t.Fatalf("unsafe copy accepted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if seen == 0 {
					t.Fatal("native copy omitted callback")
				}
				if err = copied.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if name == "cancel-first" || name == "cancel-after-copy" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			}
			if _, e := os.Stat(outside); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("outside path touched: %v", e)
			}
			replacementCopyCallbacks.Lock()
			count := len(replacementCopyCallbacks.states)
			replacementCopyCallbacks.Unlock()
			if count != 0 {
				t.Fatalf("callback registry leaked: %d", count)
			}
		})
	}
}

func TestReplacementWindowsEFSKeyComparison(t *testing.T) {
	first, second := byte(1), byte(2)
	a := &replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &first}}
	b := &replacementEFSHash{Hash: &replacementEFSBlob{Size: 1, Data: &second}}
	makeList := func(keys ...*replacementEFSHash) *replacementEFSList {
		if len(keys) == 0 {
			return &replacementEFSList{}
		}
		return &replacementEFSList{Count: uint32(len(keys)), Entries: &keys[0]}
	}
	for _, tc := range []struct {
		name  string
		a, b  *replacementEFSList
		equal bool
	}{
		{"none", nil, nil, true}, {"missing", nil, makeList(), false}, {"empty", makeList(), makeList(), true}, {"reordered", makeList(a, b), makeList(b, a), true}, {"lost", makeList(a, b), makeList(a), false}, {"substituted", makeList(a, b), makeList(a, a), false}, {"nil-key", makeList(nil), makeList(nil), false}, {"nil-hash", makeList(&replacementEFSHash{}), makeList(a), false}, {"nil-array", &replacementEFSList{Count: 1}, makeList(a), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := replacementEFSKeysEqual(tc.a, tc.b); got != tc.equal {
				t.Fatalf("got %v want %v", got, tc.equal)
			}
		})
	}
}

func replacementDenyWrites(t *testing.T, path string) {
	t.Helper()
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	original, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		t.Fatal(e)
	}
	oldACL, _, e := original.DACL()
	if e != nil {
		t.Fatal(e)
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(D;;0x102;;;WD)(A;;FA;;;" + user.User.Sid.String() + ")")
	if e != nil {
		t.Fatal(e)
	}
	acl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, oldACL, nil); e != nil {
			t.Error(e)
		}
		if e := windows.CloseHandle(h); e != nil {
			t.Error(e)
		}
	})
}

func TestReplacementWindowsHeldRenamedSource(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		original := filepath.Join(t.TempDir(), "source")
		if e := os.WriteFile(original, []byte("held bytes"), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(original+":identity", []byte("held stream"), 0600); e != nil {
			t.Fatal(e)
		}
		name, e := windows.UTF16PtrFromString(original)
		if e != nil {
			t.Fatal(e)
		}
		handle, e := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		source := os.NewFile(uintptr(handle), original)
		defer source.Close()
		moved := original + "-moved"
		if e = os.Rename(original, moved); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(original, []byte("rebound bytes"), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(original+":identity", []byte("wrong stream"), 0600); e != nil {
			t.Fatal(e)
		}
		r, e := prepare(source, t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		got, e := os.ReadFile(r.File.Name() + ":identity")
		if e != nil || string(got) != "held stream" {
			t.Fatalf("copied rebound source: %q %v", got, e)
		}
		if got, e = os.ReadFile(moved); e != nil || string(got) != "held bytes" {
			t.Fatal(string(got), e)
		}
		if got, e = os.ReadFile(original); e != nil || string(got) != "rebound bytes" {
			t.Fatal(string(got), e)
		}
	})
}
