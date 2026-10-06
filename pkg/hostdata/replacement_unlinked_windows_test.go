package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestReplacementWindowsPreparedUnlinkedSource(t *testing.T) {
	for _, rooted := range []bool{false, true} {
		for _, kind := range []string{"ordinary", "compressed", "sparse", "encrypted", "deny-write", "readonly"} {
			for _, canceled := range []bool{false, true} {
				name := map[bool]string{false: "path", true: "root"}[rooted] + "/" + kind + "/" + map[bool]string{false: "publish", true: "cancel"}[canceled]
				t.Run(name, func(t *testing.T) {
					sourceName := filepath.Join(t.TempDir(), "source")
					payload := []byte("held main data survives namespace unlink")
					stream := bytes.Repeat([]byte("held named metadata"), 4097)
					if err := os.WriteFile(sourceName, payload, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(sourceName+":metadata", stream, 0600); err != nil {
						t.Fatal(err)
					}
					strictWindowsSet(t, sourceName, "replacement.test", []byte("native EA survives unlink"))
					var sparseAllocation int64
					switch kind {
					case "compressed":
						replacementCompress(t, sourceName)
					case "encrypted":
						replacementEncrypt(t, sourceName)
					case "sparse":
						for _, path := range []string{sourceName, sourceName + ":sparse"} {
							file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
							if err != nil {
								t.Fatal(err)
							}
							err = replacementSparse(file)
							if path != sourceName && err == nil {
								_, err = file.WriteAt([]byte("tail"), int64(4<<30)+23)
								if err == nil {
									sparseAllocation = replacementUnlinkedAllocation(t, file)
								}
							}
							if err = errors.Join(err, file.Close()); err != nil {
								t.Fatal(err)
							}
						}
					}
					replacementSetCreation(t, sourceName)
					pointer, err := windows.UTF16PtrFromString(sourceName)
					if err != nil {
						t.Fatal(err)
					}
					if kind == "readonly" {
						if err = windows.SetFileAttributes(pointer, windows.FILE_ATTRIBUTE_READONLY); err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() {
							if _, e := os.Stat(sourceName); e == nil {
								if e = windows.SetFileAttributes(pointer, windows.FILE_ATTRIBUTE_NORMAL); e != nil {
									t.Error(e)
								}
							}
						})
					}
					if kind == "deny-write" {
						replacementDenyWrites(t, sourceName)
					}
					handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
					if err != nil {
						t.Fatal(err)
					}
					source := os.NewFile(uintptr(handle), sourceName)
					defer source.Close()
					before := replacementNativeSnapshot(t, source)
					securityFlags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
					security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityFlags)
					if err != nil {
						t.Fatal(err)
					}
					queries := []*windows.LazyProc{replacementQueryUsers, replacementQueryRecovery}
					var keys [2]*replacementEFSList
					if kind == "encrypted" {
						for i, query := range queries {
							keys[i], err = replacementQueryEFS(t.Context(), sourceName, query)
							if err != nil {
								t.Fatal(err)
							}
							if keys[i] != nil {
								defer freeReplacementEFS(keys[i])
							}
						}
					}
					parent := t.TempDir()
					var file *os.File
					var restore func(context.Context) error
					var closeStage func() error
					var publish func() error
					output := filepath.Join(parent, "published")
					if rooted {
						root, e := os.OpenRoot(parent)
						if e != nil {
							t.Fatal(e)
						}
						r, e := PrepareReplacementAtContext(t.Context(), source, root, ".")
						if e != nil {
							_ = root.Close()
							t.Fatal(e)
						}
						file, restore = r.File, r.RestoreMetadataContext
						closeStage = func() error { return errors.Join(r.Close(), root.Close()) }
						publish = func() error { return root.Rename(r.Path, "published") }
					} else {
						r, e := PrepareReplacementContext(t.Context(), source, parent)
						if e != nil {
							t.Fatal(e)
						}
						file, restore, closeStage = r.File, r.RestoreMetadataContext, r.Close
						publish = func() error { return os.Rename(file.Name(), output) }
					}
					defer closeStage()
					deleteHandle, err := windows.CreateFile(pointer, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
					if err != nil {
						t.Fatal(err)
					}
					flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
					var status windows.IO_STATUS_BLOCK
					err = windows.NtSetInformationFile(deleteHandle, &status, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileDispositionInformationEx)
					if err = errors.Join(err, windows.CloseHandle(deleteHandle)); err != nil {
						t.Fatalf("native post-preparation unlink: %v", err)
					}
					if _, err = os.Stat(sourceName); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("source namespace survived unlink: %v", err)
					}
					var nativeInfo windows.ByHandleFileInformation
					if err = windows.GetFileInformationByHandle(handle, &nativeInfo); err != nil || nativeInfo.NumberOfLinks != 0 {
						t.Fatalf("held zero-link control: links=%d %v", nativeInfo.NumberOfLinks, err)
					}
					held := make([]byte, len(payload))
					if _, err = source.ReadAt(held, 0); err != nil || !bytes.Equal(held, payload) {
						t.Fatalf("held source changed: %q %v", held, err)
					}
					rewritten := []byte("replacement main bytes")
					if _, err = file.WriteAt(rewritten, 0); err != nil {
						t.Fatal(err)
					}
					if err = file.Truncate(int64(len(rewritten))); err != nil {
						t.Fatal(err)
					}
					if canceled {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						if err = restore(ctx); !errors.Is(err, context.Canceled) {
							t.Fatalf("post-unlink cancellation: %v", err)
						}
						if err = closeStage(); err != nil {
							t.Fatal(err)
						}
						entries, e := os.ReadDir(parent)
						if e != nil || len(entries) != 0 {
							t.Fatalf("canceled stage retained: %v %v", entries, e)
						}
						return
					}
					if err = restore(t.Context()); err != nil {
						t.Fatalf("restore from held zero-link source: %v", err)
					}
					if err = file.Close(); err != nil {
						t.Fatal(err)
					}
					if err = publish(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { replacementResetTestFile(t, output) })
					if err = closeStage(); err != nil {
						t.Fatal(err)
					}
					result, err := os.Open(output)
					if err != nil {
						t.Fatal(err)
					}
					defer result.Close()
					actual := replacementNativeSnapshot(t, result)
					if actual.FileAttributes != before.FileAttributes || actual.CreationTime != before.CreationTime {
						t.Fatalf("published source metadata: %#v want %#v", actual, before)
					}
					copiedSecurity, err := windows.GetSecurityInfo(windows.Handle(result.Fd()), windows.SE_FILE_OBJECT, securityFlags)
					if err != nil {
						t.Fatal(err)
					}
					if copiedSecurity.String() != security.String() {
						t.Fatalf("published security: %s want %s", copiedSecurity.String(), security.String())
					}
					got, err := io.ReadAll(result)
					if err != nil || !bytes.Equal(got, rewritten) {
						t.Fatalf("published data: %q %v", got, err)
					}
					got, err = os.ReadFile(output + ":metadata")
					if err != nil || !bytes.Equal(got, stream) {
						t.Fatalf("published named metadata: %d %v", len(got), err)
					}
					ea, present, err := ReadXattr(result, "replacement.test", 128)
					if err != nil || !present || string(ea) != "native EA survives unlink" {
						t.Fatalf("published EA: %q %v %v", ea, present, err)
					}
					if kind == "sparse" {
						named, e := os.Open(output + ":sparse")
						if e != nil {
							t.Fatal(e)
						}
						defer named.Close()
						if allocation := replacementUnlinkedAllocation(t, named); allocation != sparseAllocation {
							t.Fatalf("sparse ADS allocation changed: %d want %d", allocation, sparseAllocation)
						}
						var tail [4]byte
						_, e = named.ReadAt(tail[:], int64(4<<30)+23)
						if e = errors.Join(e, named.Close()); e != nil || string(tail[:]) != "tail" {
							t.Fatalf("published sparse stream: %q %v", tail, e)
						}
					}
					if kind == "encrypted" {
						for i, query := range queries {
							copied, e := replacementQueryEFS(t.Context(), output, query)
							if e != nil {
								t.Fatal(e)
							}
							equal := replacementEFSKeysEqual(keys[i], copied)
							if copied != nil {
								freeReplacementEFS(copied)
							}
							if !equal {
								t.Fatal("post-unlink EFS recipient/recovery keys changed")
							}
						}
					}
					// Cleanup of a committed stage must leave the published metadata untouched.
					if err = closeStage(); err != nil {
						t.Fatal(err)
					}
					final := replacementNativeSnapshot(t, result)
					if final.FileAttributes != actual.FileAttributes || final.CreationTime != actual.CreationTime {
						t.Fatalf("committed cleanup changed metadata: %#v %#v", final, actual)
					}
					entries, err := os.ReadDir(parent)
					if err != nil || len(entries) != 1 || entries[0].Name() != "published" {
						t.Fatalf("private stage survived publication: %v %v", entries, err)
					}
				})
			}
		}
	}
}

func replacementUnlinkedAllocation(t *testing.T, file *os.File) int64 {
	t.Helper()
	var info struct {
		AllocationSize, EndOfFile int64
		NumberOfLinks             uint32
		DeletePending, Directory  byte
		_                         [2]byte
	}
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileStandardInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		t.Fatal(err)
	}
	return info.AllocationSize
}
