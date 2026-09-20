package hostmeta

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReplacementWindowsStreamsAndSecurity(t *testing.T) {
	source := replacementSource(t, 0600)
	if err := os.WriteFile(source.Name()+":test-metadata", []byte("alternate stream"), 0600); err != nil {
		t.Fatal(err)
	}
	// A protected DACL must retain that protection, not inherit new ACEs.
	sd, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	path, err := windows.UTF16PtrFromString(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	r, err := PrepareReplacement(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.RestoreMetadata(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(r.File.Name() + ":test-metadata"); err != nil || string(got) != "alternate stream" {
		t.Fatalf("stream = %q, %v", got, err)
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	before, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetSecurityInfo(windows.Handle(r.File.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("security = %s; want %s", after.String(), before.String())
	}
}
