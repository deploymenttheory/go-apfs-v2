package hostmeta

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var copyFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("CopyFileW")

func prepareReplacement(source *os.File, path string, _ os.FileInfo) (*os.File, error) {
	from, err := windows.UTF16PtrFromString(source.Name())
	if err != nil {
		return nil, err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Preserve alternate data streams and file attributes in the private staging
	// directory. No signing implementation or Apple services are involved.
	result, _, err := copyFileW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 1)
	if result == 0 {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(to, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func restoreReplacementMetadata(source, target *os.File, st os.FileInfo) error {
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	sd, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, flags)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	group, _, err := sd.Group()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetSecurityInfo(windows.Handle(target.Fd()), windows.SE_FILE_OBJECT, flags, owner, group, dacl, nil); err != nil {
		return err
	}
	return target.Chmod(st.Mode())
}
