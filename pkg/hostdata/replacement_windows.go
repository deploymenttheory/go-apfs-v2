package hostdata

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"unsafe"
)

var replacementSetSecurityObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetSecurityObject")

// Restore the complete descriptor through the held file. SetSecurityInfo with
// UNPROTECTED_DACL_SECURITY_INFORMATION re-inherits from the temporary private
// directory and therefore changes the source's inherited ACEs. The documented
// NtSetSecurityObject interface accepts the descriptor and its control bits:
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetsecurityobject
func replacementSetFileSecurity(target *os.File, flags windows.SECURITY_INFORMATION, sd *windows.SECURITY_DESCRIPTOR) error {
	conn, err := target.SyscallConn()
	if err != nil {
		return err
	}
	// AI is persisted only together with its write-side AR request. GetSecurityInfo
	// returns the persisted AI bit, not AR. Use a private descriptor so the caller's
	// captured descriptor remains unchanged.
	owned, err := sd.ToAbsolute()
	if err != nil {
		return err
	}
	control, _, err := owned.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_AUTO_INHERITED != 0 {
		if err = owned.SetControl(windows.SE_DACL_AUTO_INHERIT_REQ, windows.SE_DACL_AUTO_INHERIT_REQ); err != nil {
			return err
		}
	}
	var native error
	err = conn.Control(func(fd uintptr) {
		result, _, _ := replacementSetSecurityObject.Call(fd, uintptr(flags), uintptr(unsafe.Pointer(owned)))
		if status := windows.NTStatus(result); status != 0 {
			native = status.Errno()
		}
	})
	runtime.KeepAlive(owned)
	return errors.Join(err, native)
}

func restoreReplacementMetadataContext(ctx context.Context, source, target *os.File, st os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	sd, err := replacementValue(ctx, func() (*windows.SECURITY_DESCRIPTOR, error) {
		return windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, flags)
	})
	if err != nil {
		return err
	}
	if err = replacementStep(ctx, func() error { return replacementSetFileSecurity(target, flags, sd) }); err != nil {
		return err
	}
	return replacementStep(ctx, func() error { return target.Chmod(st.Mode()) })
}
