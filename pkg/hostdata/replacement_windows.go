package hostdata

import (
	"context"
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
	result, _, _ := replacementSetSecurityObject.Call(target.Fd(), uintptr(flags), uintptr(unsafe.Pointer(sd)))
	runtime.KeepAlive(target)
	runtime.KeepAlive(sd)
	if status := windows.NTStatus(result); status != 0 {
		return status.Errno()
	}
	return nil
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
