package hostdata

import (
	"context"
	"os"

	"golang.org/x/sys/windows"
)

func restoreReplacementMetadataContext(ctx context.Context, source, target *os.File, st os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	return replacementStep(ctx, func() error { return target.Chmod(st.Mode()) })
}
