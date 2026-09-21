package hostmeta

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func copyDirectoryStat(source, target *os.File, _, _ os.FileInfo) error {
	from, err := replacementBasic(source)
	if err != nil {
		return err
	}
	to, err := replacementBasic(target)
	if err != nil {
		return err
	}
	const ordinary = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	const allowed = ordinary | windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_NORMAL
	if from.Attributes & ^uint32(allowed) != 0 || to.Attributes & ^uint32(allowed) != 0 {
		return fmt.Errorf("%w: unsupported Windows directory attributes", ErrUnsupportedDirectoryStat)
	}
	// ReOpenFile requests only metadata access on the same object, including a
	// moved directory. It never resolves File.Name or copies DACL/owner state.
	file, err := reopenHostFile(target, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return err
	}
	defer file.Close()
	basic := replacementBasicInfo{
		LastAccessTime: from.LastAccessTime,
		LastWriteTime:  from.LastWriteTime,
		Attributes:     from.Attributes&ordinary | windows.FILE_ATTRIBUTE_DIRECTORY,
	}
	return windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
}
