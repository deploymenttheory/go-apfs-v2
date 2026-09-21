package hostmeta

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	reopenFile  = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")
	backupRead  = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupRead")
	backupWrite = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupWrite")
)

// ReOpenFile adds access to an already opened object without resolving its name.
// It also gives BackupRead/Write synchronous handles and independent file offsets.
func reopenReplacementFile(f *os.File, access uint32) (*os.File, error) {
	return reopenHostFile(f, access, 0)
}

func reopenHostFile(f *os.File, access, flags uint32) (*os.File, error) {
	h, _, err := reopenFile.Call(f.Fd(), uintptr(access), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, uintptr(flags))
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, err
	}
	return os.NewFile(h, f.Name()), nil
}

type replacementBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	Attributes                                              uint32
	_                                                       uint32
}

func replacementBasic(f *os.File) (replacementBasicInfo, error) {
	var basic replacementBasicInfo
	err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
	return basic, err
}

func prepareReplacementAt(source *os.File, stage *os.Root, _ os.FileInfo) (*os.File, error) {
	basic, err := replacementBasic(source)
	if err != nil {
		return nil, err
	}
	if basic.Attributes&(windows.FILE_ATTRIBUTE_COMPRESSED|windows.FILE_ATTRIBUTE_ENCRYPTED|windows.FILE_ATTRIBUTE_SPARSE_FILE|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, fmt.Errorf("%w: compressed, encrypted, sparse or reparse source", ErrUnsupportedReplacement)
	}
	f, err := stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	target, err := reopenReplacementFile(f, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER)
	closeErr := f.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		target.Close()
		return nil, closeErr
	}
	if err := copyReplacementStreams(source, target); err != nil {
		target.Close()
		return nil, err
	}
	return target, nil
}

func restoreReplacementMetadataAt(source, target *os.File, info os.FileInfo) error {
	if err := restoreReplacementMetadata(source, target, info); err != nil {
		return err
	}
	basic, err := replacementBasic(source)
	if err != nil {
		return err
	}
	// Zero leaves the destination's write/access/change times unchanged. Copy
	// creation time and attributes, including hidden/system/archive/readonly.
	basic.LastAccessTime, basic.LastWriteTime, basic.ChangeTime = 0, 0, 0
	return windows.SetFileInformationByHandle(windows.Handle(target.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
}

type replacementBackup struct {
	file  *os.File
	proc  *windows.LazyProc
	state uintptr
}

func (b *replacementBackup) transfer(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n uint32
	ok, _, err := b.proc.Call(b.file.Fd(), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&n)), 0, 0, uintptr(unsafe.Pointer(&b.state)))
	if ok == 0 {
		return 0, err
	}
	if n > uint32(len(p)) {
		return 0, fmt.Errorf("invalid backup transfer length")
	}
	return int(n), nil
}

func (b *replacementBackup) Read(p []byte) (int, error) {
	n, err := b.transfer(p)
	if n == 0 && err == nil && len(p) != 0 {
		err = io.EOF
	}
	return n, err
}

func (b *replacementBackup) Write(p []byte) (int, error) {
	n, err := b.transfer(p)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (b *replacementBackup) close() error {
	if b.state == 0 {
		return nil
	}
	ok, _, err := b.proc.Call(0, 0, 0, 0, 1, 0, uintptr(unsafe.Pointer(&b.state)))
	if ok == 0 {
		return err
	}
	return nil
}

// WIN32_STREAM_ID is a 20-byte wire header followed by a UTF-16 stream name
// and Size bytes. Copy only EAs and named data streams. In particular, never
// feed BACKUP_LINK or OBJECT_ID to BackupWrite: replacement must detach links
// and must not recreate an identity or resolve a pathname from metadata.
func copyReplacementStreams(source, target *os.File) (err error) {
	input, err := reopenReplacementFile(source, windows.GENERIC_READ)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	r := &replacementBackup{file: input, proc: backupRead}
	w := &replacementBackup{file: target, proc: backupWrite}
	defer func() { err = errors.Join(err, r.close(), w.close()) }()
	reader := bufio.NewReaderSize(r, 64<<10)
	writer := bufio.NewWriterSize(w, 64<<10)
	budget := uint64(8 << 20)
	for count := 0; count < 65536; count++ {
		var header [20]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if err == io.EOF {
				return writer.Flush()
			}
			return err
		}
		id := binary.LittleEndian.Uint32(header[:4])
		size := binary.LittleEndian.Uint64(header[8:16])
		nameSize := binary.LittleEndian.Uint32(header[16:])
		if size > 1<<63-1 || nameSize > 64<<10 || nameSize%2 != 0 {
			return fmt.Errorf("invalid backup stream size")
		}
		name := make([]byte, int(nameSize))
		if _, err := io.ReadFull(reader, name); err != nil {
			return err
		}
		switch id {
		case 1, 5, 7: // main data, hard-link records, object identity
			if _, err := io.CopyN(io.Discard, reader, int64(size)); err != nil {
				return err
			}
		case 2, 4: // extended attributes, alternate data
			if uint64(nameSize) > budget || size > budget-uint64(nameSize) {
				return fmt.Errorf("%w: extended attributes/streams exceed limit", ErrUnsupportedReplacement)
			}
			budget -= uint64(nameSize) + size
			if id == 4 {
				units := make([]uint16, len(name)/2)
				for i := range units {
					units[i] = binary.LittleEndian.Uint16(name[2*i:])
				}
				text := string(utf16.Decode(units))
				if !strings.HasPrefix(text, ":") || !strings.HasSuffix(text, ":$DATA") || strings.Count(text, ":") != 2 || strings.ContainsAny(text, "\\/\x00") {
					return fmt.Errorf("%w: alternate stream name", ErrUnsupportedReplacement)
				}
			}
			if _, err := writer.Write(header[:]); err != nil {
				return err
			}
			if _, err := writer.Write(name); err != nil {
				return err
			}
			if _, err := io.CopyN(writer, reader, int64(size)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: backup stream type %d", ErrUnsupportedReplacement, id)
		}
	}
	return fmt.Errorf("%w: backup stream count", ErrUnsupportedReplacement)
}
