// The APFS object definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Object represents the APFS object structure
type Object struct {
	// The checksum
	// Consists of 8 bytes
	Checksum uint64

	// The identifier
	// Consists of 8 bytes
	Identifier uint64

	// The transaction identifier
	// Consists of 8 bytes
	TransactionIdentifier uint64

	// The type
	// Consists of 4 bytes
	Type uint32

	// The subtype
	// Consists of 4 bytes
	Subtype uint32
}

// ObjectHeaderSize is the size of an APFS object header in bytes
const ObjectHeaderSize = 32

// NewObject creates a new object
func NewObject() (*Object, error) {
	return &Object{}, nil
}

// Free releases resources associated with the object
func (o *Object) Free() error {
	if o == nil {
		return fmt.Errorf("invalid object")
	}
	// Nothing to free in Go
	return nil
}

// ReadFileIOHandle reads the object from a file at the specified offset
// Corresponds to libfsapfs_object_read_file_io_handle
func (o *Object) ReadFileIOHandle(fileHandle io.ReaderAt, fileOffset int64) error {
	if o == nil {
		return fmt.Errorf("invalid object")
	}

	if IsVerbose() {
		Printf("%s: reading object at offset: %d (0x%08x)\n",
			"ReadFileIOHandle", fileOffset, fileOffset)
	}

	// Read object header (32 bytes)
	data := make([]byte, ObjectHeaderSize)
	n, err := fileHandle.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read object data at offset: %d (0x%08x)", fileOffset, fileOffset)
	}
	if n != ObjectHeaderSize {
		return fmt.Errorf("unable to read object data at offset: %d (0x%08x)", fileOffset, fileOffset)
	}

	if err := o.ReadData(data); err != nil {
		return fmt.Errorf("unable to read object data: %w", err)
	}

	return nil
}

// ReadData reads the object from binary data
// Corresponds to libfsapfs_object_read_data
func (o *Object) ReadData(data []byte) error {
	if o == nil {
		return fmt.Errorf("invalid object")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ObjectHeaderSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if IsVerbose() {
		Printf("%s: object data:\n", "ReadData")
		PrintData(data[:ObjectHeaderSize], true)
	}

	// Parse object header
	o.Checksum = binary.LittleEndian.Uint64(data[0:8])
	o.Identifier = binary.LittleEndian.Uint64(data[8:16])
	o.TransactionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	o.Type = binary.LittleEndian.Uint32(data[24:28])
	o.Subtype = binary.LittleEndian.Uint32(data[28:32])

	if IsVerbose() {
		Printf("%s: checksum\t\t\t\t\t: 0x%08x\n", "ReadData", o.Checksum)
		Printf("%s: identifier\t\t\t\t\t: %d\n", "ReadData", o.Identifier)
		Printf("%s: transaction identifier\t\t\t: %d\n", "ReadData", o.TransactionIdentifier)
		Printf("%s: type\t\t\t\t\t: 0x%08x\n", "ReadData", o.Type)
		Printf("%s: subtype\t\t\t\t\t: 0x%08x\n", "ReadData", o.Subtype)
		Printf("\n")
	}

	return nil
}

// GetIdentifier retrieves the object identifier
// Corresponds to libfsapfs_object_get_identifier
func (o *Object) GetIdentifier() (uint64, error) {
	if o == nil {
		return 0, fmt.Errorf("invalid object")
	}
	return o.Identifier, nil
}

// GetTransactionIdentifier retrieves the transaction identifier
// Corresponds to libfsapfs_object_get_transaction_identifier
func (o *Object) GetTransactionIdentifier() (uint64, error) {
	if o == nil {
		return 0, fmt.Errorf("invalid object")
	}
	return o.TransactionIdentifier, nil
}

// GetType retrieves the object type
// Corresponds to libfsapfs_object_get_type
func (o *Object) GetType() (uint32, error) {
	if o == nil {
		return 0, fmt.Errorf("invalid object")
	}
	return o.Type, nil
}

// GetSubtype retrieves the object subtype
// Corresponds to libfsapfs_object_get_subtype
func (o *Object) GetSubtype() (uint32, error) {
	if o == nil {
		return 0, fmt.Errorf("invalid object")
	}
	return o.Subtype, nil
}
