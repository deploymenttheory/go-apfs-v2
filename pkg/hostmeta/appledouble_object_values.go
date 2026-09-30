package hostmeta

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type logicalObjectAttributes struct {
	meta   *LogicalMetadata
	order  []string
	values map[string]appledouble.Value
	mount  *bool
}

func newLogicalObjectAttributes(meta *LogicalMetadata, attrs []appledouble.StreamAttr, noSetID *bool) (*logicalObjectAttributes, error) {
	a := &logicalObjectAttributes{meta: meta, values: map[string]appledouble.Value{}}
	if noSetID != nil {
		value := *noSetID
		a.mount = &value
	}
	for _, attr := range attrs {
		if attr.Name == "" || strings.ContainsRune(attr.Name, 0) || len(attr.Name) > 127 {
			return nil, os.ErrInvalid
		}
		if _, exists := a.values[attr.Name]; exists {
			return nil, ErrXattrListMalformed
		}
		v := attr.Value
		if v == nil {
			v = bytes.NewReader(nil)
		}
		if v.Size() < 0 {
			return nil, os.ErrInvalid
		}
		a.order = append(a.order, attr.Name)
		a.values[attr.Name] = v
	}
	return a, nil
}
func (a *logicalObjectAttributes) snapshot() []appledouble.StreamAttr {
	out := make([]appledouble.StreamAttr, 0, len(a.order))
	for _, name := range a.order {
		out = append(out, appledouble.StreamAttr{Name: name, Value: a.values[name]})
	}
	return out
}
func (a *logicalObjectAttributes) listSize() (int, error) {
	n := 0
	for _, name := range a.order {
		n += len(name) + 1
	}
	return n, nil
}
func (a *logicalObjectAttributes) names(capacity int) ([]string, error) {
	n, _ := a.listSize()
	if capacity < n {
		return nil, ErrXattrTooLarge
	}
	return slices.Clone(a.order), nil
}
func (a *logicalObjectAttributes) size(name string) (int64, error) {
	v, ok := a.values[name]
	if !ok {
		return 0, os.ErrNotExist
	}
	return v.Size(), nil
}
func (a *logicalObjectAttributes) read(name string, dst []byte) (int, error) {
	v, ok := a.values[name]
	if !ok {
		return 0, os.ErrNotExist
	}
	if v.Size() > int64(len(dst)) {
		return 0, ErrXattrTooLarge
	}
	n, err := v.ReadAt(dst[:int(v.Size())], 0)
	if errors.Is(err, io.EOF) && int64(n) == v.Size() {
		err = nil
	}
	if err == nil && int64(n) != v.Size() {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
func (a *logicalObjectAttributes) remove(name string) error {
	if _, ok := a.values[name]; !ok {
		return os.ErrNotExist
	}
	delete(a.values, name)
	a.order = slices.DeleteFunc(a.order, func(n string) bool { return n == name })
	return nil
}
func (a *logicalObjectAttributes) write(name string, value []byte) error {
	if name == "" || len(name) > 127 || strings.ContainsRune(name, 0) {
		return os.ErrInvalid
	}
	if name == appledouble.FinderInfoName {
		if len(value) != 32 {
			return os.ErrInvalid
		}
		if [32]byte(value) == [32]byte{} {
			if _, ok := a.values[name]; ok {
				return a.remove(name)
			}
			return nil
		}
	}
	old, present := a.values[name]
	if name == appledouble.ResourceForkName && len(value) == 0 {
		return nil
	}
	if !present {
		a.order = append(a.order, name)
	}
	owned := bytes.Clone(value)
	var next appledouble.Value = bytes.NewReader(owned)
	if name == appledouble.ResourceForkName && present && old.Size() > int64(len(owned)) {
		next = &prefixObjectValue{head: owned, tail: old}
	}
	a.values[name] = next
	return nil
}
func (a *logicalObjectAttributes) noSetID() (bool, error) {
	if a.mount == nil {
		return false, errors.ErrUnsupported
	}
	return *a.mount, nil
}
func (a *logicalObjectAttributes) quarantine(ctx context.Context, profile appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := a.quarantineBytes()
	if err != nil || b == nil {
		return nil, err
	}
	return appledouble.ParseQuarantineXattrWithProfile(b, profile)
}
func (a *logicalObjectAttributes) quarantineBytes() ([]byte, error) {
	size, err := a.size(appledouble.QuarantineName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if size > appledouble.MaxQuarantineXattrSize {
		return nil, appledouble.ErrQuarantine
	}
	b := make([]byte, int(size))
	_, err = a.read(appledouble.QuarantineName, b)
	return b, err
}
func (a *logicalObjectAttributes) applyQuarantine(ctx context.Context, q *appledouble.Quarantine, process QuarantineProcessCapture, timestamp uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := process.Process()
	if err != nil {
		return err
	}
	existing, err := a.quarantineBytes()
	if err != nil {
		return err
	}
	stat, _ := a.meta.CaptureStat()
	kind := appledouble.QuarantineRegularFile
	switch stat.Mode & 0170000 {
	case 0040000:
		kind = appledouble.QuarantineDirectory
	case 0120000:
		kind = appledouble.QuarantineSymlink
	}
	plan, err := q.PlanApplication(appledouble.QuarantineApplicationContext{Profile: process.Profile, Process: p, ExistingXattr: existing, Timestamp: timestamp, Kind: kind})
	if err != nil {
		return err
	}
	if plan.Write {
		return a.write(appledouble.QuarantineName, plan.Value)
	}
	return nil
}

type prefixObjectValue struct {
	head []byte
	tail appledouble.Value
}

func (v *prefixObjectValue) Size() int64 { return v.tail.Size() }
func (v *prefixObjectValue) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= v.Size() {
		return 0, io.EOF
	}
	want := min(int64(len(p)), v.Size()-off)
	n := 0
	if off < int64(len(v.head)) {
		n = copy(p[:want], v.head[off:])
	}
	if int64(n) < want {
		read, err := v.tail.ReadAt(p[n:want], off+int64(n))
		n += read
		if err != nil && !errors.Is(err, io.EOF) {
			return n, err
		}
		if int64(n) != want {
			return n, io.ErrUnexpectedEOF
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
