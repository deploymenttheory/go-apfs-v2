package hfsplus

import (
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostmeta"
)

// FileTimes reads catalog timestamps in UTC, resolving hard links but never
// following the final symlink. HFS stores whole seconds since 1904. Raw catalog
// dates are returned; this does not apply a host driver's sentinel conversion.
func (v *Volume) FileTimes(name string) (hostmeta.FileTimes, error) {
	if v == nil {
		return hostmeta.FileTimes{}, &fs.PathError{Op: "timestamps", Path: name, Err: fs.ErrInvalid}
	}
	info, err := v.Stat(name)
	if err != nil {
		return hostmeta.FileTimes{}, err
	}
	var values [4]hfsTime
	if s, ok := info.Sys().(*HFSPlusCatalogFolder); ok {
		values = [4]hfsTime{s.CreateDate, s.ContentModDate, s.AttributeModDate, s.AccessDate}
	} else {
		s := info.Sys().(*HFSPlusCatalogFile)
		values = [4]hfsTime{s.CreateDate, s.ContentModDate, s.AttributeModDate, s.AccessDate}
	}
	return hostmeta.FileTimes{Birth: values[0].Time(), Modify: values[1].Time(), Change: values[2].Time(), Access: values[3].Time()}, nil
}
