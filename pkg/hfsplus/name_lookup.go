package hfsplus

import (
	"strings"
	"syscall"
)

// ValidateLookupName checks one existing-object pathname component using HFS's
// catalog conversion. Illegal UTF-8 bytes are percent escaped, not replaced by
// U+FFFD or universally rejected. The 255-unit limit applies after that escaping
// and frozen HFS canonical decomposition. Directory search is authorized first.
func ValidateLookupName(name string) error {
	if strings.ContainsAny(name, "/\x00") {
		return syscall.EINVAL
	}
	if name == "" {
		return syscall.ENOENT
	}
	units := 0
	for _, r := range normalizeName(catalogName(name)) {
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > 255 {
		return syscall.ENAMETOOLONG
	}
	return nil
}
