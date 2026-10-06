package apfs

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestLookupNameValidation(t *testing.T) {
	for _, c := range []struct {
		name string
		want error
	}{{"", syscall.ENOENT}, {"a/b", syscall.EINVAL}, {"a\x00b", syscall.EINVAL}, {"x\x80y", syscall.ENOENT}, {strings.Repeat("a", 256) + "\x80", syscall.ENOENT}, {strings.Repeat("a", 255), nil}, {strings.Repeat("a", 256), syscall.ENAMETOOLONG}, {strings.Repeat("é", 255), nil}, {strings.Repeat("e\u0301", 128), syscall.ENAMETOOLONG}, {strings.Repeat("😀", 127), nil}, {strings.Repeat("😀", 128), syscall.ENAMETOOLONG}, {"x\u0378y", nil}} {
		if e := ValidateLookupName(c.name); !errors.Is(e, c.want) {
			t.Fatalf("%q got%v want%v", c.name, e, c.want)
		}
	}
}
