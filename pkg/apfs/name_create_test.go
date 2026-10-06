package apfs

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"strings"
	"syscall"
	"testing"
)

func TestCreateNameTargetAdmission(t *testing.T) {
	for _, major := range []uint32{15, 26, 27} {
		target := osversion.Version{Major: major}
		for _, c := range []struct {
			name string
			want error
		}{{"plain", nil}, {"", syscall.EINVAL}, {"a/b", syscall.EINVAL}, {"a\x00b", syscall.EINVAL}, {"x\x80y", syscall.EILSEQ}, {"x\u0378y", syscall.EILSEQ}, {"x\uffffy", syscall.EILSEQ}, {strings.Repeat("é", 255), nil}, {strings.Repeat("a", 256), syscall.ENAMETOOLONG}, {"�", nil}} {
			if e := ValidateCreateName(c.name, target); !errors.Is(e, c.want) {
				t.Fatalf("macOS%d %q:%v want%v", major, c.name, e, c.want)
			}
		}
		e := ValidateCreateName("x\uA7CEy", target)
		if (e == nil) != (major != 15) {
			t.Fatal("native version admission", major, e)
		}
	}
	if ValidateCreateName("x", osversion.Version{}) == nil {
		t.Fatal("implicit profile")
	}
}
