package cli

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func TestLockedVolumeUnlockError(t *testing.T) {
	withoutKeybag := lockedVolumeUnlockError(&apfs.Volume{})
	if withoutKeybag == nil || !strings.Contains(withoutKeybag.Error(), "no software-readable keybag") {
		t.Fatalf("missing keybag error = %v", withoutKeybag)
	}
	if strings.Contains(withoutKeybag.Error(), "wrong password") {
		t.Fatal("missing keybag blamed the password")
	}

	withKeybags := lockedVolumeUnlockError(&apfs.Volume{
		VolumeKeybag:    &apfs.VolumeKeybag{},
		ContainerKeybag: &apfs.ContainerKeybag{},
	})
	if withKeybags == nil || !strings.Contains(withKeybags.Error(), "wrong password") {
		t.Fatalf("rejected password error = %v", withKeybags)
	}
}
