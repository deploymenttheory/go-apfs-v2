// Reading a FileVault-encrypted volume with a supplied password.
//
// The fixture is a real APFS volume that `diskutil apfs encryptVolume`
// encrypted, so nothing here is circular: this toolkit never wrote those bytes
// and cannot have encrypted them the way it happens to decrypt them. It is
// committed gzipped (a 48 MiB image compresses to about 100 KB, since most of
// it is unallocated) and runs on every platform, because the decryption is pure
// Go.
//
// The password is in the clear on purpose: it protects a test fixture whose
// plaintext is also in this file.
package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

const (
	encryptedPassword = "hunter2hunter2"
	encryptedSecret   = "secret content for the encrypted volume\n"
	encryptedNested   = "nested secret\n"
)

// TestEncryptedVolumeIsDetectedWithoutAPassword is the bug this fixes. Before,
// nothing in the toolkit noticed encryption at all: the volume superblock's
// APFS_FS_UNENCRYPTED flag was never read, no keybag was ever loaded, and
// IsLocked always answered false. A read then failed deep inside the B-tree
// parser with "invalid object type: 0x...", which tells a user nothing about
// what is actually wrong.
func TestEncryptedVolumeIsDetectedWithoutAPassword(t *testing.T) {
	stdout, stderr, code := run(t, "list", fixtureEnc)
	if code != exitcode.Auth {
		t.Errorf("exited %s, want %s\nstdout: %s\nstderr: %s",
			exitcode.Name(code), exitcode.Name(exitcode.Auth), stdout, stderr)
	}
	if !strings.Contains(stderr, "encrypted") {
		t.Errorf("the error does not say the volume is encrypted: %s", stderr)
	}
	// The old failure leaked parser internals; a user should never see them.
	if strings.Contains(stderr, "invalid object type") {
		t.Errorf("a structural parse error surfaced instead of an authentication one: %s", stderr)
	}
}

// TestEncryptedVolumeRejectsTheWrongPassword checks a wrong password is an
// authentication failure, not a decryption that quietly produces noise.
func TestEncryptedVolumeRejectsTheWrongPassword(t *testing.T) {
	stdout, stderr, code := run(t, "list", fixtureEnc, "--password", "not-the-password")
	if code != exitcode.Auth {
		t.Errorf("exited %s, want %s\nstdout: %s\nstderr: %s",
			exitcode.Name(code), exitcode.Name(exitcode.Auth), stdout, stderr)
	}
	if strings.Contains(stdout, "secret.txt") {
		t.Error("a wrong password listed the volume's contents")
	}
}

// TestEncryptedVolumeUnlocksWithThePassword is the feature: the right password
// decrypts both the file-system tree and the file contents.
func TestEncryptedVolumeUnlocksWithThePassword(t *testing.T) {
	listing := mustRun(t, "list", fixtureEnc, "--password", encryptedPassword)
	for _, want := range []string{"secret.txt", "dir"} {
		if !strings.Contains(listing, want) {
			t.Errorf("the listing is missing %q:\n%s", want, listing)
		}
	}

	// Contents, which need the extents decrypted rather than just the tree.
	if got := mustRun(t, "cat", fixtureEnc, "secret.txt", "--password", encryptedPassword); got != encryptedSecret {
		t.Errorf("secret.txt = %q, want %q", got, encryptedSecret)
	}
	// A nested file, so the walk crosses more than one tree node.
	if got := mustRun(t, "cat", fixtureEnc, "dir/nested.txt", "--password", encryptedPassword); got != encryptedNested {
		t.Errorf("dir/nested.txt = %q, want %q", got, encryptedNested)
	}
}

// TestEncryptedVolumeExtracts covers the path that writes files out, since it
// reads extents through a different route from cat.
func TestEncryptedVolumeExtracts(t *testing.T) {
	dest := t.TempDir()
	stdout, stderr, code := run(t, "extract", fixtureEnc, "-C", dest, "--password", encryptedPassword)
	if code != exitcode.OK {
		t.Fatalf("extract exited %s\nstdout: %s\nstderr: %s", exitcode.Name(code), stdout, stderr)
	}
	for name, want := range map[string]string{
		"secret.txt":     encryptedSecret,
		"dir/nested.txt": encryptedNested,
	} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Errorf("reading the extracted %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("extracted %s = %q, want %q", name, got, want)
		}
	}
}
