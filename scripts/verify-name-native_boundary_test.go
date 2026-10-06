//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

// These stages deliberately transfer one temporary mount between workflow steps.
// The always-running detach step owns cleanup even if a prior stage fails. The
// workflow persists the exact checkpoint before every native operation.
func boundaryResult(t *testing.T, out, phase string, value any) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(out, "boundary-"+phase+".json"), b, 0644); err != nil {
		t.Fatal(err)
	}
}
func boundaryMount(out string, c singleNameCheckpoint) string {
	return filepath.Join(out, fmt.Sprintf("%d-%s-mount", c.Profile, strings.ReplaceAll(c.Filesystem, "+", "plus")))
}
func boundaryAttached(t *testing.T, out, mount string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, "boundary-attach.plist"))
	if err != nil {
		t.Fatal(err)
	}
	device, err := diskimage.AttachmentDevice(raw)
	if err != nil || device == "" {
		t.Fatal("native attachment identity missing", err)
	}
	var marker struct{ Mount, Checkpoint string }
	b, err := os.ReadFile(filepath.Join(out, "boundary-attach-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &marker); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := os.ReadFile(filepath.Join(out, "pre-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	if marker.Mount != mount || marker.Checkpoint != sum(checkpoint) {
		t.Fatal("attachment ownership checkpoint mismatch")
	}
	return device
}
func TestNativeNameBoundaryIdentity(t *testing.T) {
	c, out, _, _, raw := preparedSingleNameInput(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "boundary-identity-commands")}
	host, err := commands.run(ctx, "sw_vers")
	if err != nil || string(host) != c.Host {
		t.Fatal("native host identity changed", err)
	}
	revision, err := commands.run(ctx, "git", "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(revision)) != c.ConsumerRevision {
		t.Fatal("consumer revision changed", err)
	}
	boundaryResult(t, out, "identity", map[string]any{"diagnostic_only": true, "checkpoint_sha256": sum(raw), "host": string(host), "revision": strings.TrimSpace(string(revision))})
}
func TestNativeNameBoundaryAttach(t *testing.T) {
	c, out, dir, _, raw := preparedSingleNameInput(t)
	if _, err := os.ReadFile(filepath.Join(out, "boundary-identity.json")); err != nil {
		t.Fatal(err)
	}
	mount := boundaryMount(out, c)
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	boundaryResult(t, out, "attach-intent", struct{ Mount, Checkpoint string }{mount, sum(raw)})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "boundary-attach-commands")}
	image := filepath.Join(dir, strings.ReplaceAll(c.Filesystem, "+", "plus")+".dmg")
	attached, err := commands.run(ctx, "hdiutil", "attach", "-readonly", "-plist", "-nobrowse", "-owners", "on", "-mountpoint", mount, image)
	writeErr := os.WriteFile(filepath.Join(out, "boundary-attach.plist"), attached, 0644)
	if err = errors.Join(err, writeErr); err != nil {
		t.Fatal(err)
	}
	device := boundaryAttached(t, out, mount)
	boundaryResult(t, out, "attached", map[string]any{"diagnostic_only": true, "device": device, "mount": mount, "checkpoint_sha256": sum(raw), "attachment_sha256": sum(attached)})
}
func TestNativeNameBoundaryReadback(t *testing.T) {
	c, out, dir, volume, raw := preparedSingleNameInput(t)
	mount := boundaryMount(out, c)
	boundaryAttached(t, out, mount)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "boundary-readback-commands")}
	result, err := commands.run(ctx, filepath.Join(out, "native-probe"), mount, filepath.Join(dir, "cases.tsv"))
	writeErr := os.WriteFile(filepath.Join(out, "boundary-readback-native.json"), result, 0644)
	if err = errors.Join(err, writeErr); err != nil {
		t.Fatal(err)
	}
	validateNativeNameReadback(t, result, volume)
	name := strings.ReplaceAll(volume.Kind, "+", "plus") + ".dmg"
	after, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || sum(after) != c.InputSHA256[name] {
		t.Fatal("native readback changed the image", err)
	}
	boundaryResult(t, out, "readback", map[string]any{"diagnostic_only": true, "qualifies_full_gate": false, "observations": 7506, "checkpoint_sha256": sum(raw), "readback_sha256": sum(result)})
}
func TestNativeNameBoundaryDetach(t *testing.T) {
	// Cleanup intentionally does not require successful source/image revalidation:
	// a failed or modified input must not prevent releasing the owned attachment.
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "artifacts/name-native-diagnostic")
	major, _, err := singleNameSelector(os.Getenv("APFS_NAME_DIAGNOSTIC_PROFILE"), os.Getenv("APFS_NAME_DIAGNOSTIC_FILESYSTEM"))
	if err != nil {
		t.Fatal(err)
	}
	mount := boundaryMount(out, singleNameCheckpoint{Profile: major, Filesystem: os.Getenv("APFS_NAME_DIAGNOSTIC_FILESYSTEM")})
	if _, err = os.ReadFile(filepath.Join(out, "boundary-attach-intent.json")); errors.Is(err, os.ErrNotExist) {
		boundaryResult(t, out, "detach", map[string]any{"diagnostic_only": true, "attachment_attempted": false})
		return
	} else if err != nil {
		t.Fatal(err)
	}
	raw, readErr := os.ReadFile(filepath.Join(out, "boundary-attach.plist"))
	device, parseErr := diskimage.AttachmentDevice(raw)
	if device == "" {
		device = mount
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	commands := &nativeCommandRunner{Directory: filepath.Join(out, "boundary-detach-commands")}
	var detached []byte
	detachErr := diskimage.RetryDetach(ctx, func() (int, error) {
		output, err := commands.run(ctx, "hdiutil", "detach", device)
		detached = append(detached, output...)
		if err == nil {
			return 0, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), err
		}
		return -1, err
	})
	// Remove only the owned empty mount directory; os.Remove never recursively
	// removes mounted content, even when attachment/detachment failed.
	detachErr = errors.Join(detachErr, os.Remove(mount))
	writeErr := os.WriteFile(filepath.Join(out, "boundary-detach.stdout"), detached, 0644)
	err = errors.Join(readErr, parseErr, detachErr, writeErr)
	boundaryResult(t, out, "detach", map[string]any{"diagnostic_only": true, "device": device, "mount": mount, "error": fmt.Sprint(err)})
	if err != nil {
		t.Fatal(err)
	}
}
