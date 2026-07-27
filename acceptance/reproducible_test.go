// CLI acceptance tests for reproducible output: every write command must
// produce byte-identical results for identical input, so a built image can be
// content-addressed, compared by hash, and attested over. These exercise the
// built binary end to end.
package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

// packedTwice runs the same command into two destinations under a fresh temp
// directory and returns whether the two outputs are byte-identical, along with
// the two paths for diagnostics.
func packedTwice(t *testing.T, args ...string) (string, string, bool) {
	t.Helper()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.dmg")
	second := filepath.Join(dir, "second.dmg")

	mustRun(t, append(append([]string{}, args...), first)...)
	mustRun(t, append(append([]string{}, args...), second)...)

	return first, second, sameFile(t, first, second)
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	sumA, err := fileSHA256(a)
	if err != nil {
		t.Fatalf("hashing %s: %v", a, err)
	}
	sumB, err := fileSHA256(b)
	if err != nil {
		t.Fatalf("hashing %s: %v", b, err)
	}
	return sumA == sumB
}

// TestCreateIsReproducible formats an empty volume twice and requires the two
// images to be byte-identical.
func TestCreateIsReproducible(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"apfs", []string{"create", "--fs", "apfs", "--volname", "REPRO", "-q"}},
		{"hfs+", []string{"create", "--fs", "hfs+", "--volname", "REPRO", "-q"}},
		{"apfs with snapshot", []string{"create", "--fs", "apfs", "--volname", "REPRO", "--snapshot", "snap-1", "-q"}},
		{"apfs case-sensitive", []string{"create", "--fs", "apfs", "--volname", "REPRO", "--case-sensitive", "-q"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second, same := packedTwice(t, tc.args...)
			if !same {
				t.Errorf("two runs of %v produced different images (%s, %s)", tc.args, first, second)
			}
		})
	}
}

// TestPackDirIsReproducible packs the same directory twice. It needs no
// controlled modification times: both runs read the same tree, so the source
// mtimes are already constant. TestPackWithSourceDateEpochClampsMtimes is the
// test that varies them.
func TestPackDirIsReproducible(t *testing.T) {
	src, _ := buildSampleTree(t)

	for _, fs := range []string{"apfs", "hfs+"} {
		t.Run(fs, func(t *testing.T) {
			first, second, same := packedTwice(t, "pack", src, "--fs", fs, "--volname", "REPRO", "-q")
			if !same {
				t.Errorf("packing %s twice as %s produced different images (%s, %s)", src, fs, first, second)
			}
		})
	}
}

// TestRepackIsReproducible guards a property the UDIF encoder already had but
// nothing asserted: repacking the same DMG twice is byte-identical. The repack
// path has no file system writer in the loop, so this is a regression guard for
// the encoder rather than for the writers.
func TestRepackIsReproducible(t *testing.T) {
	first, second, same := packedTwice(t, "pack", fixtureDMG, "-q")
	if !same {
		t.Errorf("repacking %s twice produced different images (%s, %s)", fixtureDMG, first, second)
	}
}

// TestSnapshotCreateIsReproducible rebuilds an image carrying a snapshot twice.
func TestSnapshotCreateIsReproducible(t *testing.T) {
	dir := t.TempDir()
	src, _ := buildSampleTree(t)
	source := filepath.Join(dir, "source.dmg")
	mustRun(t, "pack", src, source, "--fs", "apfs", "--volname", "REPRO", "-q")

	first := filepath.Join(dir, "snap-first.dmg")
	second := filepath.Join(dir, "snap-second.dmg")
	mustRun(t, "snapshot", "create", source, "--name", "snap-1", "-O", first, "-q")
	mustRun(t, "snapshot", "create", source, "--name", "snap-1", "-O", second, "-q")

	if !sameFile(t, first, second) {
		t.Error("two snapshot rebuilds of the same image produced different results")
	}
}

// TestPackWithSourceDateEpochClampsMtimes is the test that needs controlled
// modification times. Under a fixed epoch, bumping every source file's mtime
// into the future must not change the packed image: newer times clamp down to
// the epoch. The fixture is created by the test rather than committed, because
// git does not preserve mtimes.
func TestPackWithSourceDateEpochClampsMtimes(t *testing.T) {
	const epoch = "1700000000"
	src, _ := buildSampleTree(t)
	dir := t.TempDir()

	before := filepath.Join(dir, "before.dmg")
	mustRun(t, "pack", src, before, "--fs", "apfs", "--volname", "REPRO", "-q", "--source-date-epoch", epoch)

	// Push every regular file a year past the epoch.
	future := time.Unix(1700000000, 0).AddDate(1, 0, 0)
	touchTree(t, src, future)

	after := filepath.Join(dir, "after.dmg")
	mustRun(t, "pack", src, after, "--fs", "apfs", "--volname", "REPRO", "-q", "--source-date-epoch", epoch)

	if !sameFile(t, before, after) {
		t.Error("a fixed epoch did not clamp future modification times: the packed image changed")
	}

	// Without the epoch the bump must show through, or the clamp above proves
	// nothing about mtimes actually reaching the image.
	past := filepath.Join(dir, "past.dmg")
	touchTree(t, src, time.Unix(1600000000, 0))
	mustRun(t, "pack", src, past, "--fs", "apfs", "--volname", "REPRO", "-q")

	unclamped := filepath.Join(dir, "unclamped.dmg")
	touchTree(t, src, future)
	mustRun(t, "pack", src, unclamped, "--fs", "apfs", "--volname", "REPRO", "-q")

	if sameFile(t, past, unclamped) {
		t.Error("without an epoch, changing every source mtime left the image unchanged; mtimes are not reaching the image")
	}
}

// touchTree sets the modification time of every regular file under root.
func touchTree(t *testing.T, root string, when time.Time) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return os.Chtimes(path, when, when)
	})
	if err != nil {
		t.Fatalf("setting modification times under %s: %v", root, err)
	}
}

// TestSourceDateEpochPrecedence pins the resolution order:
// --source-date-epoch > SOURCE_DATE_EPOCH > APFS_SOURCE_DATE_EPOCH > config.
// The bare variable outranking the APFS_ form is a deliberate departure from
// the precedence every other option follows.
func TestSourceDateEpochPrecedence(t *testing.T) {
	const wanted = "1600000000"
	const decoy = "1234567890"
	dir := t.TempDir()

	create := func(name string, env []string, args ...string) string {
		path := filepath.Join(dir, name)
		full := append([]string{"create", "--fs", "apfs", "--volname", "REPRO", "-q"}, args...)
		_, stderr, code := runEnv(t, env, append(full, path)...)
		if code != exitcode.OK {
			t.Fatalf("create %s exited %d\nstderr: %s", name, code, stderr)
		}
		return path
	}

	// Baselines built from a single source each.
	viaFlag := create("flag.dmg", nil, "--source-date-epoch", wanted)
	viaBare := create("bare.dmg", []string{"SOURCE_DATE_EPOCH=" + wanted})
	viaPrefixed := create("prefixed.dmg", []string{"APFS_SOURCE_DATE_EPOCH=" + wanted})

	if !sameFile(t, viaFlag, viaBare) {
		t.Error("SOURCE_DATE_EPOCH and --source-date-epoch with the same value produced different images")
	}
	if !sameFile(t, viaFlag, viaPrefixed) {
		t.Error("APFS_SOURCE_DATE_EPOCH and --source-date-epoch with the same value produced different images")
	}

	// The flag beats both variables.
	flagWins := create("flag-wins.dmg",
		[]string{"SOURCE_DATE_EPOCH=" + decoy, "APFS_SOURCE_DATE_EPOCH=" + decoy},
		"--source-date-epoch", wanted)
	if !sameFile(t, viaFlag, flagWins) {
		t.Error("--source-date-epoch did not outrank the environment variables")
	}

	// The bare variable beats the APFS_ form.
	bareWins := create("bare-wins.dmg",
		[]string{"SOURCE_DATE_EPOCH=" + wanted, "APFS_SOURCE_DATE_EPOCH=" + decoy})
	if !sameFile(t, viaFlag, bareWins) {
		t.Error("SOURCE_DATE_EPOCH did not outrank APFS_SOURCE_DATE_EPOCH")
	}
}

// TestSourceDateEpochInvalid checks malformed values are a usage error rather
// than being silently ignored, which would produce a plausible-looking but
// unpinned image.
func TestSourceDateEpochInvalid(t *testing.T) {
	dir := t.TempDir()
	for _, value := range []string{"banana", "-1", "1.5", "12abc", "2023-11-14T22:13:20Z"} {
		t.Run(value, func(t *testing.T) {
			out := filepath.Join(dir, "invalid.dmg")

			_, _, code := run(t, "create", "--fs", "apfs", "-q", "--source-date-epoch", value, out)
			if code != exitcode.Usage {
				t.Errorf("--source-date-epoch %q exited %s, want %s", value, exitcode.Name(code), exitcode.Name(exitcode.Usage))
			}

			_, _, code = runEnv(t, []string{"SOURCE_DATE_EPOCH=" + value}, "create", "--fs", "apfs", "-q", out)
			if code != exitcode.Usage {
				t.Errorf("SOURCE_DATE_EPOCH=%q exited %s, want %s", value, exitcode.Name(code), exitcode.Name(exitcode.Usage))
			}
		})
	}
}

// TestUUIDFlagsControlOutput checks the identity flags reach the image, are
// reported back, and are reproducible.
func TestUUIDFlagsControlOutput(t *testing.T) {
	const volumeUUID = "11111111-2222-3333-4444-555555555555"
	const otherUUID = "99999999-2222-3333-4444-555555555555"
	dir := t.TempDir()

	create := func(name, uuid string) string {
		path := filepath.Join(dir, name)
		mustRun(t, "create", "--fs", "apfs", "--volname", "REPRO", "-q", "--uuid", uuid, path)
		return path
	}

	first := create("first.dmg", volumeUUID)
	second := create("second.dmg", volumeUUID)
	other := create("other.dmg", otherUUID)

	if !sameFile(t, first, second) {
		t.Error("the same --uuid produced different images")
	}
	if sameFile(t, first, other) {
		t.Error("different --uuid values produced identical images; the flag is not reaching the image")
	}

	// The volume UUID must be observable through info, and the container UUID
	// must be derived from it rather than left at the built-in default.
	var info struct {
		UUID    string `json:"uuid"`
		Volumes []struct {
			UUID string `json:"uuid"`
		} `json:"volumes"`
	}
	if err := json.Unmarshal([]byte(mustRun(t, "info", first, "-o", "json")), &info); err != nil {
		t.Fatalf("parsing info JSON: %v", err)
	}
	if len(info.Volumes) != 1 {
		t.Fatalf("volume count = %d, want 1", len(info.Volumes))
	}
	if info.Volumes[0].UUID != volumeUUID {
		t.Errorf("volume UUID = %q, want %q", info.Volumes[0].UUID, volumeUUID)
	}
	if info.UUID == volumeUUID {
		t.Error("container UUID equals the volume UUID; they must be distinct")
	}
	if info.UUID == "" {
		t.Error("container UUID is empty")
	}
}

// TestUUIDFlagsRejected checks the flags fail loudly where they cannot apply,
// rather than being accepted and quietly doing nothing.
func TestUUIDFlagsRejected(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.dmg")

	cases := []struct {
		name string
		args []string
	}{
		{"container uuid on hfs+", []string{"create", "--fs", "hfs+", "-q", "--container-uuid", "11111111-2222-3333-4444-555555555555", out}},
		{"all-zero uuid", []string{"create", "--fs", "apfs", "-q", "--uuid", "00000000-0000-0000-0000-000000000000", out}},
		{"malformed uuid", []string{"create", "--fs", "apfs", "-q", "--uuid", "not-a-uuid", out}},
		{"uuid on a repack", []string{"pack", fixtureDMG, out, "-q", "--uuid", "11111111-2222-3333-4444-555555555555"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, tc.args...)
			if code != exitcode.Usage {
				t.Errorf("exited %s, want %s\nstderr: %s", exitcode.Name(code), exitcode.Name(exitcode.Usage), stderr)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("a rejected invocation still wrote the destination")
				os.Remove(out)
			}
		})
	}
}
