// CLI acceptance tests for volume roles and volume groups: what makes a
// multi-volume container legible. Without them a macOS installer or system
// image shows N similarly-named volumes with no indication which holds the OS.
package acceptance

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/exitcode"
)

type roleVolumeJSON struct {
	Name          string `json:"name"`
	Role          string `json:"role"`
	RoleName      string `json:"roleName"`
	RoleValue     uint16 `json:"roleValue"`
	VolumeGroupID string `json:"volumeGroupId"`
}

type roleInfoJSON struct {
	Volumes []roleVolumeJSON `json:"volumes"`
}

func infoRoleJSON(t *testing.T, image string) roleVolumeJSON {
	t.Helper()
	var info roleInfoJSON
	if err := json.Unmarshal([]byte(mustRun(t, "info", image, "-o", "json")), &info); err != nil {
		t.Fatalf("parsing info JSON for %s: %v", image, err)
	}
	if len(info.Volumes) != 1 {
		t.Fatalf("%s: volume count = %d, want 1", image, len(info.Volumes))
	}
	return info.Volumes[0]
}

// TestCreateWithRoleRoundTrip writes a volume carrying each role and reads it
// back through the CLI. The update case is the one that matters most: its raw
// value 0x00c0 is APFS_VOL_ROLE_UPDATE, but read as bits it is exactly
// DATA|BASEBAND, so a bitwise decode reports it as two roles that no volume can
// legally hold at once.
func TestCreateWithRoleRoundTrip(t *testing.T) {
	cases := []struct {
		token     string
		wantName  string
		wantValue uint16
	}{
		{"system", "System", 0x0001},
		{"user", "User", 0x0002},
		{"recovery", "Recovery", 0x0004},
		{"vm", "VM", 0x0008},
		{"preboot", "Preboot", 0x0010},
		{"installer", "Installer", 0x0020},
		{"data", "Data", 0x0040},
		{"update", "Update", 0x00c0},
		{"prelogin", "Prelogin", 0x02c0},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			image := filepath.Join(dir, tc.token+".dmg")
			mustRun(t, "create", image, "--fs", "apfs", "--volname", "ROLES", "--role", tc.token, "-q")

			got := infoRoleJSON(t, image)
			if got.Role != tc.token {
				t.Errorf("role = %q, want %q", got.Role, tc.token)
			}
			if got.RoleName != tc.wantName {
				t.Errorf("role name = %q, want %q", got.RoleName, tc.wantName)
			}
			if got.RoleValue != tc.wantValue {
				t.Errorf("raw apfs_role = %#04x, want %#04x", got.RoleValue, tc.wantValue)
			}
			if got.VolumeGroupID != "" {
				t.Errorf("volume group id = %q, want empty for an ungrouped volume", got.VolumeGroupID)
			}

			// The text renderer must name the role too.
			if out := mustRun(t, "info", image); !strings.Contains(out, "Role") || !strings.Contains(out, tc.wantName) {
				t.Errorf("text output does not report the role:\n%s", out)
			}
		})
	}
}

// TestCreateVolumeGroup checks the group identifier round-trips and is reported.
// TestCreateVolumeGroup checks --volume-group produces a complete group. A
// group is a system/data pair, so one flag makes both halves: asking for only
// one would be asking for a group that is not one, and the writer refuses it.
func TestCreateVolumeGroup(t *testing.T) {
	const groupID = "11111111-2222-3333-4444-555555555555"
	image := filepath.Join(t.TempDir(), "group.dmg")
	mustRun(t, "create", image, "--fs", "apfs", "--volname", "Macintosh HD",
		"--volume-group", groupID, "-q")

	var info roleInfoJSON
	if err := json.Unmarshal([]byte(mustRun(t, "info", image, "-o", "json")), &info); err != nil {
		t.Fatalf("parsing info JSON: %v", err)
	}
	if len(info.Volumes) != 2 {
		t.Fatalf("volume count = %d, want 2: a group is a system/data pair", len(info.Volumes))
	}

	for i, want := range []struct{ role, name string }{
		{"system", "Macintosh HD"},
		{"data", "Macintosh HD - Data"},
	} {
		got := info.Volumes[i]
		if got.Role != want.role {
			t.Errorf("volume %d role = %q, want %q", i, got.Role, want.role)
		}
		if got.Name != want.name {
			t.Errorf("volume %d name = %q, want %q", i, got.Name, want.name)
		}
		if got.VolumeGroupID != groupID {
			t.Errorf("volume %d group id = %q, want %q", i, got.VolumeGroupID, groupID)
		}
	}

	if out := mustRun(t, "info", image); !strings.Contains(out, "Volume group") {
		t.Errorf("text output does not report the volume group:\n%s", out)
	}
}

// TestRoleFlagsRejected checks the combinations that would produce an image a
// checker rejects fail as usage errors, before anything is written.
func TestRoleFlagsRejected(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bad.dmg")

	cases := []struct {
		name string
		args []string
	}{
		{"unknown role", []string{"create", out, "--fs", "apfs", "--role", "banana", "-q"}},
		// A volume group is a system/data pair and only one volume per
		// container can be written, so the data half cannot stand alone:
		// apfsck's "system volume is missing" is its hard-corruption path.
		{"group combined with a role", []string{"create", out, "--fs", "apfs", "--role", "data",
			"--volume-group", "11111111-2222-3333-4444-555555555555", "-q"}},
		{"malformed group uuid", []string{"create", out, "--fs", "apfs", "--role", "system",
			"--volume-group", "not-a-uuid", "-q"}},
		{"role on hfs+", []string{"create", out, "--fs", "hfs+", "--role", "system", "-q"}},
		{"volume group on hfs+", []string{"create", out, "--fs", "hfs+",
			"--volume-group", "11111111-2222-3333-4444-555555555555", "-q"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := run(t, tc.args...)
			if code != exitcode.Usage {
				t.Errorf("exited %s, want %s\nstderr: %s", exitcode.Name(code), exitcode.Name(exitcode.Usage), stderr)
			}
		})
	}
}

// TestVolumeSelectorByRole covers selecting a volume by its role, which is the
// point of decoding apfs_role: asking for the OS volume without knowing its
// name or index.
func TestVolumeSelectorByRole(t *testing.T) {
	image := filepath.Join(t.TempDir(), "system.dmg")
	mustRun(t, "create", image, "--fs", "apfs", "--volname", "Macintosh HD", "--role", "system", "-q")

	for _, selector := range []string{"system", "role:system"} {
		if _, stderr, code := run(t, "info", image, "-v", selector); code != exitcode.OK {
			t.Errorf("-v %s exited %s\nstderr: %s", selector, exitcode.Name(code), stderr)
		}
	}

	t.Run("absent role is an error", func(t *testing.T) {
		_, stderr, code := run(t, "list", image, "-v", "role:data")
		if code == exitcode.OK {
			t.Error("selecting an absent role succeeded")
		}
		if !strings.Contains(stderr, "data") {
			t.Errorf("stderr does not name the requested role: %s", stderr)
		}
	})

	t.Run("unknown role is an error", func(t *testing.T) {
		if _, _, code := run(t, "list", image, "-v", "role:banana"); code == exitcode.OK {
			t.Error("selecting an unknown role succeeded")
		}
	})
}

// TestRolelessVolumeJSONUnchanged guards the existing fixtures: a volume with
// no role must not gain populated role keys, so consumers of the JSON schema
// see no change.
func TestRolelessVolumeJSONUnchanged(t *testing.T) {
	raw := mustRun(t, "info", fixtureDMG, "-o", "json")

	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("parsing info JSON: %v", err)
	}
	volumes, ok := decoded["volumes"].([]any)
	if !ok || len(volumes) == 0 {
		t.Fatal("no volumes in info JSON")
	}
	volume, ok := volumes[0].(map[string]any)
	if !ok {
		t.Fatal("volume entry is not an object")
	}

	for _, key := range []string{"role", "roleName", "volumeGroupId"} {
		if _, present := volume[key]; present {
			t.Errorf("roleless volume has a %q key; it must be omitted so the existing schema is unchanged", key)
		}
	}
	// The raw value is always present, so a consumer can see a role this build
	// does not recognize rather than having it silently vanish.
	if got, present := volume["roleValue"]; !present {
		t.Error("roleValue is missing; it must always be present")
	} else if got.(float64) != 0 {
		t.Errorf("roleValue = %v, want 0 for a roleless volume", got)
	}
}
