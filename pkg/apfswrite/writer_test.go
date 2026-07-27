// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// memImage is a growable in-memory io.WriterAt / io.ReaderAt used to build and
// then read back a container without touching the file system.
type memImage struct {
	data []byte
}

func (m *memImage) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if end > int64(len(m.data)) {
		grown := make([]byte, end)
		copy(grown, m.data)
		m.data = grown
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *memImage) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, fmt.Errorf("read past end of image")
	}
	n := copy(p, m.data[off:])
	return n, nil
}

// TestCreateContainerReadRoundTrip formats a container in memory and reads it
// back with the MIT reader. It runs on every OS and is the cross-platform gate.
func TestCreateContainerReadRoundTrip(t *testing.T) {
	containerUUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	volumeUUID := [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x47, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cases := []struct {
		name          string
		caseSensitive bool
	}{
		{"case-insensitive", false},
		{"case-sensitive", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const size = 8 * 1024 * 1024
			img := &memImage{}
			opts := &apfswrite.CreateOptions{
				VolumeName:    "RoundTrip",
				CaseSensitive: tc.caseSensitive,
				ContainerUUID: containerUUID,
				VolumeUUID:    volumeUUID,
			}
			if err := apfswrite.CreateContainer(img, size, opts); err != nil {
				t.Fatalf("CreateContainer: %v", err)
			}

			container, err := apfs.Open(img, &apfs.OpenOptions{})
			if err != nil {
				t.Fatalf("apfs.Open: %v", err)
			}

			// Container UUID.
			gotCUUID, err := container.Identifier()
			if err != nil {
				t.Fatalf("container GetIdentifier: %v", err)
			}
			if !bytesEqual(gotCUUID, containerUUID[:]) {
				t.Errorf("container UUID = %x, want %x", gotCUUID, containerUUID)
			}

			// Exactly one volume.
			volumes, err := container.Volumes()
			if err != nil {
				t.Fatalf("Volumes: %v", err)
			}
			if len(volumes) != 1 {
				t.Fatalf("volume count = %d, want 1", len(volumes))
			}
			v := volumes[0]

			// Name.
			name, err := v.UTF8Name()
			if err != nil {
				t.Fatalf("GetUTF8Name: %v", err)
			}
			if name != "RoundTrip" {
				t.Errorf("volume name = %q, want %q", name, "RoundTrip")
			}

			// Volume UUID.
			gotVUUID, err := v.Identifier()
			if err != nil {
				t.Fatalf("volume GetIdentifier: %v", err)
			}
			if gotVUUID != volumeUUID {
				t.Errorf("volume UUID = %x, want %x", gotVUUID, volumeUUID)
			}

			// Case sensitivity.
			caseInsensitive, err := v.IsCaseInsensitive()
			if err != nil {
				t.Fatalf("IsCaseInsensitive: %v", err)
			}
			if caseInsensitive != !tc.caseSensitive {
				t.Errorf("IsCaseInsensitive = %v, want %v", caseInsensitive, !tc.caseSensitive)
			}

			// Zero user files: the root directory is empty.
			entries, err := v.ReadDir(".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 0 {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Errorf("root has %d entries %v, want 0", len(entries), names)
			}
		})
	}
}

func bytesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- darwin test helpers ---
