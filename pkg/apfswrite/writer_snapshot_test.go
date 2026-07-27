// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestSnapshotWriterRejectsBadSpecs covers the snapshot validation error paths
// (cross-platform, no external tools).
func TestSnapshotWriterRejectsBadSpecs(t *testing.T) {
	cases := []struct {
		name  string
		snaps []apfswrite.SnapshotSpec
	}{
		{"empty name", []apfswrite.SnapshotSpec{{Name: ""}}},
		{"duplicate-nul", []apfswrite.SnapshotSpec{{Name: "a\x00b"}}},
		{"more than one", []apfswrite.SnapshotSpec{{Name: "a"}, {Name: "b"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "snap-*.img")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			err = apfswrite.CreateContainer(f, 32*1024*1024, &apfswrite.CreateOptions{
				VolumeName: "V",
				RootFiles:  []apfswrite.RootFile{{Name: "f", Data: []byte("x")}},
				Snapshots:  tc.snaps,
			})
			if err == nil {
				t.Errorf("expected an error for %q, got nil", tc.name)
			}
		})
	}
}
