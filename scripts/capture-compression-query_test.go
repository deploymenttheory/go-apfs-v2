//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueryDetachEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		codes []int
		want  error
	}{
		{"success", []int{0}, nil},
		{"busy then success", []int{16, 0}, nil},
		{"permanent busy", []int{16, 16, 16, 16, 16, 16, 16, 16, 16, 16}, io.ErrClosedPipe},
		{"nonbusy failure", []int{1}, io.ErrClosedPipe},
		{"launch failure", []int{-1}, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "detach.json")
			calls := 0
			err := detachQueryImage(t.Context(), "/dev/disk99", logPath, func(ctx context.Context, device string) ([]byte, []byte, int, error) {
				if ctx == nil || device != "/dev/disk99" || calls >= len(tc.codes) {
					t.Fatal("incorrect detach invocation", device, calls)
				}
				code := tc.codes[calls]
				calls++
				var err error
				if code != 0 {
					err = io.ErrClosedPipe
				}
				return []byte("stdout retained"), []byte("stderr retained"), code, err
			})
			if !errors.Is(err, tc.want) || calls != len(tc.codes) {
				t.Fatal(err, calls)
			}
			b, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			var attempts []queryDetachAttempt
			if err = json.Unmarshal(b, &attempts); err != nil {
				t.Fatal(err)
			}
			if len(attempts) != calls {
				t.Fatal(attempts)
			}
			for i, a := range attempts {
				if a.Device != "/dev/disk99" || a.Stdout != "stdout retained" || a.Stderr != "stderr retained" || a.Exit != tc.codes[i] {
					t.Fatal(a)
				}
				if (a.Error == "") != (a.Exit == 0) {
					t.Fatal("lost error evidence", a)
				}
			}
		})
	}
}

func TestQueryDetachCancellationAndLogFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logPath := filepath.Join(t.TempDir(), "cancelled.json")
	err := detachQueryImage(ctx, "/dev/disk99", logPath, func(context.Context, string) ([]byte, []byte, int, error) {
		t.Fatal("detach after cancellation")
		return nil, nil, 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil || strings.TrimSpace(string(b)) != "[]" {
		t.Fatal(string(b), err)
	}
	err = detachQueryImage(t.Context(), "/dev/disk99", filepath.Join(t.TempDir(), "missing", "log.json"), func(context.Context, string) ([]byte, []byte, int, error) {
		return nil, []byte("failure"), 1, io.ErrClosedPipe
	})
	if !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("must retain both detach and artifact failure", err)
	}
	during, stop := context.WithCancel(t.Context())
	defer stop()
	calls := 0
	err = detachQueryImage(during, "/dev/disk99", logPath, func(context.Context, string) ([]byte, []byte, int, error) {
		calls++
		stop()
		return nil, nil, 16, io.ErrClosedPipe
	})
	if calls != 1 || !errors.Is(err, context.Canceled) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err, calls)
	}
}
