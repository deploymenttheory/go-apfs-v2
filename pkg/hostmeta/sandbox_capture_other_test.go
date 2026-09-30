//go:build !darwin

package hostmeta

import (
	"errors"
	"testing"
)

func TestSandboxCaptureForeign(t *testing.T) {
	if _, err := CaptureAppSandbox(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
