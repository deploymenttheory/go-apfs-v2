//go:build !darwin

package hostmeta

import (
	"context"
	"errors"
	"testing"
)

func TestQuarantineFileNativeUnavailable(t *testing.T) {
	file := replacementSource(t, 0600)
	if _, err := CaptureQuarantineFile(context.Background(), file, 0); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if err := ApplyQuarantineFile(context.Background(), file, nil, QuarantineProcessCapture{}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
