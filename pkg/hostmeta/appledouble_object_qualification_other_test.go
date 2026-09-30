//go:build !darwin

package hostmeta

import (
	"context"
	"errors"
	"testing"
)

func TestAppleDoubleObjectForeignAcquisition(t *testing.T) {
	file := replacementSource(t, 0600)
	if _, err := NewHostAppleDoubleObject(context.Background(), file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := newHostObjectAttributes(file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
