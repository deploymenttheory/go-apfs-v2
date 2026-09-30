//go:build !darwin

package hostmeta

import (
	"context"
	"errors"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func newNativeACLIdentityCapture(context.Context, int) (*appledouble.ACLIdentityCapture, error) {
	return nil, errors.ErrUnsupported
}
