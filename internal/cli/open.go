// Shared image/volume opening for all commands.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// openContainer opens an image with the global options applied. Errors are
// coded: missing/unrecognizable images exit 3.
func openContainer(imagePath string) (*apfs.Container, io.Closer, error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}

	container, closer, err := apfs.OpenImage(imagePath, &apfs.OpenOptions{
		Offset:           opts.Offset,
		Password:         opts.Password,
		RecoveryPassword: opts.RecoveryPassword,
	})
	if err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("%s does not contain a readable APFS container: %w", imagePath, err))
	}

	return container, closer, nil
}

// openVolume opens the volume selected by --volume (default: first) and
// enforces the authentication contract (locked volumes exit 4).
func openVolume(container *apfs.Container) (*apfs.Volume, error) {
	volume, err := container.VolumeBySelector(opts.Volume)
	if err != nil {
		return nil, usageErrorf("%v", err)
	}

	if locked, err := volume.IsLocked(); err == nil && locked {
		if opts.Password == "" && opts.RecoveryPassword == "" {
			return nil, withCode(ExitAuth, fmt.Errorf("volume is encrypted; supply --password or --recovery-password"))
		}
		return nil, withCode(ExitAuth, fmt.Errorf("unable to unlock volume: wrong password"))
	}

	return volume, nil
}

// fsNameFromVolumePath converts an absolute volume path ("/a/b") to an fs.FS
// name ("a/b", or "." for the root). Accepts already-relative input too.
func fsNameFromVolumePath(volumePath string) string {
	name := strings.Trim(strings.TrimSpace(volumePath), "/")
	if name == "" {
		return "."
	}
	return name
}
