// Platform-independent mount server abstraction
package tools

// MountServer is the platform-independent handle to a mounted file system.
// On FUSE platforms it is backed by *fuse.Server.
type MountServer interface {
	Unmount() error
}

// UnmountAPFS unmounts a mounted APFS file system
func UnmountAPFS(server MountServer) error {
	if server == nil {
		return nil
	}
	return server.Unmount()
}
