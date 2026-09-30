//go:build darwin || linux

package hostmeta

import "os"

func openTimeTestFile(name string, directory bool) (*os.File, error) {
	if directory {
		return os.Open(name)
	}
	return os.OpenFile(name, os.O_RDWR, 0)
}
