//go:build windows

package procgroup

import (
	"errors"
	"os"
	"syscall"
)

func attr() *syscall.SysProcAttr { return nil }

func killTree(p *os.Process) error {
	if p == nil {
		return nil
	}
	if err := p.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func descendants(int) []int { return nil }
