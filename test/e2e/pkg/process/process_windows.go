//go:build windows

package process

import (
	"os/exec"
	"syscall"
)

func setSysProcAttr(_ *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd, _ syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
