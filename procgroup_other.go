//go:build !unix

package main

import "os/exec"

// setPgid is a no-op on non-unix platforms; Setpgid isn't part of
// syscall.SysProcAttr there and the default cancel path is the best we have.
func setPgid(cmd *exec.Cmd) {}

// killGroup falls back to killing just the direct child on non-unix.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return cmd.Process.Kill()
	}
	return nil
}
