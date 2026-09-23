//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// setPgid puts the child in its own process group so we can signal the whole
// group later. Without this, a non-interactive run (systemd/nohup/cron) that
// puts sift in its own pgid can't propagate SIGTERM to grandchildren of the
// engine — feroxbuster's rate-limit goroutines, nomore403's payload workers —
// and they end up orphaned.
func setPgid(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killGroup signals the entire process group of cmd. Called from exec.Cmd.Cancel
// so a cancelled root context tears down the engine AND its children in one go
// (default cancel calls Process.Kill which reaches only the direct child).
// ESRCH is fine — race with a natural exit — so we swallow errors.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	// Negative pid targets the group led by pid (guaranteed by Setpgid above).
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	return nil
}
