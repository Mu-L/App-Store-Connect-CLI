//go:build !darwin && !windows

package xcode

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

var terminateXcodeProcessGroupFn = terminateExactXcodeProcessGroup

func runXcodeCommandWithProcessGroupCleanup(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return killExactXcodeProcessGroup(cmd.Process.Pid)
	}
	cmd.WaitDelay = xcodeCommandPipeWaitDelay
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	waitErr := normalizeXcodeCommandWaitError(cmd, cmd.Wait())
	cleanupErr := terminateXcodeProcessGroupFn(pid)
	return errors.Join(waitErr, cleanupErr)
}

func killExactXcodeProcessGroup(pid int) error {
	if err := syscall.Kill(-pid, 0); errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	} else if err != nil {
		return err
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	} else {
		return err
	}
}

func terminateExactXcodeProcessGroup(pid int) error {
	err := killExactXcodeProcessGroup(pid)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("terminate xcodebuild process group: %w", err)
	}
	return nil
}
