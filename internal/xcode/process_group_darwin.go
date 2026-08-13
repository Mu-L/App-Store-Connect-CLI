package xcode

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

var terminateXcodeProcessGroupFn = terminateExactXcodeProcessGroup

// runXcodeCommandWithProcessGroupCleanup owns a fresh process group for one
// xcodebuild invocation. Its cancellation hook kills the group immediately;
// the post-Wait cleanup handles build scripts left after a successful parent
// exit before the signing environment can be torn down.
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
	// The group ID is the exact child PID created with Setsid. Check it still
	// exists immediately before signalling, which avoids a broad or inferred
	// target and makes an already-finished group benign.
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
	// A successful SIGKILL syscall has synchronously delivered an uncatchable
	// signal to every current member. Do not poll the numeric PGID afterward:
	// once the group disappears, that number can be reused by an unrelated
	// process group before a subsequent probe.
	return nil
}
