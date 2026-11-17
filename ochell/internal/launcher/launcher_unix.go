//go:build unix

package launcher

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup makes the agent the leader of a new process group, so the
// group can be signalled as a whole and a Ctrl-C in ochell's terminal does
// not reach the agent directly.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup signals every process in the agent's process group: SIGKILL
// when force is set, SIGTERM otherwise. A group that is already gone is not
// an error.
func killGroup(leader *os.Process, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(-leader.Pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
