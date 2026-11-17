//go:build !unix

package launcher

import (
	"errors"
	"os"
	"os/exec"
)

// There are no process groups to signal here: a stop ends the agent process
// only, and at once.
func setProcessGroup(*exec.Cmd) {}

func killGroup(leader *os.Process, _ bool) error {
	if err := leader.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
