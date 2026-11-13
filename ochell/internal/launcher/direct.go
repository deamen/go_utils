package launcher

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Direct runs the agent as a child process of ochell, without a shell.
type Direct struct{}

func (Direct) Start(spec Spec) (Process, error) {
	if err := os.MkdirAll(spec.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Dir = spec.Dir
	// Never ochell's own environment: it holds the webhook secrets.
	cmd.Env = append(append([]string{}, spec.Inherited...), spec.Env...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	cmd.Stdout, cmd.Stderr = spec.Output, spec.Output
	// A child of the agent that keeps the output open must not block Wait.
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	return &directProcess{cmd: cmd}, nil
}

type directProcess struct {
	cmd *exec.Cmd
}

func (p *directProcess) Wait() (int, error) {
	return exitCode(p.cmd, p.cmd.Wait())
}

func (p *directProcess) Stop() error {
	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// exitCode turns the result of cmd.Wait into the agent's exit code. A
// non-zero exit is not an error here; failing to wait is.
func exitCode(cmd *exec.Cmd, err error) (int, error) {
	var exit *exec.ExitError
	if err == nil || errors.As(err, &exit) || errors.Is(err, exec.ErrWaitDelay) {
		return cmd.ProcessState.ExitCode(), nil
	}
	return -1, err
}
