package launcher

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// outputWait is how long Wait keeps reading the agent's output after the
// agent has exited. Only a child that left the process group and still
// holds the output open makes it wait.
const outputWait = 5 * time.Second

// Direct runs the agent as a child process of ochell, without a shell.
//
// The agent gets its own process group, and a stop signals the whole group:
// sub-agents, MCP servers and git children end with it. A child that leaves
// the group (setsid) is not reached; the systemd launcher has no such gap.
type Direct struct {
	// StopGrace is the time between SIGTERM and SIGKILL when stopping.
	StopGrace time.Duration
}

func (d Direct) Start(spec Spec) (Process, error) {
	if err := os.MkdirAll(spec.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}
	if spec.RunDir != "" {
		if err := os.MkdirAll(spec.RunDir, 0o750); err != nil {
			return nil, fmt.Errorf("create run directory: %w", err)
		}
	}
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Dir = spec.Dir
	// Never ochell's own environment: it holds the webhook secrets.
	cmd.Env = append(append([]string{}, spec.Inherited...), spec.Env...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	// The output goes through a pipe that this launcher reads itself, so
	// that cmd.Wait returns when the agent exits, even while children of
	// the agent still hold the pipe open.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	// Bounds the wait for the stdin copy when the agent never reads it.
	cmd.WaitDelay = 10 * time.Second
	setProcessGroup(cmd)
	err = cmd.Start()
	pw.Close()
	if err != nil {
		pr.Close()
		return nil, fmt.Errorf("%w: %v", ErrNotStarted, err)
	}
	p := &directProcess{cmd: cmd, grace: d.StopGrace, out: pr, copied: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		io.Copy(spec.Output, pr)
		close(p.copied)
	}()
	return p, nil
}

type directProcess struct {
	cmd    *exec.Cmd
	grace  time.Duration
	out    *os.File
	copied chan struct{} // closed when all output has been read
	exited chan struct{} // closed when the agent process has exited
	stop   sync.Once
}

func (p *directProcess) Wait() (int, error) {
	code, err := exitCode(p.cmd, p.cmd.Wait())
	close(p.exited)
	// The agent is gone; nothing it left behind in its group may live on.
	killGroup(p.cmd.Process, true)
	select {
	case <-p.copied:
	case <-time.After(outputWait):
	}
	p.out.Close()
	<-p.copied
	return code, err
}

// Stop sends SIGTERM to the agent's process group, and SIGKILL after the
// grace period if the agent has not exited by then. It returns at once.
func (p *directProcess) Stop() error {
	var err error
	p.stop.Do(func() {
		err = killGroup(p.cmd.Process, false)
		go func() {
			select {
			case <-p.exited:
			case <-time.After(p.grace):
				killGroup(p.cmd.Process, true)
			}
		}()
	})
	return err
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
