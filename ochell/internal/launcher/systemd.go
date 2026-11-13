package launcher

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Exit codes from 200 are not the agent's. systemd uses 200 to 243 for a
// unit it could not start (203: the command could not be executed), and
// ochell-launch uses 250 when it refuses a request.
const firstLaunchExitCode = 200

// runtimeBackstop is added to the run's time limit for the unit's own limit.
// ochell keeps the timer and stops the unit; the unit's limit only applies
// if ochell is gone.
const runtimeBackstop = time.Minute

// stopMargin is how long Stop waits for the stop command beyond the grace
// period that systemd gives the unit's processes.
const stopMargin = 30 * time.Second

// Systemd runs each agent as a transient unit under a separate OS user, so
// the agent cannot read ochell's files and a stop reaches all its children.
//
// ochell has no permission to create units, because that would let it run
// anything as root. It calls two root-owned scripts through sudo instead.
type Systemd struct {
	// LaunchCommand and StopCommand are the scripts with their sudo prefix.
	LaunchCommand []string
	StopCommand   []string
	// StopGrace is how long systemd waits between SIGTERM and SIGKILL.
	StopGrace time.Duration
}

func seconds(d time.Duration) string {
	return strconv.FormatInt(int64(math.Ceil(d.Seconds())), 10)
}

func (s *Systemd) Start(spec Spec) (Process, error) {
	if len(s.LaunchCommand) == 0 || len(s.StopCommand) == 0 {
		return nil, errors.New("systemd launcher: launch_command and stop_command are required")
	}
	// The launch script creates the working directory, as the agent user.
	args := append([]string{}, s.LaunchCommand[1:]...)
	args = append(args, "--task", spec.TaskID, "--workdir", spec.Dir)
	if spec.Timeout > 0 {
		args = append(args, "--runtime-max", seconds(spec.Timeout+runtimeBackstop))
	}
	if s.StopGrace > 0 {
		args = append(args, "--stop-grace", seconds(s.StopGrace))
	}
	for _, e := range spec.Env {
		args = append(args, "--setenv", e)
	}
	args = append(args, "--", spec.Command)
	args = append(args, spec.Args...)

	cmd := exec.Command(s.LaunchCommand[0], args...)
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	cmd.Stdout, cmd.Stderr = spec.Output, spec.Output
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNotStarted, s.LaunchCommand[0], err)
	}
	return &systemdProcess{s: s, taskID: spec.TaskID, cmd: cmd}, nil
}

type systemdProcess struct {
	s      *Systemd
	taskID string
	cmd    *exec.Cmd
}

func (p *systemdProcess) Wait() (int, error) {
	code, err := exitCode(p.cmd, p.cmd.Wait())
	if err == nil && code >= firstLaunchExitCode {
		return code, fmt.Errorf("%w: launch exit code %d", ErrNotStarted, code)
	}
	return code, err
}

// Stop stops the unit. ochell cannot signal the launch process, which runs
// as root; it ends by itself when the unit has stopped.
func (p *systemdProcess) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.s.StopGrace+stopMargin)
	defer cancel()
	args := append(append([]string{}, p.s.StopCommand[1:]...), p.taskID)
	out, err := exec.CommandContext(ctx, p.s.StopCommand[0], args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", p.s.StopCommand[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
