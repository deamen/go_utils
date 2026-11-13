// Package launcher runs and stops the agent process for one task.
//
// The runner decides what to run and for how long; a launcher only starts
// the process, reports how it exited and stops it on request. There are two:
//
//   - direct: the agent is a child process of ochell, under ochell's own OS
//     user. For development and tests.
//   - systemd: the agent is a systemd transient unit under a separate OS
//     user, started and stopped through two root-owned scripts that ochell
//     calls with sudo (scripts/ochell-launch and scripts/ochell-stop).
package launcher

import (
	"errors"
	"fmt"
	"io"
	"time"

	"ochell/internal/config"
)

// ErrNotStarted marks a run whose agent never ran: the command could not be
// executed, or the launch was refused. It is not a failure of the agent.
var ErrNotStarted = errors.New("the agent could not be started")

// Spec describes one agent run.
type Spec struct {
	// TaskID is unique per run. The systemd launcher uses it in the unit name.
	TaskID  string
	Command string
	Args    []string
	// Dir is the working directory. The launcher creates it when missing.
	Dir string
	// Env is set for the agent, as NAME=VALUE: ORCH_TASK_* and agent.env.
	// With the systemd launcher other local users can read these values.
	Env []string
	// Inherited is copied from ochell's own environment (agent.env_pass), as
	// NAME=VALUE. Only the direct launcher uses it: a unit has the
	// environment of the agent user instead.
	Inherited []string
	// Stdin is written to the agent's stdin; nil means no input.
	Stdin io.Reader
	// Output receives the agent's stdout and stderr.
	Output io.Writer
	// Timeout is the run's time limit, which the runner enforces by calling
	// Stop. A launcher may also hand it to the system as a backstop.
	Timeout time.Duration
}

// Launcher starts agent processes.
type Launcher interface {
	// Start starts the agent. An error that wraps ErrNotStarted means the
	// command could not be executed.
	Start(spec Spec) (Process, error)
}

// Process is one started agent run.
type Process interface {
	// Wait blocks until the run has ended and returns the agent's exit code.
	// The error is nil when the agent exited by itself, with any code; it
	// wraps ErrNotStarted when the agent never ran.
	//
	// The exit code does not say why a run ended: a unit that systemd
	// stopped exits with 0. The caller knows whether it asked for a stop.
	Wait() (exitCode int, err error)
	// Stop ends the run. It may be called once, while Wait is in progress.
	Stop() error
}

// New returns the launcher selected by agent.launcher.
func New(cfg config.Agent) (Launcher, error) {
	switch cfg.Launcher {
	case "", "direct":
		return Direct{StopGrace: cfg.StopGrace}, nil
	case "systemd":
		return &Systemd{
			LaunchCommand: cfg.Systemd.LaunchCommand,
			StopCommand:   cfg.Systemd.StopCommand,
			StopGrace:     cfg.StopGrace,
		}, nil
	}
	return nil, fmt.Errorf("agent.launcher: unknown launcher %q", cfg.Launcher)
}
