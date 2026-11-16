// Package launcher runs and stops the agent process for one task.
//
// The runner decides what to run and for how long; a launcher only starts
// the process, reports how it exited and stops it on request. There are
// three:
//
//   - direct: the agent is a child process of ochell, under ochell's own OS
//     user. For development and tests.
//   - systemd: the agent is a systemd transient unit under a separate OS
//     user, started and stopped through two root-owned scripts that ochell
//     calls with sudo (scripts/ochell-launch and scripts/ochell-stop).
//   - podman: the agent is in a container of its own, which ochell's own
//     OS user starts, and sees only the directories of its ticket and run.
package launcher

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"ochell/internal/config"
)

// ErrNotStarted marks a run whose agent never ran: the command could not be
// executed, or the launch was refused. It is not a failure of the agent.
var ErrNotStarted = errors.New("the agent could not be started")

// Spec describes one agent run.
type Spec struct {
	// TaskID is unique per run. The systemd launcher uses it in the unit
	// name, the podman launcher in the name of the container.
	TaskID  string
	Command string
	Args    []string
	// Dir is the working directory. The launcher creates it when missing.
	Dir string
	// RunDir is a directory of this run alone, for what the agent leaves
	// for ochell (the result file). The launcher creates it when missing,
	// so that the agent can write in it. Empty: none.
	RunDir string
	// Home is a directory of the run's ticket alone, which is the home
	// directory of the agent in its container: what the agent CLI keeps
	// between the runs of a ticket. Only the podman launcher uses it, and
	// creates it when missing. Empty: none.
	Home string
	// ReadOnly are files of the host that the run may read: what its tier
	// grants (the MCP configuration). Only the podman launcher uses them,
	// to mount them; with the others the agent sees the host's files.
	ReadOnly []string
	// Env is set for the agent, as NAME=VALUE: ORCH_TASK_* and agent.env.
	// With the systemd and podman launchers other local users can read
	// these values.
	Env []string
	// Inherited is copied from ochell's own environment (agent.env_pass), as
	// NAME=VALUE. Only the direct launcher uses it: a unit has the
	// environment of the agent user instead, and a container that of its
	// image.
	Inherited []string
	// Secrets are set for the agent as well, as NAME=VALUE, and must not
	// become visible to other local users: the systemd launcher hands them
	// over in a file that only ochell and root can read, not as part of
	// the unit, and so does the podman launcher, not on the command line.
	Secrets []string
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
	// Reap ends what an earlier ochell process may have left running for
	// the run with this task id: ochell was killed, and the agent was not.
	// It returns when nothing of that run is left, as far as the launcher
	// can tell, and it is not an error when nothing was.
	Reap(taskID string) error
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
		// The launch script takes the file with a run's credentials only by
		// its full path.
		secrets := cfg.SecretsDir
		if secrets != "" {
			var err error
			if secrets, err = filepath.Abs(secrets); err != nil {
				return nil, fmt.Errorf("agent.secrets_dir: %w", err)
			}
		}
		return &Systemd{
			LaunchCommand: cfg.Systemd.LaunchCommand,
			StopCommand:   cfg.Systemd.StopCommand,
			StopGrace:     cfg.StopGrace,
			SecretsDir:    secrets,
		}, nil
	case "podman":
		p := &Podman{
			Command:   cfg.Podman.Command,
			Image:     cfg.Podman.Image,
			Pull:      cfg.Podman.Pull,
			Args:      cfg.Podman.Args,
			StopGrace: cfg.StopGrace,
		}
		// podman takes the files by their full paths, and the directories
		// of ochell's own are compared with what is mounted.
		var err error
		abs := func(name, path string) string {
			if path == "" || err != nil {
				return ""
			}
			var full string
			if full, err = filepath.Abs(path); err != nil {
				err = fmt.Errorf("agent.%s: %w", name, err)
			}
			return full
		}
		p.SecretsDir = abs("secrets_dir", cfg.SecretsDir)
		p.EnvFile = abs("podman.env_file", cfg.Podman.EnvFile)
		for name, dir := range map[string]string{"log_dir": cfg.LogDir, "run_dir": cfg.RunDir, "secrets_dir": cfg.SecretsDir, "podman.state_dir": cfg.Podman.StateDir} {
			if full := abs(name, dir); full != "" {
				p.Protected = append(p.Protected, full)
			}
		}
		if err != nil {
			return nil, err
		}
		if err := checkEnvFile(p.EnvFile); err != nil {
			return nil, err
		}
		return p, nil
	}
	return nil, fmt.Errorf("agent.launcher: unknown launcher %q", cfg.Launcher)
}

// checkEnvFile refuses a file with the agent's credential that is missing,
// or that users other than its owner can read.
func checkEnvFile(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("agent.podman.env_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("agent.podman.env_file %s: not a regular file", path)
	}
	// Windows has no such permission bits, and no podman launcher in use.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("agent.podman.env_file %s: it holds a credential and must not be accessible to its group or to others (chmod 600)", path)
	}
	return nil
}
