// Package agent holds what differs between agent CLIs: how a run is started,
// how a session is resumed, and how the output is read. An adapter builds
// commands and parses output; it runs and stops nothing. That is the
// launcher's job, so every adapter works with every launcher.
package agent

import (
	"errors"
	"fmt"
	"io"

	"ochell/internal/config"
)

// ErrNoResume is returned by Resume when the agent cannot continue an
// earlier session. The caller starts a new run instead.
var ErrNoResume = errors.New("this agent adapter cannot resume a session")

// Run is what the runner wants executed.
type Run struct {
	// Args are the configured arguments, already rendered for the task.
	Args []string
	// Prompt is the rendered prompt.
	Prompt string
}

// Command is how the agent is to be called: the arguments after
// agent.command, and what to write to its stdin (nil: nothing).
type Command struct {
	Args  []string
	Stdin io.Reader
}

// Report is what an adapter read from the output of one run.
type Report struct {
	// Message is the agent's final message. An adapter that cannot tell it
	// apart gives the last part of the output.
	Message string
	// SessionID identifies the agent's session, for Resume. Empty when the
	// agent has no sessions.
	SessionID string
	// CostUSD is what the run cost, 0 when the agent does not say.
	CostUSD float64
	Usage   Usage
}

// Usage is the token count of one run, as far as the agent reports it.
type Usage struct {
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
}

// Event is something an adapter read from the output while the agent is
// still running.
type Event struct {
	// SessionID is the agent's session, as soon as the output names it.
	SessionID string
}

// Output receives everything the agent writes to stdout and stderr during
// one run. Report may be called once the agent has exited, also after a run
// that failed or was stopped.
type Output interface {
	io.Writer
	Report() Report
}

// Adapter is one kind of agent CLI.
type Adapter interface {
	// Start builds the command of a new run.
	Start(run Run) (Command, error)
	// Resume builds the command that continues the session of an earlier
	// run, or returns ErrNoResume.
	Resume(run Run, sessionID string) (Command, error)
	// Output returns the reader for the output of one run. on, when not
	// nil, is called for what the adapter learns while the agent runs; it
	// is called from Write and must not call the Output.
	Output(on func(Event)) Output
}

// New returns the adapter selected by agent.adapter.
func New(cfg config.Agent) (Adapter, error) {
	switch cfg.Adapter {
	case "", "plain":
		return Plain{PromptOnStdin: cfg.PromptVia != "arg"}, nil
	case "claude":
		if cfg.PromptVia == "arg" {
			return nil, errors.New("agent.adapter claude requires prompt_via: stdin")
		}
		if err := checkClaudeArgs(cfg.Args); err != nil {
			return nil, err
		}
		return Claude{}, nil
	}
	return nil, fmt.Errorf("agent.adapter: unknown adapter %q", cfg.Adapter)
}
