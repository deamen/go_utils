// Package task defines the source-independent unit of work handed to the agent.
package task

import (
	"context"
	"time"
)

type Task struct {
	// ID is unique per task and used for log file names.
	ID string
	// Source is "jira" or "linear".
	Source string
	// Key is the human readable ticket key, e.g. "ENG-123".
	Key   string
	Title string
	URL   string
	// Context is optional extra text from the source (e.g. Linear promptContext).
	Context string
	// DeliveryID identifies the webhook delivery for de-duplication.
	DeliveryID string
	Received   time.Time

	// Prompt is rendered by the runner from the prompt template.
	Prompt string

	// Optional callbacks to report progress back to the source.
	OnStart  func(ctx context.Context, t *Task) error
	OnFinish func(ctx context.Context, t *Task, result Result) error
}

// Outcome says why a run ended. ochell sets it from its own record of what
// it asked for; the exit code alone cannot tell a stopped run from a
// finished one.
type Outcome string

const (
	// OutcomeFinished: the agent exited by itself with status 0.
	OutcomeFinished Outcome = "finished"
	// OutcomeFailed: the agent exited by itself with another status.
	OutcomeFailed Outcome = "failed"
	// OutcomeTimedOut: ochell stopped the agent at the time limit.
	OutcomeTimedOut Outcome = "timed_out"
	// OutcomeStopped: ochell stopped the agent for another reason, such as
	// its own shutdown.
	OutcomeStopped Outcome = "stopped"
	// OutcomeNotStarted: the agent never ran.
	OutcomeNotStarted Outcome = "not_started"
)

type Result struct {
	Outcome Outcome
	// ExitCode is the agent's exit status, or -1 when there is none. Read
	// Outcome first.
	ExitCode int
	// Err is nil only when Outcome is OutcomeFinished.
	Err      error
	LogFile  string
	Duration time.Duration
	// Tail holds the last part of the agent output.
	Tail string
}
