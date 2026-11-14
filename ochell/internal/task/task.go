// Package task defines the source-independent unit of work handed to the agent.
package task

import (
	"time"

	"ochell/internal/agent"
	"ochell/internal/result"
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
	// Comment is the comment that triggered this run, when a person asked
	// for it in one (a mention in Linear). Empty for a plain assignment.
	Comment string
	// TrackerSession is where the source wants progress reported: the id of
	// the Linear agent session. Empty when there is no such place.
	TrackerSession string
	// DeliveryID identifies the webhook delivery for de-duplication.
	DeliveryID string
	Received   time.Time

	// Attempt says which run of the ticket this is, counting from 1. The
	// store sets it when the run starts.
	Attempt int
	// AgentSession is the agent's session id from an earlier run of the
	// ticket, and Workspace the working directory of that run. The store
	// sets them when the run starts; a run in the same directory resumes
	// the session if the agent can.
	AgentSession string
	Workspace    string
	// PRURL and Branch are the pull request and the branch that earlier
	// runs of the ticket reported, if any. The store sets them too.
	PRURL  string
	Branch string
	// Prompt is rendered by the runner from the prompt template.
	Prompt string
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
	// OutcomeInterrupted: ochell itself stopped while the agent was running,
	// and found the run unfinished when it started again.
	OutcomeInterrupted Outcome = "interrupted"
)

type Result struct {
	Outcome Outcome
	// ExitCode is the agent's exit status, or -1 when there is none. Read
	// Outcome first.
	ExitCode int
	// Err is nil only when Outcome is OutcomeFinished.
	Err     error
	LogFile string
	// Workdir is the working directory the agent ran in.
	Workdir  string
	Duration time.Duration
	// Resumed says that the run continued the session of an earlier run.
	Resumed bool
	// SessionID is the agent's session, for a later resume; CostUSD and
	// Usage are what the run cost. All three are empty for an agent that
	// does not report them.
	SessionID string
	CostUSD   float64
	Usage     agent.Usage
	// Signal is what the agent's result file says about the run, and
	// SignalMessage its text for the people on the ticket. Signal is
	// result.None when the run left no valid file. PRURL and Branch are
	// the pull request and the branch the file names, if any.
	Signal        result.Status
	SignalMessage string
	PRURL         string
	Branch        string
	// Message is the agent's final message, as its adapter read it: for
	// the plain adapter, the last part of the output.
	Message string
}
