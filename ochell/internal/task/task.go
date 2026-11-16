// Package task defines the source-independent unit of work handed to the agent.
package task

import (
	"fmt"
	"time"

	"ochell/internal/agent"
	"ochell/internal/result"
)

// Cause says why a run was queued, when it was not a plain assignment.
type Cause string

const (
	// CauseRecovery: ochell itself stopped during the earlier run of the
	// ticket, and this run takes its place.
	CauseRecovery Cause = "recovery"
	// CauseRetry: the earlier run failed with an error that looked
	// temporary, such as a rate limit.
	CauseRetry Cause = "retry"
	// CauseStalled: the earlier run was stopped because the agent was
	// silent for too long.
	CauseStalled Cause = "stalled"
	// CauseFollowUp: a person wrote to the agent on a ticket that ochell
	// already knows. The message is in Comment.
	CauseFollowUp Cause = "follow_up"
	// CauseChecks: the checks of the ticket's pull request failed, and
	// this run is to fix them. What failed is in Comment.
	CauseChecks Cause = "checks_failed"
	// CauseApproved: a person approved the agent's plan for the ticket.
	// ApprovedBy on the task names them.
	CauseApproved Cause = "plan_approved"
	// CausePoll: ochell found the ticket itself when it asked the tracker
	// for the bot's tickets; the webhook of its assignment never arrived.
	CausePoll Cause = "poll"
)

// CommentSeparator stands between the messages in Task.Comment when a run
// delivers more than one. It is a character that no ticket text holds.
const CommentSeparator = "\n\x1e\n"

// NewID returns the id of a task that is received now. It is unique per
// ticket and millisecond, and safe in a file name.
func NewID(now time.Time, source, key string) string {
	return fmt.Sprintf("%s-%s-%s", now.UTC().Format("20060102T150405.000Z"), source, key)
}

type Task struct {
	// ID is unique per task and used for log file names.
	ID string
	// Source is "jira" or "linear".
	Source string
	// Key is the human readable ticket key, e.g. "ENG-123".
	Key   string
	Title string
	URL   string
	// Repo is the repository the ticket belongs to, from the repos setting.
	// Empty when no mapping is configured.
	Repo string
	// Tier is the risk tier of the policy that the ticket runs under.
	Tier string
	// Priority is the priority that the tracker gives the ticket, as a
	// rank: 1 is the most urgent, 5 the least; 0: none, or not known. The
	// queue hands out the lower rank first, and a ticket without one last.
	Priority int
	// Hold, when set on a task that is submitted, says why scheduling
	// keeps the ticket from starting for now. The run stays queued until
	// the hold is taken off.
	Hold string
	// Context is optional extra text from the source (e.g. Linear promptContext).
	Context string
	// Comment is the comment that triggered this run, when a person asked
	// for it in one: a mention in Linear, or a follow-up message. Empty for
	// a plain assignment. Several messages that waited for the same run
	// are joined with CommentSeparator, oldest first.
	Comment string
	// Actor identifies the person who assigned the ticket, as the source
	// names them (a Jira accountId, a Linear user id). Empty when the
	// source does not say, and for a run that is no assignment.
	Actor string
	// Cause says why the run was queued; empty for a plain assignment.
	Cause Cause
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
	// PreparedWorkspace is the working directory in which the after_create
	// hook has run for this ticket; the store sets it too.
	PreparedWorkspace string
	// PRURL and Branch are the pull request and the branch that earlier
	// runs of the ticket reported, if any. The store sets them too.
	PRURL  string
	Branch string
	// Prompt is rendered by the runner from the prompt template.
	Prompt string
	// BudgetUSD is what this run may cost: what the ticket has left of the
	// budget of its tier. The runner sets it; 0: no limit.
	BudgetUSD float64
	// MaxTurns is how many turns this run may take, from its tier; 0: no
	// limit. The runner sets it.
	MaxTurns int
	// PlanApproved says that a person approved the agent's plan for the
	// ticket since it was last assigned, and ApprovedBy who. The store
	// sets both when the run starts.
	PlanApproved bool
	ApprovedBy   string
	// Phase is PhasePlan for a run that may only make a plan: the tier of
	// the ticket requires an approved plan, and there is none yet. The
	// runner sets it.
	Phase Phase
}

// Phase is the part of a ticket's work that a run is for.
type Phase string

const (
	// PhaseWork: the run does the work. It is the only phase of a ticket
	// whose tier has no plan gate.
	PhaseWork Phase = ""
	// PhasePlan: the run researches and writes a plan, and changes nothing.
	PhasePlan Phase = "plan"
)

// Escalation says which trigger stopped a ticket and left it waiting for a
// human. Each one fires before the work goes on: the run is stopped, or
// not started, and nothing follows by itself.
type Escalation string

const (
	// EscalationBudget: the ticket used up the budget of its tier.
	EscalationBudget Escalation = "budget"
	// EscalationTurns: the run reached the turn limit of its tier.
	EscalationTurns Escalation = "turns"
	// EscalationRetries: the run failed for a temporary reason again, and
	// the ticket has no attempt left for another try.
	EscalationRetries Escalation = "retries"
	// EscalationTierChange: the ticket moved to a higher tier while the
	// agent was working on it.
	EscalationTierChange Escalation = "tier_change"
	// EscalationLowConfidence and EscalationOutOfScope: the agent said so
	// itself, in its result file.
	EscalationLowConfidence Escalation = "low_confidence"
	EscalationOutOfScope    Escalation = "out_of_scope"
)

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
	// OutcomeStalled: ochell stopped the agent because it wrote no output
	// for agent.stall_timeout.
	OutcomeStalled Outcome = "stalled"
	// OutcomeStopped: ochell stopped the agent for another reason, such as
	// its own shutdown.
	OutcomeStopped Outcome = "stopped"
	// OutcomeCancelled: a person stopped the run, or released the ticket:
	// from the ticket, by unassigning it, or from ochell itself.
	OutcomeCancelled Outcome = "cancelled"
	// OutcomeOverBudget: the ticket has used up the budget of its tier.
	// The agent was stopped when the run reached it, or was not started
	// because nothing was left.
	OutcomeOverBudget Outcome = "over_budget"
	// OutcomeOverTurns: the agent was stopped at the turn limit of the
	// ticket's tier.
	OutcomeOverTurns Outcome = "over_turns"
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
	// Usage are what this run alone cost. All three are empty for an agent
	// that does not report them.
	SessionID string
	CostUSD   float64
	Usage     agent.Usage
	// SessionCostUSD is what the agent's session has cost so far, earlier
	// runs included, for an agent that reports that; 0 otherwise.
	SessionCostUSD float64
	// Signal is what the agent's result file says about the run, and
	// SignalMessage its text for the people on the ticket. Signal is
	// result.None when the run left no valid file. PRURL and Branch are
	// the pull request and the branch the file names, if any.
	Signal        result.Status
	SignalMessage string
	PRURL         string
	Branch        string
	// Phase is the phase the run was for.
	Phase Phase
	// PromptHash is the SHA-256 of the prompt the agent was given, and
	// Grants names what the run's tier granted it: the names of the tools
	// file and of the variables, never a value. Both are for the audit
	// record of the run.
	PromptHash string
	Grants     string
	// Workflow is the version of the repository's WORKFLOW.md that the
	// run ran under; empty: none.
	Workflow string
	// AwaitChecks says that the work was handed over with a pull request
	// whose checks ochell follows: the ticket is not in review yet.
	AwaitChecks bool
	// Escalation is set when a trigger stopped the ticket: it now waits
	// for a human, whatever the outcome says. TierBefore and TierAfter are
	// set when the escalation moved the ticket to a higher tier.
	Escalation Escalation
	TierBefore string
	TierAfter  string
	// Next is set when ochell has queued another run of the ticket in
	// place of this one, and says why. The ticket is then not waiting for
	// anyone.
	Next Cause
	// NextAt is when that run may start; zero: at once.
	NextAt time.Time
	// Message is the agent's final message, as its adapter read it: for
	// the plain adapter, the last part of the output.
	Message string
	// AgentError says that the agent itself called the run a failure in
	// its output, whatever its exit status was.
	AgentError bool
}
