// Package ticket defines the states of a ticket and the moves between them.
// This is the one place that says what is allowed; the store asks it before
// every change of state.
//
//	                 ┌──────────────── new run (assigned again, a reply, a retry) ───────────────┐
//	                 ▼                                                                            │
//	(new) ──► queued ──► running ──┬──► in_review ──► done ───────────────────────────────────────┤
//	   │         │                 ├──► waiting (with a reason) ───────────────────────────────────┤
//	   │         │                 ├──► failed ───────────────────────────────────────────────────┤
//	   │         └──► cancelled ◄──┴── (also from waiting, in_review and failed) ──────────────────┘
//	   └──► waiting (no_repo_mapping: the ticket is not started)
//
// Pausing is not a state: it holds the queue, and queued tickets stay queued.
package ticket

import (
	"fmt"
	"slices"

	"ochell/internal/task"
)

// State is where a ticket is in its life in ochell.
type State string

const (
	// None: ochell has not seen the ticket.
	None State = ""
	// Queued: a run of the ticket waits for a free worker.
	Queued State = "queued"
	// Running: an agent is working on the ticket.
	Running State = "running"
	// Waiting: nothing happens until a human acts. It always has a Reason.
	Waiting State = "waiting"
	// InReview: the agent handed its work over, and a human reviews it.
	InReview State = "in_review"
	// Done: the work was accepted, or the ticket was closed.
	Done State = "done"
	// Failed: the last run did not succeed, and nothing is retrying it.
	Failed State = "failed"
	// Cancelled: the ticket was stopped or released by a human. It is not
	// started again until it is assigned again.
	Cancelled State = "cancelled"
)

// Active reports whether the ticket has a run that is queued or running. An
// active ticket takes no second run.
func (s State) Active() bool { return s == Queued || s == Running }

// Reason says what a waiting ticket waits for.
type Reason string

const (
	// ReasonInput: the agent asked a question.
	ReasonInput Reason = "input"
	// ReasonPlanApproval: the agent's plan needs an approval.
	ReasonPlanApproval Reason = "plan_approval"
	// ReasonBlocked: the agent cannot go on, for a cause outside the ticket.
	ReasonBlocked Reason = "blocked"
	// ReasonStalled: the agent stopped making progress and was stopped.
	ReasonStalled Reason = "stalled"
	// ReasonNoResult: the run ended without saying how.
	ReasonNoResult Reason = "no_result"
	// ReasonNoRepoMapping: ochell does not know which repository the ticket
	// belongs to.
	ReasonNoRepoMapping Reason = "no_repo_mapping"
	// ReasonEscalation: a limit or a policy rule stopped the run.
	ReasonEscalation Reason = "escalation"
	// ReasonInterrupted: ochell itself stopped during the run, and the run
	// was not resumed.
	ReasonInterrupted Reason = "interrupted"
)

var reasons = map[Reason]bool{
	ReasonInput: true, ReasonPlanApproval: true, ReasonBlocked: true, ReasonStalled: true,
	ReasonNoResult: true, ReasonNoRepoMapping: true, ReasonEscalation: true, ReasonInterrupted: true,
}

// moves lists, for each state, the states a ticket may move to.
var moves = map[State][]State{
	// A ticket with no repository mapping is recorded without being started.
	None:   {Queued, Waiting},
	Queued: {Running, Cancelled},
	// Back to queued: a retry, or a run that is resumed after a restart.
	Running: {Waiting, InReview, Done, Failed, Cancelled, Queued},
	// A human acted: a new run, or the ticket was closed. Waiting again:
	// the reason changed.
	Waiting:  {Queued, Cancelled, Done, Waiting},
	InReview: {Queued, Done, Cancelled, Waiting},
	// From here on only a new assignment starts the ticket again.
	Done:      {Queued, Waiting},
	Failed:    {Queued, Cancelled, Waiting},
	Cancelled: {Queued, Waiting},
}

// Move checks a change of state. A ticket that moves to Waiting must give a
// known reason; any other move must give none.
func Move(from, to State, reason Reason) error {
	targets, known := moves[from]
	if !known {
		return fmt.Errorf("ticket: unknown state %q", from)
	}
	if !slices.Contains(targets, to) {
		return fmt.Errorf("ticket: a move from %s to %s is not allowed", name(from), name(to))
	}
	switch {
	case to == Waiting && reason == "":
		return fmt.Errorf("ticket: a waiting ticket needs a reason")
	case to == Waiting && !reasons[reason]:
		return fmt.Errorf("ticket: unknown reason %q", reason)
	case to != Waiting && reason != "":
		return fmt.Errorf("ticket: only a waiting ticket has a reason, not one that is %s", name(to))
	}
	return nil
}

func name(s State) string {
	if s == None {
		return "(new)"
	}
	return string(s)
}

// AfterRun returns the state a running ticket moves to when its run ends.
//
// A run that ended by itself with status 0 handed its work over. Until the
// agent can say more (the result file of the signal contract), that is all
// ochell knows.
func AfterRun(o task.Outcome) (State, Reason) {
	switch o {
	case task.OutcomeFinished:
		return InReview, ""
	case task.OutcomeStopped, task.OutcomeInterrupted:
		return Waiting, ReasonInterrupted
	}
	// failed, timed_out, not_started
	return Failed, ""
}
