package ticket

import (
	"strings"
	"testing"

	"ochell/internal/result"
	"ochell/internal/task"
)

var all = []State{None, Queued, Running, Waiting, InReview, Done, Failed, Cancelled}

// The whole table, written out: a change to the moves must change this too.
func TestMoves(t *testing.T) {
	want := map[State]string{
		//         to: (new) queued running waiting in_review done failed cancelled
		None:      "  -     yes    -       yes     -         -    -      -",
		Queued:    "  -     -      yes     -       -         -    -      yes",
		Running:   "  -     yes    -       yes     yes       yes  yes    yes",
		Waiting:   "  -     yes    -       yes     -         yes  -      yes",
		InReview:  "  -     yes    -       yes     -         yes  -      yes",
		Done:      "  -     yes    -       yes     -         -    -      -",
		Failed:    "  -     yes    -       yes     -         -    -      yes",
		Cancelled: "  -     yes    -       yes     -         -    -      -",
	}
	for _, from := range all {
		cells := strings.Fields(want[from])
		if len(cells) != len(all) {
			t.Fatalf("row of %q has %d cells", from, len(cells))
		}
		for i, to := range all {
			reason := Reason("")
			if to == Waiting {
				reason = ReasonInput
			}
			err := Move(from, to, reason)
			if allowed := cells[i] == "yes"; allowed != (err == nil) {
				t.Errorf("%s -> %s: allowed = %v, want %v (%v)", name(from), name(to), err == nil, allowed, err)
			}
		}
	}
}

func TestReasons(t *testing.T) {
	for r := range reasons {
		if err := Move(Running, Waiting, r); err != nil {
			t.Errorf("waiting for %s: %v", r, err)
		}
	}
	if err := Move(Running, Waiting, ""); err == nil {
		t.Error("a waiting ticket without a reason must be refused")
	}
	if err := Move(Running, Waiting, "bored"); err == nil {
		t.Error("an unknown reason must be refused")
	}
	if err := Move(Running, Failed, ReasonBlocked); err == nil {
		t.Error("a reason on a state other than waiting must be refused")
	}
	if err := Move("paused", Queued, ""); err == nil {
		t.Error("an unknown state must be refused")
	}
}

func TestActive(t *testing.T) {
	for _, s := range all {
		if got, want := s.Active(), s == Queued || s == Running; got != want {
			t.Errorf("%s.Active() = %v", name(s), got)
		}
	}
}

// Whatever a run ends with, the ticket can move there from running, and is
// then free for a new run.
func TestAfterRun(t *testing.T) {
	type run struct {
		outcome task.Outcome
		signal  result.Status
	}
	want := map[run]struct {
		state  State
		reason Reason
	}{
		// A run that ended by itself with status 0: the agent's signal decides.
		{task.OutcomeFinished, result.Done}:          {InReview, ""},
		{task.OutcomeFinished, result.NeedsInput}:    {Waiting, ReasonInput},
		{task.OutcomeFinished, result.Blocked}:       {Waiting, ReasonBlocked},
		{task.OutcomeFinished, result.LowConfidence}: {Waiting, ReasonEscalation},
		{task.OutcomeFinished, result.OutOfScope}:    {Waiting, ReasonEscalation},
		{task.OutcomeFinished, result.None}:          {Waiting, ReasonNoResult},
		// Any other run: the outcome decides, whatever the agent wrote.
		{task.OutcomeFailed, result.None}:      {Failed, ""},
		{task.OutcomeFailed, result.Done}:      {Failed, ""},
		{task.OutcomeTimedOut, result.Done}:    {Failed, ""},
		{task.OutcomeNotStarted, result.None}:  {Failed, ""},
		{task.OutcomeStopped, result.Done}:     {Waiting, ReasonInterrupted},
		{task.OutcomeInterrupted, result.None}: {Waiting, ReasonInterrupted},
	}
	for r, w := range want {
		o := r.outcome
		state, reason := AfterRun(r.outcome, r.signal)
		if state != w.state || reason != w.reason {
			t.Errorf("AfterRun(%s, %q) = %s, %q; want %s, %q", o, r.signal, state, reason, w.state, w.reason)
		}
		if err := Move(Running, state, reason); err != nil {
			t.Errorf("after a %s run: %v", o, err)
		}
		if state.Active() {
			t.Errorf("after a %s run the ticket is still active", o)
		}
		if err := Move(state, Queued, ""); err != nil {
			t.Errorf("a new run after a %s run: %v", o, err)
		}
	}
}
