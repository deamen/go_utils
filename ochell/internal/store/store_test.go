package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ochell/internal/agent"
	"ochell/internal/result"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTask(id, key string, received time.Time) *task.Task {
	return &task.Task{
		ID: id, Source: "linear", Key: key, Title: "Title of " + key, URL: "https://example.test/" + key,
		Context: "context of " + id, Comment: "comment of " + id, TrackerSession: "session-" + id, DeliveryID: "delivery-" + id, Received: received,
	}
}

func TestQueue(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

	if got, err := s.Claim(); err != nil || got != nil {
		t.Fatalf("Claim on an empty store = %v, %v", got, err)
	}
	// Queued out of order: the oldest is claimed first.
	if err := s.Enqueue(newTask("r2", "ENG-2", t0.Add(time.Second)), Limits{MaxQueued: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), Limits{MaxQueued: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r1b", "ENG-1", t0), Limits{}); !errors.Is(err, ErrBusy) {
		t.Errorf("second run of a queued ticket: %v, want ErrBusy", err)
	}
	if err := s.Enqueue(newTask("r3", "ENG-3", t0), Limits{MaxQueued: 2}); !errors.Is(err, ErrQueueFull) {
		t.Errorf("third queued run with a limit of 2: %v, want ErrQueueFull", err)
	}
	if n, _ := s.Active(); n != 2 {
		t.Errorf("Active = %d, want 2", n)
	}

	got, err := s.Claim()
	if err != nil {
		t.Fatal(err)
	}
	want := newTask("r1", "ENG-1", t0)
	want.Attempt = 1
	if *got != *want {
		t.Errorf("claimed %+v\nwant    %+v", got, want)
	}
	if err := s.Enqueue(newTask("r1c", "ENG-1", t0), Limits{}); !errors.Is(err, ErrBusy) {
		t.Errorf("second run of a running ticket: %v, want ErrBusy", err)
	}
	// A running run no longer counts against the queue limit.
	if err := s.Enqueue(newTask("r3", "ENG-3", t0.Add(2*time.Second)), Limits{MaxQueued: 2}); err != nil {
		t.Errorf("queue with one waiting run and a limit of 2: %v", err)
	}

	res := task.Result{Outcome: task.OutcomeFailed, ExitCode: 3, Err: errors.New("exit status 3"), LogFile: "logs/r1.log", Workdir: "/work/ENG-1"}
	if err := s.Finish("r1", res); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish("r1", res); err == nil {
		t.Error("finishing a run twice must fail")
	}
	tk, err := s.Ticket("linear", "ENG-1")
	if err != nil || tk == nil {
		t.Fatalf("Ticket = %v, %v", tk, err)
	}
	if tk.State != ticket.Failed || tk.Reason != "" || tk.Attempts != 1 || tk.Workspace != "/work/ENG-1" || tk.Title != "Title of ENG-1" {
		t.Errorf("ticket = %+v", tk)
	}

	// The ticket is free again; its next run is attempt 2.
	if err := s.Enqueue(newTask("r4", "ENG-1", t0.Add(-time.Hour)), Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); got == nil || got.ID != "r4" || got.Attempt != 2 {
		t.Errorf("second run of the ticket = %+v, want r4 as attempt 2", got)
	}
	if tk, _ := s.Ticket("jira", "ENG-1"); tk != nil {
		t.Errorf("the same key in another source = %+v, want none", tk)
	}
}

// What the done-when asks for: queued and running runs survive a restart.
func TestRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "ochell.db")
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"run-a", "run-b", "run-c"} {
		if err := s.Enqueue(newTask(id, "ENG-"+id, t0.Add(time.Duration(i)*time.Second)), Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.Claim(); got == nil || got.ID != "run-a" {
		t.Fatalf("claimed %+v", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("store file mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	// No Close: ochell was killed.

	s = open(t, path)
	interrupted, err := s.Recover(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(interrupted) != 1 || interrupted[0].Task.ID != "run-a" || interrupted[0].Task.TrackerSession != "session-run-a" || interrupted[0].Next != "" {
		t.Fatalf("interrupted = %+v, want run-a with its tracker session", interrupted)
	}
	if tk, _ := s.Ticket("linear", "ENG-run-a"); tk == nil || tk.State != ticket.Waiting || tk.Reason != ticket.ReasonInterrupted || tk.Attempts != 1 {
		t.Errorf("ticket of the interrupted run = %+v", tk)
	}
	if again, _ := s.Recover(nil); len(again) != 0 {
		t.Errorf("a second Recover returned %+v", again)
	}
	// The queued runs are still there, in order, with what a run needs.
	for _, id := range []string{"run-b", "run-c"} {
		got, err := s.Claim()
		if err != nil || got == nil || got.ID != id {
			t.Fatalf("Claim = %+v, %v; want %s", got, err, id)
		}
		if got.Context != "context of "+id || got.Title == "" || got.URL == "" || got.Received.IsZero() {
			t.Errorf("claimed task lost fields: %+v", got)
		}
	}
	// The interrupted ticket can be started again.
	if err := s.Enqueue(newTask("run-a2", "ENG-run-a", t0), Limits{}); err != nil {
		t.Errorf("new run of an interrupted ticket: %v", err)
	}
}

// A run that ochell did not see the end of is closed, and another run of
// its ticket takes its place: same context, comment and tracker session,
// and the agent session that the interrupted run had opened.
func TestRecoverQueuesAgain(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	first := newTask("run-1", "ENG-1", t0)
	first.Comment = "please also fix the typo"
	if err := s.Enqueue(first, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); got == nil || got.Cause != "" {
		t.Fatalf("claimed %+v", got)
	}
	// The agent names its session while it runs.
	if err := s.NoteSession("linear", "ENG-1", "session-abc", "/work/ENG-1"); err != nil {
		t.Fatal(err)
	}
	// ochell is killed here.

	again := func(max int) func(*task.Task) Again {
		return func(tk *task.Task) Again {
			return Again{ID: tk.ID + "-again", Cause: task.CauseRecovery, MaxAttempts: max}
		}
	}
	in, err := s.Recover(again(5))
	if err != nil || len(in) != 1 || in[0].Next != task.CauseRecovery {
		t.Fatalf("Recover = %+v, %v; want one run that was queued again", in, err)
	}
	if run, _ := s.Run("run-1"); run == nil || run.Status != "ended" || run.Result.Outcome != task.OutcomeInterrupted {
		t.Errorf("the interrupted run = %+v", run)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk == nil || tk.State != ticket.Queued {
		t.Fatalf("ticket = %+v, want queued", tk)
	}
	got, err := s.Claim()
	if err != nil || got == nil {
		t.Fatalf("Claim = %+v, %v", got, err)
	}
	if got.ID != "run-1-again" || got.Cause != task.CauseRecovery || got.Attempt != 2 ||
		got.AgentSession != "session-abc" || got.Workspace != "/work/ENG-1" ||
		got.Comment != first.Comment || got.Context != first.Context || got.TrackerSession != first.TrackerSession {
		t.Errorf("the run that takes its place = %+v", got)
	}

	// FinishAndQueue does the same for a run that ochell stops itself.
	queued, err := s.FinishAndQueue("run-1-again", task.Result{Outcome: task.OutcomeStopped}, &Again{ID: "run-3", Cause: task.CauseRecovery, MaxAttempts: 5})
	if err != nil || queued != task.CauseRecovery {
		t.Fatalf("FinishAndQueue = %v, %v", queued, err)
	}
	if got, _ := s.Claim(); got == nil || got.ID != "run-3" || got.Attempt != 3 {
		t.Fatalf("claimed %+v, want run-3 as the third attempt", got)
	}

	// A ticket that has used up its attempts is not queued again: it waits.
	in, err = s.Recover(again(3))
	if err != nil || len(in) != 1 || in[0].Next != "" {
		t.Fatalf("Recover at the attempt cap = %+v, %v", in, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Waiting || tk.Reason != ticket.ReasonInterrupted {
		t.Errorf("ticket = %s (%s), want waiting (interrupted)", tk.State, tk.Reason)
	}
	if n, _ := s.Active(); n != 0 {
		t.Errorf("%d runs are queued or running, want none", n)
	}
}

// What the adapter read from a run is stored, and the ticket's next run gets
// the session and the working directory to resume in.
func TestAgentSession(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	run := func(id string, res task.Result) *task.Task {
		t.Helper()
		if err := s.Enqueue(newTask(id, "ENG-1", t0), Limits{}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Claim()
		if err != nil || got == nil || got.ID != id {
			t.Fatalf("Claim = %+v, %v", got, err)
		}
		if err := s.Finish(id, res); err != nil {
			t.Fatal(err)
		}
		return got
	}

	first := task.Result{
		Outcome: task.OutcomeFinished, ExitCode: 0, Workdir: "/work/ENG-1", LogFile: "logs/r1.log",
		Message: "Opened PR #7", SessionID: "sess-1", CostUSD: 0.25,
		Signal: result.Done, SignalMessage: "Ready for review.", PRURL: "https://github.com/x/y/pull/7", Branch: "bot/ENG-1",
		Usage: agent.Usage{InputTokens: 2, OutputTokens: 4, CacheReadTokens: 11852, CacheWriteTokens: 8403},
	}
	if got := run("r1", first); got.AgentSession != "" || got.Workspace != "" {
		t.Errorf("first run of a ticket: session %q in %q, want none", got.AgentSession, got.Workspace)
	}
	stored, err := s.Run("r1")
	if err != nil || stored == nil {
		t.Fatalf("Run = %v, %v", stored, err)
	}
	if stored.Status != "ended" || stored.Attempt != 1 || stored.Key != "ENG-1" || stored.Result != first {
		t.Errorf("stored run = %+v\nwant result %+v", stored, first)
	}
	if missing, err := s.Run("nope"); missing != nil || err != nil {
		t.Errorf("Run of an unknown id = %v, %v", missing, err)
	}

	// The second run is told what to resume. It reports no session of its
	// own (it was stopped early): the ticket keeps the one it has.
	second := run("r2", task.Result{Outcome: task.OutcomeTimedOut, ExitCode: -1, Err: errors.New("agent timed out"), Resumed: true})
	if second.AgentSession != "sess-1" || second.Workspace != "/work/ENG-1" || second.Attempt != 2 {
		t.Errorf("second run = %+v, want session sess-1 in /work/ENG-1", second)
	}
	// It also learns what the first run left behind, for its prompt.
	if second.PRURL != "https://github.com/x/y/pull/7" || second.Branch != "bot/ENG-1" {
		t.Errorf("second run = %+v, want the pull request and the branch of the first", second)
	}
	if stored, _ := s.Run("r2"); !stored.Result.Resumed || stored.Result.Err == nil || stored.Result.Err.Error() != "agent timed out" {
		t.Errorf("stored second run = %+v", stored.Result)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.AgentSession != "sess-1" {
		t.Errorf("session after a run that reported none = %q, want sess-1", tk.AgentSession)
	}
	// The pull request and the branch of the first run stay with the ticket.
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.PRURL != "https://github.com/x/y/pull/7" || tk.Branch != "bot/ENG-1" {
		t.Errorf("ticket lost its pull request or branch: %q, %q", tk.PRURL, tk.Branch)
	}

	// A resumed run that fails without opening a session: the session is
	// gone, and the next run must start a new one.
	run("r3", task.Result{Outcome: task.OutcomeFailed, ExitCode: 1, Err: errors.New("exit status 1"), Resumed: true})
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.AgentSession != "" {
		t.Errorf("session after a failed resume = %q, want none", tk.AgentSession)
	}
	if fourth := run("r4", task.Result{Outcome: task.OutcomeFinished, SessionID: "sess-2"}); fourth.AgentSession != "" {
		t.Errorf("run after a failed resume was told to resume %q", fourth.AgentSession)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.AgentSession != "sess-2" {
		t.Errorf("session = %q, want sess-2", tk.AgentSession)
	}
}

// The guards: a ticket's attempts are limited, and a pause holds the queue.
func TestGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ochell.db")
	s := open(t, path)
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	lim := Limits{MaxAttempts: 2}
	for _, id := range []string{"r1", "r2"} {
		if err := s.Enqueue(newTask(id, "ENG-1", t0), lim); err != nil {
			t.Fatal(err)
		}
		s.Claim()
		if err := s.Finish(id, task.Result{Outcome: task.OutcomeFailed}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Enqueue(newTask("r3", "ENG-1", t0), lim); !errors.Is(err, ErrAttempts) {
		t.Errorf("third run with a limit of 2: %v, want ErrAttempts", err)
	}
	if err := s.Enqueue(newTask("other", "ENG-2", t0), lim); err != nil {
		t.Errorf("the limit is per ticket: %v", err)
	}
	if err := s.ResetAttempts("linear", "ENG-0"); !errors.Is(err, ErrUnknown) {
		t.Errorf("reset of an unknown ticket: %v", err)
	}
	if err := s.ResetAttempts("linear", "ENG-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r3", "ENG-1", t0.Add(time.Second)), lim); err != nil {
		t.Errorf("after the reset: %v", err)
	}

	// Paused: nothing is handed out, and nothing is lost.
	if err := s.SetPaused(true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPaused(true); err != nil {
		t.Errorf("pausing twice: %v", err)
	}
	if got, err := s.Claim(); got != nil || err != nil {
		t.Errorf("Claim while paused = %v, %v", got, err)
	}
	if queued, running, _ := s.Counts(); queued != 2 || running != 0 {
		t.Errorf("Counts = %d queued, %d running; want 2, 0", queued, running)
	}
	// The flag is kept across a restart.
	s2 := open(t, path)
	if held, _ := s2.Paused(); !held {
		t.Error("the pause was forgotten by a restart")
	}
	if err := s2.SetPaused(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Claim(); got == nil || got.ID != "other" {
		t.Errorf("Claim after the resume = %+v, want the oldest queued run", got)
	}
	if queued, running, _ := s2.Counts(); queued != 1 || running != 1 {
		t.Errorf("Counts = %d queued, %d running; want 1, 1", queued, running)
	}
}

// What the tracker's report of a closed ticket does, by the ticket's state.
func TestCloseTicket(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	if _, err := s.CloseTicket("linear", "ENG-0"); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown ticket: %v, want ErrUnknown", err)
	}
	ended := func(key string, res task.Result) {
		t.Helper()
		if err := s.Enqueue(newTask("run-"+key, key, t0), Limits{}); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Claim(); err != nil || got == nil {
			t.Fatalf("Claim = %v, %v", got, err)
		}
		if err := s.Finish("run-"+key, res); err != nil {
			t.Fatal(err)
		}
	}
	ended("ENG-1", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done, Workdir: "/work/ENG-1", SessionID: "sess-1"}) // in_review
	ended("ENG-2", task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput})                                        // waiting
	ended("ENG-3", task.Result{Outcome: task.OutcomeFailed})                                                                     // failed
	for _, key := range []string{"ENG-1", "ENG-2", "ENG-3"} {
		tk, err := s.CloseTicket("linear", key)
		if err != nil || tk.State != ticket.Done || tk.Reason != "" {
			t.Errorf("%s: %+v, %v; want done", key, tk, err)
		}
	}
	// The ticket still has what is needed to remove its working directory.
	if tk, _ := s.CloseTicket("linear", "ENG-1"); tk == nil || tk.State != ticket.Done || tk.Workspace != "/work/ENG-1" {
		t.Errorf("closing a done ticket again: %+v", tk)
	}

	// A queued and a running ticket are left as they are.
	if err := s.Enqueue(newTask("run-q", "ENG-4", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloseTicket("linear", "ENG-4"); !errors.Is(err, ErrBusy) {
		t.Errorf("queued ticket: %v, want ErrBusy", err)
	}
	s.Claim()
	if _, err := s.CloseTicket("linear", "ENG-4"); !errors.Is(err, ErrBusy) {
		t.Errorf("running ticket: %v, want ErrBusy", err)
	}
	if tk, _ := s.Ticket("linear", "ENG-4"); tk.State != ticket.Running {
		t.Errorf("state = %s, want running", tk.State)
	}

	// The working directory and what depends on it.
	if err := s.SetPrepared("linear", "ENG-1", "/work/ENG-1"); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.PreparedWorkspace != "/work/ENG-1" || tk.AgentSession != "sess-1" {
		t.Errorf("ticket = %+v", tk)
	}
	if err := s.ClearWorkspace("linear", "ENG-1"); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.Workspace != "" || tk.PreparedWorkspace != "" || tk.AgentSession != "" {
		t.Errorf("after ClearWorkspace: %+v", tk)
	}
}

// A ticket that cannot be started is recorded as waiting, without a run.
func TestHold(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	if err := s.Hold(newTask("r1", "OPS-7", t0), ticket.ReasonNoRepoMapping); err != nil {
		t.Fatal(err)
	}
	tk, _ := s.Ticket("linear", "OPS-7")
	if tk == nil || tk.State != ticket.Waiting || tk.Reason != ticket.ReasonNoRepoMapping || tk.Attempts != 0 || tk.Title != "Title of OPS-7" {
		t.Fatalf("held ticket = %+v", tk)
	}
	if got, _ := s.Claim(); got != nil {
		t.Errorf("a held ticket has a run: %+v", got)
	}
	if n, _ := s.Active(); n != 0 {
		t.Errorf("Active = %d, want 0", n)
	}

	// Once a repository is mapped, the same ticket is queued, and its
	// task carries the repository.
	mapped := newTask("r2", "OPS-7", t0)
	mapped.Repo = "git@example.com:org/ops.git"
	if err := s.Enqueue(mapped, Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Hold(newTask("r3", "OPS-7", t0), ticket.ReasonNoRepoMapping); !errors.Is(err, ErrBusy) {
		t.Errorf("holding a queued ticket: %v, want ErrBusy", err)
	}
	got, _ := s.Claim()
	if got == nil || got.Repo != "git@example.com:org/ops.git" {
		t.Errorf("claimed %+v, want the repository", got)
	}
	if tk, _ := s.Ticket("linear", "OPS-7"); tk.Repo != "git@example.com:org/ops.git" {
		t.Errorf("ticket repo = %q", tk.Repo)
	}
}

// The store refuses a change of state that package ticket does not allow,
// and changes nothing then.
func TestStateIsEnforced(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	if err := s.Enqueue(newTask("r1", "ENG-1", time.Now()), Limits{}); err != nil {
		t.Fatal(err)
	}
	// A queued ticket cannot go straight to review.
	err := s.tx(func(tx *sql.Tx) error { return s.move(tx, "linear", "ENG-1", ticket.InReview, "") })
	if err == nil || !strings.Contains(err.Error(), "from queued to in_review is not allowed") {
		t.Errorf("queued -> in_review: %v", err)
	}
	// Finishing a run that was never started would move queued to failed.
	if err := s.Finish("r1", task.Result{Outcome: task.OutcomeFailed}); err == nil {
		t.Error("finishing a run that is still queued must fail")
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Queued {
		t.Errorf("state after the refused moves = %s, want queued", tk.State)
	}
	if got, _ := s.Claim(); got == nil || got.ID != "r1" {
		t.Errorf("the run is no longer queued: %+v", got)
	}
	if err := s.Finish("r1", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.InReview || tk.Reason != "" {
		t.Errorf("after a finished run: %s (%q), want in_review", tk.State, tk.Reason)
	}
}

// A file written before the state machine existed is converted.
func TestMigrateProvisionalStates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ochell.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0] + `; PRAGMA user_version = 1;
		INSERT INTO tickets (source, key, state, created_at, updated_at) VALUES
			('jira', 'OK-1', 'ended', 0, 0), ('jira', 'BAD-1', 'ended', 0, 0),
			('jira', 'CUT-1', 'interrupted', 0, 0), ('jira', 'Q-1', 'queued', 0, 0);
		INSERT INTO runs (id, source, key, status, received_at, ended_at, outcome) VALUES
			('a', 'jira', 'OK-1', 'ended', 0, 1, 'failed'), ('b', 'jira', 'OK-1', 'ended', 0, 2, 'finished'),
			('c', 'jira', 'BAD-1', 'ended', 0, 1, 'timed_out'), ('d', 'jira', 'CUT-1', 'ended', 0, 1, 'interrupted'),
			('e', 'jira', 'Q-1', 'queued', 0, NULL, '');`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s := open(t, path)
	for key, want := range map[string]struct {
		state  ticket.State
		reason ticket.Reason
	}{
		"OK-1":  {ticket.InReview, ""},
		"BAD-1": {ticket.Failed, ""},
		"CUT-1": {ticket.Waiting, ticket.ReasonInterrupted},
		"Q-1":   {ticket.Queued, ""},
	} {
		tk, err := s.Ticket("jira", key)
		if err != nil || tk == nil {
			t.Fatalf("%s: %v, %v", key, tk, err)
		}
		if tk.State != want.state || tk.Reason != want.reason {
			t.Errorf("%s: %s (%q), want %s (%q)", key, tk.State, tk.Reason, want.state, want.reason)
		}
	}
	if got, _ := s.Claim(); got == nil || got.ID != "e" {
		t.Errorf("the queued run of the old file: %+v", got)
	}
}

func TestDeliveries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ochell.db")
	s := open(t, path)
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	add := func(s *Store, key string) bool {
		t.Helper()
		isNew, err := s.AddDelivery(key, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return isNew
	}
	if !add(s, "jira:d-1") || add(s, "jira:d-1") {
		t.Error("a delivery must be new once")
	}
	if !add(s, "") || !add(s, "") {
		t.Error("an empty key is never a duplicate")
	}
	if err := s.RemoveDelivery("jira:d-1"); err != nil || !add(s, "jira:d-1") {
		t.Errorf("a removed delivery must be new again (%v)", err)
	}

	// Deliveries survive a restart, until they expire.
	s2 := open(t, path)
	s2.now = func() time.Time { return now.Add(59 * time.Minute) }
	if add(s2, "jira:d-1") {
		t.Error("the delivery was forgotten by a restart")
	}
	s2.now = func() time.Time { return now.Add(61 * time.Minute) }
	if !add(s2, "jira:d-1") {
		t.Error("an expired delivery must be new again")
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ochell.db")
	s := open(t, path)
	if _, err := s.db.Exec(`PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(path); err == nil {
		t.Error("a file from a newer ochell must be refused")
	}
}

// A run that was queued with a time to wait for (the backoff of a retry) is
// not handed out before that time, and holds up nothing else.
func TestNotBefore(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Enqueue(newTask("run-1", "ENG-1", now), Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); got == nil {
		t.Fatal("nothing claimed")
	}
	queued, err := s.FinishAndQueue("run-1", task.Result{Outcome: task.OutcomeFailed}, &Again{ID: "run-2", Cause: task.CauseRetry, NotBefore: now.Add(time.Minute)})
	if err != nil || queued != task.CauseRetry {
		t.Fatalf("FinishAndQueue = %v, %v", queued, err)
	}
	if got, err := s.Claim(); got != nil || err != nil {
		t.Fatalf("Claim before the time = %+v, %v; want nothing", got, err)
	}
	// The ticket is busy in the meantime, and other tickets run.
	if err := s.Enqueue(newTask("run-x", "ENG-1", now), Limits{}); !errors.Is(err, ErrBusy) {
		t.Errorf("a second run of the waiting ticket: %v, want ErrBusy", err)
	}
	if err := s.Enqueue(newTask("run-other", "ENG-2", now), Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); got == nil || got.ID != "run-other" {
		t.Fatalf("claimed %+v, want the run of the other ticket", got)
	}
	now = now.Add(time.Minute)
	got, err := s.Claim()
	if err != nil || got == nil || got.ID != "run-2" || got.Cause != task.CauseRetry || got.Attempt != 2 {
		t.Fatalf("Claim at the time = %+v, %v; want run-2", got, err)
	}
}

// A message from a person queues a run of a ticket that ochell knows, and
// the ticket's attempts count from there again.
func TestFollowUp(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	lim := Limits{MaxAttempts: 2, MaxQueued: 10}
	follow := func(id, comment string) *task.Task {
		return &task.Task{ID: id, Source: "linear", Key: "ENG-1", Comment: comment, TrackerSession: "session-reply", Cause: task.CauseFollowUp, Received: t0}
	}
	if _, err := s.FollowUp(follow("f0", "hello"), true, lim); !errors.Is(err, ErrUnknown) {
		t.Fatalf("a follow-up on an unknown ticket: %v, want ErrUnknown", err)
	}

	first := newTask("run-1", "ENG-1", t0)
	first.Repo = "git@example.com:repo.git"
	if err := s.Enqueue(first, lim); err != nil {
		t.Fatal(err)
	}

	run := func(id string) {
		t.Helper()
		if got, err := s.Claim(); err != nil || got == nil || got.ID != id {
			t.Fatalf("Claim = %+v, %v; want %s", got, err, id)
		}
		if err := s.Finish(id, task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput, SessionID: "agent-session", Workdir: "/work/ENG-1"}); err != nil {
			t.Fatal(err)
		}
	}
	run("run-1")
	second := newTask("run-2", "ENG-1", t0)
	second.Repo = first.Repo
	if err := s.Enqueue(second, lim); err != nil {
		t.Fatal(err)
	}
	run("run-2")
	// The ticket has used its two attempts.
	if err := s.Enqueue(newTask("run-3", "ENG-1", t0), lim); !errors.Is(err, ErrAttempts) {
		t.Fatalf("a third assignment: %v, want ErrAttempts", err)
	}
	// A person answers: that run is not stopped by the cap.
	if _, err := s.FollowUp(follow("f2", "use the second page"), true, lim); err != nil {
		t.Fatal(err)
	}
	got, err := s.Claim()
	if err != nil || got == nil {
		t.Fatalf("Claim = %+v, %v", got, err)
	}
	if got.ID != "f2" || got.Cause != task.CauseFollowUp || got.Comment != "use the second page" || got.TrackerSession != "session-reply" ||
		got.Attempt != 3 || got.AgentSession != "agent-session" || got.Workspace != "/work/ENG-1" {
		t.Errorf("the follow-up run = %+v", got)
	}
	// The ticket kept what the follow-up did not bring.
	if got.Title != first.Title || got.URL != first.URL || got.Repo != first.Repo {
		t.Errorf("the ticket lost its title, URL or repository: %+v", got)
	}
	if err := s.Finish("f2", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}); err != nil {
		t.Fatal(err)
	}
	// One more run is allowed from there (the reply itself was the first),
	// and no further one.
	if err := s.Enqueue(newTask("run-4", "ENG-1", t0), lim); err != nil {
		t.Errorf("an assignment after the follow-up: %v", err)
	}
	run("run-4")
	if err := s.Enqueue(newTask("run-5", "ENG-1", t0), lim); !errors.Is(err, ErrAttempts) {
		t.Errorf("the cap after the follow-up: %v, want ErrAttempts", err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.Attempts != 4 {
		t.Errorf("attempts = %d, want 4: the number still counts every run", tk.Attempts)
	}
	// A comment on the ticket is a message from a person as well.
	if _, err := s.FollowUp(follow("run-4b", "and the footer"), false, lim); err != nil {
		t.Errorf("a comment on a ticket that waits: %v", err)
	}

	// A comment on the ticket, which is not addressed to the agent, counts
	// while ochell holds the ticket, and not once the ticket is done.
	run("run-4b")
	if _, err := s.CloseTicket("linear", "ENG-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FollowUp(follow("f3", "thanks!"), false, lim); !errors.Is(err, ErrReleased) {
		t.Errorf("a comment on a ticket that is done: %v, want ErrReleased", err)
	}
	if _, err := s.FollowUp(follow("f4", "one more thing"), true, lim); err != nil {
		t.Errorf("a message to the agent on a ticket that is done: %v", err)
	}

	if key, err := s.TicketOfSession("linear", "session-reply"); err != nil || key != "ENG-1" {
		t.Errorf("TicketOfSession = %q, %v", key, err)
	}
	if key, _ := s.TicketOfSession("linear", "no-such-session"); key != "" {
		t.Errorf("TicketOfSession of an unknown session = %q", key)
	}
}

// Messages that arrive while a ticket has a run are kept, and delivered in
// order with the run that follows.
func TestFollowUpsDuringARun(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	lim := Limits{MaxAttempts: 1, MaxQueued: 10}
	msg := func(id, comment, session string) *task.Task {
		return &task.Task{ID: id, Source: "linear", Key: "ENG-1", Comment: comment, TrackerSession: session, Cause: task.CauseFollowUp, Received: t0}
	}
	if err := s.Enqueue(newTask("run-1", "ENG-1", t0), lim); err != nil {
		t.Fatal(err)
	}
	// The ticket is queued, then running: both times the message waits.
	if later, err := s.FollowUp(msg("m1", "first message", ""), false, lim); err != nil || !later {
		t.Fatalf("a message for a queued ticket: later=%v, %v", later, err)
	}
	if got, _ := s.Claim(); got == nil || got.ID != "run-1" {
		t.Fatalf("claimed %+v", got)
	}
	if later, err := s.FollowUp(msg("m2", "second message", "session-two"), true, lim); err != nil || !later {
		t.Fatalf("a message for a running ticket: later=%v, %v", later, err)
	}
	if later, err := s.FollowUp(msg("m3", "third message", ""), false, lim); err != nil || !later {
		t.Fatalf("a third message: later=%v, %v", later, err)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 3 {
		t.Errorf("%d messages wait, want 3", n)
	}
	if n, _ := s.Active(); n != 1 {
		t.Errorf("%d runs are queued or running, want 1: a waiting message is no run", n)
	}

	// The run ends. Its own result stands, and the next run is queued,
	// although the ticket had only one attempt: people asked for it.
	next, err := s.FinishAndQueue("run-1", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}, nil)
	if err != nil || next != task.CauseFollowUp {
		t.Fatalf("FinishAndQueue = %q, %v; want follow_up", next, err)
	}
	if run, _ := s.Run("run-1"); run == nil || run.Result.Signal != result.Done {
		t.Errorf("the first run = %+v", run)
	}
	got, err := s.Claim()
	if err != nil || got == nil {
		t.Fatalf("Claim = %+v, %v", got, err)
	}
	want := strings.Join([]string{"first message", "second message", "third message"}, task.CommentSeparator)
	if got.Comment != want || got.Cause != task.CauseFollowUp || got.Attempt != 2 {
		t.Errorf("the next run = %+v", got)
	}
	// It reports where the last message that named a session came in.
	if got.TrackerSession != "session-two" {
		t.Errorf("tracker session = %q, want session-two", got.TrackerSession)
	}
	if got.Context != "context of run-1" {
		t.Errorf("context = %q, want that of the ticket's run", got.Context)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 0 {
		t.Errorf("%d messages still wait", n)
	}

	// A run that is retried or recovered takes the messages along, after
	// the comment it had itself.
	if _, err := s.FollowUp(msg("m4", "fourth message", ""), false, lim); err != nil {
		t.Fatal(err)
	}
	next, err = s.FinishAndQueue(got.ID, task.Result{Outcome: task.OutcomeStopped}, &Again{ID: "run-3", Cause: task.CauseRecovery, MaxAttempts: 5})
	if err != nil || next != task.CauseRecovery {
		t.Fatalf("FinishAndQueue = %q, %v; want recovery", next, err)
	}
	got, _ = s.Claim()
	if got == nil || got.ID != "run-3" || got.Comment != want+task.CommentSeparator+"fourth message" || got.TrackerSession != "session-two" {
		t.Errorf("the recovery run = %+v", got)
	}
	// Without messages a finished run ends the matter.
	if next, err := s.FinishAndQueue("run-3", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}, nil); err != nil || next != "" {
		t.Errorf("FinishAndQueue = %q, %v; want nothing queued", next, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.InReview {
		t.Errorf("ticket = %s, want in_review", tk.State)
	}

	// The list of waiting messages is bounded.
	if err := s.Enqueue(newTask("run-9", "ENG-2", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	m := msg("m", "x", "")
	m.Key = "ENG-2"
	for i := range maxWaitingMessages + 1 {
		_, err := s.FollowUp(m, false, lim)
		if i < maxWaitingMessages && err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if i == maxWaitingMessages && !errors.Is(err, ErrQueueFull) {
			t.Errorf("message %d: %v, want ErrQueueFull", i, err)
		}
	}
}

// The ticket remembers who assigned it; a run that names nobody (a retry, a
// follow-up) does not erase that.
func TestAssigner(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	assign := func(id, actor string) {
		t.Helper()
		tk := newTask(id, "ENG-1", t0)
		tk.Actor = actor
		if err := s.Enqueue(tk, Limits{}); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Claim(); got == nil {
			t.Fatal("nothing claimed")
		}
		if err := s.Finish(id, task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput}); err != nil {
			t.Fatal(err)
		}
	}
	assigner := func() string {
		tk, err := s.Ticket("linear", "ENG-1")
		if err != nil || tk == nil {
			t.Fatalf("Ticket = %v, %v", tk, err)
		}
		return tk.Assigner
	}
	assign("run-1", "u-anna")
	if got := assigner(); got != "u-anna" {
		t.Errorf("assigner = %q, want u-anna", got)
	}
	assign("run-2", "")
	if got := assigner(); got != "u-anna" {
		t.Errorf("an assignment that names nobody: assigner = %q, want u-anna still", got)
	}
	if _, err := s.FollowUp(&task.Task{ID: "f1", Source: "linear", Key: "ENG-1", Comment: "go on", Actor: "u-bob", Received: t0}, true, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := assigner(); got != "u-anna" {
		t.Errorf("after a follow-up: assigner = %q, want u-anna", got)
	}
	if got, _ := s.Claim(); got != nil {
		s.Finish(got.ID, task.Result{Outcome: task.OutcomeFinished, Signal: result.Done})
	}
	assign("run-3", "u-carl")
	if got := assigner(); got != "u-carl" {
		t.Errorf("assigned again by someone else: assigner = %q, want u-carl", got)
	}
}

// Stop ends what ochell holds of a ticket that has no running agent.
func TestStop(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	why := errors.New("the run was stopped by Anna")
	if _, err := s.Stop("linear", "ENG-0", why); !errors.Is(err, ErrUnknown) {
		t.Errorf("an unknown ticket: %v, want ErrUnknown", err)
	}

	// A queued run is taken out of the queue, with the messages that
	// waited behind it.
	if err := s.Enqueue(newTask("run-1", "ENG-1", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FollowUp(&task.Task{ID: "m1", Source: "linear", Key: "ENG-1", Comment: "also this", Received: t0}, true, Limits{}); err != nil {
		t.Fatal(err)
	}
	queued, err := s.Stop("linear", "ENG-1", why)
	if err != nil || queued == nil || queued.ID != "run-1" || queued.TrackerSession != "session-run-1" {
		t.Fatalf("Stop = %+v, %v; want the queued run", queued, err)
	}
	if run, _ := s.Run("run-1"); run.Status != "ended" || run.Result.Outcome != task.OutcomeCancelled || run.Result.Err == nil || run.Result.Err.Error() != why.Error() {
		t.Errorf("the queued run = %+v", run)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Cancelled {
		t.Errorf("ticket = %s, want cancelled", tk.State)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 0 {
		t.Errorf("%d messages still wait for a stopped ticket", n)
	}
	if got, _ := s.Claim(); got != nil {
		t.Errorf("the stopped run was claimed: %+v", got)
	}
	// Stopped twice, and a comment afterwards: nothing.
	if _, err := s.Stop("linear", "ENG-1", why); !errors.Is(err, ErrReleased) {
		t.Errorf("a second stop: %v, want ErrReleased", err)
	}
	if _, err := s.FollowUp(&task.Task{ID: "m2", Source: "linear", Key: "ENG-1", Comment: "hello?", Received: t0}, false, Limits{}); !errors.Is(err, ErrReleased) {
		t.Errorf("a comment on a stopped ticket: %v, want ErrReleased", err)
	}
	// Assigned again, it runs again.
	if err := s.Enqueue(newTask("run-2", "ENG-1", t0), Limits{}); err != nil {
		t.Fatalf("assigned again: %v", err)
	}

	// A running ticket is the caller's to stop; the run then ends as
	// cancelled, and what waited is dropped.
	if got, _ := s.Claim(); got == nil || got.ID != "run-2" {
		t.Fatalf("claimed %+v", got)
	}
	if _, err := s.Stop("linear", "ENG-1", why); !errors.Is(err, ErrBusy) {
		t.Errorf("a running ticket: %v, want ErrBusy", err)
	}
	if _, err := s.FollowUp(&task.Task{ID: "m3", Source: "linear", Key: "ENG-1", Comment: "and this", Received: t0}, true, Limits{}); err != nil {
		t.Fatal(err)
	}
	next, err := s.FinishAndQueue("run-2", task.Result{Outcome: task.OutcomeCancelled, Err: why}, &Again{ID: "run-3", Cause: task.CauseRetry})
	if err != nil || next != "" {
		t.Errorf("FinishAndQueue of a cancelled run = %q, %v; want nothing queued", next, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Cancelled {
		t.Errorf("ticket = %s, want cancelled", tk.State)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 0 {
		t.Errorf("%d messages still wait", n)
	}

	// A ticket that waits is released: no run to return.
	if err := s.Enqueue(newTask("run-4", "ENG-2", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()
	if err := s.Finish("run-4", task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput}); err != nil {
		t.Fatal(err)
	}
	if queued, err := s.Stop("linear", "ENG-2", why); err != nil || queued != nil {
		t.Errorf("releasing a waiting ticket = %+v, %v", queued, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-2"); tk.State != ticket.Cancelled {
		t.Errorf("ticket = %s, want cancelled", tk.State)
	}
	// Where a message about it goes: the session of its last run.
	if last, err := s.LastTask("linear", "ENG-2"); err != nil || last == nil || last.ID != "run-4" || last.TrackerSession != "session-run-4" {
		t.Errorf("LastTask = %+v, %v", last, err)
	}
	if last, err := s.LastTask("linear", "ENG-404"); err != nil || last != nil {
		t.Errorf("LastTask of an unknown ticket = %+v, %v", last, err)
	}
	// A closed ticket that was stopped before can still be closed.
	if tk, err := s.CloseTicket("linear", "ENG-2"); err != nil || tk.State != ticket.Done {
		t.Errorf("closing a cancelled ticket = %+v, %v", tk, err)
	}
}

// A run records the tier its ticket has when it starts, and the version of
// the policy in force.
func TestRunsRecordTheirTier(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	s.SetPolicyVersion("2026-11")
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

	first := newTask("r1", "ENG-1", t0)
	first.Tier = "low"
	if err := s.Enqueue(first, Limits{}); err != nil {
		t.Fatal(err)
	}
	// Nothing is recorded for a run that has not started.
	if run, _ := s.Run("r1"); run.Tier != "" || run.PolicyVersion != "" {
		t.Errorf("queued run = %+v", run)
	}
	got, err := s.Claim()
	if err != nil || got.Tier != "low" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if run, _ := s.Run("r1"); run.Tier != "low" || run.PolicyVersion != "2026-11" {
		t.Errorf("started run: tier %q, policy %q", run.Tier, run.PolicyVersion)
	}
	if err := s.Finish("r1", task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput}); err != nil {
		t.Fatal(err)
	}

	// A follow-up says nothing about the tier: the run has the ticket's.
	// The policy has changed in the meantime.
	s.SetPolicyVersion("2026-12")
	if _, err := s.FollowUp(newTask("r2", "ENG-1", t0.Add(time.Minute)), true, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Claim(); err != nil || got.Tier != "low" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if run, _ := s.Run("r2"); run.Tier != "low" || run.PolicyVersion != "2026-12" {
		t.Errorf("follow-up run: tier %q, policy %q", run.Tier, run.PolicyVersion)
	}
	if err := s.Finish("r2", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}); err != nil {
		t.Fatal(err)
	}

	// A new assignment under another tier; the first run keeps its record.
	third := newTask("r3", "ENG-1", t0.Add(2*time.Minute))
	third.Tier = "high"
	if err := s.Enqueue(third, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Claim(); err != nil || got.Tier != "high" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.Tier != "high" {
		t.Errorf("ticket tier = %q", tk.Tier)
	}
	if run, _ := s.Run("r1"); run.Tier != "low" || run.PolicyVersion != "2026-11" {
		t.Errorf("the first run now says tier %q, policy %q", run.Tier, run.PolicyVersion)
	}
}

// What a ticket has cost is the sum over its runs; the part since the last
// reset is what counts against a budget.
func TestCosts(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return t0 }
	run := func(id, key string, res task.Result) {
		t.Helper()
		tk := newTask(id, key, t0)
		tk.Tier = "low"
		if err := s.Enqueue(tk, Limits{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(); err != nil {
			t.Fatal(err)
		}
		res.Outcome = task.OutcomeFinished
		if err := s.Finish(id, res); err != nil {
			t.Fatal(err)
		}
	}
	if c, err := s.TicketCost("linear", "ENG-1"); err != nil || c != nil {
		t.Fatalf("cost of an unknown ticket = %+v, %v", c, err)
	}
	run("r1", "ENG-1", task.Result{SessionID: "s1", CostUSD: 0.5, SessionCostUSD: 0.5, Usage: agent.Usage{InputTokens: 1, OutputTokens: 2, CacheReadTokens: 3, CacheWriteTokens: 4}})
	run("r2", "ENG-1", task.Result{SessionID: "s1", CostUSD: 0.25, SessionCostUSD: 0.75, Usage: agent.Usage{InputTokens: 10, OutputTokens: 20}})
	run("r3", "ENG-2", task.Result{SessionID: "s2", CostUSD: 2})
	// Queued and never started: no run that cost anything.
	if err := s.Enqueue(newTask("r4", "ENG-3", t0.Add(time.Hour)), Limits{}); err != nil {
		t.Fatal(err)
	}

	c, err := s.TicketCost("linear", "ENG-1")
	if err != nil || c.Runs != 2 || c.CostUSD != 0.75 || c.SinceResetUSD != 0.75 || c.Tier != "low" ||
		c.Usage != (agent.Usage{InputTokens: 11, OutputTokens: 22, CacheReadTokens: 3, CacheWriteTokens: 4}) {
		t.Errorf("cost of ENG-1 = %+v, %v", c, err)
	}
	if c, _ := s.TicketCost("linear", "ENG-3"); c == nil || c.Runs != 0 || c.CostUSD != 0 {
		t.Errorf("cost of a ticket that never ran = %+v", c)
	}
	// What a session had cost: the highest total a run in it reported.
	for session, want := range map[string]float64{"s1": 0.75, "s2": 2, "other": 0, "": 0} {
		if got, err := s.SessionCost("linear", "ENG-1", session); session != "s2" && (err != nil || got != want) {
			t.Errorf("SessionCost(%q) = %v, %v; want %v", session, got, err, want)
		}
	}
	// A run from before the session's total was stored has it in its cost.
	if got, _ := s.SessionCost("linear", "ENG-2", "s2"); got != 2 {
		t.Errorf("SessionCost of a run without a stored total = %v, want 2", got)
	}

	// A reset starts the budget anew and keeps the record.
	if err := s.ResetAttempts("linear", "ENG-1"); err != nil {
		t.Fatal(err)
	}
	run("r5", "ENG-1", task.Result{SessionID: "s1", CostUSD: 0.125, SessionCostUSD: 0.875})
	if c, _ := s.TicketCost("linear", "ENG-1"); c.Runs != 3 || c.CostUSD != 0.875 || c.SinceResetUSD != 0.125 {
		t.Errorf("cost of ENG-1 after a reset = %+v", c)
	}

	runs, err := s.RunCosts("linear", "ENG-1")
	if err != nil || len(runs) != 3 || runs[0].ID != "r1" || runs[2].ID != "r5" || runs[1].CostUSD != 0.25 || runs[1].Attempt != 2 || runs[1].Outcome != task.OutcomeFinished || runs[1].Tier != "low" {
		t.Errorf("RunCosts = %+v, %v", runs, err)
	}
	all, err := s.TicketCosts(10)
	if err != nil || len(all) != 3 {
		t.Fatalf("TicketCosts = %+v, %v", all, err)
	}
	if two, _ := s.TicketCosts(2); len(two) != 2 {
		t.Errorf("TicketCosts(2) returned %d tickets", len(two))
	}
	total, err := s.TotalCost(time.Time{})
	if err != nil || total.Runs != 4 || total.CostUSD != 2.875 {
		t.Errorf("TotalCost = %+v, %v", total, err)
	}
	if later, _ := s.TotalCost(t0.Add(time.Hour)); later.Runs != 0 || later.CostUSD != 0 {
		t.Errorf("TotalCost since later = %+v", later)
	}
}

// A run that ends with an escalation leaves its ticket waiting, whatever
// else would have followed: no other try, and no run for the messages that
// arrived during it. Those go with the run that someone starts later.
func TestEscalationHoldsTheTicket(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(); err != nil {
		t.Fatal(err)
	}
	during := newTask("m1", "ENG-1", t0.Add(time.Second))
	during.Comment, during.TrackerSession = "written during the run", "session-m1"
	if later, err := s.FollowUp(during, true, Limits{}); err != nil || !later {
		t.Fatalf("FollowUp during the run = %v, %v", later, err)
	}

	res := task.Result{Outcome: task.OutcomeStopped, ExitCode: -1, Err: errors.New("stopped"), Escalation: task.EscalationTierChange}
	next, err := s.FinishAndQueue("r1", res, &Again{ID: "r2", Cause: task.CauseRecovery})
	if err != nil || next != "" {
		t.Fatalf("FinishAndQueue = %q, %v; want nothing queued", next, err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Waiting || tk.Reason != ticket.ReasonEscalation {
		t.Errorf("ticket = %s (%s), want waiting (escalation)", tk.State, tk.Reason)
	}
	if run, _ := s.Run("r1"); run.Result.Escalation != task.EscalationTierChange {
		t.Errorf("stored escalation = %q", run.Result.Escalation)
	}
	if got, _ := s.Claim(); got != nil {
		t.Fatalf("a run was queued after the escalation: %+v", got)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 1 {
		t.Fatalf("%d messages are kept, want 1", n)
	}

	// A person starts the ticket again: the kept message comes first.
	reply := newTask("r3", "ENG-1", t0.Add(time.Minute))
	reply.Comment, reply.TrackerSession = "go on", ""
	if _, err := s.FollowUp(reply, true, Limits{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Claim()
	if err != nil || got == nil || got.Comment != "written during the run"+task.CommentSeparator+"go on" || got.TrackerSession != "session-m1" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if n, _ := s.Waiting("linear", "ENG-1"); n != 0 {
		t.Errorf("%d messages still wait", n)
	}

	// A person's stop wins over an escalation.
	res = task.Result{Outcome: task.OutcomeCancelled, ExitCode: -1, Err: errors.New("stopped by a person"), Escalation: task.EscalationBudget}
	if err := s.Finish("r3", res); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Cancelled {
		t.Errorf("ticket = %s, want cancelled", tk.State)
	}

	// AttemptsLeft is what the runner asks before it calls a failed retry
	// an escalation. The count starts anew at a message from a person, so
	// one run counts here.
	if left, err := s.AttemptsLeft("linear", "ENG-1", 1); err != nil || left {
		t.Errorf("AttemptsLeft(1) after one run since the reply = %v, %v", left, err)
	}
	if left, _ := s.AttemptsLeft("linear", "ENG-1", 2); !left {
		t.Error("AttemptsLeft(2) after one run since the reply = false")
	}
}

// The approval of a plan is recorded on the ticket, queues the run that
// carries the plan out, and is gone with a new assignment.
func TestApprovePlan(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	approval := func(id string) *task.Task {
		tk := newTask(id, "ENG-1", t0.Add(time.Minute))
		tk.Cause, tk.Comment = task.CauseApproved, "keep it small"
		return tk
	}
	if err := s.Approve(approval("a0"), "lead", Limits{}); !errors.Is(err, ErrUnknown) {
		t.Errorf("approval of an unknown ticket: %v", err)
	}
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(approval("a1"), "lead", Limits{}); !errors.Is(err, ErrNoPlan) {
		t.Errorf("approval of a queued ticket: %v", err)
	}
	got, _ := s.Claim()
	if got.PlanApproved {
		t.Error("a new ticket has an approved plan")
	}
	if err := s.Finish("r1", task.Result{Outcome: task.OutcomeFinished, Signal: result.Plan, SignalMessage: "the plan", Phase: task.PhasePlan}); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.Waiting || tk.Reason != ticket.ReasonPlanApproval || tk.PlanApproved {
		t.Fatalf("after the plan: %+v", tk)
	}
	if run, _ := s.Run("r1"); run.Result.Phase != task.PhasePlan {
		t.Errorf("stored phase = %q", run.Result.Phase)
	}

	if err := s.Approve(approval("a2"), "lead", Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(approval("a3"), "lead", Limits{}); !errors.Is(err, ErrNoPlan) {
		t.Errorf("a second approval: %v", err)
	}
	got, err := s.Claim()
	if err != nil || got.ID != "a2" || !got.PlanApproved || got.ApprovedBy != "lead" || got.Cause != task.CauseApproved || got.Comment != "keep it small" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if err := s.Finish("a2", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}); err != nil {
		t.Fatal(err)
	}
	if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != ticket.InReview || !tk.PlanApproved || tk.PlanApprovedBy != "lead" {
		t.Errorf("after the work: %+v", tk)
	}
	// A follow-up keeps the approval; a new assignment does not.
	if _, err := s.FollowUp(newTask("r4", "ENG-1", t0.Add(2*time.Minute)), true, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); !got.PlanApproved {
		t.Error("a follow-up lost the approval")
	}
	if err := s.Finish("r4", task.Result{Outcome: task.OutcomeFinished, Signal: result.Done}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r5", "ENG-1", t0.Add(3*time.Minute)), Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Claim(); got.PlanApproved || got.ApprovedBy != "" {
		t.Errorf("a new assignment kept the approval: %+v", got)
	}
}

// Pauses of a tier and the throttles keep Claim from handing out a run;
// everything else goes on.
func TestHolds(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	seq := 0
	queue := func(key, tier, repo string) string {
		t.Helper()
		seq++
		tk := newTask("r"+strconv.Itoa(seq), key, now.Add(time.Duration(seq)*time.Millisecond))
		tk.Tier, tk.Repo = tier, repo
		if err := s.Enqueue(tk, Limits{}); err != nil {
			t.Fatal(err)
		}
		return tk.ID
	}
	claim := func() string {
		t.Helper()
		got, err := s.Claim()
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			return ""
		}
		return got.Key
	}
	finish := func(id string, res task.Result) {
		t.Helper()
		if res.Outcome == "" {
			res.Outcome, res.Signal = task.OutcomeFinished, result.Done
		}
		if err := s.Finish(id, res); err != nil {
			t.Fatal(err)
		}
	}

	// A paused tier: its tickets wait, the others run, in their order.
	queue("HIGH-1", "high", "")
	low1 := queue("LOW-1", "low", "")
	if err := s.SetTierPaused("high", true); err != nil {
		t.Fatal(err)
	}
	if got := claim(); got != "LOW-1" {
		t.Fatalf("claimed %q, want LOW-1: HIGH-1 is in a paused tier", got)
	}
	if got := claim(); got != "" {
		t.Fatalf("claimed %q from a paused tier", got)
	}
	if h, _ := s.Holding(); h.All() || len(h.Tiers) != 1 || h.Tiers[0] != "high" {
		t.Errorf("Holding = %+v", h)
	}
	// The policy file can pause a tier too.
	s.SetHolds(Holds{PausedTiers: []string{"high"}})
	if err := s.SetTierPaused("high", false); err != nil {
		t.Fatal(err)
	}
	if got := claim(); got != "" {
		t.Fatalf("claimed %q from a tier that the policy pauses", got)
	}
	s.SetHolds(Holds{})
	if got := claim(); got != "HIGH-1" {
		t.Fatalf("claimed %q after the pause ended, want HIGH-1", got)
	}
	finish(low1, task.Result{CostUSD: 3})
	finish("r1", task.Result{CostUSD: 4})

	// Runs per hour: two have started within the hour.
	s.SetHolds(Holds{MaxRunsPerHour: 2})
	third := queue("LOW-2", "low", "")
	if got := claim(); got != "" {
		t.Fatalf("claimed %q over the limit of runs per hour", got)
	}
	if h, _ := s.Holding(); !h.All() || len(h.Throttles) != 1 || !strings.Contains(h.Throttles[0], "max_runs_per_hour: 2 runs started in the last hour, the limit is 2") {
		t.Errorf("Holding = %+v", h)
	}
	now = now.Add(61 * time.Minute)
	if got := claim(); got != "LOW-2" {
		t.Fatalf("claimed %q an hour later, want LOW-2", got)
	}
	finish(third, task.Result{CostUSD: 5})

	// The daily spend: 5 USD today (the first two runs were an hour ago,
	// but on the same day: 12 in all).
	s.SetHolds(Holds{DailySpendUSD: 12})
	queue("LOW-3", "low", "")
	if got := claim(); got != "" {
		t.Fatalf("claimed %q over the daily spend", got)
	}
	if h, _ := s.Holding(); len(h.Throttles) != 1 || !strings.Contains(h.Throttles[0], "daily_spend_usd: the runs of today (UTC) have cost 12.00 USD, the limit is 12.00") {
		t.Errorf("Holding = %+v", h)
	}
	now = now.Add(24 * time.Hour)
	if got := claim(); got != "LOW-3" {
		t.Fatalf("claimed %q the next day, want LOW-3", got)
	}
	// It opens a pull request in its repository.
	finish("r4", task.Result{PRURL: "https://example.test/pr/1"})

	// Open pull requests per repository. LOW-3 has none recorded for a
	// repository; give the next tickets one.
	s.SetHolds(Holds{MaxOpenPRsPerRepo: 1})
	a := queue("WEB-1", "low", "web")
	if got := claim(); got != "WEB-1" {
		t.Fatalf("claimed %q, want WEB-1: no pull request is open in web", got)
	}
	finish(a, task.Result{PRURL: "https://example.test/web/pr/7"})
	queue("WEB-2", "low", "web")
	other := queue("API-1", "low", "api")
	if got := claim(); got != "API-1" {
		t.Fatalf("claimed %q, want API-1: WEB-2 would open a second pull request in web", got)
	}
	finish(other, task.Result{})
	if repos, _ := s.HeldByPRs(1); len(repos) != 1 || repos[0] != "web" {
		t.Errorf("HeldByPRs = %v", repos)
	}
	// The ticket that has the pull request works on it.
	if _, err := s.FollowUp(newTask("r9", "WEB-1", now), true, Limits{}); err != nil {
		t.Fatal(err)
	}
	if got := claim(); got != "WEB-1" {
		t.Fatalf("claimed %q, want WEB-1: it has the pull request already", got)
	}
	finish("r9", task.Result{})
	if got := claim(); got != "" {
		t.Fatalf("claimed %q while a pull request is open in web", got)
	}
	// The ticket of the pull request is closed: the next one may start.
	if _, err := s.CloseTicket("linear", "WEB-1"); err != nil {
		t.Fatal(err)
	}
	if got := claim(); got != "WEB-2" {
		t.Fatalf("claimed %q after the pull request's ticket was closed, want WEB-2", got)
	}
}

// Every pull request that a run names is tracked, until it is merged or
// closed or its ticket is done.
func TestPullRequests(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	run := func(id, key, pr string) {
		t.Helper()
		if err := s.Enqueue(newTask(id, key, t0), Limits{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(); err != nil {
			t.Fatal(err)
		}
		if err := s.Finish(id, task.Result{Outcome: task.OutcomeFinished, Signal: result.Done, PRURL: pr}); err != nil {
			t.Fatal(err)
		}
	}
	run("r1", "ENG-1", "https://example.test/pr/1")
	run("r2", "ENG-1", "https://example.test/pr/1")
	run("r3", "ENG-1", "https://example.test/pr/2")
	run("r4", "ENG-2", "https://example.test/pr/3")
	run("r5", "ENG-3", "")

	prs, err := s.PullRequests("linear", "ENG-1")
	if err != nil || len(prs) != 2 || prs[0].URL != "https://example.test/pr/1" || prs[0].State != PROpen || prs[1].URL != "https://example.test/pr/2" {
		t.Fatalf("pull requests of ENG-1 = %+v, %v", prs, err)
	}
	if open, _ := s.OpenPullRequests(); len(open) != 3 {
		t.Errorf("%d open pull requests, want 3", len(open))
	}
	if err := s.SetPullRequest("linear", "ENG-1", "https://example.test/pr/1", PRMerged, "reviewer", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPullRequest("linear", "ENG-1", "https://example.test/pr/2", PRRejected, "", "another branch"); err != nil {
		t.Fatal(err)
	}
	prs, _ = s.PullRequests("linear", "ENG-1")
	if prs[0].State != PRMerged || prs[0].ClosedBy != "reviewer" || prs[1].State != PRRejected || prs[1].Note != "another branch" {
		t.Errorf("pull requests of ENG-1 = %+v", prs)
	}
	// The pull request of a ticket that is done is not asked about again.
	if _, err := s.CloseTicket("linear", "ENG-2"); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenPullRequests(); len(open) != 0 {
		t.Errorf("open pull requests = %+v, want none", open)
	}
}

// A ticket whose run handed over a pull request waits for its checks
// before it is in review; failed checks queue it again.
func TestWaitingForChecks(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	state := func(want ticket.State) {
		t.Helper()
		if tk, _ := s.Ticket("linear", "ENG-1"); tk.State != want {
			t.Fatalf("ticket = %s, want %s", tk.State, want)
		}
	}
	done := task.Result{Outcome: task.OutcomeFinished, Signal: result.Done, AwaitChecks: true}

	// Without a pull request there is nothing to wait for.
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()
	if err := s.Finish("r1", done); err != nil {
		t.Fatal(err)
	}
	state(ticket.InReview)
	if err := s.ToReview("linear", "ENG-1"); !errors.Is(err, ErrNotChecking) {
		t.Errorf("ToReview of a ticket in review: %v", err)
	}
	if err := s.WakeForChecks(newTask("w0", "ENG-1", t0), Limits{}); !errors.Is(err, ErrNotChecking) {
		t.Errorf("WakeForChecks of a ticket in review: %v", err)
	}

	// With one, the ticket waits for the checks.
	if _, err := s.FollowUp(newTask("r2", "ENG-1", t0.Add(time.Minute)), true, Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()
	withPR := done
	withPR.PRURL = "https://example.test/pr/1"
	if err := s.Finish("r2", withPR); err != nil {
		t.Fatal(err)
	}
	state(ticket.Checking)

	// They fail: a run with the failure, which counts as an attempt.
	wake := newTask("w1", "ENG-1", t0.Add(2*time.Minute))
	wake.Cause, wake.Comment = task.CauseChecks, "Check \"test\": failure"
	if err := s.WakeForChecks(wake, Limits{MaxAttempts: 1}); !errors.Is(err, ErrAttempts) {
		t.Errorf("WakeForChecks without an attempt left: %v", err)
	}
	if err := s.WakeForChecks(wake, Limits{MaxAttempts: 5}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Claim()
	if err != nil || got.ID != "w1" || got.Cause != task.CauseChecks || got.Comment != "Check \"test\": failure" || got.PRURL != "https://example.test/pr/1" {
		t.Fatalf("claimed %+v, %v", got, err)
	}
	if err := s.Finish("w1", done); err != nil {
		t.Fatal(err)
	}
	state(ticket.Checking)

	// How far the pull request was followed.
	seen := t0.Add(3 * time.Minute)
	if err := s.NotePullRequest("linear", "ENG-1", withPR.PRURL, "sha-1", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.NotePullRequest("linear", "ENG-1", withPR.PRURL, "", seen); err != nil {
		t.Fatal(err)
	}
	if prs, _ := s.PullRequests("linear", "ENG-1"); len(prs) != 1 || prs[0].CheckedSHA != "sha-1" || !prs[0].SeenComment.Equal(seen) {
		t.Errorf("pull request = %+v", prs)
	}

	// They pass: review. A message from a person also ends the wait.
	if err := s.ToReview("linear", "ENG-1"); err != nil {
		t.Fatal(err)
	}
	state(ticket.InReview)
	if _, err := s.FollowUp(newTask("r3", "ENG-1", t0.Add(4*time.Minute)), true, Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()
	if err := s.Finish("r3", done); err != nil {
		t.Fatal(err)
	}
	state(ticket.Checking)
	if later, err := s.FollowUp(newTask("r4", "ENG-1", t0.Add(5*time.Minute)), false, Limits{}); err != nil || later {
		t.Fatalf("a comment on a ticket that waits for its checks: later %v, %v", later, err)
	}
	state(ticket.Queued)
	// A pull request that is no longer open is nothing to wait for.
	s.Claim()
	if err := s.SetPullRequest("linear", "ENG-1", withPR.PRURL, PRRejected, "", "another branch"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish("r4", done); err != nil {
		t.Fatal(err)
	}
	state(ticket.InReview)
}

// The outcome metrics per tier, for a period.
func TestOutcomes(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	now := t0
	s.now = func() time.Time { return now }
	seq := 0
	// run queues, starts and ends one run of a ticket; the clock moves on
	// by took while it runs.
	run := func(key, tier string, followUp bool, took time.Duration, res task.Result) {
		t.Helper()
		seq++
		tk := newTask("r"+strconv.Itoa(seq), key, now)
		tk.Tier = tier
		var err error
		if followUp {
			tk.Cause = task.CauseFollowUp
			_, err = s.FollowUp(tk, true, Limits{})
		} else {
			err = s.Enqueue(tk, Limits{})
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(); err != nil {
			t.Fatal(err)
		}
		now = now.Add(took)
		if res.Outcome == "" {
			res.Outcome, res.Signal = task.OutcomeFinished, result.Done
		}
		if err := s.Finish(tk.ID, res); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	pr := func(n string) string { return "https://example.test/pr/" + n }

	// LOW-1: a pull request after 10 minutes, merged as it was.
	run("LOW-1", "low", false, 10*time.Minute, task.Result{CostUSD: 1, PRURL: pr("1")})
	s.SetPullRequest("linear", "LOW-1", pr("1"), PRMerged, "reviewer", "")
	// LOW-2: two runs to its pull request (30 minutes and a pause), sent
	// back once by a person, then merged.
	run("LOW-2", "low", false, 10*time.Minute, task.Result{CostUSD: 1, Outcome: task.OutcomeFinished, Signal: result.NeedsInput})
	run("LOW-2", "low", true, 18*time.Minute, task.Result{CostUSD: 2, PRURL: pr("2")})
	run("LOW-2", "low", true, 5*time.Minute, task.Result{CostUSD: 0.5})
	s.SetPullRequest("linear", "LOW-2", pr("2"), PRMerged, "reviewer", "")
	// LOW-3: no pull request.
	run("LOW-3", "low", false, time.Minute, task.Result{CostUSD: 0.5, Outcome: task.OutcomeFailed, ExitCode: 1, Err: errors.New("exit status 1")})
	// HIGH-1: done, then assigned again: reopened.
	run("HIGH-1", "high", false, 20*time.Minute, task.Result{CostUSD: 4, PRURL: pr("3")})
	if _, err := s.CloseTicket("linear", "HIGH-1"); err != nil {
		t.Fatal(err)
	}
	run("HIGH-1", "high", false, 5*time.Minute, task.Result{CostUSD: 1})
	end := now

	got, err := s.Outcomes(t0, end)
	if err != nil || len(got) != 2 {
		t.Fatalf("Outcomes = %+v, %v", got, err)
	}
	high, low := got[0], got[1]
	if low.Tier != "low" || low.Tickets != 3 || low.Runs != 5 || low.CostUSD != 5 || low.PullRequests != 2 || low.Reworked != 1 ||
		low.Merged != 2 || low.MergedUntouched != 1 || low.Reopened != 0 {
		t.Errorf("low = %+v", low)
	}
	// 10 minutes for LOW-1; for LOW-2 from the start of its first run to
	// the end of the run with the pull request: 10 + 1 + 18.
	if len(low.TimeToPR) != 2 || low.TimeToPR[0]+low.TimeToPR[1] != 39*time.Minute {
		t.Errorf("time to pull request of low = %v", low.TimeToPR)
	}
	if high.Tier != "high" || high.Tickets != 1 || high.Runs != 2 || high.CostUSD != 5 || high.PullRequests != 1 || high.Reworked != 0 || high.Merged != 0 || high.Reopened != 1 {
		t.Errorf("high = %+v", high)
	}
	// A period before all this, and one that covers only the last run.
	if got, _ := s.Outcomes(t0.Add(-time.Hour), t0); len(got) != 0 {
		t.Errorf("outcomes of an empty period = %+v", got)
	}
	last, _ := s.Outcomes(end.Add(-6*time.Minute-30*time.Second), end)
	if len(last) != 1 || last[0].Tier != "high" || last[0].Runs != 1 || last[0].CostUSD != 1 || last[0].Reopened != 1 || last[0].PullRequests != 0 {
		t.Errorf("outcomes of the last minutes = %+v", last)
	}
}

// A backup is a whole copy of the store at one moment, which can be
// opened as a store.
func TestBackupAndVerify(t *testing.T) {
	dir := t.TempDir()
	s := open(t, filepath.Join(dir, "ochell.db"))
	t0 := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()
	if err := s.Finish("r1", task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput, SessionID: "sess-1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r2", "ENG-2", t0), Limits{}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "it's a backup.db")
	if err := s.Backup(backup); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the backup file: %v, %v; want mode 0600", info, err)
	}
	if err := s.Backup(backup); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("a backup over an existing file: %v", err)
	}
	if _, err := os.Stat(backup + ".partial"); err == nil {
		t.Error("the partial file was left behind")
	}
	// What happens after the backup is not in it.
	if err := s.Enqueue(newTask("r3", "ENG-3", t0), Limits{}); err != nil {
		t.Fatal(err)
	}

	if err := Verify(backup); err != nil {
		t.Fatalf("Verify of a backup: %v", err)
	}
	restored := open(t, backup)
	if tk, _ := restored.Ticket("linear", "ENG-1"); tk == nil || tk.State != ticket.Waiting || tk.AgentSession != "sess-1" {
		t.Errorf("ENG-1 in the backup = %+v", tk)
	}
	if tk, _ := restored.Ticket("linear", "ENG-2"); tk == nil || tk.State != ticket.Queued {
		t.Errorf("ENG-2 in the backup = %+v", tk)
	}
	if tk, _ := restored.Ticket("linear", "ENG-3"); tk != nil {
		t.Errorf("the backup has a ticket from after it was made: %+v", tk)
	}

	// What is no store of ochell.
	text := filepath.Join(dir, "notes.db")
	os.WriteFile(text, []byte("this is not a database"), 0o600)
	if err := Verify(text); err == nil {
		t.Error("a text file passed for a store")
	}
	if err := Verify(filepath.Join(dir, "missing.db")); err == nil {
		t.Error("a missing file passed for a store")
	}
	if err := Verify(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	empty := filepath.Join(dir, "empty.db")
	db, _ := sql.Open("sqlite", "file:"+empty)
	db.Exec(`CREATE TABLE other (x)`)
	db.Close()
	if err := Verify(empty); err == nil || !strings.Contains(err.Error(), "not a store of ochell") {
		t.Errorf("another database: %v", err)
	}
	newer := filepath.Join(dir, "newer.db")
	if err := s.Backup(newer); err != nil {
		t.Fatal(err)
	}
	db, _ = sql.Open("sqlite", "file:"+newer)
	db.Exec(`PRAGMA user_version = 9999`)
	db.Close()
	if err := Verify(newer); err == nil || !strings.Contains(err.Error(), "written by a newer ochell") {
		t.Errorf("a store of a newer ochell: %v", err)
	}
}

func TestMetrics(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	seq := 0
	run := func(key string, cause task.Cause, took time.Duration, res task.Result) {
		t.Helper()
		seq++
		tk := newTask("r"+strconv.Itoa(seq), key, now)
		tk.Cause = cause
		if err := s.Enqueue(tk, Limits{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(); err != nil {
			t.Fatal(err)
		}
		now = now.Add(took)
		if err := s.Finish(tk.ID, res); err != nil {
			t.Fatal(err)
		}
	}
	run("ENG-1", "", 30*time.Second, task.Result{Outcome: task.OutcomeFinished, Signal: result.Done, CostUSD: 1, Usage: agent.Usage{InputTokens: 10, OutputTokens: 20, CacheReadTokens: 30, CacheWriteTokens: 40}})
	run("ENG-2", "", 10*time.Minute, task.Result{Outcome: task.OutcomeFailed, ExitCode: 1, Err: errors.New("exit status 1"), CostUSD: 0.5})
	run("ENG-2", task.CauseRetry, 3*time.Hour, task.Result{Outcome: task.OutcomeFinished, Signal: result.NeedsInput, CostUSD: 2})
	if err := s.Enqueue(newTask("q1", "ENG-3", now), Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("q2", "ENG-4", now), Limits{}); err != nil {
		t.Fatal(err)
	}
	s.Claim()

	m, err := s.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	if m.Queued != 1 || m.Running != 1 || m.Tickets[ticket.InReview] != 1 || m.Tickets[ticket.Waiting] != 1 || m.Tickets[ticket.Queued] != 1 || m.Tickets[ticket.Running] != 1 {
		t.Errorf("gauges: %+v", m)
	}
	if m.Started["assigned"] != 3 || m.Started["retry"] != 1 || m.Ended[task.OutcomeFinished] != 2 || m.Ended[task.OutcomeFailed] != 1 {
		t.Errorf("counters: started %v, ended %v", m.Started, m.Ended)
	}
	// 30s, 10m and 3h: one run within a minute, two within 15 minutes, and
	// the long one in no bucket but the last, which is the count.
	if m.DurationCount != 3 || m.DurationSum != 30+600+10800 || m.DurationBucket[0] != 1 || m.DurationBucket[1] != 1 || m.DurationBucket[2] != 2 || m.DurationBucket[5] != 2 {
		t.Errorf("durations: count %d, sum %v, buckets %v", m.DurationCount, m.DurationSum, m.DurationBucket)
	}
	if m.CostUSD != 3.5 || m.Usage != (agent.Usage{InputTokens: 10, OutputTokens: 20, CacheReadTokens: 30, CacheWriteTokens: 40}) {
		t.Errorf("cost %v, usage %+v", m.CostUSD, m.Usage)
	}
}
