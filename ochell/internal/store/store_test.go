package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
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
		Context: "context of " + id, TrackerSession: "session-" + id, DeliveryID: "delivery-" + id, Received: received,
	}
}

func TestQueue(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

	if got, err := s.Claim(); err != nil || got != nil {
		t.Fatalf("Claim on an empty store = %v, %v", got, err)
	}
	// Queued out of order: the oldest is claimed first.
	if err := s.Enqueue(newTask("r2", "ENG-2", t0.Add(time.Second)), 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r1", "ENG-1", t0), 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(newTask("r1b", "ENG-1", t0), 0); !errors.Is(err, ErrBusy) {
		t.Errorf("second run of a queued ticket: %v, want ErrBusy", err)
	}
	if err := s.Enqueue(newTask("r3", "ENG-3", t0), 2); !errors.Is(err, ErrQueueFull) {
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
	if err := s.Enqueue(newTask("r1c", "ENG-1", t0), 0); !errors.Is(err, ErrBusy) {
		t.Errorf("second run of a running ticket: %v, want ErrBusy", err)
	}
	// A running run no longer counts against the queue limit.
	if err := s.Enqueue(newTask("r3", "ENG-3", t0.Add(2*time.Second)), 2); err != nil {
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
	if err := s.Enqueue(newTask("r4", "ENG-1", t0.Add(-time.Hour)), 0); err != nil {
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
		if err := s.Enqueue(newTask(id, "ENG-"+id, t0.Add(time.Duration(i)*time.Second)), 0); err != nil {
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
	interrupted, err := s.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if len(interrupted) != 1 || interrupted[0].ID != "run-a" || interrupted[0].TrackerSession != "session-run-a" {
		t.Fatalf("interrupted = %+v, want run-a with its tracker session", interrupted)
	}
	if tk, _ := s.Ticket("linear", "ENG-run-a"); tk == nil || tk.State != ticket.Waiting || tk.Reason != ticket.ReasonInterrupted || tk.Attempts != 1 {
		t.Errorf("ticket of the interrupted run = %+v", tk)
	}
	if again, _ := s.Recover(); len(again) != 0 {
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
	if err := s.Enqueue(newTask("run-a2", "ENG-run-a", t0), 0); err != nil {
		t.Errorf("new run of an interrupted ticket: %v", err)
	}
}

// What the adapter read from a run is stored, and the ticket's next run gets
// the session and the working directory to resume in.
func TestAgentSession(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	run := func(id string, res task.Result) *task.Task {
		t.Helper()
		if err := s.Enqueue(newTask(id, "ENG-1", t0), 0); err != nil {
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

// The store refuses a change of state that package ticket does not allow,
// and changes nothing then.
func TestStateIsEnforced(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "ochell.db"))
	if err := s.Enqueue(newTask("r1", "ENG-1", time.Now()), 0); err != nil {
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
