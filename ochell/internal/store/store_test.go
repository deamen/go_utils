package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ochell/internal/task"
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
	if tk.State != StateEnded || tk.Attempts != 1 || tk.Workspace != "/work/ENG-1" || tk.Title != "Title of ENG-1" {
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
	if tk, _ := s.Ticket("linear", "ENG-run-a"); tk == nil || tk.State != StateInterrupted || tk.Attempts != 1 {
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
