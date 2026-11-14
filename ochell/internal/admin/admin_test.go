package admin

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ochell/internal/runner"
	"ochell/internal/store"
)

type fakeControl struct {
	st      runner.Status
	reset   []string
	stopped []string
}

func (f *fakeControl) Pause() error                   { f.st.Paused = true; return nil }
func (f *fakeControl) Resume() error                  { f.st.Paused = false; return nil }
func (f *fakeControl) Status() (runner.Status, error) { return f.st, nil }
func (f *fakeControl) Stop(source, key, by string) (runner.Stopped, error) {
	f.stopped = append(f.stopped, source+":"+key+" by "+by)
	switch key {
	case "NOPE-1":
		return 0, store.ErrUnknown
	case "DONE-1":
		return 0, store.ErrReleased
	case "QUEUED-1":
		return runner.StoppedQueued, nil
	case "WAITS-1":
		return runner.Released, nil
	}
	return runner.StoppedRun, nil
}

func (f *fakeControl) ResetAttempts(source, key string) error {
	if key == "NOPE-1" {
		return store.ErrUnknown
	}
	f.reset = append(f.reset, source+":"+key)
	return nil
}

// socketPath returns a short path: a unix socket path may only be about a
// hundred bytes long, and a test's temporary directory can be longer.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ochell-adm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

func TestCommands(t *testing.T) {
	path := socketPath(t)
	c := &fakeControl{st: runner.Status{Queued: 2, Running: 1}}
	s, err := Listen(path, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	for _, step := range []struct{ method, command, want string }{
		{"GET", "status", "running; 2 queued, 1 running"},
		{"POST", "pause", "paused: no new run starts; 2 queued, 1 running"},
		{"GET", "status", "paused: no new run starts; 2 queued, 1 running"},
		{"POST", "resume", "running; 2 queued, 1 running"},
	} {
		got, err := Call(path, step.method, step.command, nil)
		if err != nil || got != step.want {
			t.Errorf("%s %s = %q, %v; want %q", step.method, step.command, got, err, step.want)
		}
	}
	if got, err := Call(path, "GET", "status", url.Values{"format": {"json"}}); err != nil || got != `{"paused":false,"queued":2,"running":1}` {
		t.Errorf("status as JSON = %q, %v", got, err)
	}

	got, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"DEV-1"}})
	if err != nil || !strings.Contains(got, "attempts of jira DEV-1 are reset") || len(c.reset) != 1 || c.reset[0] != "jira:DEV-1" {
		t.Errorf("reset = %q, %v; reset %v", got, err, c.reset)
	}
	if _, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"NOPE-1"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("reset of an unknown ticket: %v", err)
	}
	// stop: what was done, and who asked, for the note on the ticket.
	for key, want := range map[string]string{
		"DEV-1":    "the agent of jira DEV-1 is being stopped",
		"QUEUED-1": "the queued run of jira QUEUED-1 was removed",
		"WAITS-1":  "jira WAITS-1 had no run; the ticket is released",
	} {
		got, err := Call(path, "POST", "stop", url.Values{"source": {"jira"}, "key": {key}, "user": {"anna"}})
		if err != nil || !strings.Contains(got, want) || !strings.Contains(got, "not started again until it is assigned again") {
			t.Errorf("stop %s = %q, %v; want %q", key, got, err, want)
		}
	}
	if want := `jira:DEV-1 by the operator anna, with "ochell stop" on the host`; !slices.Contains(c.stopped, want) {
		t.Errorf("stops = %q, want %q", c.stopped, want)
	}
	if _, err := Call(path, "POST", "stop", url.Values{"source": {"jira"}, "key": {"NOPE-1"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("stop of an unknown ticket: %v", err)
	}
	if _, err := Call(path, "POST", "stop", url.Values{"source": {"jira"}, "key": {"DONE-1"}}); err == nil || !strings.Contains(err.Error(), "nothing to stop") {
		t.Errorf("stop of a ticket that is done: %v", err)
	}
	if n := len(c.stopped); n != 5 || !strings.Contains(c.stopped[n-1], "by an operator, with") {
		t.Errorf("stops = %q", c.stopped)
	}
	if _, err := Call(path, "GET", "stop", url.Values{"source": {"jira"}, "key": {"DEV-1"}}); err == nil || len(c.stopped) != 5 {
		t.Errorf("GET stop: %v, %d stops", err, len(c.stopped))
	}
	// A command is not triggered by a plain GET.
	if _, err := Call(path, "GET", "pause", nil); err == nil || c.st.Paused {
		t.Errorf("GET pause: %v, paused %v", err, c.st.Paused)
	}
}

func TestSocketLifecycle(t *testing.T) {
	path := socketPath(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &fakeControl{}
	s, err := Listen(path, c, log)
	if err != nil {
		t.Fatal(err)
	}
	// A second ochell must not take over a socket that is in use.
	if _, err := Listen(path, c, log); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("second Listen on a live socket: %v", err)
	}
	s.Close()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket was not removed on Close: %v", err)
	}
	if _, err := Call(path, "GET", "status", nil); err == nil || !strings.Contains(err.Error(), "cannot reach ochell") {
		t.Errorf("Call without a server: %v", err)
	}
	if _, err := Call("", "GET", "status", nil); err == nil {
		t.Error("Call without a socket path must fail")
	}

	// A socket file left behind by a crash is replaced.
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the stale socket is not there: %v", err)
	}
	s, err = Listen(path, c, log)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	s.Close()

	// Any other file at that path is not touched.
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, c, log); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("Listen over a regular file: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "precious" {
		t.Error("a regular file at the socket path was changed")
	}
}
