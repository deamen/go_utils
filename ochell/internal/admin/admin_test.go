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

	"ochell/internal/agent"
	"ochell/internal/runner"
	"ochell/internal/store"
)

type fakeControl struct {
	st      runner.Status
	reset   []string
	stopped []string
	tier    string
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

func (f *fakeControl) Cost(source, key string) (*runner.CostReport, error) {
	if key == "NOPE-1" {
		return nil, store.ErrUnknown
	}
	tk := runner.TicketCost{BudgetUSD: 5}
	tk.Source, tk.Key, tk.Tier, tk.State = "jira", "DEV-1", "low", "waiting"
	tk.Cost = store.Cost{Runs: 2, CostUSD: 1.25, Usage: agent.Usage{InputTokens: 10, OutputTokens: 20, CacheReadTokens: 30, CacheWriteTokens: 40}}
	tk.SinceResetUSD = 0.25
	rep := &runner.CostReport{Total: store.Cost{Runs: 7, CostUSD: 3.5}, Today: store.Cost{Runs: 2, CostUSD: 1.25}, Tickets: []runner.TicketCost{tk}}
	if key != "" {
		rep.Runs = []store.RunCost{
			{ID: "r1", Attempt: 1, Tier: "low", Outcome: "finished", Cost: store.Cost{CostUSD: 1, Usage: agent.Usage{InputTokens: 4}}},
			{ID: "r2", Attempt: 2, Tier: "low", Cost: store.Cost{CostUSD: 0.25, Usage: agent.Usage{InputTokens: 6}}},
		}
	}
	return rep, nil
}

func (f *fakeControl) SetTier(source, key, tier string) error {
	if tier != "low" && tier != "high" {
		return runner.ErrNoTier
	}
	if key != "DEV-1" {
		return store.ErrUnknown
	}
	f.tier = tier
	return nil
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
	if err != nil || !strings.Contains(got, "attempts and the budget of jira DEV-1 are reset") || len(c.reset) != 1 || c.reset[0] != "jira:DEV-1" {
		t.Errorf("reset = %q, %v; reset %v", got, err, c.reset)
	}
	if _, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"NOPE-1"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("reset of an unknown ticket: %v", err)
	}
	// What the tickets have cost, and one ticket with its runs.
	got, err = Call(path, "GET", "cost", nil)
	if err != nil || !strings.Contains(got, "all runs: 7 run(s), 3.5000 USD; today (UTC): 2 run(s), 1.2500 USD") ||
		!strings.Contains(got, "jira DEV-1  low   waiting  2     1.2500    0.2500 of 5.00  10     20      30          40") {
		t.Errorf("cost = %v\n%s", err, got)
	}
	got, err = Call(path, "GET", "cost", url.Values{"source": {"jira"}, "key": {"DEV-1"}})
	if err != nil || !strings.Contains(got, "jira DEV-1: tier low, waiting, 2 run(s), 1.2500 USD\nbudget: 0.2500 USD of 5.00 USD used since the last reset") ||
		!strings.Contains(got, "r2     2        low   running   0.2500    6") || !strings.Contains(got, "1.2500    10     20      30          40") {
		t.Errorf("cost of a ticket = %v\n%s", err, got)
	}
	if _, err := Call(path, "GET", "cost", url.Values{"source": {"jira"}, "key": {"NOPE-1"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("cost of an unknown ticket: %v", err)
	}
	// With a tier, the ticket is also put under it.
	got, err = Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"DEV-1"}, "tier": {"low"}})
	if err != nil || !strings.Contains(got, "attempts and the budget of jira DEV-1 are reset and its tier is now low") || c.tier != "low" || len(c.reset) != 2 {
		t.Errorf("reset with a tier = %q, %v; tier %q, reset %v", got, err, c.tier, c.reset)
	}
	// A tier that the policy does not have changes nothing.
	if _, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"DEV-1"}, "tier": {"lowest"}}); err == nil || !strings.Contains(err.Error(), `no tier "lowest"; nothing was reset`) || len(c.reset) != 2 {
		t.Errorf("reset with an unknown tier: %v; reset %v", err, c.reset)
	}
	if _, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"NOPE-1"}, "tier": {"low"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("reset with a tier of an unknown ticket: %v", err)
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
