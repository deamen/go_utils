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
	"time"

	"ochell/internal/runner"
	"ochell/internal/store"
)

type fakeControl struct {
	st      runner.Status
	reset   []string
	stopped []string
	tier    string
	// levels are the levels of autonomy by tier; nil: the policy has none.
	levels  map[string]string
	changes []store.LevelChange
}

func (f *fakeControl) Pause(tier string) error {
	if tier == "nope" {
		return runner.ErrNoTier
	}
	if tier != "" {
		f.st.Holds = []string{"tier " + tier + " is paused by a command"}
		return nil
	}
	f.st.Paused = true
	return nil
}
func (f *fakeControl) Resume(tier string) error {
	if tier == "nope" {
		return runner.ErrNoTier
	}
	f.st.Paused, f.st.Holds = false, nil
	return nil
}
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

func (f *fakeControl) Outcomes(since, until time.Time) ([]store.Outcomes, error) {
	return []store.Outcomes{{Tier: "low", Tickets: 4, Runs: 6, PullRequests: 3, Reworked: 1, Merged: 2, MergedUntouched: 1, Reopened: 1,
		TimeToPR: []time.Duration{10 * time.Minute, 30 * time.Minute, 20 * time.Minute}}}, nil
}

func (f *fakeControl) Backup(dest string) (string, error) {
	if dest == "" {
		return "", runner.ErrNoBackupDir
	}
	return dest, nil
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
	if err != nil || !strings.Contains(got, "attempts of jira DEV-1 are reset") || len(c.reset) != 1 || c.reset[0] != "jira:DEV-1" {
		t.Errorf("reset = %q, %v; reset %v", got, err, c.reset)
	}
	if _, err := Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"NOPE-1"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("reset of an unknown ticket: %v", err)
	}
	// A pause of one tier.
	got, err = Call(path, "POST", "pause", url.Values{"tier": {"high"}})
	if err != nil || !strings.Contains(got, "\nheld: tier high is paused by a command") {
		t.Errorf("pause of a tier = %q, %v", got, err)
	}
	if _, err := Call(path, "POST", "pause", url.Values{"tier": {"nope"}}); err == nil || !strings.Contains(err.Error(), `no tier "nope"`) {
		t.Errorf("pause of an unknown tier: %v", err)
	}
	if got, err = Call(path, "POST", "resume", url.Values{"tier": {"high"}}); err != nil || strings.Contains(got, "held:") {
		t.Errorf("resume of a tier = %q, %v", got, err)
	}
	// A backup of the store.
	if got, err = Call(path, "POST", "backup", url.Values{"to": {"/var/backups/ochell.db"}}); err != nil || got != "the store is backed up to /var/backups/ochell.db" {
		t.Errorf("backup = %q, %v", got, err)
	}
	if _, err := Call(path, "POST", "backup", nil); err == nil || !strings.Contains(err.Error(), "no backup directory is configured") {
		t.Errorf("backup without a directory: %v", err)
	}
	// The outcome metrics per tier, for a period.
	period := url.Values{"since": {"2026-11-01T00:00:00Z"}, "until": {"2026-11-15T00:00:00Z"}}
	got, err = Call(path, "GET", "outcomes", period)
	if err != nil || !strings.Contains(got, "outcomes per tier, 2026-11-01 00:00 to 2026-11-15 00:00 (UTC)") ||
		!strings.Contains(got, "low   4        6     3              20m0s                1 of 3 (33%)  2       1 of 2 (50%)      1") || strings.Contains(got, "COST") {
		t.Errorf("outcomes = %v\n%s", err, got)
	}
	if _, err := Call(path, "GET", "outcomes", url.Values{"since": {"yesterday"}, "until": {"2026-11-15T00:00:00Z"}}); err == nil {
		t.Error("outcomes with a since that is no time were accepted")
	}
	// ochell records no cost: there is no cost to ask for.
	if _, err := Call(path, "GET", "cost", nil); err == nil {
		t.Error("the admin channel still answers cost")
	}
	// With a tier, the ticket is also put under it.
	got, err = Call(path, "POST", "reset", url.Values{"source": {"jira"}, "key": {"DEV-1"}, "tier": {"low"}})
	if err != nil || !strings.Contains(got, "attempts of jira DEV-1 are reset and its tier is now low") || c.tier != "low" || len(c.reset) != 2 {
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

func (f *fakeControl) Autonomy() ([]runner.Class, []store.LevelChange, error) {
	if f.levels == nil {
		return nil, nil, runner.ErrNoLevels
	}
	since := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	rec := store.Record{Since: since, PullRequests: 4, SentBack: 1, Merged: 2, MergedUntouched: 2}
	return []runner.Class{{Tier: "low", Level: f.levels["low"], Since: &since, By: "the operator ada", Record: &rec}, {Tier: "high", Level: "observe", Record: &store.Record{}}}, f.changes, nil
}

func (f *fakeControl) step(tier, by, reason string, to map[string]string) (store.LevelChange, error) {
	switch {
	case f.levels == nil:
		return store.LevelChange{}, runner.ErrNoLevels
	case tier != "low":
		return store.LevelChange{}, runner.ErrNoTier
	case to[f.levels[tier]] == "":
		return store.LevelChange{}, runner.ErrTopLevel
	}
	c := store.LevelChange{Class: tier, From: f.levels[tier], To: to[f.levels[tier]], By: by, Reason: reason, At: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC),
		Record: store.Record{Since: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC), PullRequests: 4, SentBack: 1}}
	f.levels[tier] = c.To
	f.changes = append([]store.LevelChange{c}, f.changes...)
	return c, nil
}

func (f *fakeControl) Promote(tier, by, reason string) (store.LevelChange, error) {
	return f.step(tier, by, reason, map[string]string{"observe": "assisted", "assisted": "autonomous"})
}

func (f *fakeControl) Demote(tier, by, reason string) (store.LevelChange, error) {
	return f.step(tier, by, reason, map[string]string{"autonomous": "assisted", "assisted": "observe"})
}

func (f *fakeControl) Flag(source, key, by, reason string) (store.LevelChange, error) {
	if key == "NOPE-1" {
		return store.LevelChange{}, store.ErrUnknown
	}
	c, err := f.step("low", by, "a guardrail flagged the run: "+reason, map[string]string{"autonomous": "assisted", "assisted": "observe", "observe": "observe"})
	if err == nil {
		f.changes[0].Source, f.changes[0].Key, f.changes[0].Run = source, key, "run-1"
	}
	return c, err
}

// The commands of graduated autonomy: the levels, a promotion, a demotion
// and a guardrail's flag.
func TestAutonomyCommands(t *testing.T) {
	path := socketPath(t)
	c := &fakeControl{}
	s, err := Listen(path, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// A policy without levels has nothing to show or to change.
	for _, cmd := range [][2]string{{"GET", "autonomy"}, {"POST", "promote"}, {"POST", "demote"}} {
		if _, err := Call(path, cmd[0], cmd[1], url.Values{"tier": {"low"}}); err == nil || !strings.Contains(err.Error(), "no autonomy section") {
			t.Errorf("%s without levels: %v", cmd[1], err)
		}
	}
	c.levels = map[string]string{"low": "assisted"}

	got, err := Call(path, "POST", "promote", url.Values{"tier": {"low"}, "user": {"ada"}, "reason": {"four weeks\nwithout a problem"}})
	if err != nil || !strings.Contains(got, "the tier low is now at the level autonomous (it was at assisted)") ||
		!strings.Contains(got, "recorded: by the operator ada, with 4 ticket(s) with a pull request since 2026-11-02 10:00, sent back: 1 of 4 (25%)") {
		t.Errorf("promote = %q, %v", got, err)
	}
	// The reason is kept as one line.
	if c.changes[0].Reason != "four weeks without a problem" {
		t.Errorf("recorded reason = %q", c.changes[0].Reason)
	}
	for _, bad := range []url.Values{{"tier": {"low"}}, {"tier": {"nope"}}} {
		if _, err := Call(path, "POST", "promote", bad); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("promote %v: %v", bad, err)
		}
	}
	if got, err = Call(path, "POST", "demote", url.Values{"tier": {"low"}}); err != nil || !strings.Contains(got, "now at the level assisted (it was at autonomous)") || !strings.Contains(got, "by an operator") {
		t.Errorf("demote = %q, %v", got, err)
	}

	// A flag needs a reason and a ticket that ochell knows.
	if _, err := Call(path, "POST", "flag", url.Values{"source": {"jira"}, "key": {"DEV-1"}}); err == nil || !strings.Contains(err.Error(), "needs a reason") {
		t.Errorf("flag without a reason: %v", err)
	}
	if _, err := Call(path, "POST", "flag", url.Values{"source": {"jira"}, "key": {"NOPE-1"}, "reason": {"x"}}); err == nil || !strings.Contains(err.Error(), "knows no jira ticket NOPE-1") {
		t.Errorf("flag of an unknown ticket: %v", err)
	}
	got, err = Call(path, "POST", "flag", url.Values{"source": {"jira"}, "key": {"DEV-1"}, "reason": {"CI failed three times"}, "user": {"ci-watch"}})
	if err != nil || !strings.Contains(got, "the flag on jira DEV-1 is recorded; its tier low is now at the level observe (it was at assisted)") {
		t.Errorf("flag = %q, %v", got, err)
	}
	if got, err = Call(path, "POST", "flag", url.Values{"source": {"jira"}, "key": {"DEV-1"}, "reason": {"again"}}); err != nil || !strings.Contains(got, "at the lowest level already (observe)") {
		t.Errorf("flag at the lowest level = %q, %v", got, err)
	}

	got, err = Call(path, "GET", "autonomy", nil)
	for _, want := range []string{
		"low   observe  2026-11-16 09:00  the operator ada               4              1 of 4 (25%)  2       2 of 2 (100%)",
		"high  observe  -                 the policy file (start_level)  0              -             0       -",
		"2026-11-16 10:00  low: stays at observe, by an operator; flagged: jira DEV-1, run run-1; a guardrail flagged the run: again [",
		"2026-11-16 10:00  low: assisted -> observe, by the operator ci-watch; flagged: jira DEV-1, run run-1; a guardrail flagged the run: CI failed three times [",
		"2026-11-16 10:00  low: assisted -> autonomous, by the operator ada; four weeks without a problem [4 ticket(s) with a pull request since 2026-11-02 10:00, sent back: 1 of 4 (25%), merged untouched: -]",
	} {
		if err != nil || !strings.Contains(got, want) {
			t.Errorf("autonomy lacks %q (%v):\n%s", want, err, got)
		}
	}

	// The status names the level of each tier.
	since := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	c.st.Autonomy = []runner.Class{{Tier: "low", Level: "observe", Since: &since, By: runner.ByOchell}, {Tier: "high", Level: "assisted"}}
	if got, err = Call(path, "GET", "status", nil); err != nil ||
		!strings.Contains(got, "\nautonomy: the tier low is at the level observe since 2026-11-16 09:00 UTC, by ochell itself\nautonomy: the tier high is at the level assisted") {
		t.Errorf("status = %q, %v", got, err)
	}
}
