package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ochell/internal/auth"
	"ochell/internal/policy"
	"ochell/internal/store"
	"ochell/internal/tracker"
)

// jiraAssign sends the webhook of a Jira ticket that was created for the
// bot; fields is more JSON for the fields of the issue, such as
// `,"priority":{"name":"High"}`.
func jiraAssign(s *Server, key, fields string) *httptest.ResponseRecorder {
	body := `{"timestamp":` + strconv.FormatInt(time.Now().UnixMilli(), 10) + `,"webhookEvent":"jira:issue_created","user":{"accountId":"557058:anna"},` +
		`"issue":{"key":"` + key + `","fields":{"summary":"Summary of ` + key + `","assignee":{"accountId":"` + bot + `"}` + fields + `}}}`
	return do(s, "/webhooks/jira", body, map[string]string{"X-Hub-Signature": "sha256=" + auth.SignHex("jira-secret", []byte(body))})
}

// waitComments waits until a ticket has n comments, and returns them.
func waitComments(jira *tracker.Fake, key string, n int) []string {
	deadline := time.Now().Add(5 * time.Second)
	for len(jira.Comments(key)) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return jira.Comments(key)
}

// The gates of the policy hold a ticket until its tracker says that it
// carries the required labels, from a person, and that nothing blocks it.
func TestSchedulingGates(t *testing.T) {
	pol, err := policy.Parse([]byte("tiers: [{name: normal}]\ndefault_tier: normal\nscheduling: {required_labels: [agent-ready], blocked_by: wait}"))
	if err != nil {
		t.Fatal(err)
	}
	ready := tracker.Label{Name: "Agent-Ready", By: []string{"557058:anna"}}
	jira := &tracker.Fake{Schedulings: map[string]tracker.Scheduling{
		"DEV-1": {PriorityName: "High", Labels: []tracker.Label{ready}},
		"DEV-2": {Labels: []tracker.Label{{Name: "other", By: []string{"557058:anna"}}}},
		// The label is there, but the bot account put it there: once as
		// the tracker's client says, once by the configured account id.
		"DEV-3": {Labels: []tracker.Label{{Name: "agent-ready", Bot: true}}},
		"DEV-4": {Labels: []tracker.Label{{Name: "agent-ready", By: []string{bot}}}},
		"DEV-5": {Labels: []tracker.Label{ready}, BlockedBy: []string{"DEV-9", "DEV-8"}},
		"DEV-6": {BlockedBy: []string{"DEV-9"}},
		// DEV-7 is not in the tracker at all.
	}}
	fr := &fakeRunner{}
	s := newServer(t, testConfig(), fr)
	s.UsePolicy(pol)
	s.UseJira(jira)
	ctx := context.Background()

	keys := []string{"DEV-1", "DEV-2", "DEV-3", "DEV-4", "DEV-5", "DEV-6", "DEV-7"}
	for _, key := range keys {
		// What the payload says about labels opens no gate.
		if w := jiraAssign(s, key, `,"labels":["agent-ready"],"priority":{"name":"Low"}`); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
			t.Fatalf("%s: %d %s", key, w.Code, w.Body)
		}
		// Every ticket is queued, and none may start before it was looked at.
		if hold, held := fr.hold("jira", key); !held || hold != store.HoldPending {
			t.Fatalf("%s: hold = %q, %v; want it pending", key, hold, held)
		}
	}
	s.CheckHeld(ctx, false)
	const fromPerson = " from a person (a label that the bot account added does not count)"
	want := map[string]string{
		"DEV-1": "",
		"DEV-2": "it needs the label agent-ready",
		"DEV-3": "it needs the label agent-ready" + fromPerson,
		"DEV-4": "it needs the label agent-ready" + fromPerson,
		"DEV-5": "it is blocked by DEV-8, DEV-9, which is not done",
		"DEV-6": "it needs the label agent-ready; it is blocked by DEV-9, which is not done",
		"DEV-7": "it needs the label agent-ready",
	}
	check := func(when string) {
		t.Helper()
		for _, key := range keys {
			if hold, _ := fr.hold("jira", key); hold != want[key] {
				t.Errorf("%s: %s: hold = %q, want %q", when, key, hold, want[key])
			}
		}
	}
	check("first look")
	// The tracker's priority takes the place of the payload's.
	if got := fr.priorities["jira:DEV-1"]; got != 2 {
		t.Errorf("priority of DEV-1 = %d, want 2 (High)", got)
	}
	// A held ticket is told once why it waits; one that starts is not.
	if got := waitComments(jira, "DEV-5", 1); len(got) != 1 || !strings.Contains(got[0], "has not started work on DEV-5 yet: it is blocked by DEV-8, DEV-9, which is not done. The work starts by itself once that has changed.") {
		t.Errorf("comments on DEV-5 = %q", got)
	}
	if got := jira.Comments("DEV-1"); len(got) != 0 {
		t.Errorf("comments on DEV-1 = %q", got)
	}

	// One blocker is done, and a person labels DEV-2. A look at the new
	// tickets only does not ask about these; a look at the ticket that
	// changed asks about that one, and a look at all about both.
	jira.Set(func(f *tracker.Fake) {
		f.Schedulings["DEV-5"] = tracker.Scheduling{Labels: []tracker.Label{ready}, BlockedBy: []string{"DEV-9"}}
		f.Schedulings["DEV-2"] = tracker.Scheduling{Labels: []tracker.Label{ready}}
	})
	s.CheckHeld(ctx, false)
	check("a look at the new tickets")
	s.checkHeld(ctx, look{tickets: map[string]bool{"jira:DEV-2": true}})
	want["DEV-2"] = ""
	check("a look at the ticket that changed")
	s.CheckHeld(ctx, true)
	want["DEV-5"] = "it is blocked by DEV-9, which is not done"
	check("second look")
	// The reason changed, and the ticket is not told again.
	time.Sleep(50 * time.Millisecond)
	if got := jira.Comments("DEV-5"); len(got) != 1 {
		t.Errorf("comments on DEV-5 after the second look = %q", got)
	}
	jira.Set(func(f *tracker.Fake) { f.Schedulings["DEV-5"] = tracker.Scheduling{Labels: []tracker.Label{ready}} })
	s.CheckHeld(ctx, true)
	want["DEV-5"] = ""
	check("third look")

	// A tracker that does not answer: the gate stays shut.
	jira.Set(func(f *tracker.Fake) { f.Err = errors.New("HTTP 503") })
	if w := jiraAssign(s, "DEV-10", ""); w.Code != 200 {
		t.Fatalf("DEV-10: %d %s", w.Code, w.Body)
	}
	s.CheckHeld(ctx, false)
	if hold, _ := fr.hold("jira", "DEV-10"); hold != holdNoAnswer {
		t.Errorf("DEV-10 with a failing tracker: hold = %q", hold)
	}
	jira.Set(func(f *tracker.Fake) {
		f.Err, f.Schedulings["DEV-10"] = nil, tracker.Scheduling{Labels: []tracker.Label{ready}}
	})
	s.CheckHeld(ctx, true)
	if hold, held := fr.hold("jira", "DEV-10"); held {
		t.Errorf("DEV-10 after the tracker answered: hold = %q", hold)
	}
}

// Without a gate the tracker is asked only for a priority that the source
// did not name, and a tracker that does not answer holds nothing.
func TestSchedulingWithoutGates(t *testing.T) {
	jira := &tracker.Fake{Schedulings: map[string]tracker.Scheduling{
		"DEV-2": {PriorityName: "Highest", BlockedBy: []string{"DEV-9"}},
	}}
	fr := &fakeRunner{}
	s := newServer(t, testConfig(), fr)
	s.UseJira(jira)
	ctx := context.Background()
	last := func() (priority int, hold string) {
		tk := fr.tasks[len(fr.tasks)-1]
		return tk.Priority, tk.Hold
	}

	// The payload names the priority: nothing to ask.
	jiraAssign(s, "DEV-1", `,"priority":{"name":"Low"}`)
	if p, hold := last(); p != 4 || hold != "" {
		t.Errorf("DEV-1: priority %d, hold %q; want 4 and none", p, hold)
	}
	// It does not: the ticket waits for the tracker's answer, and no
	// longer. What blocks it does not matter without the rule.
	jiraAssign(s, "DEV-2", "")
	if p, hold := last(); p != 0 || hold != store.HoldPending {
		t.Errorf("DEV-2: priority %d, hold %q; want it pending", p, hold)
	}
	s.CheckHeld(ctx, false)
	if _, held := fr.hold("jira", "DEV-2"); held || fr.priorities["jira:DEV-2"] != 1 {
		t.Errorf("DEV-2 after the look: held %v, priority %d", held, fr.priorities["jira:DEV-2"])
	}
	// The tracker does not answer: the ticket starts without a priority.
	jira.Set(func(f *tracker.Fake) { f.Err = errors.New("HTTP 503") })
	jiraAssign(s, "DEV-3", "")
	s.CheckHeld(ctx, false)
	if hold, held := fr.hold("jira", "DEV-3"); held {
		t.Errorf("DEV-3 with a failing tracker: hold = %q", hold)
	}
	time.Sleep(50 * time.Millisecond)
	if got := jira.Comments("DEV-3"); len(got) != 0 {
		t.Errorf("comments on DEV-3 = %q", got)
	}
	// No access to the tracker: nothing is held to begin with.
	s.UseJira(nil)
	jiraAssign(s, "DEV-4", "")
	if _, hold := last(); hold != "" {
		t.Errorf("DEV-4 without the Jira API: hold %q", hold)
	}
	// A ticket that was held under another configuration is let go.
	fr.holds = map[string]string{"jira:DEV-5": holdNoAnswer}
	s.CheckHeld(ctx, true)
	if hold, held := fr.hold("jira", "DEV-5"); held {
		t.Errorf("DEV-5 without gates and without the API: hold = %q", hold)
	}
}

// A policy with a gate needs a tracker that can be asked, for every source
// that is turned on.
func TestCheckScheduling(t *testing.T) {
	gated, err := policy.Parse([]byte("tiers: [{name: normal}]\ndefault_tier: normal\nscheduling: {blocked_by: wait}"))
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(t, testConfig(), &fakeRunner{})
	if err := s.CheckScheduling(); err != nil {
		t.Errorf("without a gate: %v", err)
	}
	s.UsePolicy(gated)
	err = s.CheckScheduling()
	if err == nil || !strings.Contains(err.Error(), "the Jira sources need sources.jira_api") || !strings.Contains(err.Error(), "sources.linear needs the app") {
		t.Errorf("with a gate and no tracker: %v", err)
	}
	cfg := testConfig()
	cfg.Sources.Linear.Enabled = false
	s = newServer(t, cfg, &fakeRunner{})
	s.UsePolicy(gated)
	s.UseJira(&tracker.Fake{})
	if err := s.CheckScheduling(); err != nil {
		t.Errorf("with a gate and the Jira API: %v", err)
	}
}

// An update records the priority that the ticket has now and makes ochell
// look at that ticket again; a close makes it look at every held ticket.
func TestUpdatesReachScheduling(t *testing.T) {
	fr := &fakeRunner{tiers: map[string]string{"DEV-1": "normal", "ENG-1": "normal"}}
	s := newServer(t, testConfig(), fr)
	// kicked returns what the loop was told to look at, "" for nothing.
	kicked := func() string {
		select {
		case <-s.gateKick:
		default:
			return ""
		}
		at := s.gateNext
		s.gateNext = look{}
		if at.all {
			return "all"
		}
		var keys []string
		for k := range at.tickets {
			keys = append(keys, k)
		}
		return strings.Join(keys, ",")
	}
	stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	body := `{"timestamp":` + stamp + `,"webhookEvent":"jira:issue_updated","user":{"accountId":"557058:anna"},"issue":{"key":"DEV-1","fields":{"priority":{"name":"Highest"}}},"changelog":{"items":[{"field":"priority"}]}}`
	if w := do(s, "/webhooks/jira", body, map[string]string{"X-Hub-Signature": "sha256=" + auth.SignHex("jira-secret", []byte(body))}); w.Code != 200 {
		t.Fatalf("jira update: %d %s", w.Code, w.Body)
	}
	if got, at := fr.priorities["jira:DEV-1"], kicked(); got != 1 || at != "jira:DEV-1" {
		t.Errorf("after the Jira update: priority %d, looking at %q", got, at)
	}
	body = `{"type":"Issue","action":"update","data":{"identifier":"ENG-1","priority":3},"updatedFrom":{"priority":0},"webhookTimestamp":` + stamp + `}`
	if w := do(s, "/webhooks/linear", body, map[string]string{"Linear-Signature": auth.SignHex("linear-secret", []byte(body))}); w.Code != 200 {
		t.Fatalf("linear update: %d %s", w.Code, w.Body)
	}
	if got, at := fr.priorities["linear:ENG-1"], kicked(); got != 3 || at != "linear:ENG-1" {
		t.Errorf("after the Linear update: priority %d, looking at %q", got, at)
	}
	// What the bot account changes is not looked at.
	body = `{"timestamp":` + stamp + `,"webhookEvent":"jira:issue_updated","user":{"accountId":"` + bot + `"},"issue":{"key":"DEV-1","fields":{"priority":{"name":"Lowest"}}},"changelog":{"items":[{"field":"priority"}]}}`
	do(s, "/webhooks/jira", body, map[string]string{"X-Hub-Signature": "sha256=" + auth.SignHex("jira-secret", []byte(body))})
	if got, at := fr.priorities["jira:DEV-1"], kicked(); got != 1 || at != "" {
		t.Errorf("after an update by the bot: priority %d, looking at %q", got, at)
	}
	// A ticket that ochell does not know was closed: it may have blocked
	// one that it holds.
	body = `{"timestamp":` + stamp + `,"webhookEvent":"jira:issue_updated","user":{"accountId":"557058:anna"},"issue":{"key":"OTHER-1"},"changelog":{"items":[{"field":"resolution","to":"10000"}]}}`
	do(s, "/webhooks/jira", body, map[string]string{"X-Hub-Signature": "sha256=" + auth.SignHex("jira-secret", []byte(body))})
	if at := kicked(); at != "all" {
		t.Errorf("after a ticket was closed ochell looks at %q, want at every held ticket", at)
	}
}

// The poller hands on the priority that the list of the bot's tickets has.
func TestPollPassesThePriorityOn(t *testing.T) {
	fr := &fakeRunner{}
	s := newServer(t, testConfig(), fr)
	jira := &tracker.Fake{
		Issues:    []tracker.Issue{{Key: "DEV-1", PriorityName: "Low"}, {Key: "DEV-2"}},
		Assigners: map[string][]string{"DEV-1": {"557058:anna"}, "DEV-2": {"557058:anna"}},
	}
	s.UseJira(jira)
	s.Poll(context.Background())
	if len(fr.tasks) != 2 {
		t.Fatalf("started %d tickets, want 2", len(fr.tasks))
	}
	if tk := fr.tasks[0]; tk.Priority != 4 || tk.Hold != "" {
		t.Errorf("DEV-1: priority %d, hold %q", tk.Priority, tk.Hold)
	}
	if tk := fr.tasks[1]; tk.Priority != 0 || tk.Hold != store.HoldPending {
		t.Errorf("DEV-2: priority %d, hold %q", tk.Priority, tk.Hold)
	}
}
