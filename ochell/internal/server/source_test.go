package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ochell/internal/auth"
	"ochell/internal/config"
	"ochell/internal/github"
	"ochell/internal/github/githubtest"
	"ochell/internal/policy"
	"ochell/internal/result"
	"ochell/internal/store"
	"ochell/internal/task"
	"ochell/internal/ticket"
)

const (
	ghSecret = "github-secret"
	ghBot    = githubtest.Bot
)

// githubConfig is testConfig with the GitHub source, which asks gh when
// it is not nil.
func githubConfig(gh *githubtest.Server) *config.Config {
	cfg := testConfig()
	cfg.GitHub.BotLogin = ghBot
	cfg.Sources.GitHub = config.GitHubSource{Enabled: true, Path: "/webhooks/github", Secret: ghSecret,
		Repos: []config.GitHubRepo{{Repo: "acme/shop"}, {Repo: "acme/api", Project: "API"}}}
	if gh != nil {
		cfg.GitHub.APIURL = gh.URL
		cfg.Sources.GitHub.Token = githubtest.IssuesToken
	}
	return cfg
}

// ghEvent is a GitHub webhook about the issue or pull request number of
// acme/shop.
type ghEvent struct {
	event, action string
	number        int
	// sender did it; assignee is who an assignment is about.
	sender, assignee string
	// author opened the issue; empty: alice.
	author string
	// unassigned: the issue is not the bot's.
	unassigned bool
	labels     []string
	comment    string
	repo       string
}

func (e ghEvent) send(s *Server) *httptest.ResponseRecorder {
	if e.sender == "" {
		e.sender = "alice"
	}
	if e.author == "" {
		e.author = "alice"
	}
	if e.repo == "" {
		e.repo = "acme/shop"
	}
	kind := "issues"
	if e.event == "pull_request" {
		kind = "pull"
	}
	labels := []map[string]string{}
	for _, l := range e.labels {
		labels = append(labels, map[string]string{"name": l})
	}
	is := map[string]any{"number": e.number, "title": fmt.Sprintf("Title of %d", e.number), "html_url": fmt.Sprintf("https://github.com/%s/%s/%d", e.repo, kind, e.number),
		"user": map[string]string{"login": e.author}, "labels": labels}
	if !e.unassigned {
		is["assignees"] = []map[string]string{{"login": ghBot}}
	}
	p := map[string]any{"action": e.action, "repository": map[string]string{"full_name": e.repo}, "sender": map[string]string{"login": e.sender}}
	if e.event == "pull_request" {
		p["pull_request"] = is
	} else {
		p["issue"] = is
	}
	if e.assignee != "" {
		p["assignee"] = map[string]string{"login": e.assignee}
	}
	if e.event == "issue_comment" {
		p["comment"] = map[string]any{"body": e.comment, "user": map[string]string{"login": e.sender}}
	}
	body, _ := json.Marshal(p)
	return do(s, "/webhooks/github", string(body), map[string]string{
		"X-GitHub-Event": e.event, "X-GitHub-Delivery": "d-" + time.Now().Format(time.RFC3339Nano),
		"X-Hub-Signature-256": "sha256=" + auth.SignHex(ghSecret, body)})
}

func assigned(n int) ghEvent {
	return ghEvent{event: "issues", action: "assigned", number: n, assignee: ghBot}
}

// waitIssueComments waits until an issue of acme/shop has n comments.
func waitIssueComments(gh *githubtest.Server, number, n int) []githubtest.IssueComment {
	deadline := time.Now().Add(5 * time.Second)
	for len(gh.IssueComments("acme", "shop", number)) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return gh.IssueComments("acme", "shop", number)
}

// An issue that is assigned to the bot starts a run, as a Jira ticket does.
func TestGitHubIssueAssigned(t *testing.T) {
	fr := &fakeRunner{}
	s := newServer(t, githubConfig(nil), fr)

	body := readFile(t, "github-issue-assigned.json")
	hdr := map[string]string{"X-GitHub-Event": "issues", "X-GitHub-Delivery": "d-1", "X-Hub-Signature-256": "sha256=" + auth.SignHex(ghSecret, []byte(body))}
	w := do(s, "/webhooks/github", body, hdr)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Fatalf("assigned: %d %s", w.Code, w.Body)
	}
	if len(fr.tasks) != 1 {
		t.Fatalf("tasks = %d", len(fr.tasks))
	}
	tk := fr.tasks[0]
	if tk.Source != "github" || tk.Key != "shop-12" || tk.Title != "The login page shows a blank screen" || tk.URL != "https://github.com/acme/shop/issues/12" ||
		tk.Repo != "https://github.com/acme/shop.git" || tk.Actor != "alice" || tk.Tier != policy.Builtin().DefaultTier || tk.DeliveryID != "d-1" ||
		tk.Hold != "" || !strings.Contains(tk.Context, "issue #12 of the GitHub repository acme/shop") || !strings.Contains(tk.ID, "github-shop-12") {
		t.Errorf("task = %+v", tk)
	}

	// The same body again, under another delivery id: GitHub's payload has
	// no time in it, so the body is what a replay is known by.
	hdr["X-GitHub-Delivery"] = "d-2"
	if w := do(s, "/webhooks/github", body, hdr); w.Code != 200 || !strings.Contains(w.Body.String(), "duplicate delivery") {
		t.Errorf("replay: %d %s", w.Code, w.Body)
	}
	// A body that the secret did not sign.
	hdr["X-Hub-Signature-256"] = "sha256=" + auth.SignHex("another", []byte(body))
	if w := do(s, "/webhooks/github", body, hdr); w.Code != 401 {
		t.Errorf("bad signature: %d %s", w.Code, w.Body)
	}
	delete(hdr, "X-Hub-Signature-256")
	hdr["X-Hub-Signature"] = "sha256=" + auth.SignHex(ghSecret, []byte(body))
	if w := do(s, "/webhooks/github", body, hdr); w.Code != 401 {
		t.Errorf("the signature in the header of Jira: %d %s", w.Code, w.Body)
	}
	if len(fr.tasks) != 1 {
		t.Errorf("tasks = %d, want 1", len(fr.tasks))
	}
}

func TestGitHubAssignmentIsRefused(t *testing.T) {
	cfg := githubConfig(nil)
	cfg.Sources.GitHub.AllowedAssigners = []string{"Alice"}
	fr := &fakeRunner{pulls: []*store.PullRequest{{Source: "jira", Key: "DEV-1", URL: "https://github.com/acme/shop/pull/31/files", State: store.PROpen}}}
	s := newServer(t, cfg, fr)
	for name, c := range map[string]struct {
		ev   ghEvent
		code int
		want string
	}{
		"by the bot itself":         {ghEvent{event: "issues", action: "assigned", number: 1, assignee: ghBot, sender: ghBot}, 403, "cannot assign work to itself"},
		"by the bot, in upper case": {ghEvent{event: "issues", action: "assigned", number: 1, assignee: ghBot, sender: strings.ToUpper(ghBot)}, 403, "cannot assign work to itself"},
		"by someone not allowed":    {ghEvent{event: "issues", action: "assigned", number: 1, assignee: ghBot, sender: "mallory"}, 403, "not allowed to assign work"},
		"another repository":        {ghEvent{event: "issues", action: "assigned", number: 1, assignee: ghBot, repo: "acme/secrets"}, 200, "ignored: the repository acme/secrets is not one of sources.github.repos"},
		"to someone else":           {ghEvent{event: "issues", action: "assigned", number: 1, assignee: "bob"}, 200, "ignored"},
		"the bot's own pull request": {ghEvent{event: "pull_request", action: "assigned", number: 30, assignee: ghBot, author: ghBot}, 200,
			"ignored: a pull request that the digital employee opened"},
		// Opened under another account, and named by a ticket as its work.
		"the pull request of a ticket": {ghEvent{event: "pull_request", action: "assigned", number: 31, assignee: ghBot}, 200, "ignored: the pull request is the work of a ticket"},
		"a review request":             {ghEvent{event: "pull_request", action: "review_requested", number: 32}, 200, "ignored"},
	} {
		if w := c.ev.send(s); w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if len(fr.tasks) != 0 || len(fr.states) != 0 {
		t.Errorf("tasks = %d, states = %v; want nothing started or recorded", len(fr.tasks), fr.states)
	}
	// What is allowed: the person on the list, and a pull request of a
	// person.
	if w := assigned(2).send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Errorf("allowed: %d %s", w.Code, w.Body)
	}
	if w := (ghEvent{event: "pull_request", action: "assigned", number: 33, assignee: ghBot}).send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Errorf("a pull request of a person: %d %s", w.Code, w.Body)
	}
	if len(fr.tasks) != 2 || fr.tasks[1].Key != "shop-33" {
		t.Errorf("tasks = %d", len(fr.tasks))
	}
}

// The repository of a GitHub ticket is its own, unless the repos setting
// names another; it is never held for want of a mapping.
func TestGitHubRepoMapping(t *testing.T) {
	cfg := githubConfig(nil)
	cfg.Repos = []config.Repo{{Source: "jira", Project: "DEV", Repo: "git@example.com:org/backend.git"},
		{Source: "github", Project: "api", Repo: "git@github.com:acme/api.git"}}
	fr := &fakeRunner{}
	s := newServer(t, cfg, fr)
	if w := assigned(5).send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Fatalf("shop: %d %s", w.Code, w.Body)
	}
	e := assigned(6)
	e.repo = "acme/api"
	if w := e.send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Fatalf("api: %d %s", w.Code, w.Body)
	}
	if len(fr.held) != 0 || len(fr.tasks) != 2 {
		t.Fatalf("held = %v, tasks = %d", fr.held, len(fr.tasks))
	}
	if got := fr.tasks[0]; got.Key != "shop-5" || got.Repo != "https://github.com/acme/shop.git" {
		t.Errorf("shop = %+v", got)
	}
	if got := fr.tasks[1]; got.Key != "API-6" || got.Repo != "git@github.com:acme/api.git" {
		t.Errorf("api = %+v", got)
	}
	// A Jira ticket without an entry is still held.
	if w := jiraAssign(s, "OPS-1", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "no repository is mapped") {
		t.Errorf("jira: %d %s", w.Code, w.Body)
	}
}

func TestGitHubCommentsStopsAndCloses(t *testing.T) {
	gh := githubtest.New(t)
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 1})
	cfg := githubConfig(gh)
	cfg.Sources.GitHub.AllowedFollowUps = []string{"assigner", "bob"}
	fr := &fakeRunner{assigners: map[string]string{"shop-1": "alice"}, plans: map[string]bool{"shop-1": true}}
	s := newServer(t, cfg, fr)
	comment := func(by, text string) ghEvent {
		return ghEvent{event: "issue_comment", action: "created", number: 1, sender: by, comment: text}
	}

	// A person's comment is a follow-up.
	if w := comment("alice", "Use the page under /account.").send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Fatalf("comment: %d %s", w.Code, w.Body)
	}
	if got := fr.tasks[0]; got.Source != "github" || got.Key != "shop-1" || got.Comment != "Use the page under /account." || got.Cause != task.CauseFollowUp || fr.addressed {
		t.Errorf("follow-up = %+v", got)
	}
	// What the bot writes wakes nobody up, and is no command.
	for _, text := range []string{"I have a question.", "/approve", "/stop"} {
		if w := comment(ghBot, text).send(s); w.Code != 200 || !strings.Contains(w.Body.String(), "comment by the bot") {
			t.Errorf("the bot wrote %q: %d %s", text, w.Code, w.Body)
		}
	}
	// Nor does someone who is not on the list; they are told once.
	for i := 0; i < 2; i++ {
		if w := comment("mallory", fmt.Sprintf("/approve %d", i)).send(s); w.Code != 200 || !strings.Contains(w.Body.String(), "the author is not allowed") {
			t.Errorf("mallory: %d %s", w.Code, w.Body)
		}
	}
	if got := waitIssueComments(gh, 1, 1); len(got) != 1 || !strings.Contains(got[0].Body, "mallory is not on the list") || got[0].Author != ghBot {
		t.Errorf("comments = %+v", got)
	}
	// A comment on an issue that is not the bot's is people talking.
	e := comment("alice", "Hello Bob.")
	e.unassigned = true
	if w := e.send(s); w.Code != 200 || w.Body.String() != "ignored\n" {
		t.Errorf("not assigned: %d %s", w.Code, w.Body)
	}
	if len(fr.tasks) != 1 || len(fr.approved) != 0 || len(fr.stopped) != 0 {
		t.Fatalf("tasks = %d, approved = %v, stopped = %v", len(fr.tasks), fr.approved, fr.stopped)
	}

	// The commands, as the first line of a comment by a person.
	if w := comment("bob", "/approve\nBut keep the old page.").send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "approved; queued ") {
		t.Errorf("approve: %d %s", w.Code, w.Body)
	}
	if len(fr.approved) != 1 || fr.approved[0] != "github:shop-1 by bob" || fr.tasks[1].Comment != "But keep the old page." {
		t.Errorf("approved = %v, comment %q", fr.approved, fr.tasks[1].Comment)
	}
	if w := comment("alice", "/stop").send(s); w.Code != 200 || w.Body.String() != "stopped shop-1\n" {
		t.Errorf("stop: %d %s", w.Code, w.Body)
	}
	if len(fr.stopped) != 1 || fr.stopped[0] != "github:shop-1 by alice, with /stop in a comment" {
		t.Errorf("stopped = %v", fr.stopped)
	}

	// Taking the issue away stops it too, whoever does it.
	if w := (ghEvent{event: "issues", action: "unassigned", number: 1, assignee: ghBot, sender: "carol", unassigned: true}).send(s); w.Code != 200 || w.Body.String() != "stopped shop-1\n" {
		t.Errorf("unassigned: %d %s", w.Code, w.Body)
	}
	if len(fr.stopped) != 2 || fr.stopped[1] != "github:shop-1 by carol, who took the ticket away from the digital employee" {
		t.Errorf("stopped = %v", fr.stopped)
	}

	// A close by the bot is no acceptance; a close by a person is.
	if w := (ghEvent{event: "issues", action: "closed", number: 1, sender: ghBot}).send(s); w.Code != 200 || !strings.Contains(w.Body.String(), "closed by the bot") {
		t.Errorf("closed by the bot: %d %s", w.Code, w.Body)
	}
	if len(fr.closed) != 0 {
		t.Fatalf("closed = %v", fr.closed)
	}
	if w := (ghEvent{event: "issues", action: "closed", number: 1, sender: "alice"}).send(s); w.Code != 200 || w.Body.String() != "closed shop-1\n" {
		t.Errorf("closed: %d %s", w.Code, w.Body)
	}
	if len(fr.closed) != 1 || fr.closed[0] != "github:shop-1" {
		t.Errorf("closed = %v", fr.closed)
	}
}

// A label moves a ticket to a higher tier, unless the bot put it there.
func TestGitHubLabelRaisesTheTier(t *testing.T) {
	pol, err := policy.Parse([]byte("tiers: [{name: low}, {name: high, labels: [risk-high]}]\ndefault_tier: low\nrules: [{source: github, issue_type: Pull Request, tier: high}]"))
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{}
	s := newServer(t, githubConfig(nil), fr)
	s.UsePolicy(pol)
	if w := assigned(1).send(s); w.Code != 200 || fr.tasks[0].Tier != "low" {
		t.Fatalf("assigned: %d %s", w.Code, w.Body)
	}
	fr.tiers = map[string]string{"shop-1": "low"}
	labeled := ghEvent{event: "issues", action: "labeled", number: 1, labels: []string{"risk-high"}, sender: ghBot}
	if w := labeled.send(s); w.Code != 200 || !strings.Contains(w.Body.String(), "changed by the bot") || len(fr.raised) != 0 {
		t.Errorf("labeled by the bot: %d %s, raised %v", w.Code, w.Body, fr.raised)
	}
	labeled.sender = "alice"
	if w := labeled.send(s); w.Code != 200 || !strings.Contains(w.Body.String(), "raised to high") {
		t.Errorf("labeled: %d %s", w.Code, w.Body)
	}
	if len(fr.raised) != 1 || fr.raised[0] != "github:shop-1 to high" {
		t.Errorf("raised = %v", fr.raised)
	}
	// The kind of the ticket is what a rule sees as its issue type.
	if w := (ghEvent{event: "pull_request", action: "assigned", number: 2, assignee: ghBot}).send(s); w.Code != 200 || fr.tasks[1].Tier != "high" {
		t.Errorf("a pull request: %d %s, tier %q", w.Code, w.Body, fr.tasks[1].Tier)
	}
}

// The issue is told how its runs go, with the token of the source.
func TestGitHubIssueIsTold(t *testing.T) {
	gh := githubtest.New(t)
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 4})
	fr := &fakeRunner{}
	s := newServer(t, githubConfig(gh), fr)
	ctx := context.Background()
	tk := &task.Task{Source: "github", Key: "shop-4", Attempt: 1}
	if err := s.Started(ctx, tk); err != nil {
		t.Fatal(err)
	}
	if err := s.Finished(ctx, tk, task.Result{Signal: result.NeedsInput, SignalMessage: "Which page do you mean?"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Finished(ctx, tk, task.Result{Err: fmt.Errorf("exit status 1"), ExitCode: 1, Message: "panic: ```"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Finished(ctx, tk, task.Result{Signal: result.Done, SignalMessage: "Fixed.", PRURL: "https://github.com/acme/shop/pull/9"}); err != nil {
		t.Fatal(err)
	}
	got := gh.IssueComments("acme", "shop", 4)
	if len(got) != 4 {
		t.Fatalf("comments = %+v", got)
	}
	for i, want := range []string{"started work on this ticket", "Which page do you mean?\n\nReply in a comment on this ticket", "The agent failed (exit 1): exit status 1\n\n```\npanic: '''\n```",
		"ready for review.\n\nFixed.\n\nPull request: https://github.com/acme/shop/pull/9"} {
		if !strings.Contains(got[i].Body, want) || got[i].Author != ghBot {
			t.Errorf("comment %d = %q by %s, want %q", i, got[i].Body, got[i].Author, want)
		}
	}
	s.tell("github", "shop-4", "The pull request was merged.", s.log)
	if got := waitIssueComments(gh, 4, 5); len(got) != 5 || got[4].Body != "The pull request was merged." {
		t.Errorf("tell: %+v", got)
	}
	if gh.Refused() != 0 {
		t.Errorf("GitHub refused %d requests", gh.Refused())
	}

	// Without the token the issue hears nothing, and that is no error.
	quiet := newServer(t, githubConfig(nil), fr)
	if err := quiet.Started(ctx, tk); err != nil {
		t.Errorf("Started without a token: %v", err)
	}
	if err := quiet.Finished(ctx, tk, task.Result{Signal: result.Done}); err != nil {
		t.Errorf("Finished without a token: %v", err)
	}
	if quiet.Tickets("github") != nil || s.Tickets("github") == nil {
		t.Error("the ticket tools have the GitHub tickets with the token only")
	}
}

// The poller starts an issue whose webhook was missed, and stops what is
// no longer the bot's.
func TestGitHubPoller(t *testing.T) {
	gh := githubtest.New(t)
	for n, by := range map[int]string{1: "alice", 2: ghBot, 3: "mallory"} {
		gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: n, Title: fmt.Sprintf("Issue %d", n), Author: "alice"})
		gh.Assign("acme", "shop", n, ghBot, by)
	}
	// Pull requests: one that the bot opened, one that a Jira ticket named
	// as its work, and one of a person.
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 4, Author: ghBot, Assignees: []string{ghBot}, PullRequest: true})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 5, Author: "agent-account", Assignees: []string{ghBot}, PullRequest: true})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 6, Author: "alice", PullRequest: true})
	gh.Assign("acme", "shop", 5, ghBot, "alice")
	gh.Assign("acme", "shop", 6, ghBot, "alice")
	cfg := githubConfig(gh)
	cfg.Sources.GitHub.AllowedAssigners = []string{"alice"}
	fr := &fakeRunner{pulls: []*store.PullRequest{{Source: "jira", Key: "DEV-1", URL: gh.URL + "/acme/shop/pull/5", State: store.PROpen}}}
	s := newServer(t, cfg, fr)
	ctx := context.Background()

	s.Poll(ctx)
	if len(fr.tasks) != 2 {
		t.Fatalf("tasks = %d, want the issue 1 and the pull request 6", len(fr.tasks))
	}
	if got := fr.tasks[0]; got.Source != "github" || got.Key != "shop-1" || got.Title != "Issue 1" || got.Actor != "alice" || got.Cause != task.CausePoll ||
		got.Repo != "https://"+gh.Host()+"/acme/shop.git" || got.Hold != "" {
		t.Errorf("task = %+v", got)
	}
	if fr.tasks[1].Key != "shop-6" {
		t.Errorf("second task = %+v", fr.tasks[1])
	}
	// A second round starts nothing again.
	s.Poll(ctx)
	if len(fr.tasks) != 2 {
		t.Fatalf("tasks after a second round = %d", len(fr.tasks))
	}

	// The issue is closed, the pull request taken away.
	gh.CloseIssue("acme", "shop", 1)
	gh.Unassign("acme", "shop", 6, ghBot)
	s.Poll(ctx)
	if len(fr.closed) != 1 || fr.closed[0] != "github:shop-1" {
		t.Errorf("closed = %v", fr.closed)
	}
	if len(fr.stopped) != 1 || !strings.HasPrefix(fr.stopped[0], "github:shop-6 by the orchestrator") {
		t.Errorf("stopped = %v", fr.stopped)
	}

	// Without the token GitHub is not asked.
	if got := newServer(t, githubConfig(nil), fr).trackerFor("github"); got != nil {
		t.Error("a source without a token has a tracker")
	}
}

// The gates of scheduling: a label counts only from a person, and what
// cannot be checked for GitHub is refused at the start.
func TestGitHubScheduling(t *testing.T) {
	labels, err := policy.Parse([]byte("tiers: [{name: normal}]\ndefault_tier: normal\nscheduling: {required_labels: [agent-ready]}"))
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := policy.Parse([]byte("tiers: [{name: normal}]\ndefault_tier: normal\nscheduling: {blocked_by: wait}"))
	if err != nil {
		t.Fatal(err)
	}
	gh := githubtest.New(t)
	fr := &fakeRunner{}
	// GitHub alone: the other sources have their own needs for a gate.
	only := func(cfg *config.Config) *config.Config {
		cfg.Sources.JiraWebhook.Enabled, cfg.Sources.JiraAutomation.Enabled, cfg.Sources.Linear.Enabled = false, false, false
		return cfg
	}
	s := newServer(t, only(githubConfig(gh)), fr)
	s.UsePolicy(blocked)
	if err := s.CheckScheduling(); err == nil || !strings.Contains(err.Error(), "cannot check for GitHub issues") {
		t.Errorf("blocked_by with the GitHub source: %v", err)
	}
	s.UsePolicy(labels)
	if err := s.CheckScheduling(); err != nil {
		t.Errorf("required_labels with a token: %v", err)
	}
	quiet := newServer(t, only(githubConfig(nil)), fr)
	quiet.UsePolicy(labels)
	if err := quiet.CheckScheduling(); err == nil || !strings.Contains(err.Error(), "sources.github needs its token") {
		t.Errorf("required_labels without a token: %v", err)
	}

	for n := 1; n <= 3; n++ {
		gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: n, Author: "alice"})
	}
	gh.Label("acme", "shop", 1, "Agent-Ready", "alice")
	gh.Label("acme", "shop", 2, "agent-ready", ghBot)
	for n := 1; n <= 3; n++ {
		e := assigned(n)
		e.labels = []string{"agent-ready"}
		if w := e.send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
			t.Fatalf("%d: %d %s", n, w.Code, w.Body)
		}
		// What the payload says about labels opens no gate.
		if hold, held := fr.hold("github", fmt.Sprintf("shop-%d", n)); !held || hold != store.HoldPending {
			t.Fatalf("%d: hold = %q, %v", n, hold, held)
		}
	}
	s.CheckHeld(context.Background(), false)
	for key, want := range map[string]string{
		"shop-1": "",
		"shop-2": "it needs the label agent-ready from a person (a label that the bot account added does not count)",
		"shop-3": "it needs the label agent-ready",
	} {
		if hold, _ := fr.hold("github", key); hold != want {
			t.Errorf("%s: hold = %q, want %q", key, hold, want)
		}
	}
	// The issue is told why it waits.
	if got := waitIssueComments(gh, 3, 1); len(got) != 1 || !strings.Contains(got[0].Body, "has not started work on shop-3 yet: it needs the label agent-ready") {
		t.Errorf("comments = %+v", got)
	}
	if fr.states["github:shop-1"] == ticket.None {
		t.Error("shop-1 is not known")
	}
}

// The conversation of a pull request that is itself a ticket reaches the
// agent through the webhook, and not a second time through the handoff.
func TestGitHubPullRequestTicketGetsACommentOnce(t *testing.T) {
	gh := githubtest.New(t)
	u := gh.Open(githubtest.PullRequest{Owner: "acme", Repo: "shop", Number: 8, HeadRef: "bot/shop-8", Author: "alice"})
	cfg := githubConfig(gh)
	cfg.GitHub.Token = githubtest.Token
	fr := &fakeRunner{pulls: []*store.PullRequest{{Source: "github", Key: "shop-8", URL: u, State: store.PROpen}}, states: map[string]ticket.State{"github:shop-8": ticket.InReview}}
	s := newServer(t, cfg, fr)
	s.UseGitHub(github.New(gh.URL, githubtest.Token))
	// The address of the fake site is not github.com.
	if !samePull(u, "http://"+gh.Host()+"/acme/shop/pull/8") || samePull(u, "http://"+gh.Host()+"/acme/shop/pull/80") {
		t.Fatal("samePull")
	}
	gh.Comment("acme", "shop", 8, githubtest.Comment{Kind: "issue", Author: "lead", Association: "MEMBER", Body: "Rebase it, please."})
	gh.Comment("acme", "shop", 8, githubtest.Comment{Kind: "diff", Author: "lead", Association: "MEMBER", Body: "This can be nil.", Path: "main.go"})

	// The webhook brings the comment of the conversation.
	if w := (ghEvent{event: "issue_comment", action: "created", number: 8, sender: "lead", comment: "Rebase it, please."}).send(s); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "queued ") {
		t.Fatalf("comment: %d %s", w.Code, w.Body)
	}
	// The handoff reads the same pull request, and passes on what the
	// webhook does not bring: the comment on the diff.
	s.PollPullRequests(context.Background())
	if len(fr.tasks) != 2 {
		t.Fatalf("tasks = %d, want the comment and the review comment", len(fr.tasks))
	}
	if got := fr.tasks[1].Comment; strings.Contains(got, "Rebase it") || !strings.Contains(got, "This can be nil.") {
		t.Errorf("the handoff passed on %q", got)
	}
}
