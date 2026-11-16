package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"ochell/internal/auth"
	"ochell/internal/config"
	ghapi "ochell/internal/github"
	"ochell/internal/github/githubtest"
	"ochell/internal/source"
	"ochell/internal/tracker"
)

const (
	secret = "github-secret"
	bot    = "digital-employee"
)

func testSource(token string) *Source {
	return New(config.GitHubSource{Enabled: true, Secret: secret, Token: token,
		Repos: []config.GitHubRepo{{Repo: "acme/shop"}, {Repo: "acme/web.site"}, {Repo: "other/shop", Project: "OTHER"}}},
		config.GitHub{BotLogin: bot})
}

func signed(event string, body []byte) http.Header {
	h := http.Header{}
	h.Set("X-GitHub-Event", event)
	h.Set("X-GitHub-Delivery", "d-1")
	h.Set("X-Hub-Signature-256", "sha256="+auth.SignHex(secret, body))
	return h
}

// GitHub's own example of a signed delivery.
func TestSignatureVector(t *testing.T) {
	const want = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	if got := "sha256=" + auth.SignHex("It's a Secret to Everybody", []byte("Hello, World!")); got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestReceiveSample(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/github-issue-assigned.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := testSource("").Receive(signed("issues", body), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != source.Assigned || ev.Key != "shop-12" || ev.Title != "The login page shows a blank screen" || ev.URL != "https://github.com/acme/shop/issues/12" ||
		ev.Repo != "https://github.com/acme/shop.git" || ev.Actor != "alice" || ev.Reporter != "alice" || !ev.Mine || ev.Delivery != "d-1" ||
		!slices.Equal(ev.Labels, []string{"bug"}) || ev.IssueType != TypeIssue || !ev.HasPriority || ev.Priority != 0 || ev.PullRequest != "" ||
		ev.Context != "The ticket is the issue #12 of the GitHub repository acme/shop." {
		t.Errorf("event = %+v", ev)
	}
}

func TestReceiveRefusesWhatIsNotSigned(t *testing.T) {
	body := []byte(`{"action":"assigned"}`)
	s := testSource("")
	for name, h := range map[string]http.Header{
		"no signature":    {"X-Github-Event": {"issues"}},
		"another secret":  {"X-Github-Event": {"issues"}, "X-Hub-Signature-256": {"sha256=" + auth.SignHex("other", body)}},
		"sha1":            {"X-Github-Event": {"issues"}, "X-Hub-Signature": {"sha1=00"}},
		"not a signature": {"X-Github-Event": {"issues"}, "X-Hub-Signature-256": {"sha256=zz"}},
	} {
		if _, err := s.Receive(h, body); !errors.Is(err, source.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want ErrUnauthorized", name, err)
		}
	}
	// Signed, and not something to read.
	for name, c := range map[string]struct{ event, body string }{
		"no event":      {"", `{}`},
		"a form":        {"issues", `payload=%7B%7D`},
		"no issue":      {"issues", `{"action":"assigned","repository":{"full_name":"acme/shop"}}`},
		"no repository": {"issues", `{"action":"assigned","issue":{"number":1}}`},
		"no comment":    {"issue_comment", `{"action":"created","issue":{"number":1},"repository":{"full_name":"acme/shop"}}`},
	} {
		h := signed(c.event, []byte(c.body))
		if c.event == "" {
			h.Del("X-GitHub-Event")
		}
		if _, err := s.Receive(h, []byte(c.body)); !errors.Is(err, source.ErrBadPayload) {
			t.Errorf("%s: err = %v, want ErrBadPayload", name, err)
		}
	}
}

// delivery builds the body of a webhook.
type delivery struct {
	action, repo   string
	number         int
	pr             bool
	author         string
	assignees      []string
	assignee       string
	sender         string
	comment, by    string
	labels         []string
	issueType      string
	commentOnAPull bool
}

func (d delivery) body(event string) []byte {
	if d.repo == "" {
		d.repo = "acme/shop"
	}
	if d.number == 0 {
		d.number = 7
	}
	if d.author == "" {
		d.author = "alice"
	}
	if d.sender == "" {
		d.sender = "alice"
	}
	kind := "issues"
	if d.pr || d.commentOnAPull {
		kind = "pull"
	}
	is := map[string]any{"number": d.number, "title": "A title", "html_url": fmt.Sprintf("https://github.com/%s/%s/%d", d.repo, kind, d.number),
		"user": map[string]string{"login": d.author}}
	var as []map[string]string
	for _, a := range d.assignees {
		as = append(as, map[string]string{"login": a})
	}
	is["assignees"] = as
	var ls []map[string]string
	for _, l := range d.labels {
		ls = append(ls, map[string]string{"name": l})
	}
	is["labels"] = ls
	if d.issueType != "" {
		is["type"] = map[string]string{"name": d.issueType}
	}
	if d.commentOnAPull {
		is["pull_request"] = map[string]string{"url": "x"}
	}
	p := map[string]any{"action": d.action, "repository": map[string]string{"full_name": d.repo}, "sender": map[string]string{"login": d.sender}}
	if event == "pull_request" {
		p["pull_request"] = is
	} else {
		p["issue"] = is
	}
	if d.assignee != "" {
		p["assignee"] = map[string]string{"login": d.assignee}
	}
	if event == "issue_comment" {
		by := d.by
		if by == "" {
			by = d.sender
		}
		p["comment"] = map[string]any{"id": 99, "body": d.comment, "user": map[string]string{"login": by}}
	}
	raw, _ := json.Marshal(p)
	return raw
}

func TestReceive(t *testing.T) {
	s := testSource("")
	for name, c := range map[string]struct {
		event string
		d     delivery
		kind  source.Kind
		// key is the key of the ticket; why a part of Event.Why.
		key, why string
		refused  bool
		check    func(*source.Event) bool
	}{
		"issue assigned to the bot": {event: "issues", d: delivery{action: "assigned", assignee: bot, assignees: []string{bot}}, kind: source.Assigned, key: "shop-7"},
		"the login in another case": {event: "issues", d: delivery{action: "assigned", assignee: "Digital-Employee"}, kind: source.Assigned, key: "shop-7"},
		"a name with a dot":         {event: "issues", d: delivery{action: "assigned", assignee: bot, repo: "acme/web.site"}, kind: source.Assigned, key: "web_site-7"},
		"a project of its own":      {event: "issues", d: delivery{action: "assigned", assignee: bot, repo: "Other/Shop", number: 123456789}, kind: source.Assigned, key: "OTHER-123456789"},
		"assigned to someone else":  {event: "issues", d: delivery{action: "assigned", assignee: "bob"}, kind: source.Ignored, key: "shop-7", why: "someone else"},
		"not a configured repository": {event: "issues", d: delivery{action: "assigned", assignee: bot, repo: "acme/secrets"}, kind: source.Ignored,
			why: "acme/secrets is not one of sources.github.repos", refused: true},
		"the same name under another owner": {event: "issues", d: delivery{action: "assigned", assignee: bot, repo: "evil/shop"}, kind: source.Ignored, why: "not one of", refused: true},
		"unassigned from the bot":           {event: "issues", d: delivery{action: "unassigned", assignee: bot}, kind: source.Unassigned, key: "shop-7"},
		"someone else unassigned":           {event: "issues", d: delivery{action: "unassigned", assignee: "bob", assignees: []string{bot}}, kind: source.Ignored, key: "shop-7"},
		"closed":                            {event: "issues", d: delivery{action: "closed", sender: "bob"}, kind: source.Closed, key: "shop-7", check: func(ev *source.Event) bool { return ev.Actor == "bob" }},
		"deleted":                           {event: "issues", d: delivery{action: "deleted"}, kind: source.Closed, key: "shop-7"},
		"reopened":                          {event: "issues", d: delivery{action: "reopened"}, kind: source.Ignored, key: "shop-7", why: "issue was reopened"},
		"labeled": {event: "issues", d: delivery{action: "labeled", labels: []string{"bug", "payments"}, issueType: "Bug"}, kind: source.Updated, key: "shop-7",
			check: func(ev *source.Event) bool {
				return slices.Equal(ev.Labels, []string{"bug", "payments"}) && ev.IssueType == "Bug"
			}},
		"a comment": {event: "issue_comment", d: delivery{action: "created", comment: "Use the other page.", by: "bob", assignees: []string{"carol", bot}}, kind: source.Commented, key: "shop-7",
			check: func(ev *source.Event) bool {
				return ev.Comment == "Use the other page." && ev.Actor == "bob" && ev.Mine && ev.Reporter == "alice"
			}},
		"a comment on an issue of someone else": {event: "issue_comment", d: delivery{action: "created", comment: "Hi.", assignees: []string{"carol"}}, kind: source.Commented, key: "shop-7",
			check: func(ev *source.Event) bool { return !ev.Mine }},
		"a comment that was edited": {event: "issue_comment", d: delivery{action: "edited", comment: "Hi."}, kind: source.Ignored, key: "shop-7"},
		"a comment on the bot's own pull request": {event: "issue_comment", d: delivery{action: "created", comment: "Please add a test.", commentOnAPull: true, author: bot, assignees: []string{bot}},
			kind: source.Ignored, key: "shop-7", why: "follows the pull request"},
		"a comment on a pull request that is a ticket": {event: "issue_comment", d: delivery{action: "created", comment: "Rebase it.", commentOnAPull: true, assignees: []string{bot}}, kind: source.Commented, key: "shop-7",
			check: func(ev *source.Event) bool { return ev.PullRequest == "https://github.com/acme/shop/pull/7" }},
		"pull request assigned to the bot": {event: "pull_request", d: delivery{action: "assigned", assignee: bot, pr: true}, kind: source.Assigned, key: "shop-7",
			check: func(ev *source.Event) bool {
				return ev.IssueType == TypePullRequest && ev.PullRequest == "https://github.com/acme/shop/pull/7" && strings.Contains(ev.Context, "pull request #7")
			}},
		"the bot's own pull request assigned to it": {event: "pull_request", d: delivery{action: "assigned", assignee: bot, pr: true, author: bot}, kind: source.Ignored, key: "shop-7",
			why: "not a new ticket", refused: true},
		"a review is requested":    {event: "pull_request", d: delivery{action: "review_requested", pr: true}, kind: source.Ignored, key: "shop-7"},
		"a pull request is closed": {event: "pull_request", d: delivery{action: "closed", pr: true}, kind: source.Closed, key: "shop-7"},
		"a push to a pull request": {event: "pull_request", d: delivery{action: "synchronize", pr: true}, kind: source.Ignored, key: "shop-7"},
		"ping":                     {event: "ping", d: delivery{}, kind: source.Ignored, why: "ping"},
		"a push":                   {event: "push", d: delivery{}, kind: source.Ignored, why: "push"},
	} {
		body := c.d.body(c.event)
		ev, err := s.Receive(signed(c.event, body), body)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ev.Kind != c.kind || ev.Key != c.key || !strings.Contains(ev.Why, c.why) || ev.Refused != c.refused || (c.check != nil && !c.check(ev)) {
			t.Errorf("%s: event = %+v", name, ev)
		}
	}
}

func TestBot(t *testing.T) {
	s := testSource("")
	if !s.Bot(bot) || !s.Bot("DIGITAL-employee") || s.Bot("") || s.Bot("alice") || s.Bot(bot+"2") {
		t.Error("Bot")
	}
}

// fake returns a source that asks a fake GitHub.
func fake(t *testing.T) (*Source, *githubtest.Server) {
	gh := githubtest.New(t)
	s := testSource(githubtest.IssuesToken)
	s.UseAPI(ghapi.New(gh.URL, githubtest.IssuesToken))
	return s, gh
}

func TestWithoutAToken(t *testing.T) {
	s := testSource("")
	if s.Tracker() != nil || s.Tickets() != nil {
		t.Error("a source without a token cannot be asked")
	}
	if err := s.Tell(context.Background(), "shop-1", "Hello."); !errors.Is(err, source.ErrSilent) {
		t.Errorf("Tell = %v, want ErrSilent", err)
	}
	if err := s.CheckGates(false, false); err != nil {
		t.Errorf("no gate: %v", err)
	}
	if err := s.CheckGates(true, false); err == nil || !strings.Contains(err.Error(), "sources.github.token") {
		t.Errorf("required_labels without a token: %v", err)
	}
}

func TestCheckGates(t *testing.T) {
	s, _ := fake(t)
	if err := s.CheckGates(true, false); err != nil {
		t.Errorf("required_labels with a token: %v", err)
	}
	if err := s.CheckGates(false, true); err == nil || !strings.Contains(err.Error(), "blocked_by") {
		t.Errorf("blocked_by: %v", err)
	}
}

func TestAssigned(t *testing.T) {
	s, gh := fake(t)
	ctx := context.Background()
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 1, Title: "One", Author: "alice", Labels: []string{"bug"}, Assignees: []string{bot}})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 2, Title: "Someone else's", Assignees: []string{"bob"}})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 3, Title: "Closed", Assignees: []string{bot}, Closed: true})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 4, Title: "A pull request of a person", Author: "alice", Assignees: []string{bot}, PullRequest: true})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 5, Title: "The bot's own pull request", Author: bot, Assignees: []string{bot}, PullRequest: true})
	gh.AddIssue(githubtest.Issue{Owner: "other", Repo: "shop", Number: 1, Title: "Typed", Type: "Bug", Assignees: []string{bot}})
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "secrets", Number: 1, Title: "Not configured", Assignees: []string{bot}})
	got, err := s.Assigned(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, is := range got {
		keys = append(keys, is.Key+" "+is.Type)
	}
	if want := []string{"shop-1 Issue", "shop-4 Pull Request", "OTHER-1 Bug"}; !slices.Equal(keys, want) {
		t.Fatalf("Assigned = %q, want %q", keys, want)
	}
	if is := got[0]; is.Title != "One" || is.URL != gh.URL+"/acme/shop/issues/1" || !slices.Equal(is.Labels, []string{"bug"}) || is.Repo != "https://github.com/acme/shop.git" || is.PullRequest != "" {
		t.Errorf("issue = %+v", is)
	}
	if got[1].PullRequest != gh.URL+"/acme/shop/pull/4" {
		t.Errorf("pull request = %+v", got[1])
	}

	// A long list is read to its end.
	for n := 100; n < 250; n++ {
		gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "web.site", Number: n, Assignees: []string{bot}})
	}
	if got, err = s.Assigned(ctx); err != nil || len(got) != 153 {
		t.Errorf("a long list: %d issues, %v", len(got), err)
	}
	// And one that is too long is an error, not a part of it.
	for n := 250; n < 1101; n++ {
		gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "web.site", Number: n, Assignees: []string{bot}})
	}
	if _, err = s.Assigned(ctx); err == nil || !strings.Contains(err.Error(), "more than 1000") {
		t.Errorf("a list that is too long: %v", err)
	}
}

func TestAssignerLookupAndScheduling(t *testing.T) {
	s, gh := fake(t)
	ctx := context.Background()
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 1, Author: "alice", Labels: []string{"from-the-start"}})
	if who, err := s.Assigner(ctx, "shop-1"); err != nil || who != nil {
		t.Errorf("never assigned: %v, %v", who, err)
	}
	gh.Assign("acme", "shop", 1, bot, "alice")
	gh.Assign("acme", "shop", 1, "carol", "dave")
	if who, err := s.Assigner(ctx, "shop-1"); err != nil || !slices.Equal(who, []string{"alice"}) {
		t.Errorf("Assigner = %v, %v", who, err)
	}
	gh.Unassign("acme", "shop", 1, bot)
	gh.Assign("acme", "shop", 1, bot, "bob")
	if who, _ := s.Assigner(ctx, "shop-1"); !slices.Equal(who, []string{"bob"}) {
		t.Errorf("Assigner after a second assignment = %v", who)
	}

	if st, err := s.Lookup(ctx, "shop-1"); err != nil || st.Closed || st.Unassigned {
		t.Errorf("Lookup = %+v, %v", st, err)
	}
	gh.Unassign("acme", "shop", 1, bot)
	if st, _ := s.Lookup(ctx, "shop-1"); st.Closed || !st.Unassigned {
		t.Errorf("unassigned: %+v", st)
	}
	gh.CloseIssue("acme", "shop", 1)
	if st, _ := s.Lookup(ctx, "shop-1"); !st.Closed {
		t.Errorf("closed: %+v", st)
	}
	if st, err := s.Lookup(ctx, "shop-404"); err != nil || !st.Closed {
		t.Errorf("gone: %+v, %v", st, err)
	}
	if _, err := s.Lookup(ctx, "nowhere-1"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("a key of no repository: %v", err)
	}

	gh.Label("acme", "shop", 1, "ready", "alice")
	gh.Label("acme", "shop", 1, "approved", bot)
	sch, err := s.Scheduling(ctx, "shop-1")
	if err != nil || sch.Priority != 0 || sch.PriorityName != "" || len(sch.BlockedBy) != 0 || len(sch.Labels) != 3 {
		t.Fatalf("Scheduling = %+v, %v", sch, err)
	}
	for i, want := range []tracker.Label{{Name: "from-the-start", By: []string{"alice"}}, {Name: "ready", By: []string{"alice"}}, {Name: "approved", By: []string{bot}, Bot: true}} {
		if got := sch.Labels[i]; got.Name != want.Name || !slices.Equal(got.By, want.By) || got.Bot != want.Bot {
			t.Errorf("label %d = %+v, want %+v", i, got, want)
		}
	}
	if _, err := s.Scheduling(ctx, "shop-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("Scheduling of an issue that is gone: %v", err)
	}
}

func TestTicketAndComment(t *testing.T) {
	s, gh := fake(t)
	ctx := context.Background()
	gh.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 9, Title: "Fix it", Body: "The page is blank.", Author: "alice", Labels: []string{"bug"}})
	tk, err := s.Ticket(ctx, "shop-9")
	if err != nil || tk.Key != "shop-9" || tk.Title != "Fix it" || tk.Description != "The page is blank." || tk.Status != "open" || len(tk.Comments) != 0 {
		t.Fatalf("Ticket = %+v, %v", tk, err)
	}
	for i := 0; i < 130; i++ {
		gh.CommentIssue("acme", "shop", 9, "alice", fmt.Sprintf("comment %d", i))
	}
	if err := s.Comment(ctx, "shop-9", "I am on it."); err != nil {
		t.Fatal(err)
	}
	tk, err = s.Ticket(ctx, "shop-9")
	if err != nil || len(tk.Comments) != tracker.MaxComments || tk.MoreComments != 131-tracker.MaxComments {
		t.Fatalf("Ticket with many comments: %d comments, %d more, %v", len(tk.Comments), tk.MoreComments, err)
	}
	if first, last := tk.Comments[0], tk.Comments[len(tk.Comments)-1]; first.Body != "comment 101" || first.Bot || last.Body != "I am on it." || !last.Bot || last.Author != bot {
		t.Errorf("comments from %+v to %+v", first, last)
	}
	if _, err := s.Ticket(ctx, "shop-404"); !errors.Is(err, tracker.ErrNotFound) {
		t.Errorf("a ticket that is gone: %v", err)
	}

	// A token of another account writes nothing: its comment would come
	// back as a person's.
	other, gh2 := fake(t)
	gh2.Login = "alice"
	gh2.AddIssue(githubtest.Issue{Owner: "acme", Repo: "shop", Number: 9})
	if err := other.Tell(ctx, "shop-9", "Hello."); err == nil || !strings.Contains(err.Error(), "is not the digital employee's") {
		t.Errorf("Tell with another account's token: %v", err)
	}
	if got := gh2.IssueComments("acme", "shop", 9); len(got) != 0 {
		t.Errorf("comments = %+v, want none", got)
	}
}

func TestPullRequestOf(t *testing.T) {
	s := testSource("")
	if got := s.PullRequestOf("OTHER-4"); got != "https://github.com/other/shop/pull/4" {
		t.Errorf("PullRequestOf = %q", got)
	}
	for _, key := range []string{"DEV-4", "shop", "shop-x", "shop-0", "-4"} {
		if got := s.PullRequestOf(key); got != "" {
			t.Errorf("PullRequestOf(%q) = %q, want none", key, got)
		}
	}
}
